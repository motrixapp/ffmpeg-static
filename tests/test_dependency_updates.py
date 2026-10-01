from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import apply_musl_patches as musl  # noqa: E402
import audit_action_dependencies as dependencies  # noqa: E402
import pipeline_lib  # noqa: E402
import validate_action_review as reviews  # noqa: E402


class DependencyUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.review = json.loads((ROOT / "security/action-risk-review.json").read_text())
        self.today = dt.date.fromisoformat(self.review["reviewedAt"])
        self.references = set(self.review["actionReferences"])

    def approved_review(self) -> dict:
        result = copy.deepcopy(self.review)
        result["status"] = "approved"
        result["reviewedBy"] = "test-maintainer"
        result["decision"] = "Test fixture only, not a production approval."
        return result

    def test_recorded_approval_and_blocked_fixture(self) -> None:
        reviews.validate(self.review, self.references, self.today)
        reviews.validate_scope(self.review, ROOT / ".github/workflows", ROOT / "sources.env",
                               self.review["releaseTag"], ROOT / "security/action-reachability-review.json")
        self.assertEqual(self.review["releaseTag"], "v9.0.2-motrix.1")
        self.assertEqual(self.review["reviewedBy"], "agalwood")
        blocked = copy.deepcopy(self.review)
        blocked["status"] = "blocked"
        with self.assertRaisesRegex(ValueError, "formal release blocked"):
            reviews.validate(blocked, self.references, self.today)

    def test_call_path_assessment_covers_every_advisory_and_exact_input(self) -> None:
        evidence = json.loads((ROOT / "security/action-reachability-review.json").read_text())
        report_data = (ROOT / "security/action-dependency-audit.json").read_bytes()
        report = json.loads(report_data)
        self.assertEqual(evidence["schemaVersion"], 1)
        self.assertEqual(evidence["status"], "assessment-only")
        self.assertEqual(evidence["reviewedAt"], self.review["reviewedAt"])
        self.assertEqual(evidence["auditReportSha256"], hashlib.sha256(report_data).hexdigest())
        self.assertEqual(evidence["actionReferences"], self.review["actionReferences"])
        self.assertEqual(set(evidence["bundles"]), self.references)
        self.assertEqual(evidence["releaseTag"], pipeline_lib.release_tag(pipeline_lib.load_sources()))
        self.assertEqual(evidence["sourceLockSha256"], hashlib.sha256((ROOT / "sources.env").read_bytes()).hexdigest())
        for workflow, digest in evidence["workflowSha256"].items():
            self.assertEqual(digest, hashlib.sha256((ROOT / workflow).read_bytes()).hexdigest())
        self.assertEqual(set(evidence["workflowSha256"]), {
            ".github/workflows/ci.yml", ".github/workflows/dependency-audit.yml",
            ".github/workflows/release.yml",
        })
        records = evidence["advisories"]
        ids = [item["id"] for item in records]
        self.assertEqual(ids, sorted(set(self.review["advisories"])))
        for record in records:
            expected = [
                {"action": finding["action"], "package": finding["package"],
                 "version": finding["version"]}
                for finding in report["findings"]
                if any(item["id"] == record["id"] for item in finding["advisories"])
            ]
            self.assertEqual(record["affected"], expected)
            severities = {
                item["severity"] for finding in report["findings"]
                for item in finding["advisories"] if item["id"] == record["id"]
            }
            self.assertEqual(severities, {record["severity"]})
            self.assertEqual(record["url"], "https://github.com/advisories/" + record["id"])
            self.assertTrue(record["summary"])
            self.assertTrue(record["upstreamRanges"])
            group = evidence["groups"][record["group"]]
            for field in ("assessment", "controls", "residualRisk", "evidence"):
                self.assertTrue(group[field])
        self.assertIn("not complete dynamic", evidence["limitations"][0])
        self.assertIn("Authority is only the separately recorded", evidence["decision"])
        self.assertEqual(self.review["status"], "approved")
        self.assertEqual(self.review["assessmentSha256"], hashlib.sha256(
            (ROOT / "security/action-reachability-review.json").read_bytes()).hexdigest())

    def test_approval_cannot_be_reused_for_another_tag_lock_workflow_or_assessment(self) -> None:
        def check(review: dict, tag: str | None = None, sources: Path | None = None,
                  assessment: Path | None = None) -> None:
            reviews.validate_scope(review, ROOT / ".github/workflows", sources or ROOT / "sources.env",
                                   tag or review["releaseTag"], assessment or ROOT / "security/action-reachability-review.json")

        with self.assertRaisesRegex(ValueError, "different release tag"):
            check(self.review, "v9.0.2-motrix.2")
        for field, value, error in (
            ("sourceLockSha256", "0" * 64, "source lock differs"),
            ("assessmentSha256", "0" * 64, "assessment differs"),
            ("workflowSha256", {}, "workflow inputs differ"),
        ):
            review = copy.deepcopy(self.review)
            review[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, error):
                check(review)
        with tempfile.TemporaryDirectory() as directory:
            sources = Path(directory) / "sources.env"
            sources.write_bytes((ROOT / "sources.env").read_bytes() + b"\n# scope probe\n")
            with self.assertRaisesRegex(ValueError, "source lock differs"):
                check(self.review, sources=sources)
            assessment = Path(directory) / "assessment.json"
            data = (ROOT / "security/action-reachability-review.json").read_bytes()
            assessment.write_bytes(data + b" ")
            with self.assertRaisesRegex(ValueError, "assessment differs"):
                check(self.review, assessment=assessment)
            obj = json.loads(data)
            obj["advisories"] = obj["advisories"][:-1]
            changed = json.dumps(obj).encode()
            assessment.write_bytes(changed)
            review = copy.deepcopy(self.review)
            review["assessmentSha256"] = hashlib.sha256(changed).hexdigest()
            with self.assertRaisesRegex(ValueError, "every approved advisory"):
                check(review, assessment=assessment)

    def test_review_binds_exact_actions_and_fresh_dates(self) -> None:
        review = self.approved_review()
        reviews.validate(review, self.references, self.today)
        with self.assertRaisesRegex(ValueError, "exact workflow commits"):
            reviews.validate(review, self.references | {"actions/cache@" + "a" * 40}, self.today)
        end = dt.date.fromisoformat(review["validUntil"])
        for day in (self.today - dt.timedelta(days=1), end + dt.timedelta(days=1)):
            with self.subTest(day=day), self.assertRaisesRegex(ValueError, "expired"):
                reviews.validate(review, self.references, day)

    def test_review_fails_closed_on_tampering(self) -> None:
        mutations = (
            {"schemaVersion": True}, {"schemaVersion": 1}, {"schemaVersion": 3}, {"status": True},
            {"auditReportSha256": "not-a-hash"},
            {"status": "Approved"}, {"reviewedBy": " "}, {"decision": ""},
            {"validUntil": "2027-01-01"}, {"reviewedAt": "20260930"},
            {"actionReferences": self.review["actionReferences"] * 2},
            {"advisories": ["not-an-advisory"]}, {"advisories": [True]},
            {"advisories": self.review["advisories"] * 2}, {"extra": "bypass"},
            {"reviewedBy": "pending-maintainer-review"}, {"releaseTag": "latest"},
            {"sourceLockSha256": "bad"}, {"assessmentSha256": "bad"},
            {"workflowSha256": {}}, {"workflowSha256": {"../ci.yml": "0" * 64}},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                review = self.approved_review()
                review.update(mutation)
                reviews.validate(review, self.references, self.today)

    def test_review_binds_complete_advisory_evidence_not_a_subset(self) -> None:
        review = self.approved_review()
        data = (ROOT / "security/action-dependency-audit.json").read_bytes()
        reviews.validate_report(review, data, self.references)
        with self.assertRaisesRegex(ValueError, "reviewed hash"):
            reviews.validate_report(review, data + b" ", self.references)
        review["advisories"] = review["advisories"][:-1]
        with self.assertRaisesRegex(ValueError, "every inventoried advisory"):
            reviews.validate_report(review, data, self.references)
        review = self.approved_review()
        review["reviewedAt"] = (self.today + dt.timedelta(days=1)).isoformat()
        with self.assertRaisesRegex(ValueError, "review date"):
            reviews.validate_report(review, data, self.references)

    def test_release_review_runs_before_cache_tag_binding_or_any_signing(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        step = workflow.split("      - name: Require a current review of Action dependency risks", 1)[1]
        gate = step.split("      - name:", 1)[0]
        self.assertIn("if: ${{ steps.release.outputs.formal_release == 'true' }}", gate)
        self.assertIn("--review security/action-risk-review.json", gate)
        self.assertIn("--workflows .github/workflows", gate)
        self.assertIn("--sources release-subject/sources.env", gate)
        self.assertIn('--release-tag "$REVIEW_RELEASE_TAG"', gate)
        self.assertIn("--assessment security/action-reachability-review.json", gate)
        self.assertNotIn("continue-on-error", gate)
        gate_index = workflow.index("scripts/validate_action_review.py")
        for marker in ("Bind requested remote tag", "uses: actions/cache@", "environment: macos-release-signing",
                       "environment: release-manifest-signing", "environment: github-release"):
            self.assertLess(gate_index, workflow.index(marker))

    def test_runtime_inventory_keeps_nested_versions_but_excludes_dev_only(self) -> None:
        lock = {"lockfileVersion": 3, "packages": {
            "": {"version": "1.0.0"},
            "node_modules/brace-expansion": {"version": "5.0.9"},
            "node_modules/glob/node_modules/brace-expansion": {"version": "2.1.4"},
            "node_modules/@actions/core": {"version": "2.0.0"},
            "node_modules/test": {"version": "1.0.0", "dev": True},
        }}
        self.assertEqual(dependencies.runtime_packages(lock), {
            ("brace-expansion", "5.0.9"), ("brace-expansion", "2.1.4"), ("@actions/core", "2.0.0")})

    def test_runtime_inventory_rejects_unqueryable_or_empty_inputs(self) -> None:
        for lock in ({}, {"lockfileVersion": 1, "packages": {}}, {"lockfileVersion": 3, "packages": {}},
                     {"lockfileVersion": 3, "packages": {"node_modules/test": {"version": "git:unlocked"}}},
                     {"lockfileVersion": 3, "packages": {"node_modules/test": {"version": "1.0.0", "link": True}}}):
            with self.subTest(lock=lock), self.assertRaises(ValueError):
                dependencies.runtime_packages(lock)

    def test_advisory_pagination_withdrawals_and_severity(self) -> None:
        live = {"ghsa_id": "GHSA-qhr7-859c-m2p7", "severity": "high", "withdrawn_at": None}
        withdrawn = dict(live, ghsa_id="GHSA-6j4f-fj2g-mc7p", withdrawn_at="2026-09-30")
        with mock.patch.object(dependencies, "gh_json", return_value=[[live], [withdrawn]]) as query:
            result = dependencies.package_advisories("brace-expansion", "5.0.9")
            self.assertEqual([item["id"] for item in result], [live["ghsa_id"]])
            arguments = query.call_args.args[0]
            self.assertIn("affects=brace-expansion@5.0.9", arguments)
            self.assertIn("--paginate", arguments)
        for value in (None, {}, [], [None], [[{}]], [[dict(live, severity="unknown")]]):
            with self.subTest(value=value), mock.patch.object(dependencies, "gh_json", return_value=value):
                with self.assertRaises(ValueError):
                    dependencies.package_advisories("test", "1.0.0")

    def test_musl_patches_are_locked_and_published_with_application_script(self) -> None:
        sources = pipeline_lib.load_sources()
        for filename, key in musl.PATCHES:
            self.assertEqual(hashlib.sha256((ROOT / "patches" / filename).read_bytes()).hexdigest(), sources[key])
        build = (ROOT / "scripts/build.sh").read_text()
        self.assertLess(build.index("apply_musl_patches.py"), build.index('log "building authenticated musl'))
        self.assertIn("apply_musl_patches.py", (ROOT / "scripts/fetch-sources.sh").read_text())
        spec = importlib.util.spec_from_file_location("assemble_release_updates", ROOT / "scripts/assemble-release.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for filename, _ in musl.PATCHES:
            self.assertIn("patches/" + filename, module.BUILD_PIPELINE_FILES)
        self.assertIn("scripts/apply_musl_patches.py", module.BUILD_PIPELINE_FILES)
        self.assertIn("security/action-risk-review.json", module.BUILD_PIPELINE_FILES)

    def test_every_new_musl_digest_is_strictly_validated(self) -> None:
        original = (ROOT / "sources.env").read_text()
        sources = pipeline_lib.load_sources()
        for key in [key for _, key in musl.PATCHES] + [key for _, key in musl.RESULTS]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                source_lock = Path(temporary) / "sources.env"
                source_lock.write_text(original.replace(key + "=" + sources[key], key + "=invalid"))
                with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
                    pipeline_lib.load_sources(source_lock)

    def musl_fixture(self, directory: Path) -> tuple[Path, Path, dict]:
        root = directory / "musl"
        (root / "src/locale").mkdir(parents=True)
        (root / "src/stdlib").mkdir()
        (root / "src/locale/iconv.c").write_bytes(b"old iconv\n")
        (root / "src/stdlib/qsort.c").write_bytes(b"old qsort\n")
        patches = directory / "patches"
        patches.mkdir()
        sources = {}
        for filename, key in musl.PATCHES:
            data = ("fixture " + filename).encode()
            (patches / filename).write_bytes(data)
            sources[key] = hashlib.sha256(data).hexdigest()
        for _, key in musl.RESULTS:
            sources[key] = hashlib.sha256(b"patched\n").hexdigest()
        return root, patches, sources

    def test_musl_rejects_patch_tampering_before_child_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, patches, sources = self.musl_fixture(Path(temporary))
            (patches / musl.PATCHES[0][0]).write_bytes(b"tampered")
            with mock.patch.object(musl.subprocess, "run") as child:
                with self.assertRaisesRegex(ValueError, "patch hash mismatch"):
                    musl.apply(root, sources, patches)
                child.assert_not_called()

    def test_musl_rejects_fuzzy_offset_failed_or_repeated_application(self) -> None:
        for output, status in ((b"Hunk succeeded with offset 1", 0), (b"fuzz 1", 0), (b"FAILED", 1)):
            with self.subTest(output=output), tempfile.TemporaryDirectory() as temporary:
                root, patches, sources = self.musl_fixture(Path(temporary))
                result = subprocess.CompletedProcess([], status, output)
                with mock.patch.object(musl.subprocess, "run", return_value=result):
                    with self.assertRaisesRegex(ValueError, "did not apply exactly"):
                        musl.apply(root, sources, patches)
        with tempfile.TemporaryDirectory() as temporary:
            root, patches, sources = self.musl_fixture(Path(temporary))
            (root / "src/locale/gb18030utf.h").write_bytes(b"exists")
            with self.assertRaisesRegex(ValueError, "fresh unpatched"):
                musl.apply(root, sources, patches)

    def test_musl_verifies_patched_bytes_and_refuses_symlink_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, _, sources = self.musl_fixture(Path(temporary))
            for relative, _ in musl.RESULTS:
                (root / relative).write_bytes(b"patched\n")
            musl.verify_results(root, sources)
            (root / "src/locale/iconv.c").write_bytes(b"wrong")
            with self.assertRaisesRegex(ValueError, "source hash mismatch"):
                musl.verify_results(root, sources)
            (root / "src/locale/iconv.c").unlink()
            (root / "src/locale/gb18030utf.h").unlink()
            (root / "src/locale").rmdir()
            (root / "src/locale").symlink_to(root / "src/stdlib", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "unsafe musl source directory"):
                musl.verify_results(root, sources)

    def test_llvm_size_exception_is_hash_bound_and_not_global(self) -> None:
        common = (ROOT / "scripts/common.sh").read_text()
        self.assertIn("local maximum_total_size=2147483648", common)
        self.assertIn('if [[ "$expected_sha256" == "$LLVM_RUNTIME_SHA256" ]]; then', common)
        self.assertIn("maximum_total_size=2415919104", common)
        self.assertIn("maximum_member_size = 256 * 1024 * 1024", common)

    def test_patch_byte_preservation_keeps_existing_line_ending_policy(self) -> None:
        attributes = (ROOT / ".gitattributes").read_text()
        self.assertIn("* text=auto", attributes)
        for extension in ("env", "json", "md", "py", "ps1", "sh", "txt", "yaml", "yml", "asc"):
            self.assertIn(f"*.{extension} text eol=lf", attributes)
        exceptions = [line for line in attributes.splitlines() if "-whitespace" in line]
        self.assertEqual(set(exceptions), {
            "patches/musl-CVE-2026-6042.patch -text -whitespace",
            "patches/musl-CVE-2026-40200.patch -text -whitespace",
        })

    def test_windows_loader_compatibility_preserves_security_and_os_contract(self) -> None:
        sources = pipeline_lib.load_sources()
        for target in ("win32-x64", "win32-arm64"):
            arguments = pipeline_lib.expected_configure_args(target, sources)
            joined = " ".join(arguments)
            self.assertIn("--major-subsystem-version,6,--minor-subsystem-version,2", joined)
            self.assertIn("--major-os-version,10,--minor-os-version,0", joined)
            for flag in ("-mguard=cf", "-fstack-protector-strong", "--nxcompat", "--dynamicbase",
                         "--high-entropy-va", "-D_WIN32_WINNT=0x0A00", "-DWINVER=0x0A00"):
                self.assertIn(flag, joined)
        verifier = (ROOT / "scripts/verify-binary.sh").read_text()
        self.assertIn("'MajorSubsystemVersion: 6'", verifier)
        self.assertIn("'MinorSubsystemVersion: 2'", verifier)

    def test_reused_artifacts_cannot_satisfy_required_native_ci_checks(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        job = workflow.split("  windows-native-smoke:", 1)[1]
        self.assertIn("inputs.windows_artifact_run_id != '' && 'Diagnostic native unsigned smoke'", job)
        self.assertIn("|| 'Native unsigned smoke'", job)
        self.assertNotIn("WriteAllBytes", job)


if __name__ == "__main__":
    unittest.main()
