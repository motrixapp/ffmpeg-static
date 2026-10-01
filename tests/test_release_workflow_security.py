from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseWorkflowSecurityTests(unittest.TestCase):
    def test_windows_ci_parses_the_current_native_contract_not_removed_docs(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        native = workflow.split("  windows-native-smoke:\n", 1)[1]
        self.assertIn("Parse the native Windows smoke contract", native)
        self.assertIn(
            "$contract = Get-Content -LiteralPath scripts/motrix-media-smoke.ps1 -Raw",
            native,
        )
        self.assertIn("[scriptblock]::Create($contract) | Out-Null", native)
        self.assertNotIn("SECURITY.md -Raw", native)
        self.assertNotIn("$blocks", native)
        self.assertIn("Get-AuthenticodeSignature", native)
        self.assertIn("'NotSigned'", native)
        self.assertIn("-FFmpegPath $ffmpeg", native)
        self.assertIn("-FFprobePath $ffprobe", native)

    def test_inline_python_is_isolated_and_signing_secrets_are_not_exported(self) -> None:
        for workflow_path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            workflow = workflow_path.read_text(encoding="utf-8")
            for line_number, line in enumerate(workflow.splitlines(), start=1):
                if "python" in line and "<<'PY'" in line:
                    self.assertIn(
                        "-I",
                        line,
                        f"non-isolated Python heredoc at {workflow_path}:{line_number}",
                    )
            self.assertNotRegex(
                workflow,
                r"(?m)(?<![/A-Za-z0-9_])(?:python3|python)[ \t]+-(?:c\b|[ \t]*<<)",
                f"non-isolated inline Python in {workflow_path}",
            )

        signer = (ROOT / "scripts/sign-macos.sh").read_text(encoding="utf-8")
        self.assertIn("isolated_python=/usr/bin/python3", signer)
        self.assertIn("export -n MAC_CERTS MAC_CERTS_PASSWORD", signer)
        self.assertIn('"$isolated_python" -I -c', signer)
        self.assertLess(
            signer.index("export -n MAC_CERTS MAC_CERTS_PASSWORD"),
            signer.index('"$isolated_python" -I -c'),
        )
        self.assertLess(signer.index("unset MAC_CERTS\n"), signer.index("chmod 600"))
        self.assertLess(
            signer.index("unset MAC_CERTS_PASSWORD"),
            signer.index("security set-key-partition-list"),
        )

        notary = (ROOT / "scripts/notarize-macos.sh").read_text(encoding="utf-8")
        self.assertIn("isolated_python=/usr/bin/python3", notary)
        self.assertIn("export -n API_KEY API_KEY_ID API_KEY_ISSUER_ID", notary)
        self.assertEqual(notary.count('"$isolated_python" -I '), 2)

        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        immutable_policy = release.split(
            "      - name: Require repository immutable releases policy\n", 1
        )[1].split(
            "      - name: Create draft, verify exact remote assets, and publish\n", 1
        )[0]
        self.assertLess(
            immutable_policy.index("unset GH_TOKEN"),
            immutable_policy.index("/usr/bin/python3 -I - <<'PY'"),
        )

        system_python = Path("/usr/bin/python3")
        self.assertTrue(system_python.is_file(), "trusted system Python is unavailable")
        with tempfile.TemporaryDirectory() as temporary_directory:
            shadow = Path(temporary_directory)
            (shadow / "base64.py").write_text(
                "raise RuntimeError('repository base64 shadow loaded')\n",
                encoding="utf-8",
            )
            (shadow / "sitecustomize.py").write_text(
                "raise RuntimeError('repository sitecustomize loaded')\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = temporary_directory
            result = subprocess.run(
                [
                    str(system_python),
                    "-I",
                    "-c",
                    "import base64, json; assert base64.b64decode(b'QQ==') == b'A'",
                ],
                cwd=temporary_directory,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_clean_environment_helpers_execute_under_system_bash_with_nounset(self) -> None:
        build = (ROOT / "scripts/build.sh").read_text(encoding="utf-8")
        run_clean = build.split("run_clean() {\n", 1)[1].split(
            "\n}\n\nrun_with_x264_assembler()", 1
        )[0]
        run_x264 = build.split("run_with_x264_assembler() {\n", 1)[1].split(
            "\n}\n\ncapture_version()", 1
        )[0]
        probe = f"""set -Eeuo pipefail
SAFE_HOME=/private/tmp
SAFE_TMP=/private/tmp
BUILD_PATH=/usr/bin:/bin
SOURCE_DATE_EPOCH=1700000000
DEPLOYMENT_TARGET=
TARGET_NODE_ARCH=arm64
run_clean() {{
{run_clean}
}}
run_with_x264_assembler() {{
{run_x264}
}}
run_clean /usr/bin/true
if run_with_x264_assembler /usr/bin/env | /usr/bin/grep -q '^AS='; then exit 31; fi
TARGET_NODE_ARCH=x64
run_with_x264_assembler /usr/bin/env | /usr/bin/grep -q '^AS=nasm$'
DEPLOYMENT_TARGET=12.0
run_clean /usr/bin/env | /usr/bin/grep -q '^MACOSX_DEPLOYMENT_TARGET=12.0$'
"""
        result = subprocess.run(
            ["/bin/bash", "-c", probe], check=False, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        if sys.platform == "darwin":
            version = subprocess.check_output(["/bin/bash", "--version"], text=True)
            self.assertIn("version 3.2", version.splitlines()[0])

    def test_x64_nasm_is_source_locked_and_runner_packages_cannot_supply_it(self) -> None:
        build = (ROOT / "scripts/build.sh").read_text(encoding="utf-8")
        fetch = (ROOT / "scripts/fetch-sources.sh").read_text(encoding="utf-8")
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn('download_verified "$NASM_URL"', fetch)
        self.assertIn('building authenticated NASM ${NASM_VERSION}', build)
        self.assertIn("PERL=false PYTHON3=false", build)
        self.assertIn("FFMPEG_CONFIGURE_ARGS+=(--x86asmexe=nasm)", build)
        self.assertIn("run_clean AS=nasm", build)
        self.assertIn("NASM_BINARY_SHA256=$(sha256_file", build)
        self.assertNotRegex(ci, r"brew install[^\n]*\bnasm\b")
        self.assertNotRegex(release, r"brew install[^\n]*\bnasm\b")
        self.assertNotRegex(ci, r"(?m)^\s+nasm \\\s*$")
        self.assertNotRegex(release, r"(?m)^\s+nasm \\\s*$")

    def test_macos_keeps_a_deterministic_content_uuid(self) -> None:
        build = (ROOT / "scripts/build.sh").read_text(encoding="utf-8")
        contract = (ROOT / "scripts/pipeline_lib.py").read_text(encoding="utf-8")
        verifier = (ROOT / "scripts/verify-binary.sh").read_text(encoding="utf-8")
        self.assertNotIn("-Wl,-no_uuid", build)
        self.assertNotIn("-Wl,-no_uuid", contract)
        self.assertIn("Mach-O must contain exactly one LC_UUID command", verifier)
        self.assertIn("Mach-O LC_UUID value is invalid", verifier)

    def test_macos_requires_linker_adhoc_baseline_before_native_ci_smoke(self) -> None:
        build = (ROOT / "scripts/build.sh").read_text(encoding="utf-8")
        contract = (ROOT / "scripts/pipeline_lib.py").read_text(encoding="utf-8")
        self.assertIn("-Wl,-dead_strip,-adhoc_codesign", build)
        self.assertIn("-Wl,-dead_strip,-adhoc_codesign", contract)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/verify_macho_codesign_delta.py --unsigned-only", workflow)

    def test_x64_staging_preserves_read_only_nasm_for_every_verification_phase(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        for step, next_step in (
            ("Stage exact signing input", "Upload signing input"),
            ("Stage exact independent rebuild result", "Upload independent clean rebuild"),
        ):
            stage = workflow.split(f"      - name: {step}\n", 1)[1].split(
                f"\n      - name: {next_step}", 1
            )[0]
            self.assertIn('if [[ "$TARGET" == *-x64 ]]', stage)
            self.assertIn('! -L "build/${TARGET}/work/nasm/bin/nasm"', stage)
            self.assertIn('install -m 0644 "build/${TARGET}/work/nasm/bin/nasm"', stage)
        mac = workflow.split("\n  macos-signed-smoke:\n", 1)[1].split(
            "\n  windows-signed-smoke:\n", 1
        )[0]
        self.assertIn('expected.add("work/nasm/bin/nasm")', mac)
        self.assertLess(
            mac.index('install -m 0644 "build/unsigned/${TARGET}/work/nasm/bin/nasm"'),
            mac.index('scripts/verify-binary.sh "$TARGET"'),
        )
        windows = workflow.split("\n  windows-signed-structural:\n", 1)[1].split(
            "\n  assemble:\n", 1
        )[0]
        self.assertIn('expected_unsigned.add("work/nasm/bin/nasm")', windows)
        self.assertIn('destination.chmod(0o644)', windows)
        self.assertNotIn('bin/nasm" --', workflow)

    def test_macos_runtime_checks_use_the_strict_shared_parser(self) -> None:
        signer = (ROOT / "scripts/sign-macos.sh").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("validate_codesign_hardened_runtime", signer)
        self.assertGreaterEqual(
            workflow.count("validate_codesign_hardened_runtime"), 4
        )
        self.assertNotIn("'$1 == \"flags\"", signer)
        self.assertNotIn("'$1 == \"flags\"", workflow)
        self.assertNotIn('r"^flags=(.+)$"', workflow)
        self.assertIn(
            '--extract-certificates="$signed_certificate_prefix"', signer
        )
        self.assertIn('--extract-certificates="$cert_dir/cert"', workflow)
        self.assertNotRegex(signer, r"--extract-certificates[ \t]+")
        self.assertNotRegex(workflow, r"--extract-certificates[ \t]+")
        self.assertIn("signed binary certificate does not match", signer)
        self.assertNotIn('find-certificate -c "$identity_label"', signer)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS codesign")
    def test_codesign_certificate_extraction_option_binding_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            certificate_prefix = Path(temporary_directory) / "certificate"
            result = subprocess.run(
                [
                    "/usr/bin/codesign",
                    "--display",
                    f"--extract-certificates={certificate_prefix}",
                    "/bin/ls",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("No such file or directory", result.stdout)

    def test_binary_verifier_uses_its_defined_target_architecture(self) -> None:
        verifier = (ROOT / "scripts/verify-binary.sh").read_text(encoding="utf-8")
        self.assertIn('TARGET_ARCH=${TARGET#*-}', verifier)
        self.assertIn('"$disassembly_file" "$fail_address" "$TARGET_ARCH"', verifier)
        self.assertNotIn("TARGET_NODE_ARCH", verifier)

    def test_annotated_tag_name_and_raw_object_are_bound_twice(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("scripts/validate_release_tag.py"), 2)
        self.assertEqual(workflow.count('git cat-file tag "$direct"'), 2)
        self.assertEqual(workflow.count('--tag "$RELEASE_TAG" --object-sha "$direct" --commit'), 2)

    def test_signed_windows_job_loads_hyphenated_archive_validator_explicitly(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertNotIn("from assemble_release import", workflow)
        self.assertIn(
            'spec_from_file_location(\n              "motrix_assemble_release", module_path',
            workflow,
        )
        marker = '          python3 -I - "$TARGET" <<\'PY\'\n'
        body = workflow.split(marker, 1)[1].split("\n          PY", 1)[0]
        script = textwrap.dedent(body)
        loader_prefix = script.split("\ntarget = sys.argv[1]", 1)[0]
        previous = Path.cwd()
        try:
            os.chdir(ROOT)
            exec(compile(loader_prefix, "windows-structural-loader", "exec"), {})
        finally:
            os.chdir(previous)

    def test_signers_require_and_recompute_independent_presign_approvals(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        mac = workflow.split("\n  sign-and-notarize-macos:\n", 1)[1].split(
            "\n  resolve-release-artifacts:\n", 1
        )[0]
        self.assertIn("      - macos-presign-approval\n", mac)
        self.assertIn("      - resolve-rebuild-inputs\n", mac)
        self.assertIn("input_digest:", mac)
        self.assertIn("rebuild_digest:", mac)
        self.assertIn('--rebuild-dir "build/rebuild/${TARGET}"', mac)
        self.assertLess(
            mac.index("--verify-approval"), mac.index("MAC_CERTS: ${{ secrets.MAC_CERTS }}")
        )

        windows = workflow.split("\n  sign-windows:\n", 1)[1]
        self.assertIn("      - windows-presign-static-approval\n", windows)
        self.assertIn("      - windows-presign-native-approval\n", windows)
        self.assertIn("      - resolve-rebuild-inputs\n", windows)
        self.assertIn('--rebuild-dir "build/rebuild/$($env:TARGET)"', windows)
        self.assertEqual(windows.count("--verify-approval $approval"), 1)
        self.assertLess(
            windows.index("--verify-approval $approval"),
            windows.index("Package unchanged verified Windows binaries"),
        )

    def test_final_grants_exist_only_after_all_secret_free_approval_jobs(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        coordinator = workflow.split("\n  finalize-signing-grants:\n", 1)[1].split(
            "\n  sign-and-notarize-macos:\n", 1
        )[0]
        for required_job in (
            "macos-presign-approval",
            "windows-presign-static-approval",
            "windows-presign-native-approval",
        ):
            self.assertIn(f"      - {required_job}\n", coordinator)
        self.assertIn("Resolve every completed approval against the run API", coordinator)
        self.assertIn("actions/artifacts/{artifact_id}", coordinator)
        self.assertEqual(coordinator.count("--write-grant \"$grant\""), 1)
        self.assertEqual(coordinator.count("id: upload-grant-"), 6)

        mac = workflow.split("\n  sign-and-notarize-macos:\n", 1)[1].split(
            "\n  resolve-release-artifacts:\n", 1
        )[0]
        windows = workflow.split("\n  sign-windows:\n", 1)[1]
        for signer in (mac, windows):
            self.assertIn("      - finalize-signing-grants\n", signer)
            self.assertIn("--verify-grant", signer)
            self.assertNotIn("name: presign-approval-${{ matrix.target }}", signer)
            if signer is mac:
                self.assertLess(signer.index("--verify-grant"), signer.index("secrets."))
            else:
                self.assertNotIn("secrets.", signer)
                self.assertLess(signer.index("--verify-grant"), signer.index("Package unchanged"))
        self.assertIn("artifact-ids: ${{ matrix.grant_id }}", mac)
        self.assertIn("artifact-ids: ${{ matrix.static_grant_id }}", windows)
        self.assertIn("artifact-ids: ${{ matrix.native_grant_id }}", windows)

        pipeline_files = (ROOT / "scripts/assemble-release.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"scripts/finalize_signing_grant.py"', pipeline_files)
        staging = workflow.split(
            "      - name: Stage authenticated build and redistributable source inputs", 1
        )[1].split("\n      - name: Upload authenticated core sources", 1)[0]
        self.assertIn("finalize_signing_grant.py", staging)

    def test_windows_signing_input_carries_static_link_evidence(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        staging = workflow.split("      - name: Stage exact signing input\n", 1)[1].split(
            "\n      - name: Upload signing input", 1
        )[0]
        upload = workflow.split("      - name: Upload signing input\n", 1)[1].split(
            "\n      - name: Record signing input artifact binding", 1
        )[0]
        self.assertIn('if [[ "$PLATFORM" == win32 ]]', staging)
        for evidence in (
            "ffmpeg.map",
            "ffmpeg.link-trace.txt",
            "ffprobe.map",
            "ffprobe.link-trace.txt",
        ):
            self.assertIn(evidence, staging)
        self.assertIn("build/signing-input/${{ matrix.target }}/", upload)

        approval = workflow.split("\n  windows-presign-static-approval:\n", 1)[
            1
        ].split("\n  windows-presign-native-approval:\n", 1)[0]
        self.assertLess(
            approval.index('"build/${TARGET}/payload/ffmpeg.exe"'),
            approval.index('scripts/verify-binary.sh "$TARGET"'),
        )

    def test_presign_provenance_uses_separate_bound_clean_rebuild(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        rebuild = workflow.split("\n  rebuild-signing-inputs:\n", 1)[1].split(
            "\n  resolve-rebuild-inputs:\n", 1
        )[0]
        self.assertIn('scripts/fetch-sources.sh "$TARGET"', rebuild)
        self.assertIn('scripts/build.sh "$TARGET"', rebuild)
        self.assertIn("id: upload-rebuild", rebuild)
        self.assertIn("independent-rebuild-binding-${{ matrix.target }}", rebuild)

        resolver = workflow.split("\n  resolve-rebuild-inputs:\n", 1)[1].split(
            "\n  macos-presign-approval:\n", 1
        )[0]
        self.assertIn('api(f"actions/artifacts/{record[\'artifactId\']}")', resolver)
        self.assertIn("rebuild artifact API binding mismatch", resolver)

        for job, next_job in (
            ("macos-presign-approval", "windows-presign-static-approval"),
            ("windows-presign-static-approval", "windows-presign-native-approval"),
        ):
            body = workflow.split(f"\n  {job}:\n", 1)[1].split(
                f"\n  {next_job}:\n", 1
            )[0]
            self.assertNotIn("scripts/build.sh", body)
            self.assertIn("--rebuild-artifact-id", body)
            self.assertIn("--rebuild-artifact-digest", body)

    def test_windows_project_signing_is_isolated_and_required_before_publication(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertNotIn("WINDOWS_CERTS", workflow)
        self.assertNotIn("scripts/resolve-signtool.ps1", workflow)
        windows = workflow.split("\n  sign-windows:\n", 1)[1]
        self.assertNotIn("secrets.", windows)
        self.assertIn("Package unchanged verified Windows binaries", windows)
        signer = workflow.split("\n  sign-manifest:\n", 1)[1].split("\n  attest:", 1)[0]
        self.assertIn("environment: release-manifest-signing", signer)
        self.assertIn("FFMPEG_MANIFEST_PRIVATE_KEY: ${{ secrets.FFMPEG_MANIFEST_PRIVATE_KEY }}", signer)
        self.assertIn("python3 scripts/sign_release_manifest.py sign", signer)
        self.assertNotIn("scripts/build.sh", signer)
        self.assertNotIn("scripts/motrix-media-smoke", signer)
        for job, next_job in (("attest", "publish"), ("publish", "sign-windows")):
            body = workflow.split(f"\n  {job}:\n", 1)[1].split(f"\n  {next_job}:\n", 1)[0]
            self.assertIn("      - sign-manifest\n", body)
            self.assertIn("needs.sign-manifest.outputs.artifact-id", body)
            self.assertIn("sign_release_manifest.py verify", body)
        self.assertIn('--windows-project-signature', workflow)
        self.assertIn('for name in expected_archive - generated:', workflow)
        self.assertIn('cmp "build/unsigned/', workflow)

    def test_publish_resumes_only_an_exact_unchanged_draft(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        publish = workflow.split("\n  publish:\n", 1)[1].split(
            "\n  sign-windows:\n", 1
        )[0]
        self.assertIn("validate_resumable_draft()", publish)
        self.assertIn("resolve_release_endpoint()", publish)
        self.assertNotIn("gh release view", publish)
        self.assertIn("release_api --paginate --slurp", publish)
        self.assertIn('print("absent")', publish)
        self.assertIn('if [[ "$release_lookup" == absent ]]', publish)
        self.assertLess(
            publish.index('if [[ "$release_lookup" == absent ]]'),
            publish.index('gh release create "$RELEASE_TAG"'),
        )
        self.assertGreaterEqual(publish.count("validate_github_release_identity"), 2)
        self.assertIn('state=os.environ["EXPECTED_RELEASE_STATE"]', publish)
        self.assertIn('state="draft"', publish)
        self.assertIn("existing draft asset differs", publish)
        self.assertNotIn('--target "$EVENT_COMMIT"', publish)
        self.assertGreaterEqual(publish.count('target_commitish="main"'), 2)
        self.assertNotIn("--generate-notes", publish)
        self.assertNotIn("gh release upload", publish)
        self.assertIn(
            'upload_endpoint="https://uploads.github.com/repos/${REPOSITORY}/releases/${release_id}/assets"',
            publish,
        )
        self.assertIn('release_api --method POST "$upload_endpoint"', publish)
        self.assertIn('release_api --method DELETE \\\n                "repos/${REPOSITORY}/releases/assets/${asset_id}"', publish)
        self.assertIn("starter assets remained after exact-ID cleanup", publish)
        self.assertNotIn(
            'repos/${REPOSITORY}/releases/tags/${RELEASE_TAG}', publish
        )
        patch = publish.split('release_api --method PATCH "$release_endpoint"', 1)[1].split(
            '>"${RUNNER_TEMP}/published-release.json"', 1
        )[0]
        for field in (
            '-f "tag_name=$RELEASE_TAG"',
            '-f "name=FFmpeg ${RELEASE_VERSION} for Motrix"',
            '-f "body=$release_body"',
            "-f make_latest=true",
            "-F draft=false",
            "-F prerelease=false",
        ):
            self.assertIn(field, patch)
        self.assertNotIn("discussion_category_name", patch)
        self.assertNotIn("target_commitish", patch)
        self.assertIn(
            'verify_release_file "${RUNNER_TEMP}/published-release.json" \\\n            "$release_id" publishing "$release_body"',
            publish,
        )
        self.assertIn(
            'verify_remote_assets \\\n            "$release_endpoint" "$release_id" published "$release_body"',
            publish,
        )
        self.assertGreaterEqual(publish.count("          verify_remote_tag\n"), 3)
        self.assertIn('release_api "repos/${REPOSITORY}/releases/latest"', publish)
        self.assertIn(
            'verify_release_file "${RUNNER_TEMP}/latest-release.json"', publish
        )
        self.assertIn('if [[ "$release_state" == published ]]', publish)
        self.assertIn(
            'verify_release_file "${RUNNER_TEMP}/release.json"', publish
        )
        self.assertIn(
            "existing Release is neither a mutable draft nor immutable", publish
        )
        self.assertIn("release_api()", publish)
        self.assertIn("X-GitHub-Api-Version: 2026-03-10", publish)

    def test_documented_checksum_lookup_requires_one_exact_entry(self) -> None:
        document = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertNotIn('grep "  ${asset}$" SHA256SUMS', document)
        self.assertIn('substr($0, 67) == name', document)
        self.assertIn('END { exit !(matches == 1) }', document)

    def test_documented_provenance_binds_manifest_tag_and_control_commit(self) -> None:
        document = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("ffmpeg-manifest.json", document)
        self.assertIn("releaseTagObjectSha", document)
        self.assertNotIn("MOTRIX_RELEASE_TAG_SIGNER_FINGERPRINT", document)
        self.assertNotIn("MOTRIX_RELEASE_TAG_SIGNING_PUBLIC_KEY", document)
        self.assertIn('verify-manifest --directory . --tag "$tag"', document)
        self.assertIn("[.targets[] | select(.archive == $asset)]", document)
        self.assertIn("manifest_asset_sha", document)
        self.assertIn("manifest_asset_size", document)
        self.assertNotIn(".verification.signature", document)
        self.assertNotIn(".verification.payload", document)
        self.assertIn('.object | select(.type == "tag") | .sha', document)
        self.assertIn('test "$remote_tag_object" = "$tag_object"', document)
        self.assertIn('git/tags/$tag_object', document)
        self.assertIn('--source-digest "$control_commit"', document)
        self.assertNotIn("v9.0.1-motrix.1", document)
        self.assertNotIn("ffmpeg-9.0.1-motrix.1", document)

    def test_documented_release_source_set_names_lock_and_public_key(self) -> None:
        document = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        self.assertIn("sources.env", document)
        self.assertIn("ffmpeg-release-signing-key.asc", document)

    def test_documented_platform_signature_verification_is_executable(self) -> None:
        document = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        shell_blocks = re.findall(
            r"^```bash\n(.*?)^```$", document, flags=re.MULTILINE | re.DOTALL
        )
        self.assertEqual(len(shell_blocks), 2)
        shell_parse = subprocess.run(
            ["bash", "-n"],
            input="\n".join(shell_blocks),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(shell_parse.returncode, 0, shell_parse.stdout)
        for required in (
            "common Release, tag, provenance, manifest, size, and",
            "not sufficient by itself",
            "Git Bash or WSL",
            ".identity.teamId | select",
            ".identity.certificateSha256 | select",
            "codesign --verify --strict --verbose=4",
            'codesign --display --extract-certificates="$certificate_prefix"',
            'codesign -vvvv -R="notarized" --check-notarization',
            "uncompressed_size",
            "268435456",
            "head -c 268435457",
            "actual_uncompressed_size",
            "notarization.developerLog",
            "MOTRIX_MANIFEST_VERIFIER",
            "verify-manifest --directory . --tag",
            "pinned Ed25519",
            "not Authenticode",
            "never official releases",
        ):
            self.assertIn(required, document)
        self.assertIn("The ZIP container itself is not code-signed", document)
        self.assertNotRegex(document, r"--extract-certificates[ \t]+")
        self.assertNotIn("$inputStream.CopyTo", document)
        self.assertNotIn("MOTRIX_MACOS_TEAM_ID", document)
        self.assertNotIn("MOTRIX_MACOS_CERT_SHA256", document)
        self.assertLess(document.index('verify-manifest --directory . --tag "$tag"'),
                        document.index(".identity.teamId | select"))

    def test_public_trust_is_ed25519_while_internal_apple_checks_remain(self) -> None:
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("not\nApple Team IDs or certificate fingerprints", security)
        self.assertIn("not confidential", contributing)
        self.assertIn("EXPECTED_MACOS_TEAM_ID: ${{ vars.EXPECTED_MACOS_TEAM_ID }}", workflow)
        self.assertIn("EXPECTED_MACOS_CERT_SHA256: ${{ vars.EXPECTED_MACOS_CERT_SHA256 }}", workflow)
        self.assertIn("scripts/sign-macos.sh", workflow)
        self.assertIn("scripts/notarize-macos.sh", workflow)

    def test_first_release_requires_an_out_of_band_ed25519_trust_page(self) -> None:
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        for document in (contributing, security):
            self.assertIn("Motrix-controlled HTTPS trust page", document)
            self.assertIn("Ed25519 manifest public key", document)
            self.assertIn("append-only identity history", document)
            self.assertIn("first public Release", document)
        normalized_contributing = " ".join(contributing.split())
        self.assertIn(
            "exact canonical URL in `SECURITY.md`", normalized_contributing
        )
        self.assertIn("exact deployed URL", " ".join(security.split()))

    def test_deployed_trust_reference_does_not_approve_action_risks(self) -> None:
        import hashlib
        import json

        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("https://motrix.app/manual/ffmpeg/", security)
        self.assertIn("https://motrix.app/zh/manual/ffmpeg/", security)
        for name in ("README.md", "README.zh-CN.md", "CONTRIBUTING.md"):
            self.assertRegex(
                (ROOT / name).read_text(encoding="utf-8"),
                r"https://motrix\.app/(?:zh/)?manual/ffmpeg/",
            )
        report = (ROOT / "security/action-dependency-audit.json").read_bytes()
        review = json.loads((ROOT / "security/action-risk-review.json").read_bytes())
        self.assertIn("does not approve these risks", security)
        self.assertIn("explicit maintainer", security)
        self.assertEqual(review["releaseTag"], "v9.0.2-motrix.8")
        self.assertEqual(review["auditReportSha256"], hashlib.sha256(report).hexdigest())

    def test_public_readmes_are_user_facing_download_guides(self) -> None:
        documents = {
            "README.md": (ROOT / "README.md").read_text(encoding="utf-8"),
            "README.zh-CN.md": (ROOT / "README.zh-CN.md").read_text(
                encoding="utf-8"
            ),
        }
        targets = (
            "darwin-arm64",
            "darwin-x64",
            "linux-arm64",
            "linux-x64",
            "win32-arm64",
            "win32-x64",
        )
        for document in documents.values():
            for target in targets:
                self.assertIn(target, document)
            self.assertIn("SECURITY.md#verify-a-download", document)
            self.assertIn("https://ffmpeg.org/download.html", document)
            self.assertIn("https://ffmpeg.org/legal.html", document)
            self.assertIn("Fabrice Bellard", document)
            self.assertIn("GPL-2.0-or-later", document)
            self.assertIn("Windows ARM64", document)
            self.assertNotIn("MOTRIX_RELEASE_TAG_SIGNER_FINGERPRINT", document)
            self.assertNotIn("MOTRIX_RELEASE_TAG_SIGNING_PUBLIC_KEY", document)
            self.assertNotIn("--source-digest", document)
            self.assertLess(len(document.splitlines()), 300)
        mappings = (
            "`darwin-arm64` | `...-darwin-arm64.zip` | macOS 12.0",
            "`darwin-x64` | `...-darwin-x64.zip` | macOS 12.0",
            "`linux-arm64` | `...-linux-arm64.tar.gz` | Linux kernel 3.7.0",
            "`linux-x64` | `...-linux-x64.tar.gz` | Linux kernel 2.6.39",
            "`win32-arm64` | `...-win32-arm64.zip` | Windows 10.0",
            "`win32-x64` | `...-win32-x64.zip` | Windows 10.0",
        )
        for document in documents.values():
            for mapping in mappings:
                self.assertIn(mapping, document)
        self.assertIn("not bundled with Motrix", documents["README.md"])
        self.assertIn("not official", documents["README.md"])
        self.assertIn("FFmpeg builds", documents["README.md"])
        self.assertIn("Every platform must first pass", documents["README.md"])
        normalized_english = " ".join(documents["README.md"].split())
        self.assertIn("ZIP container is not code-signed", normalized_english)
        self.assertIn("not affiliated", documents["README.md"])
        self.assertIn("patent", documents["README.md"])
        self.assertIn("not legal advice", documents["README.md"])
        self.assertIn("provided **as is**", documents["README.md"])
        self.assertIn("complete mingw-w64 upstream tree is referenced", documents["README.md"])
        self.assertNotIn("Complete corresponding source archives", documents["README.md"])
        self.assertIn("不会随 Motrix 一同分发", documents["README.zh-CN.md"])
        self.assertIn("不是 FFmpeg 官方构建", documents["README.zh-CN.md"])
        self.assertIn("所有平台都必须先完成", documents["README.zh-CN.md"])
        self.assertIn("ZIP 容器本身不做代码签名", documents["README.zh-CN.md"])
        self.assertIn("不存在隶属", documents["README.zh-CN.md"])
        self.assertIn("专利", documents["README.zh-CN.md"])
        self.assertIn("不构成法律建议", documents["README.zh-CN.md"])
        self.assertIn("按**现状**提供", documents["README.zh-CN.md"])
        self.assertIn("完整 mingw-w64 上游源码树只引用而不镜像", documents["README.zh-CN.md"])

        package_contract = (ROOT / "scripts/pipeline_lib.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("complete corresponding source archives", package_contract)
        self.assertIn("corresponding-source archives", package_contract)

    def test_signing_gate_artifacts_cover_human_approval_latency(self) -> None:
        release = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        upload_count = release.count("uses: actions/upload-artifact@")
        retentions = [
            line.strip()
            for line in release.splitlines()
            if line.strip().startswith("retention-days:")
        ]
        self.assertEqual(upload_count, 24)
        self.assertEqual(retentions, ["retention-days: 36"] * upload_count)


if __name__ == "__main__":
    unittest.main()
