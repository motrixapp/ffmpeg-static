"""Exercise the actual protected workflow bodies on native Windows, without Secrets."""

from __future__ import annotations

import ast
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".github/workflows/release.yml"
RISK_STEP = "Recheck risk approval after waiting and before privileged work"
PWSH = shutil.which("pwsh")


def job_text(path: Path, job: str) -> str:
    """Read only the repository's deliberately simple block-form YAML."""
    match = re.search(r"^  " + re.escape(job) + r":\n(.*?)(?=^  [\w-]+:|\Z)",
                      path.read_text(encoding="utf-8"), re.M | re.S)
    if match is None:
        raise AssertionError(f"missing job {job}")
    return match.group(1)


def run_steps(job: str) -> list[tuple[str, str, str]]:
    steps = []
    for match in re.finditer(r"^      - name: ([^\n]+)\n(.*?)(?=^      - |\Z)", job, re.M | re.S):
        name, block = match.groups()
        body = re.search(r"^        run: \|\n((?:          [^\n]*\n|\n)+)", block, re.M)
        if body is not None:
            shell = re.search(r"^        shell: (\S+)$", block, re.M)
            steps.append((name, shell.group(1) if shell else "", textwrap.dedent(body.group(1))))
    return steps


def risk_step() -> tuple[str, str]:
    matches = [(shell, body) for name, shell, body in run_steps(job_text(RELEASE, "sign-windows"))
               if name == RISK_STEP]
    if len(matches) != 1:
        raise AssertionError("expected exactly one Windows risk recheck")
    return matches[0]


class WindowsReleaseContractTests(unittest.TestCase):
    def test_risk_recheck_is_native_isolated_and_precedes_payload(self) -> None:
        shell, body = risk_step()
        self.assertEqual(shell, "pwsh")
        for fragment in ("Set-StrictMode -Version Latest", "'-I', 'scripts/validate_action_review.py'",
                         "'--review', 'security/action-risk-review.json'",
                         "'--audit-report', 'security/action-dependency-audit.json'",
                         "'--workflows', '.github/workflows'", "'--sources', 'sources.env'",
                         "'--release-tag', $env:REVIEW_RELEASE_TAG",
                         "'--assessment', 'security/action-reachability-review.json'",
                         "& python @riskArguments", "if ($LASTEXITCODE -ne 0) { throw"):
            self.assertIn(fragment, body)
        self.assertNotIn("/usr/bin/python", body)
        self.assertNotIn("Invoke-Expression", body)
        job = job_text(RELEASE, "sign-windows")
        self.assertLess(job.index(RISK_STEP), job.index("Download bound unsigned Windows payload"))

    def test_packaging_flags_match_the_real_command_line_parser(self) -> None:
        tree = ast.parse((ROOT / "scripts/package-artifact.py").read_text(encoding="utf-8"))
        flags = {arg.value for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument"
                 for arg in node.args if isinstance(arg, ast.Constant) and isinstance(arg.value, str)}
        steps = run_steps(job_text(RELEASE, "sign-windows"))
        body = next(body for name, _, body in steps if name == "Package unchanged verified Windows binaries")
        self.assertIn("& python -I scripts/package-artifact.py", body)
        used = set(re.findall(r"(?<!\w)--[\w-]+", body))
        self.assertEqual(used, {"--target", "--payload", "--build-info", "--output-dir"})
        self.assertLessEqual(used, flags)
        self.assertIn("if ($LASTEXITCODE -ne 0) { throw", body)

    def test_real_native_python_entrypoints_start_in_isolated_mode(self) -> None:
        scripts = set()
        for job in ("sign-windows", "windows-presign-native-approval", "windows-native-smoke"):
            for _, _, body in run_steps(job_text(RELEASE, job)):
                scripts.update(re.findall(r"python(?: -I)? (scripts/[A-Za-z0-9_-]+\.py)", body))
        self.assertIn("scripts/package-artifact.py", scripts)
        self.assertGreaterEqual(len(scripts), 4)
        for script in sorted(scripts):
            with self.subTest(script=script):
                result = subprocess.run([sys.executable, "-I", str(ROOT / script), "--help"],
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("usage:", result.stdout)

    def test_real_packaging_command_runs_before_native_approval_is_uploaded(self) -> None:
        final = next(body for name, _, body in run_steps(job_text(RELEASE, "sign-windows"))
                     if name == "Package unchanged verified Windows binaries")
        job = job_text(RELEASE, "windows-presign-native-approval")
        presign = next(body for name, _, body in run_steps(job)
                       if name == "Package exact unsigned Windows payload before approval")
        self.assertEqual(presign, final, "exercise the exact final command, not a surrogate")
        self.assertLess(job.index("Validate exact input and emit deterministic approval"),
                        job.index("Package exact unsigned Windows payload before approval"))
        self.assertLess(job.index("Package exact unsigned Windows payload before approval"),
                        job.index("Upload native Windows pre-sign approval"))
        ci_job = job_text(ROOT / ".github/workflows/ci.yml", "windows-native-smoke")
        ci = next(body for name, _, body in run_steps(ci_job)
                  if name == "Exercise exact release packaging on native Windows")
        # Only fixtures differ; required native CI executes the exact final invocation.
        self.assertEqual(ci[ci.index("& python -I scripts/package-artifact.py"):].rstrip("\n"),
                         final[final.index("& python -I scripts/package-artifact.py"):].rstrip("\n"))
        step = ci_job.split("- name: Exercise exact release packaging on native Windows", 1)[1]
        self.assertIn("if: ${{ inputs.windows_artifact_run_id == '' }}", step)

    def test_native_checks_are_required_in_ci_and_secret_free_approval(self) -> None:
        if os.name == "nt":
            self.assertIsNotNone(PWSH, "required Windows regressions must not silently skip")
        for path, job in ((ROOT / ".github/workflows/ci.yml", "windows-native-smoke"),
                          (RELEASE, "windows-presign-native-approval")):
            body = job_text(path, job)
            self.assertIn("runner: windows-2025", body)
            self.assertIn("runner: windows-11-vs2026-arm", body)
            self.assertIn("python -I -m unittest discover -s tests -p test_windows_release_contract.py -v", body)
            self.assertIn("throw 'native release-contract regression failed'", body)

    @unittest.skipUnless(PWSH, "native PowerShell execution runs in required Windows x64/ARM64 CI")
    def test_every_native_windows_run_body_parses_with_real_powershell(self) -> None:
        jobs = [(RELEASE, name) for name in (
            "windows-presign-native-approval", "sign-windows", "windows-native-smoke")]
        jobs.append((ROOT / ".github/workflows/ci.yml", "windows-native-smoke"))
        count = 0
        with tempfile.TemporaryDirectory(prefix="motrix-pwsh-parse-") as directory:
            root = Path(directory)
            parser = root / "parse.ps1"
            parser.write_text("param([string]$BodyPath)\n$ErrorActionPreference = 'Stop'\n"
                              "$tokens = $null; $errors = $null\n"
                              "[System.Management.Automation.Language.Parser]::ParseFile("
                              "$BodyPath, [ref]$tokens, [ref]$errors) | Out-Null\n"
                              "if ($errors.Count -gt 0) { throw ($errors | Out-String) }\n", encoding="utf-8")
            for path, job in jobs:
                for name, shell, body in run_steps(job_text(path, job)):
                    with self.subTest(workflow=path.name, job=job, step=name):
                        self.assertEqual(shell, "pwsh", "native jobs must declare their shell")
                        self.assertNotIn("${{", body, "put expressions in env rather than executable code")
                        script = root / "body.ps1"
                        script.write_text(body, encoding="utf-8")
                        result = subprocess.run([PWSH, "-NoLogo", "-NoProfile", "-NonInteractive",
                                                 "-File", str(parser), str(script)],
                                                capture_output=True, text=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        count += 1
        self.assertGreaterEqual(count, 10)

    @unittest.skipUnless(PWSH, "native PowerShell execution runs in required Windows x64/ARM64 CI")
    def test_actual_risk_step_accepts_only_current_untampered_scope(self) -> None:
        # Hash the checkout bytes before generating isolated test-only approval fixtures.
        original = json.loads((ROOT / "security/action-risk-review.json").read_bytes())
        expected = {"sources.env": original["sourceLockSha256"], **original["workflowSha256"],
                    "security/action-dependency-audit.json": original["auditReportSha256"],
                    "security/action-reachability-review.json": original["assessmentSha256"]}
        for path, digest in expected.items():
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest, path)

        today = dt.datetime.now(dt.timezone.utc).date()
        cases = (("valid", None), ("blocked", "formal release blocked"),
                 ("expired", "expired"), ("workflow", "workflow inputs differ"),
                 ("source", "source lock differs"), ("audit", "reviewed hash"),
                 ("assessment", "assessment differs"), ("tag", "different release tag"))
        for case, error in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="motrix-risk-fixture-") as directory:
                root = Path(directory)
                for path in expected:
                    target = root / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / path, target)
                for name in ("validate_action_review.py", "audit_workflow_actions.py", "pipeline_lib.py"):
                    target = root / "scripts" / name
                    target.parent.mkdir(exist_ok=True)
                    shutil.copyfile(ROOT / "scripts" / name, target)
                review = dict(original)
                review.update(status="approved", reviewedBy="test-fixture-not-release-authority",
                              decision="Isolated test fixture only; never a release approval.",
                              reviewedAt=today.isoformat(), validUntil=today.isoformat())
                audit_path = root / "security/action-dependency-audit.json"
                audit = json.loads(audit_path.read_bytes())
                audit["scannedAt"] = today.isoformat() + "T00:00:00+00:00"
                audit_path.write_bytes(json.dumps(audit).encode("utf-8"))
                review["auditReportSha256"] = hashlib.sha256(audit_path.read_bytes()).hexdigest()
                assessment_path = root / "security/action-reachability-review.json"
                assessment = json.loads(assessment_path.read_bytes())
                assessment.update(reviewedAt=review["reviewedAt"], auditReportSha256=review["auditReportSha256"])
                assessment_path.write_bytes(json.dumps(assessment).encode("utf-8"))
                review["assessmentSha256"] = hashlib.sha256(assessment_path.read_bytes()).hexdigest()
                if case == "blocked":
                    review["status"] = "blocked"
                elif case == "expired":
                    yesterday = (today - dt.timedelta(days=1)).isoformat()
                    review.update(reviewedAt=yesterday, validUntil=yesterday)
                elif case in {"workflow", "source", "audit", "assessment"}:
                    target = root / {"workflow": ".github/workflows/ci.yml", "source": "sources.env",
                                     "audit": "security/action-dependency-audit.json",
                                     "assessment": "security/action-reachability-review.json"}[case]
                    target.write_bytes(target.read_bytes() + b"\n ")
                (root / "security/action-risk-review.json").write_bytes(json.dumps(review).encode("utf-8"))
                script = root / "risk.ps1"
                script.write_text(risk_step()[1], encoding="utf-8")
                # No tokens, signing keys, or arbitrary job environment enter fixture processes.
                allowed = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
                           "USERPROFILE", "HOME", "LOCALAPPDATA", "APPDATA", "PSMODULEPATH"}
                env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
                env["REVIEW_RELEASE_TAG"] = "v9.0.2-motrix.0" if case == "tag" else review["releaseTag"]
                result = subprocess.run([PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
                                        cwd=root, env=env, capture_output=True, text=True, timeout=30)
                output = result.stdout + result.stderr
                if error is None:
                    self.assertEqual(result.returncode, 0, output)
                    self.assertIn("current Action risk review matches the exact release tag", output)
                else:
                    self.assertNotEqual(result.returncode, 0, output)
                    self.assertIn(error, output)
                    self.assertNotIn("current Action risk review matches", output)


if __name__ == "__main__":
    unittest.main()
