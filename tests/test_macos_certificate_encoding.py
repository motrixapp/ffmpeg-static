from __future__ import annotations

import base64
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / "scripts/sign-macos.sh"
SYSTEM_PYTHON = Path("/usr/bin/python3")
ERROR = b"invalid MAC_CERTS Base64 encoding or size\n"
PIPELINE_PATTERN = re.compile(
    r"printf '%s' \"\$MAC_CERTS\" \| \"\$isolated_python\" -I -c \\\n"
    r"  '(?P<code>[^']*)' \\\n  >\"\$certificate\""
)


class MacOSCertificateEncodingContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.signer = SIGNER.read_text(encoding="utf-8")
        matches = list(PIPELINE_PATTERN.finditer(cls.signer))
        if len(matches) != 1:
            raise AssertionError("expected exactly one actual signing decoder pipeline")
        cls.pipeline = matches[0].group(0)
        cls.decoder = matches[0].group("code")

    def run_pipeline(self, value: bytes, cwd: Path | None = None) -> subprocess.CompletedProcess:
        if not SYSTEM_PYTHON.is_file() or not Path("/bin/bash").is_file():
            self.skipTest("requires the signing system Python and Bash")
        # Public fake fixture bytes only: never a certificate, key or real Secret.
        environment = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "MAC_CERTS": value.decode("utf-8"),
            "MAC_CERTS_PASSWORD": "fake-test-password-not-a-credential",
        }
        if cwd is not None:
            environment["PYTHONPATH"] = str(cwd)
        script = (
            "set -Eeuo pipefail\n"
            "isolated_python=/usr/bin/python3\n"
            'certificate=$1\n'
            "export -n MAC_CERTS MAC_CERTS_PASSWORD\n"
            '"$isolated_python" -I -c '
            "'import os; assert not {\"MAC_CERTS\", \"MAC_CERTS_PASSWORD\"} & os.environ.keys()'\n"
            + self.pipeline
        )
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "fake-public-fixture.bin"
            result = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", "-c", script, "test-decoder", str(certificate)],
                env=environment, cwd=cwd, capture_output=True, check=False, timeout=10,
            )
            self.assertEqual(result.stdout, b"")
            output = certificate.read_bytes() if certificate.exists() else b""
        return subprocess.CompletedProcess(result.args, result.returncode, output, result.stderr)

    def assert_rejected(self, value: bytes) -> None:
        result = self.run_pipeline(value)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, ERROR)

    def test_canonical_binary_fixture(self) -> None:
        decoded = bytes(range(256)) + b"public fake PKCS12-shaped fixture\x00\xff"
        result = self.run_pipeline(base64.b64encode(decoded))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, decoded)
        self.assertEqual(result.stderr, b"")

    def test_conventional_wrapping_and_trailing_whitespace(self) -> None:
        decoded = bytes(range(256))
        encoded = base64.b64encode(decoded)
        lines = [encoded[offset:offset + 64] for offset in range(0, len(encoded), 64)]
        for value in (
            b"\n".join(lines), b"\r\n".join(lines), encoded + b"\n",
            encoded + b"\r\n", b" \t\r\n" + encoded + b" \t\r\n",
            b" \t".join(encoded[i:i + 4] for i in range(0, len(encoded), 4)),
        ):
            with self.subTest(value_length=len(value)):
                result = self.run_pipeline(value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, decoded)

    def test_empty_and_whitespace_only_are_rejected(self) -> None:
        for value in (b"", b" \t\r\n", b"\n" * 65536):
            with self.subTest(value_length=len(value)):
                self.assert_rejected(value)

    def test_invalid_alphabets_and_wrappers_are_rejected(self) -> None:
        for value in (
            b"QUJD!", b"QUJD_", b"QUJD-", b"QUJD\\n", b'"QUJD"',
            b"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----",
            b"QUJD\v", b"QUJD\f", b"QUJD\x7f", b"QUJD\xc2\xa0",
            b"\xef\xbb\xbfQUJD", b"QUJD%",
        ):
            with self.subTest(value=value):
                self.assert_rejected(value)

    def test_padding_and_noncanonical_pad_bits_are_rejected(self) -> None:
        for value in (
            b"A", b"AA", b"AAA", b"=QUJD", b"QU=JD", b"QUJD====",
            b"AA===", b"AAAA=", b"AB==", b"AAB=", b"AA==QUJD",
        ):
            with self.subTest(value=value):
                self.assert_rejected(value)

    def test_raw_input_size_is_bounded_before_whitespace_removal(self) -> None:
        encoded = b"A" * 65536
        result = self.run_pipeline(encoded)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"\x00" * 49152)
        for value in (encoded + b"A", encoded + b"\n", b"\n" * 65537):
            with self.subTest(value_length=len(value)):
                self.assert_rejected(value)

    def test_nul_stdin_is_rejected_by_actual_decoder(self) -> None:
        # Bash/environment values cannot carry NUL; exercise the same actual
        # inline production decoder directly for this binary stdin boundary.
        if not SYSTEM_PYTHON.is_file():
            self.skipTest("requires the signing system Python")
        result = subprocess.run(
            [str(SYSTEM_PYTHON), "-I", "-c", self.decoder],
            input=b"QUJD\x00", env={"PATH": "/usr/bin:/bin"},
            capture_output=True, check=False, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, ERROR)

    def test_rejection_does_not_echo_input_or_emit_partial_bytes(self) -> None:
        marker = b"unique-public-redaction-test-marker"
        result = self.run_pipeline(base64.b64encode(marker) + b"!")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, ERROR)
        self.assertNotIn(marker, result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_actual_isolated_pipeline_ignores_workspace_modules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename in ("base64.py", "sitecustomize.py"):
                (root / filename).write_text(
                    'raise RuntimeError("untrusted workspace module loaded")\n', encoding="utf-8"
                )
            result = self.run_pipeline(b"QUJD", cwd=root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"ABC")

    def test_secrets_remain_unexported_and_decoder_precedes_import(self) -> None:
        self.assertIn("isolated_python=/usr/bin/python3", self.signer)
        self.assertLess(self.signer.index("export -n MAC_CERTS MAC_CERTS_PASSWORD"),
                        self.signer.index(self.pipeline))
        self.assertLess(self.signer.index(self.pipeline), self.signer.index("unset MAC_CERTS\n"))
        self.assertLess(self.signer.index("unset MAC_CERTS\n"),
                        self.signer.index('chmod 600 "$certificate"'))
        self.assertLess(self.signer.index('chmod 600 "$certificate"'),
                        self.signer.index('security import "$certificate"'))
        self.assertIn('base64.b64decode(encoded, validate=True)', self.decoder)

    def test_native_ci_and_secret_free_presign_execute_actual_contract(self) -> None:
        command = "/usr/bin/python3 -I -m unittest discover -s tests -p test_macos_certificate_encoding.py -v"
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        step = ci.split("      - name: Test protected macOS certificate decoding contract\n", 1)[1]
        step = step.split("\n      - name:", 1)[0]
        self.assertIn("matrix.platform == 'darwin'", step)
        self.assertIn(command, step)
        self.assertLess(ci.index(command), ci.index("name: Fetch, authenticate, build"))
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        presign = workflow.split("\n  macos-presign-approval:\n", 1)[1]
        presign = presign.split("\n  windows-presign-static-approval:\n", 1)[0]
        self.assertIn(command, presign)
        self.assertNotIn("environment:", presign)
        self.assertNotIn("secrets.", presign)
        self.assertLess(presign.index(command), presign.index("uses: actions/download-artifact@"))


if __name__ == "__main__":
    unittest.main()
