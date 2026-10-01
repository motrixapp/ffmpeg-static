from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = b"locked source fixture\n"
SCRIPT = r'''
set -Eeuo pipefail
source "$1"
curl() {
  printf '%s\n' "$@" > "$CURL_ARGUMENTS"
  local output=''
  while (( $# )); do
    if [[ "$1" == --output ]]; then
      output=$2
      shift 2
    else
      shift
    fi
  done
  [[ -n "$output" ]]
  printf '%s' "$CURL_PAYLOAD" > "$output"
  return "$CURL_EXIT"
}
download_verified "$2" "$3" "$4"
'''


class SourceDownloadTests(unittest.TestCase):
    def run_download(self, root: Path, payload: bytes = PAYLOAD,
                     status: int = 0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", SCRIPT, "source-download-test", str(ROOT / "scripts/common.sh"),
             "https://example.invalid/locked.tar.gz", str(root / "downloads/locked.tar.gz"),
             hashlib.sha256(PAYLOAD).hexdigest()],
            env={**os.environ, "FFMPEG_STATIC_SOURCE_CACHE_DIR": str(root),
                 "CURL_ARGUMENTS": str(root / "curl-arguments"),
                 "CURL_PAYLOAD": payload.decode(), "CURL_EXIT": str(status)},
            text=True, capture_output=True, check=False,
        )

    def test_cdn_retry_is_bounded_and_keeps_https_and_hash_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.run_download(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = (root / "curl-arguments").read_text().splitlines()
            self.assertEqual(arguments[0], "--disable")
            for name, value in (("--retry", "4"), ("--retry-max-time", "300"),
                                ("--max-time", "600"), ("--connect-timeout", "30"),
                                ("--proto", "=https"), ("--proto-redir", "=https")):
                self.assertEqual(arguments[arguments.index(name) + 1], value)
            self.assertIn("--retry-all-errors", arguments)
            self.assertIn("--fail", arguments)
            self.assertNotIn("--insecure", arguments)
            self.assertEqual((root / "downloads/locked.tar.gz").read_bytes(), PAYLOAD)
            self.assertEqual(list((root / "downloads").glob(".*.part.*")), [])

    def test_verified_cache_is_rechecked_and_does_not_download(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "downloads/locked.tar.gz"
            destination.parent.mkdir()
            destination.write_bytes(PAYLOAD)
            result = self.run_download(root, status=22)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "curl-arguments").exists())
            self.assertEqual(destination.read_bytes(), PAYLOAD)

    def test_failed_or_mismatched_download_cannot_replace_existing_bytes(self) -> None:
        for status in (0, 22, 56):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                destination = root / "downloads/locked.tar.gz"
                destination.parent.mkdir()
                destination.write_bytes(b"previous bytes")
                result = self.run_download(root, payload=b"invalid response", status=status)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(destination.read_bytes(), b"previous bytes")
                self.assertEqual(list(destination.parent.glob(".*.part.*")), [])

    def test_cache_fallback_is_scoped_and_only_restores_source_downloads(self) -> None:
        for name, identifier in (("ci.yml", "matrix.target"), ("release.yml", "runner.os")):
            workflow = (ROOT / ".github/workflows" / name).read_text()
            cache = workflow.split("      - name: Restore locked source cache\n", 1)[1]
            cache = cache.split("      - name:", 1)[0]
            self.assertIn("path: build/source-cache/downloads", cache)
            self.assertIn(f"restore-keys: ffmpeg-static-sources-${{{{ {identifier} }}}}-", cache)
            self.assertIn("hashFiles('sources.env')", cache)
            self.assertNotIn("continue-on-error", cache)

    def test_symlinked_destination_is_rejected_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original"
            original.write_bytes(b"keep original")
            destination = root / "downloads/locked.tar.gz"
            destination.parent.mkdir()
            destination.symlink_to(original)
            result = self.run_download(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing symlinked", result.stderr)
            self.assertTrue(destination.is_symlink())
            self.assertEqual(original.read_bytes(), b"keep original")
            self.assertFalse((root / "curl-arguments").exists())


if __name__ == "__main__":
    unittest.main()
