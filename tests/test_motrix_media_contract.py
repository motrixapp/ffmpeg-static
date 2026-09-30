from __future__ import annotations

import os
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class MotrixMediaContractTests(unittest.TestCase):
    def test_shared_smoke_scripts_cover_the_motrix_v2_contract(self) -> None:
        bash_path = ROOT / "scripts" / "motrix-media-smoke.sh"
        powershell_path = ROOT / "scripts" / "motrix-media-smoke.ps1"
        self.assertTrue(os.access(bash_path, os.X_OK))
        self.assertTrue(os.access(powershell_path, os.X_OK))

        bash = bash_path.read_text(encoding="utf-8")
        powershell = powershell_path.read_text(encoding="utf-8")
        required_tokens = {
            "mp4",
            "ipod",
            "mov",
            "matroska",
            "webm",
            "mpegts",
            "flv",
            "adts",
            "mp3",
            "opus",
            "aac_adtstoasc",
            "libx264",
            "libmp3lame",
            "flac",
            "pcm_s16le",
            "mjpeg",
            "scale=64:48",
            "pipe:1",
            ".motrix",
        }
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, bash)
                self.assertIn(token, powershell)

        self.assertIn("-c copy -map 0:v:0 -map 1:a:0", bash)
        self.assertIn("'-c', 'copy', '-map', '0:v:0', '-map', '1:a:0'", powershell)
        self.assertNotIn("python", bash.lower())
        self.assertNotIn("python", powershell.lower())

    def test_verify_binary_has_a_static_motrix_capability_gate(self) -> None:
        verify = (ROOT / "scripts" / "verify-binary.sh").read_text(encoding="utf-8")
        self.assertIn(
            "for muxer in mp4 ipod mov matroska webm mpegts flv adts mp3 opus",
            verify,
        )
        self.assertIn(
            "for encoder in libx264 aac libmp3lame flac pcm_s16le mjpeg",
            verify,
        )
        self.assertIn("aac_adtstoasc", verify)
        self.assertIn('require_listing_token "$filters_output" scale filter', verify)

    def test_every_native_ci_and_release_boundary_uses_the_shared_contract(self) -> None:
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(ci.count("scripts/motrix-media-smoke.sh"), 1)
        self.assertEqual(ci.count("& scripts/motrix-media-smoke.ps1"), 1)
        self.assertEqual(release.count("scripts/motrix-media-smoke.sh"), 3)
        self.assertEqual(release.count("scripts/motrix-media-smoke.ps1"), 2)

        # The release file mentions each basename once more when staging the
        # protected-main source set that the assembler byte-compares.
        self.assertEqual(release.count("motrix-media-smoke.sh"), 4)
        self.assertEqual(release.count("motrix-media-smoke.ps1"), 3)

    def test_smoke_contract_is_in_the_published_pipeline_source_set(self) -> None:
        assembler = (ROOT / "scripts" / "assemble-release.py").read_text(
            encoding="utf-8"
        )
        for path in (
            "scripts/motrix-media-smoke.sh",
            "scripts/motrix-media-smoke.ps1",
        ):
            with self.subTest(path=path):
                self.assertIn(f'"{path}"', assembler)


if __name__ == "__main__":
    unittest.main()
