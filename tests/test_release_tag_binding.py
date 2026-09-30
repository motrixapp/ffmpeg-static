from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import validate_release_tag as tags  # noqa: E402


class ReleaseTagBindingTests(unittest.TestCase):
    def fixture(self, header: bytes | None = None, *, sha256: bool = False):
        commit = "a" * (64 if sha256 else 40)
        tag = "v9.0.2-motrix.1"
        raw = header or (f"object {commit}\ntype commit\ntag {tag}\n"
                         "tagger Test Maintainer <test@example.com> 0 +0800\n\nRelease\n").encode()
        payload = b"tag " + str(len(raw)).encode() + b"\0" + raw
        identity = (hashlib.sha256(payload) if sha256 else hashlib.sha1(payload)).hexdigest()
        record = {"sha": identity, "tag": tag, "object": {"type": "commit", "sha": commit},
                  "tagger": {"name": "Test Maintainer", "email": "test@example.com", "date": "1970-01-01T00:00:00Z"},
                  "verification": {"verified": False, "reason": "unsigned", "signature": None, "payload": None}}
        return record, raw, tag, identity, commit

    def test_unsigned_annotated_tag_is_bound_without_claiming_signer(self):
        for sha256 in (False, True):
            values = self.fixture(sha256=sha256)
            result = tags.validate(*values)
            self.assertEqual(result, {"tagObjectSha": values[3], "releaseCreated": "1970-01-01T00:00:00Z"})

    def test_tampering_or_wrong_commit_is_rejected(self):
        record, raw, tag, identity, commit = self.fixture()
        for changed in (raw + b"changed", b"", b"\0", b"x" * (1024 * 1024 + 1)):
            with self.subTest(changed=len(changed)), self.assertRaises(ValueError):
                tags.validate(record, changed, tag, identity, commit)
        with self.assertRaisesRegex(ValueError, "exact release commit"):
            tags.validate(record, raw, tag, identity, "b" * 40)

    def test_api_mutations_are_not_accepted_as_git_object_facts(self):
        record, raw, tag, identity, commit = self.fixture()
        for change in ({"sha": "b" * 40}, {"tag": "v9.0.2-motrix.2"},
                       {"object": {"type": "tag", "sha": commit}},
                       {"object": {"type": "commit", "sha": "b" * 40}},
                       {"tagger": {"name": "Test Maintainer", "email": "different@example.com", "date": "1970-01-01T00:00:00Z"}},
                       {"tagger": {"name": "Test Maintainer", "email": "test@example.com", "date": "2026-09-30T00:00:00Z"}},
                       {"tagger": None}):
            modified = copy.deepcopy(record)
            modified.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                tags.validate(modified, raw, tag, identity, commit)

    def test_tag_to_tag_malformed_or_duplicate_headers_fail_closed(self):
        original = self.fixture()[1]
        for raw in (original.replace(b"type commit", b"type tag"),
                    original.replace(b"tagger Test", b"object a\ntagger Test"),
                    original.replace(b"+0800", b"+1460"),
                    original.replace(b"+0800", b"+1401"),
                    original.replace(b"tagger Test", b"tagger \xffTest"),
                    original.replace(b"\n\n", b"\n"),
                    original.replace(b"tagger Test", b"tagger \rTest")):
            with self.subTest(raw=raw[:90]), self.assertRaises(ValueError):
                tags.validate(*self.fixture(raw))

    def test_raw_hash_matches_git_and_cli_emits_only_canonical_outputs(self):
        record, raw, tag, identity, commit = self.fixture()
        actual = subprocess.check_output(["git", "hash-object", "-t", "tag", "--stdin"], input=raw).decode().strip()
        self.assertEqual(actual, identity)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tag.raw").write_bytes(raw)
            (root / "tag.json").write_text(json.dumps(record))
            result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/validate_release_tag.py"),
                                     "--record", str(root / "tag.json"), "--raw-object", str(root / "tag.raw"),
                                     "--tag", tag, "--object-sha", identity, "--commit", commit,
                                     "--format", "github-output"], capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout, f"tag_object_sha={identity}\nrelease_created=1970-01-01T00:00:00Z\n")

    def test_invalid_expected_identity_and_output_injection_fail_closed(self):
        record, raw, tag, identity, commit = self.fixture()
        for expected in ((tag + "\nrelease_created=evil", identity, commit),
                         (tag, identity.upper(), commit),
                         (tag, identity, "a" * 64),
                         (tag, identity + "\n", commit)):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                tags.validate(record, raw, *expected)
        for record in (None, [], {"sha": identity, "tag": tag, "object": []}):
            with self.assertRaises(ValueError):
                tags.validate(record, raw, tag, identity, commit)
        for epoch in (b"-1", b"999999999999"):
            with self.assertRaises((ValueError, OverflowError)):
                tags.validate(*self.fixture(raw.replace(b" 0 +0800", b" " + epoch + b" +0800")))

    def test_real_unsigned_git_tag_matches_api_metadata(self):
        # Exercise Git's actual annotated-tag serialization in an isolated repo;
        # no public/repository release ref is created by this test.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def git(*arguments):
                return subprocess.check_output(["git", "-C", str(root), *arguments], stderr=subprocess.PIPE)
            git("init", "--quiet")
            git("-c", "user.name=Test Maintainer", "-c", "user.email=test@example.com",
                "commit", "--allow-empty", "--no-gpg-sign", "-m", "fixture")
            commit = git("rev-parse", "HEAD").decode().strip()
            tag = "v9.0.2-motrix.1"
            git("-c", "user.name=Test Maintainer", "-c", "user.email=test@example.com",
                "-c", "tag.gpgSign=false", "tag", "-a", tag, commit, "-m", "Release")
            identity = git("rev-parse", tag).decode().strip()
            raw = git("cat-file", "tag", identity)
            epoch = int(raw.split(b"\n")[3].rsplit(b" ", 2)[1])
            canonical = tags.dt.datetime.fromtimestamp(epoch, tags.dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            record = {"sha": identity, "tag": tag, "object": {"type": "commit", "sha": commit},
                      "tagger": {"name": "Test Maintainer", "email": "test@example.com", "date": canonical}}
            self.assertEqual(tags.validate(record, raw, tag, identity, commit)["tagObjectSha"], identity)

    def test_workflow_retains_tag_commit_gate_and_drops_only_project_openpgp(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertEqual(workflow.count("scripts/validate_release_tag.py"), 2)
        self.assertEqual(workflow.count('git cat-file tag "$direct"'), 2)
        self.assertIn('"$event_commit" == "$control_commit"', workflow)
        self.assertIn('"$direct" == "$EXPECTED_TAG_OBJECT_SHA"', workflow)
        for obsolete in ("EXPECTED_RELEASE_TAGGER_EMAIL", "EXPECTED_RELEASE_TAG_SIGNER_FINGERPRINT",
                         "RELEASE_TAG_SIGNING_PUBLIC_KEY", "release-tag-signer-fingerprint", "tag-signer-fingerprint"):
            self.assertNotIn(obsolete, workflow)
        self.assertIn("scripts/validate_action_review.py", workflow)
        self.assertIn("scripts/sign_release_manifest.py", workflow)
        self.assertIn("            validate_release_tag.py \\", workflow)
        self.assertIn('"scripts/validate_release_tag.py"', (ROOT / "scripts/assemble-release.py").read_text())
        fetcher = (ROOT / "scripts/fetch-sources.sh").read_text()
        self.assertIn('--verify "$VERIFIED_SIGNATURE" "$VERIFIED_FFMPEG"', fetcher)
        self.assertIn('expected="$FFMPEG_PGP_FINGERPRINT"', fetcher)


if __name__ == "__main__":
    unittest.main()
