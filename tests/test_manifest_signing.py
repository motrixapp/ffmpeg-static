import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from sign_release_manifest import DOMAIN, key_id, sign, verify


class ManifestSigningTests(unittest.TestCase):
    def test_motrix_and_publisher_pin_the_same_public_root(self):
        root = Path(__file__).resolve().parents[1]
        client = root.parent / "Motrix/src/shared/config/ffmpeg-release-key.json"
        if not client.exists():
            self.skipTest("standalone publisher checkout has no adjacent Motrix client")
        obj = json.loads(client.read_text())
        public = root / "keys/manifest-ed25519.pub"
        self.assertEqual(obj["publicKey"].strip(), public.read_text().strip())
        self.assertEqual(obj["keyId"], key_id(public))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="motrix-test-signing-")
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name) / "test-private.pem"
        self.public = Path(self.temp.name) / "test-public.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", self.private], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", self.private, "-pubout", "-out", self.public], check=True, capture_output=True)

    def test_real_ed25519_roundtrip_and_byte_tampering(self):
        raw = b'{"test":true}\n'
        envelope = sign(raw, self.private.read_text(), self.public)
        verify(raw, envelope, self.public)
        with self.assertRaises(subprocess.CalledProcessError):
            verify(raw + b' ', envelope, self.public)

    def test_key_pinning_and_unknown_key_fail_closed(self):
        raw = b'{}'
        envelope = sign(raw, self.private.read_text(), self.public)
        obj = json.loads(envelope)
        obj['keyId'] = 'sha256:' + '0' * 64
        with self.assertRaises(ValueError):
            verify(raw, json.dumps(obj).encode(), self.public)
        with self.assertRaises(ValueError):
            sign(raw, self.private.read_text())

    def test_signature_domain_cannot_be_omitted(self):
        message = Path(self.temp.name) / 'message'
        message.write_bytes(b'{}')
        sig = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', self.private, '-rawin', '-in', message], check=True, capture_output=True).stdout
        obj = {'schemaVersion': 1, 'algorithm': 'Ed25519', 'keyId': key_id(self.public), 'signature': base64.b64encode(sig).decode()}
        with self.assertRaises(subprocess.CalledProcessError):
            verify(b'{}', json.dumps(obj).encode(), self.public)
        self.assertEqual(DOMAIN, b'Motrix FFmpeg release manifest v1\n')

    def test_envelope_must_be_exact_and_signature_canonical(self):
        envelope = json.loads(sign(b'{}', self.private.read_text(), self.public))
        envelope['extra'] = 'ignored'
        with self.assertRaises(ValueError):
            verify(b'{}', json.dumps(envelope).encode(), self.public)


if __name__ == '__main__':
    unittest.main()
