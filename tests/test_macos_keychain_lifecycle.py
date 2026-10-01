from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SIGNER = ROOT / "scripts/sign-macos.sh"
LEAF = b"public fake leaf certificate; never a credential"
TEAM = "TESTTEAM01"

# Public fake fixtures run the entire production script. These commands never
# read or mutate a real keychain, sign an executable, or use a private key.
FAKE_COMMAND = r'''#!/usr/bin/python3
import json
import os
import sys
from pathlib import Path

state_path = Path(os.environ["FIXTURE_STATE"])
state = json.loads(state_path.read_text())
command = Path(sys.argv[0]).name
args = sys.argv[1:]
assert not {"MAC_CERTS", "MAC_CERTS_PASSWORD"} & os.environ.keys()

def save():
    state_path.write_text(json.dumps(state))

def fail(operation):
    if state["failure"] == operation:
        save()
        sys.exit(17)

if command == "mktemp":
    assert args == ["-d"]
    directory = Path(state["temporary"])
    directory.mkdir(mode=0o700)
    print(directory)
elif command == "openssl":
    assert args == ["rand", "-hex", "24"]
    print("a" * 48)
elif command == "security":
    operation = args[0]
    assert "-A" not in args
    if operation == "list-keychains":
        assert args[1:3] == ["-d", "user"]
        if len(args) == 3:
            state["events"].append("snapshot")
            fail("snapshot")
            if state["inventory"] is not None:
                sys.stdout.buffer.write(state["inventory"].encode())
            else:
                for path in state["search"]:
                    print('    "' + path + '"')
        else:
            assert args[3] == "-s"
            new_list = args[4:]
            temporary = str(Path(state["temporary"]) / "motrix-ffmpeg-signing.keychain-db")
            registering = bool(new_list) and new_list[0] == temporary
            name = "register" if registering else "restore"
            state["events"].append(name)
            state[name] = new_list
            fail(name)
            state["search"] = new_list
    elif operation == "create-keychain":
        state["events"].append(operation)
        assert args[1] == "-p"
        keychain = Path(args[3])
        assert keychain.parent.stat().st_mode & 0o777 == 0o700
        keychain.write_bytes(b"fake keychain")
        if state["create_mutates"]:
            state["search"].append(str(keychain))
        fail(operation)
    elif operation == "delete-keychain":
        state["events"].append(operation)
        state["delete_search"] = state["search"][:]
        fail(operation)
        Path(args[1]).unlink(missing_ok=True)
    elif operation == "import":
        state["events"].append(operation)
        certificate = Path(args[1])
        assert certificate.stat().st_mode & 0o777 == 0o600
        assert certificate.read_bytes() == b"public fake PKCS12 fixture"
        assert args[args.index("-T") + 1] == "/usr/bin/codesign"
        assert "-x" in args and args[args.index("-f") + 1] == "pkcs12"
        fail(operation)
    elif operation == "find-identity":
        state["events"].append(operation)
        fail(operation)
        print('  1) ' + '1' * 40 + ' "Developer ID Application: Public Test (TESTTEAM01)"')
    else:
        assert operation in {"set-keychain-settings", "unlock-keychain", "set-key-partition-list"}
        state["events"].append(operation)
        fail(operation)
elif command == "codesign":
    if "--sign" in args:
        state["events"].append("sign")
        keychain = args[args.index("--keychain") + 1]
        assert state["search"] == [keychain] + state["original"]
        assert args[args.index("--sign") + 1] == "1" * 40
        assert args[args.index("--options") + 1] == "runtime"
        assert "--timestamp" in args
        fail("sign")
    elif "--verify" in args:
        state["events"].append("verify")
        assert "--strict" in args
        fail("verify")
    else:
        assert "--display" in args
        extraction = [arg for arg in args if arg.startswith("--extract-certificates=")]
        if extraction:
            state["events"].append("extract")
            fail("extract")
            Path(extraction[0].split("=", 1)[1] + "0").write_bytes(
                b"public fake leaf certificate; never a credential")
        else:
            state["events"].append("display")
            fail("display")
            print("TeamIdentifier=TESTTEAM01")
            print("CDHash=" + "2" * 40)
            print("Timestamp=Oct 1, 2026 at 12:00:00 PM")
            print("Identifier=net.agalwood.motrix." + Path(args[-1]).name)
            print("CodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=1+7 location=embedded")
else:
    raise AssertionError("unexpected fake command")
save()
'''


class MacOSKeychainLifecycleContractTests(unittest.TestCase):
    def run_signer(self, failure="", original=None, inventory=None, create_mutates=False):
        if not Path("/usr/bin/python3").is_file() or not Path("/bin/bash").is_file():
            self.skipTest("requires the signing system Python and Bash")
        if original is None:
            original = ["/Users/Public Test/login.keychain-db", "/Library/Keychains/System.keychain"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / "commands"
            commands.mkdir()
            for command in ("security", "codesign", "openssl", "mktemp"):
                fixture = commands / command
                fixture.write_text(FAKE_COMMAND, encoding="utf-8")
                fixture.chmod(0o755)
            payload = root / "payload with spaces"
            payload.mkdir()
            for executable in ("ffmpeg", "ffprobe"):
                (payload / executable).write_bytes(b"public fake executable")
            facts = root / "facts"
            temporary = root / "owned signing material"
            state_path = root / "state.json"
            state_path.write_text(json.dumps({
                "original": original, "search": original[:], "events": [],
                "temporary": str(temporary), "failure": failure,
                "inventory": inventory, "create_mutates": create_mutates,
            }), encoding="utf-8")
            result = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", str(SIGNER),
                 "darwin-arm64", str(payload), str(facts)],
                env={
                    "PATH": str(commands) + ":/usr/bin:/bin",
                    "FIXTURE_STATE": str(state_path),
                    "MAC_CERTS": base64.b64encode(b"public fake PKCS12 fixture").decode(),
                    "MAC_CERTS_PASSWORD": "fake-public-password",
                    "EXPECTED_MACOS_TEAM_ID": TEAM,
                    "EXPECTED_MACOS_CERT_SHA256": hashlib.sha256(LEAF).hexdigest(),
                }, capture_output=True, timeout=30, check=False,
            )
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertFalse(temporary.exists(), "owned temporary material must be removed")
            self.assertNotIn(b"fake-public-password", result.stdout + result.stderr)
            self.assertNotIn(base64.b64encode(b"public fake PKCS12 fixture"), result.stdout + result.stderr)
            return result, state, sorted(path.name for path in facts.iterdir())

    def assert_restored(self, state):
        self.assertEqual(state["search"], state["original"])
        self.assertEqual(state["restore"], state["original"])
        self.assertEqual(state["delete_search"], state["original"])
        self.assertLess(state["events"].index("restore"), state["events"].index("delete-keychain"))

    def test_actual_signer_registers_before_signing_and_restores_before_deletion(self):
        result, state, facts = self.run_signer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_restored(state)
        self.assertLess(state["events"].index("snapshot"), state["events"].index("create-keychain"))
        self.assertLess(state["events"].index("register"), state["events"].index("find-identity"))
        self.assertLess(state["events"].index("register"), state["events"].index("sign"))
        self.assertEqual(state["events"].count("sign"), 2)
        self.assertIn("certificate-sha256.txt", facts)

    def test_create_side_effects_cannot_contaminate_the_original_snapshot(self):
        result, state, _ = self.run_signer(create_mutates=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_restored(state)

    def test_empty_original_search_list_is_restored_under_bash_nounset(self):
        result, state, _ = self.run_signer(original=[])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_restored(state)

    def test_spaces_quotes_backslashes_and_shell_metacharacters_are_literal_paths(self):
        original = [r'/Users/Public Test/a"b\c $(false);*.keychain-db', "/Library/Keychains/System.keychain"]
        result, state, _ = self.run_signer(original=original)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_restored(state)
        self.assertEqual(state["register"][1:], original)

    def test_each_mutation_or_signing_failure_restores_and_cleans(self):
        for failure in ("create-keychain", "set-keychain-settings", "unlock-keychain", "import",
                        "set-key-partition-list", "register", "find-identity", "sign",
                        "verify", "display", "extract"):
            with self.subTest(failure=failure):
                result, state, _ = self.run_signer(failure=failure, create_mutates=True)
                self.assertNotEqual(result.returncode, 0)
                self.assert_restored(state)

    def test_snapshot_failure_prevents_any_keychain_mutation(self):
        result, state, _ = self.run_signer(failure="snapshot")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state["events"], ["snapshot"])
        self.assertEqual(state["search"], state["original"])

    def test_malformed_or_unbounded_inventory_fails_before_mutation(self):
        for inventory in ('unquoted\n', '"relative.keychain"\n', '"/one"\n"/one"\n',
                          '"/control\tcharacter"\n', '"/nul\x00character"\n',
                          '"/' + 'a' * 4096 + '"\n', ' ' * 65537,
                          ''.join('"/item' + str(i) + '"\n' for i in range(257))):
            with self.subTest(length=len(inventory)):
                result, state, _ = self.run_signer(inventory=inventory)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"invalid user keychain search list", result.stderr)
                self.assertEqual(state["events"], ["snapshot"])
                self.assertEqual(state["search"], state["original"])

    def test_restore_failure_cannot_report_success_even_after_both_signatures(self):
        result, state, _ = self.run_signer(failure="restore")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state["events"].count("sign"), 2)
        self.assertIn(b"could not restore", result.stderr)
        self.assertIn("delete-keychain", state["events"])

    def test_delete_failure_cannot_report_success_and_still_removes_private_files(self):
        result, state, _ = self.run_signer(failure="delete-keychain")
        self.assertNotEqual(result.returncode, 0)
        self.assert_restored(state)
        self.assertIn(b"could not delete the temporary signing keychain", result.stderr)

    def test_native_ci_and_secret_free_presign_execute_actual_lifecycle_contract(self):
        command = "/usr/bin/python3 -I -m unittest discover -s tests -p test_macos_keychain_lifecycle.py -v"
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        presign = workflow.split("\n  macos-presign-approval:\n", 1)[1].split(
            "\n  windows-presign-static-approval:\n", 1)[0]
        self.assertIn(command, ci)
        self.assertLess(ci.index(command), ci.index("name: Fetch, authenticate, build"))
        self.assertIn(command, presign)
        self.assertLess(presign.index(command), presign.index("uses: actions/download-artifact@"))
        self.assertNotIn("environment:", presign)
        self.assertNotIn("secrets.", presign)
        signer = SIGNER.read_text(encoding="utf-8")
        self.assertNotIn("default-keychain", signer)
        self.assertNotIn("add-trusted-cert", signer)
        self.assertNotIn(" -A", signer)


if __name__ == "__main__":
    unittest.main()
