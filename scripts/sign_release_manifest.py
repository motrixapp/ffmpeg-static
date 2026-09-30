#!/usr/bin/env python3
"""Domain-separated, pinned-key Ed25519 signatures; never executes payloads."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

DOMAIN = b"Motrix FFmpeg release manifest v1\n"
MANIFEST = "ffmpeg-manifest.json"
SIGNATURE = "ffmpeg-manifest.json.sig"
ROOT = Path(__file__).resolve().parents[1]
PUBLIC_KEY = ROOT / "keys/manifest-ed25519.pub"


def openssl(*args):
    return subprocess.run(["openssl", *map(str, args)], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def key_id(public_key=PUBLIC_KEY):
    der = openssl("pkey", "-pubin", "-in", public_key, "-outform", "DER")
    if len(der) != 44 or der[:12] != bytes.fromhex("302a300506032b6570032100"):
        raise ValueError("public key must be Ed25519 SPKI")
    return "sha256:" + hashlib.sha256(der).hexdigest()


def read_regular(path, limit):
    if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > limit:
        raise ValueError(f"invalid regular file: {path.name}")
    return path.read_bytes()


def verify(raw, envelope, public_key=PUBLIC_KEY):
    obj = json.loads(envelope)
    if (set(obj) != {"schemaVersion", "algorithm", "keyId", "signature"}
            or obj["schemaVersion"] != 1 or obj["algorithm"] != "Ed25519"
            or obj["keyId"] != key_id(public_key)):
        raise ValueError("signature key or envelope mismatch")
    signature = base64.b64decode(obj["signature"], validate=True)
    if len(signature) != 64 or base64.b64encode(signature).decode() != obj["signature"]:
        raise ValueError("invalid Ed25519 signature encoding")
    with tempfile.TemporaryDirectory(prefix="motrix-manifest-") as temp:
        message, sig = Path(temp) / "message", Path(temp) / "signature"
        message.write_bytes(DOMAIN + raw)
        sig.write_bytes(signature)
        openssl("pkeyutl", "-verify", "-pubin", "-inkey", public_key,
                "-rawin", "-in", message, "-sigfile", sig)


def check_release(directory, tag, commit, signed):
    raw = read_regular(directory / MANIFEST, 1024 * 1024)
    if signed:
        verify(raw, read_regular(directory / SIGNATURE, 4096))
    manifest = json.loads(raw)
    if (manifest.get("schemaVersion") != 3 or manifest.get("formalRelease") is not True
            or manifest.get("repository") != "motrixapp/ffmpeg-static"
            or manifest.get("windowsTrust") != "motrix-ed25519"
            or manifest.get("releaseTag") != tag
            or manifest.get("releaseCommit") != commit
            or manifest.get("controlCommit") != commit):
        raise ValueError("manifest does not match protected formal release identity")
    from pipeline_lib import load_sources, TARGETS
    spec = importlib.util.spec_from_file_location("assembly", ROOT / "scripts/assemble-release.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    sources = load_sources(ROOT / "sources.env")
    targets = manifest.get("targets")
    if not isinstance(targets, list) or len(targets) != len(TARGETS):
        raise ValueError("incomplete manifest target set")
    expected = {MANIFEST, "sbom.spdx.json"}
    seen = set()
    for target in targets:
        name = target["target"]
        if name not in TARGETS or name in seen:
            raise ValueError("unexpected or duplicate manifest target")
        seen.add(name)
        archive = target["archive"]
        checked = module.verify_target(directory / f"{archive}.metadata.json",
                                       sources, require_signing="macos")
        if checked != target:
            raise ValueError("manifest differs from independently validated metadata")
        if name.startswith("win32-") and target["signing"] is not None:
            raise ValueError("Windows project-signature policy requires unsigned PE payloads")
        if name.startswith("win32-"):
            from verify_authenticode_delta import verify_unsigned
            files = module.archive_files(directory / archive, int(sources["SOURCE_DATE_EPOCH"]))
            for binary in ("ffmpeg.exe", "ffprobe.exe"):
                verify_unsigned(files[binary])
        expected.update((archive, f"{archive}.metadata.json"))
        if name.startswith("darwin-"):
            expected.add(target["signing"]["notarization"]["developerLog"]["name"])
    for asset in manifest["sourceAssets"]:
        name = asset["name"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or name in expected:
            raise ValueError("invalid or duplicate source asset")
        path = directory / name
        if (not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size != asset["size"]
                or module.sha256_file(path) != asset["sha256"]):
            raise ValueError("source asset digest mismatch")
        expected.add(name)
    if signed:
        expected.add(SIGNATURE)
    entries = list(directory.iterdir())
    if (any(not stat.S_ISREG(p.lstat().st_mode) for p in entries)
            or {p.name for p in entries} != expected | {"SHA256SUMS"}):
        raise ValueError("release asset set is not exact")
    checksums = read_regular(directory / "SHA256SUMS", 64 * 1024).decode().splitlines()
    covered = set()
    for line in checksums:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if not match or match[2] not in expected or match[2] in covered:
            raise ValueError("invalid checksum entry")
        covered.add(match[2])
        if module.sha256_file(directory / match[2]) != match[1]:
            raise ValueError("release checksum mismatch")
    if covered != expected:
        raise ValueError("checksum coverage is not exact")
    return raw


def sign(raw, private_key, public_key=PUBLIC_KEY):
    with tempfile.TemporaryDirectory(prefix="motrix-sign-") as temp:
        root = Path(temp)
        key, message, pub = root / "private.pem", root / "message", root / "public.pem"
        key.write_text(private_key, encoding="ascii")
        key.chmod(0o600)
        openssl("pkey", "-in", key, "-pubout", "-out", pub)
        if key_id(pub) != key_id(public_key):
            raise ValueError("private key does not match pinned public key")
        message.write_bytes(DOMAIN + raw)
        signature = openssl("pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", message)
    obj = {"schemaVersion": 1, "algorithm": "Ed25519", "keyId": key_id(public_key),
           "signature": base64.b64encode(signature).decode()}
    envelope = (json.dumps(obj, sort_keys=True, indent=2) + "\n").encode()
    verify(raw, envelope, public_key)
    return envelope


def check_references(directory, reference_dir, source_dir, raw, team_id, cert_sha):
    """Bind signing to independently downloaded post-smoke artifacts, not assembly."""
    from pipeline_lib import canonical_json, load_sources, sha256_file, TARGETS
    spec = importlib.util.spec_from_file_location("reference_assembly", ROOT / "scripts/assemble-release.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    manifest = json.loads(raw)
    by_target = {item["target"]: item for item in manifest["targets"]}
    module._validate_release_identities(by_target, argparse.Namespace(
        expected_macos_team_id=team_id, expected_macos_cert_sha256=cert_sha,
        expected_windows_subject=None, expected_windows_thumbprint=None,
        windows_project_signature=True,
    ))
    if {p.name for p in reference_dir.iterdir()} != set(TARGETS):
        raise ValueError("independent reference target set is not exact")
    for name in TARGETS:
        candidate = reference_dir / name
        if not stat.S_ISDIR(candidate.lstat().st_mode):
            raise ValueError("invalid independent reference directory")
        target = by_target[name]
        archive = target["archive"]
        metadata_name = f"{archive}.metadata.json"
        metadata = read_regular(candidate / metadata_name, 256 * 1024)
        if canonical_json(json.loads(metadata)) != canonical_json(target):
            raise ValueError("manifest substituted independently smoke-tested metadata")
        expected = {archive, metadata_name}
        if name.startswith("darwin-"):
            expected.add(target["signing"]["notarization"]["developerLog"]["name"])
        if {p.name for p in candidate.iterdir()} != expected:
            raise ValueError("independent candidate asset set is not exact")
        for asset in expected:
            original, assembled = candidate / asset, directory / asset
            if (not stat.S_ISREG(original.lstat().st_mode)
                    or original.stat().st_size != assembled.stat().st_size
                    or sha256_file(original) != sha256_file(assembled)):
                raise ValueError("assembled release differs from independent reference")
    sources_file = ROOT / "sources.env"
    sources = load_sources(sources_file)
    with tempfile.TemporaryDirectory(prefix="motrix-source-recheck-") as temp:
        assets = module.copy_source_assets(source_dir, Path(temp), sources, sources_file)
        if assets != manifest["sourceAssets"]:
            raise ValueError("assembled source assets differ from independently authenticated sources")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("sign", "verify", "verify-manifest"))
    parser.add_argument("--directory", type=Path, default=Path("."))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit")
    parser.add_argument("--reference-dir", type=Path)
    parser.add_argument("--source-reference-dir", type=Path)
    parser.add_argument("--expected-macos-team-id")
    parser.add_argument("--expected-macos-cert-sha256")
    args = parser.parse_args()
    # Remove credentials before any native subprocess can inherit the environment.
    private = os.environ.pop("FFMPEG_MANIFEST_PRIVATE_KEY", None)
    if args.mode == "verify-manifest":
        raw = read_regular(args.directory / MANIFEST, 1024 * 1024)
        verify(raw, read_regular(args.directory / SIGNATURE, 4096))
        manifest = json.loads(raw)
        if (manifest.get("schemaVersion") != 3 or manifest.get("formalRelease") is not True
                or manifest.get("repository") != "motrixapp/ffmpeg-static"
                or manifest.get("windowsTrust") != "motrix-ed25519"
                or manifest.get("releaseTag") != args.tag
                or not isinstance(manifest.get("releaseCommit"), str)
                or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", manifest["releaseCommit"])
                or manifest["releaseCommit"] != manifest.get("controlCommit")):
            raise ValueError("invalid formal manifest identity")
        print("verify-manifest: pinned Ed25519 signature verified")
        return
    if not args.commit:
        raise ValueError("full release sign/verify requires --commit")
    raw = check_release(args.directory, args.tag, args.commit, args.mode == "verify")
    if args.mode == "sign":
        if not args.reference_dir or not args.source_reference_dir:
            raise ValueError("signing requires independent candidate and source references")
        check_references(args.directory, args.reference_dir, args.source_reference_dir,
                         raw, args.expected_macos_team_id, args.expected_macos_cert_sha256)
        if not private:
            raise ValueError("protected manifest signing key is missing")
        envelope = sign(raw, private)
        with (args.directory / SIGNATURE).open("xb") as output:
            output.write(envelope)
        checksums = args.directory / "SHA256SUMS"
        with checksums.open("a", encoding="utf-8") as output:
            output.write(f"{hashlib.sha256(envelope).hexdigest()}  {SIGNATURE}\n")
        check_release(args.directory, args.tag, args.commit, True)
    print(f"{args.mode}: pinned Ed25519 manifest verified")


if __name__ == "__main__":
    main()
