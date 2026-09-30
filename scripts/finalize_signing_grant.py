#!/usr/bin/env python3
"""Create or verify a canonical final authorization for a signing candidate.

Pre-sign approval artifacts are intentionally produced before their jobs run
the complete secret-free semantic test suite.  A final grant is produced only
by a downstream coordinator after every required approval job has succeeded.
It binds the exact approval artifact and all of the candidate provenance that
the approval attests to, so a signer can re-derive and verify the grant before
any signing credential is placed in its environment.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from pipeline_lib import canonical_json, load_json_bytes, require_target


MAX_DOCUMENT_BYTES = 256 * 1024
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*")
APPROVAL_KINDS = {
    "macos-static": {
        "platform": "darwin",
        "approval_prefix": "presign-approval-",
    },
    "windows-static": {
        "platform": "win32",
        "approval_prefix": "presign-static-approval-",
    },
    "windows-native": {
        "platform": "win32",
        "approval_prefix": "presign-native-approval-",
    },
}
APPROVAL_KEYS = {
    "schemaVersion",
    "target",
    "inputArtifactId",
    "inputArtifactDigest",
    "rebuildArtifactId",
    "rebuildArtifactDigest",
    "runId",
    "controlSha",
    "inputTreeSha256",
    "reproducibility",
    "binaries",
}


def _read_regular(path: Path, maximum: int = MAX_DOCUMENT_BYTES) -> bytes:
    """Read one bounded regular file without following a final symlink."""

    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise ValueError(f"expected a non-empty regular file: {path}")
    if before.st_size > maximum:
        raise ValueError(f"document exceeds its size limit: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size != before.st_size
        ):
            raise ValueError(f"document changed while opening: {path}")
        data = b""
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        after = os.fstat(descriptor)
        if (
            len(data) != before.st_size
            or len(data) > maximum
            or (after.st_dev, after.st_ino, after.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
        ):
            raise ValueError(f"document changed while reading: {path}")
        return data
    finally:
        os.close(descriptor)


def _positive_integer(value: object, context: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{context} must be a positive integer")
    return value


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or LOWER_SHA256.fullmatch(value) is None:
        raise ValueError(f"{context} must be a lowercase SHA-256 digest")
    return value


def approval_artifact_name(approval_kind: str, target: str) -> str:
    return str(APPROVAL_KINDS[approval_kind]["approval_prefix"]) + target


def grant_artifact_name(approval_kind: str, target: str) -> str:
    return f"final-signing-grant-{approval_kind}-{target}"


def signing_grant(
    *,
    approval_kind: str,
    target: str,
    approval_file: Path,
    approval_artifact_id: int,
    approval_artifact_digest: str,
    candidate_artifact_id: int,
    candidate_artifact_digest: str,
    rebuild_artifact_id: int,
    rebuild_artifact_digest: str,
    control_sha: str,
    run_id: int,
) -> dict[str, object]:
    """Validate the approval and derive its deterministic final grant."""

    if approval_kind not in APPROVAL_KINDS:
        raise ValueError(f"unsupported approval kind: {approval_kind}")
    target_info = require_target(target)
    if target_info["platform"] != APPROVAL_KINDS[approval_kind]["platform"]:
        raise ValueError(f"{approval_kind} cannot authorize target {target}")
    for value, context in (
        (approval_artifact_id, "approval artifact ID"),
        (candidate_artifact_id, "candidate artifact ID"),
        (rebuild_artifact_id, "rebuild artifact ID"),
        (run_id, "run ID"),
    ):
        _positive_integer(value, context)
    for value, context in (
        (approval_artifact_digest, "approval artifact digest"),
        (candidate_artifact_digest, "candidate artifact digest"),
        (rebuild_artifact_digest, "rebuild artifact digest"),
    ):
        _digest(value, context)
    if not isinstance(control_sha, str) or COMMIT_SHA.fullmatch(control_sha) is None:
        raise ValueError("control SHA must be a lowercase Git object ID")

    approval_bytes = _read_regular(approval_file)
    approval = load_json_bytes(
        approval_bytes, "pre-sign approval", maximum=MAX_DOCUMENT_BYTES
    )
    if not isinstance(approval, dict) or set(approval) != APPROVAL_KEYS:
        raise ValueError("pre-sign approval has an unexpected schema")
    if approval_bytes != canonical_json(approval):
        raise ValueError("pre-sign approval is not canonical JSON")
    if (
        approval.get("schemaVersion") != 2
        or type(approval.get("schemaVersion")) is not int
    ):
        raise ValueError("unsupported pre-sign approval schema")

    expected_values = {
        "target": target,
        "inputArtifactId": candidate_artifact_id,
        "inputArtifactDigest": candidate_artifact_digest,
        "rebuildArtifactId": rebuild_artifact_id,
        "rebuildArtifactDigest": rebuild_artifact_digest,
        "runId": run_id,
        "controlSha": control_sha,
    }
    for key, expected in expected_values.items():
        if approval.get(key) != expected or type(approval.get(key)) is not type(expected):
            raise ValueError(f"pre-sign approval {key} binding mismatch")

    tree_sha = _digest(approval.get("inputTreeSha256"), "input tree digest")
    reproducibility = approval.get("reproducibility")
    if not isinstance(reproducibility, dict) or set(reproducibility) != {
        "mode",
        "byteForByte",
        "rebuildTreeSha256",
    }:
        raise ValueError("pre-sign approval has invalid reproducibility evidence")
    if (
        reproducibility.get("mode") != "independent-clean-rebuild"
        or reproducibility.get("byteForByte") is not True
        or _digest(
            reproducibility.get("rebuildTreeSha256"), "rebuild tree digest"
        )
        != tree_sha
    ):
        raise ValueError("pre-sign approval does not prove a byte-for-byte rebuild")

    executable = "ffmpeg.exe" if target_info["platform"] == "win32" else "ffmpeg"
    probe = "ffprobe.exe" if target_info["platform"] == "win32" else "ffprobe"
    binaries = approval.get("binaries")
    if not isinstance(binaries, dict) or set(binaries) != {executable, probe}:
        raise ValueError("pre-sign approval has an invalid binary digest set")
    bound_binaries = {
        executable: _digest(binaries.get(executable), f"{executable} digest"),
        probe: _digest(binaries.get(probe), f"{probe} digest"),
    }

    return {
        "schemaVersion": 1,
        "approvalKind": approval_kind,
        "target": target,
        "approvalArtifact": {
            "name": approval_artifact_name(approval_kind, target),
            "id": approval_artifact_id,
            "digest": approval_artifact_digest,
        },
        "approvalDocumentSha256": hashlib.sha256(approval_bytes).hexdigest(),
        "candidateArtifact": {
            "name": f"signing-input-{target}",
            "id": candidate_artifact_id,
            "digest": candidate_artifact_digest,
        },
        "rebuildArtifact": {
            "name": f"independent-rebuild-{target}",
            "id": rebuild_artifact_id,
            "digest": rebuild_artifact_digest,
        },
        "runId": run_id,
        "controlSha": control_sha,
        "inputTreeSha256": tree_sha,
        "reproducibility": {
            "mode": "independent-clean-rebuild",
            "byteForByte": True,
            "rebuildTreeSha256": tree_sha,
        },
        "binaries": bound_binaries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approval-kind", required=True, choices=sorted(APPROVAL_KINDS))
    parser.add_argument("--target", required=True)
    parser.add_argument("--approval-file", required=True, type=Path)
    parser.add_argument("--approval-artifact-id", required=True)
    parser.add_argument("--approval-artifact-digest", required=True)
    parser.add_argument("--candidate-artifact-id", required=True)
    parser.add_argument("--candidate-artifact-digest", required=True)
    parser.add_argument("--rebuild-artifact-id", required=True)
    parser.add_argument("--rebuild-artifact-digest", required=True)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--run-id", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write-grant", type=Path)
    mode.add_argument("--verify-grant", type=Path)
    args = parser.parse_args()

    integer_arguments = (
        (args.approval_artifact_id, "approval artifact ID"),
        (args.candidate_artifact_id, "candidate artifact ID"),
        (args.rebuild_artifact_id, "rebuild artifact ID"),
        (args.run_id, "run ID"),
    )
    parsed_integers: list[int] = []
    for value, context in integer_arguments:
        if POSITIVE_INTEGER.fullmatch(value) is None:
            parser.error(f"{context} must be a positive decimal integer")
        parsed_integers.append(int(value))
    try:
        grant = signing_grant(
            approval_kind=args.approval_kind,
            target=args.target,
            approval_file=args.approval_file,
            approval_artifact_id=parsed_integers[0],
            approval_artifact_digest=args.approval_artifact_digest,
            candidate_artifact_id=parsed_integers[1],
            candidate_artifact_digest=args.candidate_artifact_digest,
            rebuild_artifact_id=parsed_integers[2],
            rebuild_artifact_digest=args.rebuild_artifact_digest,
            control_sha=args.control_sha,
            run_id=parsed_integers[3],
        )
        encoded = canonical_json(grant)
        if args.write_grant is not None:
            output = args.write_grant
            if output.exists() or output.is_symlink():
                raise ValueError(f"grant output already exists: {output}")
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.parent.is_symlink():
                raise ValueError(f"grant output directory is unsafe: {output.parent}")
            with output.open("xb") as handle:
                handle.write(encoded)
        else:
            assert args.verify_grant is not None
            supplied = _read_regular(args.verify_grant)
            parsed = load_json_bytes(
                supplied, "final signing grant", maximum=MAX_DOCUMENT_BYTES
            )
            if supplied != canonical_json(parsed) or parsed != grant:
                raise ValueError("final grant does not bind this exact tested approval")
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
