#!/usr/bin/env python3
"""Validate and bind an exact secret-free signing input.

The approval emitted by this tool is intentionally deterministic.  A signing
job can recompute it from the exact artifact it downloaded and compare it with
the approval produced by an independent, secret-free verification job before
any certificate material is exposed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath

# ``python -I path/to/script.py`` intentionally omits the script directory
# from sys.path.  Add back only this protected, resolved directory so the
# adjacent dependency-free policy module can be imported without inheriting
# PYTHONPATH or the working directory.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from pipeline_lib import (
    MAX_LICENSE_FILE_BYTES,
    canonical_json,
    load_json_bytes,
    load_sources,
    parse_configure_record,
    require_target,
    required_license_files,
    validate_build_info,
)


ROOT = SCRIPT_DIR.parent
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_EVIDENCE_BYTES = 256 * 1024 * 1024
MAX_INPUT_BYTES = 2 * 1024 * 1024 * 1024
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*")


def _read_regular(path: Path, maximum: int) -> bytes:
    """Read a bounded regular file without following a final symlink."""

    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise ValueError(f"expected a non-empty regular file: {path}")
    if before.st_size > maximum:
        raise ValueError(f"file exceeds its signing-input limit: {path}")
    # CRT text mode truncates/rewrites arbitrary PE bytes on Windows.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
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
            raise ValueError(f"signing-input file changed while opening: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(data) != before.st_size
            or len(data) > maximum
            or (after.st_dev, after.st_ino, after.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
        ):
            raise ValueError(f"signing-input file changed while reading: {path}")
        return data
    finally:
        os.close(descriptor)


def _expected_files(target: str) -> dict[str, int]:
    platform = require_target(target)["platform"]
    executable = "ffmpeg.exe" if platform == "win32" else "ffmpeg"
    probe = "ffprobe.exe" if platform == "win32" else "ffprobe"
    files = {
        "build-info.json": 256 * 1024,
        "sources.env": 512 * 1024,
        f"payload/{executable}": MAX_BINARY_BYTES,
        f"payload/{probe}": MAX_BINARY_BYTES,
        "payload/configure.txt": 256 * 1024,
    }
    files.update(
        {
            f"payload/LICENSES/{name}": MAX_LICENSE_FILE_BYTES
            for name in required_license_files(target)
        }
    )
    if platform == "win32":
        for program in ("ffmpeg", "ffprobe"):
            files[f"work/link-maps/{program}.map"] = MAX_EVIDENCE_BYTES
            files[f"work/link-maps/{program}.link-trace.txt"] = MAX_EVIDENCE_BYTES
    if require_target(target)["arch"] == "x64":
        # Read-only build evidence, never a tool to execute in signing jobs.
        files["work/nasm/bin/nasm"] = 16 * 1024 * 1024
    return files


def _expected_directories(files: set[str]) -> set[str]:
    directories: set[str] = set()
    for name in files:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            directories.add(str(parent))
            parent = parent.parent
    return directories


def _inventory(root: Path) -> tuple[set[str], set[str]]:
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"signing input is not a regular directory: {root}")
    files: set[str] = set()
    directories: set[str] = set()
    for directory, child_directories, child_files in os.walk(
        root, topdown=True, followlinks=False
    ):
        base = Path(directory)
        for name in child_directories:
            path = base / name
            item = path.lstat()
            if not stat.S_ISDIR(item.st_mode):
                raise ValueError(f"signing input contains a non-directory: {path}")
            directories.add(path.relative_to(root).as_posix())
        for name in child_files:
            path = base / name
            item = path.lstat()
            if not stat.S_ISREG(item.st_mode):
                raise ValueError(f"signing input contains a non-regular file: {path}")
            files.add(path.relative_to(root).as_posix())
    return files, directories


def _validated_snapshot(
    target: str, root: Path, context: str
) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    expected = _expected_files(target)
    actual_files, actual_directories = _inventory(root)
    if actual_files != set(expected):
        raise ValueError(
            f"{context} file set mismatch; "
            f"missing={sorted(set(expected) - actual_files)}, "
            f"extra={sorted(actual_files - set(expected))}"
        )
    expected_directories = _expected_directories(set(expected))
    if actual_directories != expected_directories:
        raise ValueError(
            f"{context} directory set mismatch; "
            f"missing={sorted(expected_directories - actual_directories)}, "
            f"extra={sorted(actual_directories - expected_directories)}"
        )

    records: list[dict[str, object]] = []
    contents: dict[str, bytes] = {}
    total = 0
    for name in sorted(expected):
        data = _read_regular(root / name, expected[name])
        total += len(data)
        if total > MAX_INPUT_BYTES:
            raise ValueError(f"{context} exceeds the total size limit")
        contents[name] = data
        records.append(
            {
                "path": name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )

    protected_sources = _read_regular(ROOT / "sources.env", 512 * 1024)
    if contents["sources.env"] != protected_sources:
        raise ValueError(f"{context} sources.env differs from protected control code")
    sources = load_sources(root / "sources.env")
    configure = parse_configure_record(contents["payload/configure.txt"])
    build_info = load_json_bytes(
        contents["build-info.json"], f"{context} build info", maximum=256 * 1024
    )
    validate_build_info(build_info, target, sources, configure)
    if require_target(target)["arch"] == "x64":
        nasm_sha = hashlib.sha256(contents["work/nasm/bin/nasm"]).hexdigest()
        if nasm_sha != build_info["tools"]["nasm"]["binarySha256"]:
            raise ValueError("source-built NASM evidence differs from BUILD-INFO")
    return records, contents


def signing_approval(
    *,
    target: str,
    input_root: Path,
    rebuild_root: Path,
    artifact_id: int,
    artifact_digest: str,
    rebuild_artifact_id: int,
    rebuild_artifact_digest: str,
    control_sha: str,
    run_id: int,
) -> dict[str, object]:
    target_info = require_target(target)
    if artifact_id <= 0 or rebuild_artifact_id <= 0 or run_id <= 0:
        raise ValueError("artifact IDs and run ID must be positive")
    if LOWER_SHA256.fullmatch(artifact_digest) is None:
        raise ValueError("artifact digest must be a lowercase SHA-256 digest")
    if LOWER_SHA256.fullmatch(rebuild_artifact_digest) is None:
        raise ValueError("rebuild artifact digest must be a lowercase SHA-256 digest")
    if COMMIT_SHA.fullmatch(control_sha) is None:
        raise ValueError("control SHA must be a lowercase Git object ID")

    records, contents = _validated_snapshot(target, input_root, "signing input")
    rebuild_records, rebuild_contents = _validated_snapshot(
        target, rebuild_root, "independent rebuild"
    )
    different = sorted(
        name for name in contents if contents[name] != rebuild_contents[name]
    )
    if different:
        raise ValueError(
            "independent clean rebuild is not byte-for-byte reproducible: "
            + ", ".join(different)
        )
    tree_sha = hashlib.sha256(canonical_json(records)).hexdigest()
    rebuild_tree_sha = hashlib.sha256(canonical_json(rebuild_records)).hexdigest()
    if tree_sha != rebuild_tree_sha:
        raise ValueError("independent rebuild tree digest is inconsistent")

    executable = "ffmpeg.exe" if target_info["platform"] == "win32" else "ffmpeg"
    probe = "ffprobe.exe" if target_info["platform"] == "win32" else "ffprobe"
    return {
        "schemaVersion": 2,
        "target": target,
        "inputArtifactId": artifact_id,
        "inputArtifactDigest": artifact_digest,
        "rebuildArtifactId": rebuild_artifact_id,
        "rebuildArtifactDigest": rebuild_artifact_digest,
        "runId": run_id,
        "controlSha": control_sha,
        "inputTreeSha256": tree_sha,
        "reproducibility": {
            "mode": "independent-clean-rebuild",
            "byteForByte": True,
            "rebuildTreeSha256": rebuild_tree_sha,
        },
        "binaries": {
            executable: hashlib.sha256(contents[f"payload/{executable}"]).hexdigest(),
            probe: hashlib.sha256(contents[f"payload/{probe}"]).hexdigest(),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--rebuild-dir", required=True, type=Path)
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--rebuild-artifact-id", required=True)
    parser.add_argument("--rebuild-artifact-digest", required=True)
    parser.add_argument("--control-sha", required=True)
    parser.add_argument("--run-id", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write-approval", type=Path)
    mode.add_argument("--verify-approval", type=Path)
    args = parser.parse_args()

    if POSITIVE_INTEGER.fullmatch(args.artifact_id) is None:
        parser.error("artifact ID must be a positive decimal integer")
    if POSITIVE_INTEGER.fullmatch(args.rebuild_artifact_id) is None:
        parser.error("rebuild artifact ID must be a positive decimal integer")
    if POSITIVE_INTEGER.fullmatch(args.run_id) is None:
        parser.error("run ID must be a positive decimal integer")
    try:
        approval = signing_approval(
            target=args.target,
            input_root=args.input_dir,
            rebuild_root=args.rebuild_dir,
            artifact_id=int(args.artifact_id),
            artifact_digest=args.artifact_digest,
            rebuild_artifact_id=int(args.rebuild_artifact_id),
            rebuild_artifact_digest=args.rebuild_artifact_digest,
            control_sha=args.control_sha,
            run_id=int(args.run_id),
        )
        encoded = canonical_json(approval)
        if args.write_approval is not None:
            output = args.write_approval
            if output.exists() or output.is_symlink():
                raise ValueError(f"approval output already exists: {output}")
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.parent.is_symlink():
                raise ValueError(f"approval output directory is unsafe: {output.parent}")
            with output.open("xb") as handle:
                handle.write(encoded)
        else:
            assert args.verify_approval is not None
            supplied = _read_regular(args.verify_approval, 256 * 1024)
            parsed = load_json_bytes(supplied, "pre-sign approval", maximum=256 * 1024)
            if supplied != canonical_json(parsed) or parsed != approval:
                raise ValueError("pre-sign approval does not bind this exact signing input")
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
