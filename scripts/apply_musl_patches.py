#!/usr/bin/env python3
"""Apply only the locked upstream musl security backports, before compilation."""

from __future__ import annotations

import argparse
import hashlib
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pipeline_lib import ROOT, _read_bounded_regular_file, load_sources  # noqa: E402


PATCHES = (
    ("musl-CVE-2026-6042.patch", "MUSL_ICONV_PATCH_SHA256"),
    ("musl-CVE-2026-40200.patch", "MUSL_QSORT_PATCH_SHA256"),
)
RESULTS = (
    ("src/locale/iconv.c", "MUSL_PATCHED_ICONV_SHA256"),
    ("src/locale/gb18030utf.h", "MUSL_PATCHED_GB18030UTF_SHA256"),
    ("src/stdlib/qsort.c", "MUSL_PATCHED_QSORT_SHA256"),
)


def verify_results(root: Path, sources: dict[str, str]) -> None:
    for relative, key in RESULTS:
        # Refuse symlink ancestors as well as symlink leaves.
        current = root
        for component in Path(relative).parts[:-1]:
            current = current / component
            if not stat.S_ISDIR(current.lstat().st_mode):
                raise ValueError(f"unsafe musl source directory: {current}")
        data = _read_bounded_regular_file(root / relative, "patched musl source", 128 * 1024)
        if hashlib.sha256(data).hexdigest() != sources[key]:
            raise ValueError(f"patched musl source hash mismatch: {relative}")


def apply(root: Path, sources: dict[str, str], patch_directory: Path) -> None:
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("musl root must be a non-symlink directory")
    root = root.resolve(strict=True)
    for relative in ("src", "src/locale", "src/stdlib"):
        if not stat.S_ISDIR((root / relative).lstat().st_mode):
            raise ValueError(f"unsafe musl source directory: {relative}")
    for relative in ("src/locale/iconv.c", "src/stdlib/qsort.c"):
        _read_bounded_regular_file(root / relative, "original musl source", 128 * 1024)
    if (root / "src/locale/gb18030utf.h").exists() or (
        root / "src/locale/gb18030utf.h"
    ).is_symlink():
        raise ValueError("musl security patches require a fresh unpatched tree")
    # Read/hash both private snapshots before running patch. Never execute or
    # pass an unverified, concurrently replaceable patch path to a child.
    snapshots = []
    for filename, key in PATCHES:
        data = _read_bounded_regular_file(patch_directory / filename, "musl patch", 64 * 1024)
        if hashlib.sha256(data).hexdigest() != sources[key]:
            raise ValueError(f"musl patch hash mismatch: {filename}")
        snapshots.append(data)
    with tempfile.TemporaryDirectory(prefix=".musl-patch-", dir=root.parent) as temporary:
        for data in snapshots:
            result = subprocess.run(
                ["/usr/bin/patch", "--batch", "--forward", "--fuzz=0", "-p1"],
                input=data,
                cwd=root,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": temporary},
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=60,
                check=False,
            )
            output = result.stdout.decode("utf-8", errors="replace")
            if result.returncode or re.search(r"offset|fuzz|reversed|failed", output, re.I):
                raise ValueError(f"musl patch did not apply exactly: {output}")
    verify_results(root, sources)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    options = parser.parse_args()
    try:
        apply(options.root, load_sources(), ROOT / "patches")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, f"musl security backports: {error}\n")
    print("musl: CVE-2026-6042 and CVE-2026-40200 backports and result hashes verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
