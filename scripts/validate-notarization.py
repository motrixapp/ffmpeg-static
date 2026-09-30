#!/usr/bin/env python3
"""Validate Apple notarization responses against the exact submitted ZIP."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Isolated mode intentionally removes the script directory. Restore only this
# resolved protected directory so the adjacent policy module remains importable
# without trusting PYTHONPATH or the working directory.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from pipeline_lib import (
    MAX_NOTARIZATION_JSON_BYTES,
    load_json_file,
    safe_basename,
    sha256_file,
    validate_notarization_log,
    validate_notarization_submission,
)


def require_regular_file(path: Path, context: str) -> Path:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{context} is not a regular file: {path}")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--submission-result", required=True, type=Path)
    parser.add_argument("--developer-log", type=Path)
    parser.add_argument("--print-submission-id", action="store_true")
    args = parser.parse_args()

    archive = require_regular_file(args.archive, "notarized archive")
    safe_basename(archive.name)
    if archive.suffix != ".zip":
        raise ValueError("notarized archive must be a ZIP file")
    submission = load_json_file(
        args.submission_result,
        "notarization submission result",
        maximum=MAX_NOTARIZATION_JSON_BYTES,
    )
    submission_id = validate_notarization_submission(submission)

    if args.developer_log is not None:
        developer_log = load_json_file(
            args.developer_log,
            "notarization developer log",
            maximum=MAX_NOTARIZATION_JSON_BYTES,
        )
        validate_notarization_log(
            developer_log,
            submission_id=submission_id,
            archive_name=archive.name,
            archive_sha256=sha256_file(archive),
        )
    elif not args.print_submission_id:
        parser.error("--developer-log is required unless --print-submission-id is used")

    if args.print_submission_id:
        print(submission_id)


if __name__ == "__main__":
    main()
