#!/usr/bin/env python3
"""Bind an annotated tag to its exact Git object and protected-main commit.

This is an integrity check, NOT a maintainer signature verification. Tagger
names/emails/timestamps are descriptive metadata, not authorization evidence.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pipeline_lib import _read_bounded_regular_file, load_json_file  # noqa: E402


def validate(record: object, raw: bytes, tag: str, object_sha: str, commit: str) -> dict[str, str]:
    if (not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_sha)
            or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit)
            or len(object_sha) != len(commit)
            or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+-motrix\.[0-9]+", tag)):
        raise ValueError("invalid expected release tag identity")
    if not raw or len(raw) > 1024 * 1024 or b"\x00" in raw:
        raise ValueError("invalid annotated tag object size or bytes")
    git_object = b"tag " + str(len(raw)).encode("ascii") + b"\x00" + raw
    digest = (hashlib.sha1(git_object).hexdigest() if len(object_sha) == 40
              else hashlib.sha256(git_object).hexdigest())
    if digest != object_sha:
        raise ValueError("annotated tag bytes do not match the Git object SHA")
    header, separator, _message = raw.partition(b"\n\n")
    if not separator:
        raise ValueError("annotated tag has no header boundary")
    lines = header.decode("utf-8", errors="strict").split("\n")
    if len(lines) != 4 or lines[:3] != [f"object {commit}", "type commit", f"tag {tag}"]:
        raise ValueError("annotated tag must directly target the exact release commit")
    if any(ord(char) < 32 or ord(char) == 127 for char in lines[3]):
        raise ValueError("invalid tagger header characters")
    match = re.fullmatch(r"tagger ([^<>]+) <([^<>]+)> ([0-9]{1,12}) ([+-])([0-9]{2})([0-9]{2})", lines[3])
    if not match or not match[1].strip() or not match[2].strip():
        raise ValueError("invalid annotated tagger metadata")
    hours, minutes = int(match[5]), int(match[6])
    if hours > 14 or minutes > 59 or (hours == 14 and minutes != 0):
        raise ValueError("invalid tagger timezone")
    created = dt.datetime.fromtimestamp(int(match[3]), tz=dt.timezone.utc)
    canonical = created.isoformat(timespec="seconds").replace("+00:00", "Z")
    if not isinstance(record, dict) or record.get("sha") != object_sha or record.get("tag") != tag:
        raise ValueError("GitHub annotated tag identity mismatch")
    target, tagger = record.get("object"), record.get("tagger")
    if (not isinstance(target, dict) or target.get("type") != "commit" or target.get("sha") != commit):
        raise ValueError("GitHub tag must directly target the exact release commit")
    if (not isinstance(tagger, dict) or tagger.get("name") != match[1]
            or tagger.get("email") != match[2] or tagger.get("date") != canonical):
        raise ValueError("GitHub tagger metadata differs from the exact Git object")
    # Deliberately do not require verification.verified, GPG, or a tagger-email pin.
    return {"tagObjectSha": object_sha, "releaseCreated": canonical}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--raw-object", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--object-sha", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--format", choices=("json", "github-output"), default="json")
    options = parser.parse_args()
    try:
        result = validate(load_json_file(options.record, "GitHub tag record", maximum=2 * 1024 * 1024),
                          _read_bounded_regular_file(options.raw_object, "annotated Git tag", 1024 * 1024),
                          options.tag, options.object_sha, options.commit)
    except (OSError, ValueError, OverflowError) as error:
        parser.exit(2, f"Release tag binding: {error}\n")
    if options.format == "github-output":
        print(f"tag_object_sha={result['tagObjectSha']}\nrelease_created={result['releaseCreated']}")
    else:
        print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
