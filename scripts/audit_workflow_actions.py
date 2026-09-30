#!/usr/bin/env python3
"""Fail-closed audit for GitHub Action references in workflow YAML.

The project deliberately supports only the simple block form
``uses: actions/name@<full commit>``.  YAML aliases, anchors, tags, quoted
mapping keys, explicit mapping keys, and alternate ``uses`` spellings are
rejected so the audit cannot silently miss a semantically equivalent action
step.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Iterable


ACTION = re.compile(
    r"^(?P<indent> *)(?:- *)?uses: *"
    r"(?P<reference>actions/[A-Za-z0-9_.-]+@[0-9a-f]{40})"
    r"(?: +#.*)? *$"
)
BLOCK_SCALAR = re.compile(
    r"^(?P<indent> *)(?:- *)?(?P<key>[A-Za-z0-9_.-]+) *: *[|>]"
    r"(?:[1-9][+-]?|[+-][1-9]?)? *(?:#.*)?$"
)
USES_KEY = re.compile(r"(?<![A-Za-z0-9_.-])uses *:")
QUOTED_KEY = re.compile(r"(?:^|[,{]|-\s) *['\"][^'\"]+['\"] *:")
ANCHOR_OR_ALIAS = re.compile(r"(?<!\S)[&*][A-Za-z0-9_-]+")
EXPLICIT_KEY = re.compile(r"^ *(?:- *)?\?\s")


class AuditError(ValueError):
    """A workflow uses syntax outside the deliberately small policy."""


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _without_comments_and_strings(line: str) -> str:
    """Mask quoted scalars and discard an unquoted YAML comment."""

    output = list(line)
    quote: str | None = None
    index = 0
    while index < len(line):
        character = line[index]
        if quote is None:
            if character == "#" and (index == 0 or line[index - 1].isspace()):
                return "".join(output[:index])
            if character in ("'", '"'):
                quote = character
                output[index] = " "
        else:
            output[index] = " "
            if quote == '"' and character == "\\":
                index += 1
                if index < len(output):
                    output[index] = " "
            elif character == quote:
                if quote == "'" and index + 1 < len(line) and line[index + 1] == "'":
                    index += 1
                    output[index] = " "
                else:
                    quote = None
        index += 1
    return "".join(output)


def _without_github_expressions(line: str) -> str:
    """Mask GitHub's ``${{ ... }}`` syntax before rejecting YAML flow braces."""

    output = list(line)
    cursor = 0
    while True:
        start = line.find("${{", cursor)
        if start < 0:
            break
        end = line.find("}}", start + 3)
        if end < 0:
            raise AuditError("unterminated GitHub expression")
        for index in range(start, end + 2):
            output[index] = " "
        cursor = end + 2
    return "".join(output)


def audit_workflow(path: Path) -> set[str]:
    if not path.is_file() or path.is_symlink():
        raise AuditError(f"workflow is not a regular file: {path}")
    references: set[str] = set()
    scalar_parent_indent: int | None = None
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if "\t" in line:
            raise AuditError(f"{path}:{number}: tabs are not supported in workflow YAML")
        stripped = line.strip()
        if scalar_parent_indent is not None:
            if not stripped or _indent(line) > scalar_parent_indent:
                continue
            scalar_parent_indent = None
        if not stripped or line.lstrip().startswith("#"):
            continue
        scalar = BLOCK_SCALAR.fullmatch(line)
        if scalar:
            if scalar.group("key") == "uses":
                raise AuditError(
                    f"{path}:{number}: a uses value must not be a block scalar"
                )
            scalar_parent_indent = len(scalar.group("indent"))
            continue
        action = ACTION.fullmatch(line)
        if action:
            references.add(action.group("reference"))
            continue

        # These constructs can express or synthesize a mapping key while
        # evading a line-oriented ``uses:`` matcher.  They are unnecessary in
        # this repository, so unsupported syntax is a hard error.
        unquoted = _without_github_expressions(_without_comments_and_strings(line))
        if USES_KEY.search(unquoted) or "uses" in line and QUOTED_KEY.search(line):
            raise AuditError(
                f"{path}:{number}: unsupported uses syntax; use an unquoted block uses: key"
            )
        if QUOTED_KEY.search(line):
            raise AuditError(f"{path}:{number}: quoted mapping keys are not supported")
        if ANCHOR_OR_ALIAS.search(unquoted):
            raise AuditError(f"{path}:{number}: YAML anchors and aliases are not supported")
        # A YAML tag may change the type or interpretation of the following
        # node, including a mapping key (for example ``!!str \"uses\"``).
        # GitHub expressions have already been masked.  Reject every remaining
        # exclamation mark: ``!=`` is also a valid local YAML tag spelling, so
        # inequality operators must live inside a masked GitHub expression.
        if "!" in unquoted:
            raise AuditError(f"{path}:{number}: YAML tags are not supported")
        if EXPLICIT_KEY.match(unquoted):
            raise AuditError(f"{path}:{number}: explicit YAML mapping keys are not supported")
        if "{" in unquoted or "}" in unquoted or "[" in unquoted or "]" in unquoted:
            raise AuditError(f"{path}:{number}: YAML flow collections are not supported")
    return references


def workflow_paths(inputs: Iterable[Path]) -> list[Path]:
    result: set[Path] = set()
    for path in inputs:
        if path.is_dir():
            result.update(path.glob("*.yml"))
            result.update(path.glob("*.yaml"))
        else:
            result.add(path)
    if not result:
        raise AuditError("no workflow files found")
    return sorted(result)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    references: set[str] = set()
    try:
        for path in workflow_paths(args.paths):
            references.update(audit_workflow(path))
    except (AuditError, OSError, UnicodeError) as error:
        parser.error(str(error))
    for reference in sorted(references):
        print(reference)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
