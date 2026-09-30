#!/usr/bin/env python3
"""Parse llvm-readobj COFF imports with fail-closed delay-load handling."""

from __future__ import annotations

import argparse
import re
import sys


MAX_INPUT_BYTES = 16 * 1024 * 1024
IMPORT_START = re.compile(r"^\s*Import\s*\{\s*$")
IMPORT_TOKEN = re.compile(r"^\s*Import\b")
DELAY_TOKEN = re.compile(r"^\s*DelayImport\b")
NAME = re.compile(r"^\s*Name:\s*([^\s{}]+)\s*$")
CLOSE = re.compile(r"^\s*}\s*$")
DLL = re.compile(r"[A-Za-z0-9_.+-]+[.]dll", re.IGNORECASE)


class ImportError(ValueError):
    """llvm-readobj output violates the supported import-only profile."""


def parse_imports(text: str) -> list[str]:
    if "\0" in text:
        raise ImportError("llvm-readobj output contains NUL")
    imports: list[str] = []
    in_import = False
    names: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        if DELAY_TOKEN.match(line):
            raise ImportError(f"delay-load import is forbidden at line {number}")
        if not in_import:
            if IMPORT_START.match(line):
                in_import = True
                names = []
            elif IMPORT_TOKEN.match(line):
                raise ImportError(f"malformed import block at line {number}")
            continue

        if IMPORT_TOKEN.match(line):
            raise ImportError(f"nested or malformed import block at line {number}")
        if CLOSE.match(line):
            if len(names) != 1 or not DLL.fullmatch(names[0]):
                raise ImportError(
                    f"import block ending at line {number} lacks one safe DLL Name"
                )
            normalized = names[0].lower()
            if normalized in imports:
                raise ImportError(f"duplicate DLL import: {normalized}")
            imports.append(normalized)
            names = []
            in_import = False
            continue
        if "{" in line or "}" in line:
            raise ImportError(f"unexpected brace in import block at line {number}")
        name = NAME.match(line)
        if name:
            names.append(name.group(1))
    if in_import:
        raise ImportError("unterminated import block")
    if not imports:
        raise ImportError("no ordinary DLL imports found")
    return imports


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        parser.error("llvm-readobj output exceeds the input limit")
    try:
        text = raw.decode("utf-8", "strict")
        imports = parse_imports(text)
    except (ImportError, UnicodeError) as error:
        parser.error(str(error))
    for dependency in imports:
        print(dependency)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
