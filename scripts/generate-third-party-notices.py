#!/usr/bin/env python3
"""Generate deterministic third-party notices from caller-supplied source trees.

Authentication is the surrounding build pipeline's responsibility.  This tool
deliberately does not download, extract, or authenticate anything: it only reads
five already-extracted source trees and reproduces relevant source comment blocks
verbatim.  This is a conservative notice inventory, not a license analyzer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


MAX_ENTRIES = 100_000
MAX_TREE_BYTES = 1 * 1024 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
MAX_LEADING_COMMENT_BYTES = 512 * 1024
MAX_DIRECTORY_DEPTH = 128
MAX_BLOCKS = 100_000
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_RETAINED_NOTICE_BYTES = 48 * 1024 * 1024
_OUTPUT_FIXED_RESERVE = 16 * 1024

_C_SUFFIXES = (
    ".c",
    ".h",
    ".cc",
    ".hh",
    ".cpp",
    ".hpp",
    ".cxx",
    ".hxx",
    ".m",
    ".mm",
    ".y",
    ".l",
    ".rc",
    ".cu",
    ".cuh",
    ".cl",
    ".glsl",
    ".metal",
    ".java",
    ".js",
    ".css",
)
_C_TEMPLATE_SUFFIXES = tuple(f"{suffix}.in" for suffix in _C_SUFFIXES)
_ASM_SUFFIXES = (".asm", ".nas", ".s", ".inc", ".inl", ".def")
_ASM_TEMPLATE_SUFFIXES = tuple(f"{suffix}.in" for suffix in _ASM_SUFFIXES)
_HASH_SUFFIXES = (
    ".sh",
    ".bash",
    ".zsh",
    ".mk",
    ".mak",
    ".make",
    ".am",
    ".ac",
    ".m4",
    ".py",
    ".pl",
    ".pm",
    ".rb",
    ".awk",
)
_HASH_NAMES = frozenset({"configure", "makefile", "gnumakefile"})
# C treats vertical tab and form feed as whitespace.  They may separate
# leading comments in historical sources, but are never copied into notices.
_ASCII_LAYOUT = frozenset(b" \t\r\n\v\f")
_ASCII_HORIZONTAL = frozenset(b" \t")
_UTF8_BOM = b"\xef\xbb\xbf"


class NoticeError(ValueError):
    """An unsafe input or an incomplete notice set was encountered."""


@dataclass(frozen=True, order=True)
class SourceRef:
    component: str
    path: str


@dataclass(frozen=True)
class ScanStats:
    entries: int
    input_bytes: int
    source_files: int
    occurrences: int
    unique_blocks: int
    isc_blocks: int
    ijg_blocks: int
    glumpy_blocks: int


@dataclass(frozen=True)
class GenerationResult:
    data: bytes
    sha256: str
    stats: ScanStats


_EXACT_FIRST_BLOCK_SHA256 = {
    SourceRef("FFmpeg", "libavutil/x86/x86inc.asm"): (
        "28e1d08c3aab06bb2a0bf15365261cf8b371fe1ba8c4427b351e57429dd80e06"
    ),
    SourceRef("x264", "common/x86/x86inc.asm"): (
        "33be636fa577611ee0b64d36abf21538b11ad8ec1deacffb5d31211f6d875ee2"
    ),
    SourceRef("FFmpeg", "libavcodec/jfdctint_template.c"): (
        "90da7eecd5d9e83cb5061af38fb56c4b99b975204f98d224249770c31812275a"
    ),
    SourceRef("FFmpeg", "libavcodec/jfdctfst.c"): (
        "f831f4602bd8c0446d5e26a4b14ddfa4581b95e4b61bb7cbb4697f22558e2e0f"
    ),
    SourceRef("FFmpeg", "libavcodec/jrevdct.c"): (
        "ee552ade15c696e8e75e9c1aa91193c8299ea3961e3510ab7667f9b3eea17123"
    ),
}
_LAME_FFTTBL_SOURCE = SourceRef("LAME", "libmp3lame/i386/ffttbl.nas")
_LAME_FFTTBL_FILE_SHA256 = (
    "5ec4d552351881974d78d43b6f49502170ac77f112286c33837111069475ac26"
)
_LAME_FFTTBL_UNSAFE_BLOCK_SHA256 = (
    "87077eb1b86cef850a07bb7b2aa4a87c7947ab245f9b22f769588fb392d4b541"
)
_GLUMPY_SOURCE = SourceRef("FFmpeg", "libswscale/filters.c")
_MUSL_REQUIRED_SOURCE = SourceRef("musl", "src/crypt/crypt_blowfish.c")
_FORTIFY_REQUIRED_SOURCE = SourceRef(
    "fortify-headers", "include/fortify-headers.h"
)
_GLUMPY_LICENSE_SOURCE = SourceRef("controlled-Glumpy", "LICENSE.txt")
_GLUMPY_CONTROLLED_LICENSE = b"""Copyright (c) 2014, Nicolas P. Rougier

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.
* Neither the name of Nicolas P. Rougier nor the names of its
  contributors may be used to endorse or promote products
  derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
_GLUMPY_CONTROLLED_LICENSE_SHA256 = (
    "0c52c60c6765db44c846b5acd2533652b73db55c2d50415d1a0bca0c7eeabad3"
)


def _has_unsafe_character(value: str) -> bool:
    for index, character in enumerate(value):
        if character in "\t\n":
            continue
        if character == "\r":
            if index + 1 < len(value) and value[index + 1] == "\n":
                continue
            return True
        if unicodedata.category(character) in {"Cc", "Cf", "Cs"}:
            return True
    return False


def _validate_path_text(value: str, *, what: str) -> None:
    if not value or any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        for character in value
    ):
        raise NoticeError(f"{what} contains an empty or unsafe path component")
    if unicodedata.normalize("NFC", value) != value:
        raise NoticeError(f"{what} is not Unicode NFC-normalized")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_private_directory(path: Path, *, what: str) -> None:
    getuid = getattr(os, "getuid", None)
    if getuid is None:
        raise NoticeError(f"{what}: current-uid validation is unavailable")
    current_uid = getuid()
    metadata = path.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != current_uid:
        raise NoticeError(f"{what} must be a directory owned by the current uid")

    current = path
    while True:
        ancestor = current.stat()
        if (
            ancestor.st_uid == current_uid
            and stat.S_ISDIR(ancestor.st_mode)
            and stat.S_IMODE(ancestor.st_mode) == 0o700
        ):
            return
        parent = current.parent
        if parent == current:
            break
        current = parent
    raise NoticeError(f"{what} is not protected by a current-uid 0700 ancestor")


def _source_style(path: Path, leading: bytes = b"") -> Optional[frozenset[str]]:
    name = path.name.lower()
    without_bom = (
        leading[len(_UTF8_BOM) :] if leading.startswith(_UTF8_BOM) else leading
    )
    if name.endswith(_C_SUFFIXES) or name.endswith(_C_TEMPLATE_SUFFIXES):
        styles = {"c", "slash"}
    elif name.endswith(_ASM_SUFFIXES) or name.endswith(_ASM_TEMPLATE_SUFFIXES):
        styles = {"at", "c", "slash", "semicolon"}
    elif name in _HASH_NAMES or name.startswith("makefile") or name.endswith(
        _HASH_SUFFIXES
    ):
        styles = {"hash"}
    elif without_bom.startswith(b"#!"):
        styles = {"hash"}
    else:
        return None

    without_space = without_bom.lstrip(b" \t\r\n")
    if without_space.startswith(b";"):
        styles.add("semicolon")
    if without_space.startswith(b"@"):
        styles.add("at")
    return frozenset(styles)


def _read_regular_file(path: Path, expected: os.stat_result) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        expected_identity = (
            expected.st_dev,
            expected.st_ino,
            expected.st_mode,
            expected.st_size,
            expected.st_mtime_ns,
            expected.st_ctime_ns,
        )
        opening_identity = identity
        if os.name == "nt":
            # CPython #157671: path stat reports creation time while fstat may
            # report change time. Compare the explicit birth time across APIs;
            # retain the descriptor's full ctime for the post-read race check.
            opening_identity = identity[:-1] + (
                getattr(opened, "st_birthtime_ns", opened.st_ctime_ns),
            )
            expected_identity = expected_identity[:-1] + (
                getattr(expected, "st_birthtime_ns", expected.st_ctime_ns),
            )
        if opening_identity != expected_identity or not stat.S_ISREG(opened.st_mode):
            raise NoticeError(f"source file changed while being opened: {path}")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise NoticeError(f"source file was truncated while reading: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise NoticeError(f"source file grew while reading: {path}")
        after = os.fstat(descriptor)
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if after_identity != identity:
            raise NoticeError(f"source file changed while being read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _line_end(data: bytes, start: int) -> int:
    newline = data.find(b"\n", start)
    return len(data) if newline < 0 else newline + 1


def _skip_layout(data: bytes, position: int) -> int:
    while position < len(data) and data[position] in _ASCII_LAYOUT:
        position += 1
    return position


def _line_marker_at(data: bytes, position: int, styles: frozenset[str]) -> bool:
    if "slash" in styles and data.startswith(b"//", position):
        return True
    if "semicolon" in styles and data.startswith(b";", position):
        return True
    if "at" in styles and data.startswith(b"@", position):
        return True
    if "hash" in styles and data.startswith(b"#", position):
        return True
    return False


def _decode_notice(raw: bytes, source: SourceRef) -> str:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise NoticeError(
            f"{source.component}:{source.path}: leading notice is not UTF-8"
        ) from error
    if _has_unsafe_character(text):
        raise NoticeError(
            f"{source.component}:{source.path}: leading notice contains control characters"
        )
    return text


def _append_safe_block(
    blocks: list[bytes], raw: bytes, source: SourceRef, file_sha256: str
) -> None:
    try:
        _decode_notice(raw, source)
    except NoticeError:
        # This one authenticated LAME file has a non-UTF-8 implementation-note
        # block after its separately preserved ASCII attribution.  No marker
        # heuristic is permitted: both the whole file and skipped block must
        # match the locked byte-for-byte exception.
        allowed = (
            source == _LAME_FFTTBL_SOURCE
            and bool(blocks)
            and file_sha256 == _LAME_FFTTBL_FILE_SHA256
            and hashlib.sha256(raw).hexdigest()
            == _LAME_FFTTBL_UNSAFE_BLOCK_SHA256
        )
        if allowed:
            return
        raise
    blocks.append(raw)


def _extract_leading_blocks(
    data: bytes, styles: frozenset[str], source: SourceRef
) -> list[bytes]:
    """Return complete leading comments without decoding unrelated file data."""

    blocks: list[bytes] = []
    file_sha256 = hashlib.sha256(data).hexdigest()
    position = len(_UTF8_BOM) if data.startswith(_UTF8_BOM) else 0
    position = _skip_layout(data, position)

    if "hash" in styles and position in {0, len(_UTF8_BOM)} and data.startswith(
        b"#!", position
    ):
        shebang_end = _line_end(data, position)
        _decode_notice(data[position:shebang_end], source)
        position = _skip_layout(data, shebang_end)

    while position < len(data):
        if position >= MAX_LEADING_COMMENT_BYTES:
            raise NoticeError(
                f"{source.component}:{source.path}: leading comment region exceeds "
                f"{MAX_LEADING_COMMENT_BYTES} bytes"
            )

        line_start = position
        while position < len(data) and data[position] in _ASCII_HORIZONTAL:
            position += 1

        if "c" in styles and data.startswith(b"/*", position):
            close = data.find(b"*/", position + 2, MAX_LEADING_COMMENT_BYTES + 1)
            if close < 0:
                raise NoticeError(
                    f"{source.component}:{source.path}: unterminated or oversized "
                    "leading block comment"
                )
            block_end = close + 2
            if block_end > MAX_LEADING_COMMENT_BYTES:
                raise NoticeError(
                    f"{source.component}:{source.path}: leading block comment "
                    "exceeds its size limit"
                )
            raw = data[line_start:block_end]
            _append_safe_block(blocks, raw, source, file_sha256)
            position = _skip_layout(data, block_end)
            continue

        if _line_marker_at(data, position, styles):
            block_start = line_start
            block_end = line_start
            while line_start < len(data):
                marker = line_start
                while marker < len(data) and data[marker] in _ASCII_HORIZONTAL:
                    marker += 1
                if not _line_marker_at(data, marker, styles):
                    break
                line_finish = _line_end(data, line_start)
                if line_finish > MAX_LEADING_COMMENT_BYTES:
                    raise NoticeError(
                        f"{source.component}:{source.path}: leading line-comment "
                        "block exceeds its size limit"
                    )
                block_end = line_finish
                line_start = line_finish
            raw = data[block_start:block_end]
            _append_safe_block(blocks, raw, source, file_sha256)
            position = _skip_layout(data, block_end)
            continue

        # Validate the line containing the first real source token before
        # stopping.  Otherwise a corrupt byte or control character placed in
        # front of a notice-looking block could silently hide that block by
        # making it look like ordinary source syntax.
        _decode_notice(data[line_start:_line_end(data, line_start)], source)

        # Only the comment prefix is relevant.  Data following the first real
        # source-token line is deliberately neither decoded nor copied.
        break

    return blocks


def _extract_glumpy_block(data: bytes, source: SourceRef) -> bytes:
    if source != _GLUMPY_SOURCE:
        raise NoticeError("internal error: Glumpy extraction used for wrong source")
    anchor = b"Nicolas P. Rougier. All rights reserved."
    if data.count(anchor) != 1:
        raise NoticeError(
            "FFmpeg:libswscale/filters.c: expected exactly one Glumpy attribution"
        )
    anchor_at = data.find(anchor)
    start = data.rfind(b"/*", 0, anchor_at)
    close = data.find(b"*/", anchor_at)
    if start < 0 or close < 0:
        raise NoticeError(
            "FFmpeg:libswscale/filters.c: malformed Glumpy attribution block"
        )
    end = close + 2
    if end - start > 64 * 1024:
        raise NoticeError(
            "FFmpeg:libswscale/filters.c: Glumpy attribution block is oversized"
        )
    raw = data[start:end]
    _decode_notice(raw, source)
    required = (
        b"Some of the filter code originally derives (via libplacebo/mpv) from Glumpy",
        b"Copyright (c) 2009-2016 Nicolas P. Rougier. All rights reserved.",
        b"Distributed under the (new) BSD License.",
        b"github.com/glumpy/glumpy/blob/master/glumpy/library/build-spatial-filters.py",
    )
    if not _contains_all((raw,), required):
        raise NoticeError(
            "FFmpeg:libswscale/filters.c: incomplete Glumpy attribution block"
        )
    return raw


def _walk_tree(
    component: str,
    root: Path,
    *,
    remaining_entries: int,
    remaining_input_bytes: int,
    remaining_blocks: int,
    remaining_retained_bytes: int,
    remaining_output_bytes: int,
) -> tuple[list[tuple[SourceRef, bytes]], int, int, int, int, int]:
    occurrences: list[tuple[SourceRef, bytes]] = []
    entries = 0
    input_bytes = 0
    source_files = 0
    retained_bytes = 0
    estimated_output_bytes = 0

    def record(source: SourceRef, block: bytes) -> None:
        nonlocal retained_bytes, estimated_output_bytes
        path_bytes = len(source.component.encode("utf-8")) + len(
            source.path.encode("utf-8")
        )
        retained_bytes += len(block) + path_bytes + 512
        estimated_output_bytes += len(block) + path_bytes + 512
        if retained_bytes > remaining_retained_bytes:
            raise NoticeError("notice collection exceeds its memory budget")
        if estimated_output_bytes > remaining_output_bytes:
            raise NoticeError("estimated notice output exceeds its output-size limit")
        occurrences.append((source, block))
        if len(occurrences) > remaining_blocks:
            raise NoticeError("notice occurrence count exceeds its limit")

    def visit(directory: Path, depth: int) -> None:
        nonlocal entries, input_bytes, source_files
        if depth > MAX_DIRECTORY_DEPTH:
            raise NoticeError(
                f"{component}: source tree exceeds its directory-depth limit"
            )
        children = []
        with os.scandir(directory) as iterator:
            for child in iterator:
                children.append(child)
                if entries + len(children) > remaining_entries:
                    raise NoticeError(
                        f"{component}: source tree has too many entries"
                    )
        entries += len(children)
        children.sort(key=lambda item: item.name)
        for child in children:
            _validate_path_text(child.name, what=f"{component} source entry")
            child_path = Path(child.path)
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise NoticeError(f"{component}: symbolic link is forbidden: {child_path}")
            resolved = child_path.resolve(strict=True)
            if not _is_relative_to(resolved, root):
                raise NoticeError(f"{component}: source path escapes its root: {child_path}")
            if stat.S_ISDIR(metadata.st_mode):
                visit(child_path, depth + 1)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise NoticeError(f"{component}: non-regular input is forbidden: {child_path}")
            input_bytes += metadata.st_size
            if metadata.st_size > MAX_SOURCE_FILE_BYTES:
                raise NoticeError(f"{component}: input file is too large: {child_path}")
            if input_bytes > remaining_input_bytes:
                raise NoticeError(f"{component}: source tree exceeds its input-size limit")

            data = _read_regular_file(child_path, metadata)
            styles = _source_style(child_path, data[:8])
            if styles is None:
                continue
            source_files += 1
            relative = child_path.relative_to(root).as_posix()
            _validate_path_text(relative, what=f"{component} relative source path")
            source = SourceRef(component, relative)
            for block in _extract_leading_blocks(data, styles, source):
                record(source, block)
            if source == _GLUMPY_SOURCE:
                record(source, _extract_glumpy_block(data, source))

    visit(root, 0)
    return (
        occurrences,
        entries,
        input_bytes,
        source_files,
        retained_bytes,
        estimated_output_bytes,
    )


def _contains_all(blocks: Iterable[bytes], phrases: Iterable[bytes]) -> bool:
    required = tuple(phrase.lower() for phrase in phrases)
    return any(all(phrase in block.lower() for phrase in required) for block in blocks)


def _validate_required_notices(
    by_source: dict[SourceRef, list[bytes]], all_occurrences: list[tuple[SourceRef, bytes]]
) -> tuple[int, int, int]:
    isc_count_phrases = (
        b"Copyright",
        b"Permission to use, copy, modify, and/or distribute this software",
        b"provided that the above",
        b"copyright notice and this permission notice appear in all copies",
        b'THE SOFTWARE IS PROVIDED "AS IS"',
        b"IN NO EVENT",
    )
    ijg_count_phrases = (
        b"Independent JPEG Group",
        b"Permission is hereby granted",
        b"NO WARRANTY",
        b"NO LIABILITY",
    )

    for source, expected_digest in _EXACT_FIRST_BLOCK_SHA256.items():
        blocks = by_source.get(source, ())
        actual_digest = hashlib.sha256(blocks[0]).hexdigest() if blocks else "missing"
        if actual_digest != expected_digest:
            raise NoticeError(
                f"required exact first notice mismatch for {source.component}:"
                f"{source.path}: expected {expected_digest}, got {actual_digest}"
            )

    musl_phrases = (
        b"Written by Solar Designer",
        b"No copyright is claimed",
        b"software is hereby placed in the public",
        b"domain.",
        b"Copyright (c) 1998-2014 Solar Designer",
        b"Redistribution and use in source and binary forms",
        b"ABSOLUTELY NO WARRANTY",
    )
    if not _contains_all(by_source.get(_MUSL_REQUIRED_SOURCE, ()), musl_phrases):
        raise NoticeError(
            "required musl Solar Designer public-domain/fallback notice was not captured"
        )

    fortify_phrases = (
        b"Copyright (C) 2015-2016 Dimitris Papastamos",
        b"Copyright (C) 2022 q66",
        b"Permission to use, copy, modify, and/or distribute this software",
        b'THE SOFTWARE IS PROVIDED "AS IS"',
        b"TORTIOUS ACTION",
    )
    if not _contains_all(
        by_source.get(_FORTIFY_REQUIRED_SOURCE, ()), fortify_phrases
    ):
        raise NoticeError("required fortify-headers 0BSD notice was not captured")

    glumpy_phrases = (
        b"Nicolas P. Rougier. All rights reserved.",
        b"Distributed under the (new) BSD License.",
        b"build-spatial-filters.py",
    )
    glumpy_blocks = sum(
        1
        for source, block in all_occurrences
        if source == _GLUMPY_SOURCE and _contains_all((block,), glumpy_phrases)
    )
    if glumpy_blocks != 1:
        raise NoticeError(
            f"required Glumpy new-BSD attribution count is {glumpy_blocks}, expected 1"
        )
    controlled = by_source.get(_GLUMPY_LICENSE_SOURCE, ())
    controlled_digest = (
        hashlib.sha256(controlled[0]).hexdigest() if len(controlled) == 1 else "missing"
    )
    controlled_phrases = (
        b"Redistribution and use in source and binary forms",
        b"Neither the name of Nicolas P. Rougier",
        b"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS",
        b"EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE",
    )
    if (
        controlled_digest != _GLUMPY_CONTROLLED_LICENSE_SHA256
        or not _contains_all(controlled, controlled_phrases)
    ):
        raise NoticeError("controlled Glumpy BSD-3-Clause license text mismatch")

    isc_blocks = 0
    ijg_blocks = 0
    for _source, block in all_occurrences:
        if _contains_all((block,), isc_count_phrases):
            isc_blocks += 1
        if _contains_all((block,), ijg_count_phrases):
            ijg_blocks += 1
    return isc_blocks, ijg_blocks, glumpy_blocks


def _render(
    grouped: dict[bytes, set[SourceRef]],
    *,
    entries: int,
    input_bytes: int,
    source_files: int,
    occurrences: int,
    isc_blocks: int,
    ijg_blocks: int,
    glumpy_blocks: int,
) -> bytes:
    ordered = sorted(
        grouped.items(),
        key=lambda item: (
            tuple(sorted(item[1])),
            hashlib.sha256(item[0]).digest(),
            item[0],
        ),
    )
    output = bytearray()
    output.extend(b"Motrix static FFmpeg build - conservative source-tree notice inventory\n")
    output.extend(b"=====================================================================\n\n")
    output.extend(
        b"This conservative source-tree notice inventory reproduces leading comments "
        b"from five\ncaller-supplied FFmpeg, x264, LAME, musl, and fortify-headers trees, "
        b"plus explicitly\nvalidated embedded attributions. This generator does not authenticate "
        b"those inputs; input\nauthentication is the surrounding pipeline's responsibility. Identical "
        b"blocks are emitted\nonce with every source path listed. This inventory "
        b"does not determine an artifact's effective\nor concluded license.\n\n"
    )
    output.extend(
        b"A controlled, hash-locked copy of the complete Glumpy BSD-3-Clause text is "
        b"included to\naccompany FFmpeg's embedded Glumpy attribution.\n"
    )
    output.extend(
        b"Controlled Glumpy BSD-3-Clause SHA-256: "
        + _GLUMPY_CONTROLLED_LICENSE_SHA256.encode("ascii")
        + b"\n\n"
    )
    output.extend(f"Source entries inspected: {entries}\n".encode("ascii"))
    output.extend(f"Source bytes bounded: {input_bytes}\n".encode("ascii"))
    output.extend(f"Source files scanned: {source_files}\n".encode("ascii"))
    output.extend(f"Notice occurrences: {occurrences}\n".encode("ascii"))
    output.extend(f"Unique notice blocks: {len(ordered)}\n".encode("ascii"))
    output.extend(f"Complete ISC-form occurrences: {isc_blocks}\n".encode("ascii"))
    output.extend(f"Complete IJG occurrences: {ijg_blocks}\n".encode("ascii"))
    output.extend(
        f"Validated Glumpy attribution occurrences: {glumpy_blocks}\n\n".encode(
            "ascii"
        )
    )

    for number, (block, sources) in enumerate(ordered, start=1):
        digest = hashlib.sha256(block).hexdigest()
        output.extend(f"=== Notice {number:05d} ===\n".encode("ascii"))
        output.extend(f"SHA-256: {digest}\n".encode("ascii"))
        output.extend(f"Raw-Bytes: {len(block)}\n".encode("ascii"))
        trailing_newline = "yes" if block.endswith(b"\n") else "no"
        output.extend(f"Ends-With-Newline: {trailing_newline}\n".encode("ascii"))
        output.extend(b"Sources:\n")
        for source in sorted(sources):
            output.extend(f"  - {source.component}: {source.path}\n".encode("utf-8"))
        output.extend(b"----- BEGIN VERBATIM NOTICE -----\n")
        output.extend(block)
        if not block.endswith(b"\n"):
            output.extend(b"\n")
        output.extend(b"----- END VERBATIM NOTICE -----\n\n")
        if len(output) > MAX_OUTPUT_BYTES:
            raise NoticeError("generated notice file exceeds its output-size limit")
    return bytes(output)


def generate(
    ffmpeg: Path,
    x264: Path,
    lame: Path,
    musl: Path,
    fortify_headers: Path,
) -> GenerationResult:
    roots: list[tuple[str, Path]] = []
    candidates = (
        ("FFmpeg", ffmpeg),
        ("x264", x264),
        ("LAME", lame),
        ("musl", musl),
        ("fortify-headers", fortify_headers),
    )
    for component, candidate in candidates:
        _validate_path_text(candidate.name, what=f"{component} source root")
        metadata = candidate.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise NoticeError(f"{component} source root must be a real directory: {candidate}")
        resolved = candidate.resolve(strict=True)
        _validate_private_directory(resolved, what=f"{component} source root")
        roots.append((component, resolved))

    for index, (component, root) in enumerate(roots):
        for other_component, other_root in roots[index + 1 :]:
            if _is_relative_to(root, other_root) or _is_relative_to(other_root, root):
                raise NoticeError(
                    f"source roots must not overlap: {component} and {other_component}"
                )

    controlled_cost = (
        len(_GLUMPY_CONTROLLED_LICENSE)
        + len(_GLUMPY_LICENSE_SOURCE.component.encode("utf-8"))
        + len(_GLUMPY_LICENSE_SOURCE.path.encode("utf-8"))
        + 512
    )
    if MAX_BLOCKS < 1:
        raise NoticeError("notice occurrence count cannot accommodate required notices")
    if controlled_cost > MAX_RETAINED_NOTICE_BYTES:
        raise NoticeError("combined notice collection exceeds its memory budget")
    if _OUTPUT_FIXED_RESERVE + controlled_cost > MAX_OUTPUT_BYTES:
        raise NoticeError("combined estimated notice output exceeds its output-size limit")

    occurrences: list[tuple[SourceRef, bytes]] = []
    total_entries = 0
    total_bytes = 0
    source_files = 0
    retained_notice_bytes = controlled_cost
    estimated_output_bytes = _OUTPUT_FIXED_RESERVE + controlled_cost
    for component, root in roots:
        found, entries, input_bytes, scanned, retained, estimated = _walk_tree(
            component,
            root,
            remaining_entries=MAX_ENTRIES - total_entries,
            remaining_input_bytes=MAX_TREE_BYTES - total_bytes,
            remaining_blocks=MAX_BLOCKS - len(occurrences) - 1,
            remaining_retained_bytes=(
                MAX_RETAINED_NOTICE_BYTES - retained_notice_bytes
            ),
            remaining_output_bytes=MAX_OUTPUT_BYTES - estimated_output_bytes,
        )
        occurrences.extend(found)
        total_entries += entries
        total_bytes += input_bytes
        source_files += scanned
        retained_notice_bytes += retained
        estimated_output_bytes += estimated
        if total_entries > MAX_ENTRIES:
            raise NoticeError("combined source trees have too many entries")
        if total_bytes > MAX_TREE_BYTES:
            raise NoticeError("combined source trees exceed the input-size limit")
        if len(occurrences) > MAX_BLOCKS:
            raise NoticeError("combined notice occurrence count exceeds its limit")
        if retained_notice_bytes > MAX_RETAINED_NOTICE_BYTES:
            raise NoticeError("combined notice collection exceeds its memory budget")
        if estimated_output_bytes > MAX_OUTPUT_BYTES:
            raise NoticeError("combined estimated notice output exceeds its size limit")

    occurrences.append((_GLUMPY_LICENSE_SOURCE, _GLUMPY_CONTROLLED_LICENSE))

    by_source: dict[SourceRef, list[bytes]] = {}
    grouped: dict[bytes, set[SourceRef]] = {}
    for source, block in occurrences:
        by_source.setdefault(source, []).append(block)
        grouped.setdefault(block, set()).add(source)
    isc_blocks, ijg_blocks, glumpy_blocks = _validate_required_notices(
        by_source, occurrences
    )
    data = _render(
        grouped,
        entries=total_entries,
        input_bytes=total_bytes,
        source_files=source_files,
        occurrences=len(occurrences),
        isc_blocks=isc_blocks,
        ijg_blocks=ijg_blocks,
        glumpy_blocks=glumpy_blocks,
    )
    stats = ScanStats(
        entries=total_entries,
        input_bytes=total_bytes,
        source_files=source_files,
        occurrences=len(occurrences),
        unique_blocks=len(grouped),
        isc_blocks=isc_blocks,
        ijg_blocks=ijg_blocks,
        glumpy_blocks=glumpy_blocks,
    )
    return GenerationResult(data, hashlib.sha256(data).hexdigest(), stats)


def _validate_output(output: Path, roots: Iterable[Path]) -> Path:
    parent = output.parent.resolve(strict=True)
    if not parent.is_dir():
        raise NoticeError(f"output parent is not a directory: {output.parent}")
    _validate_private_directory(parent, what="output parent")
    resolved_output = parent / output.name
    _validate_path_text(output.name, what="output file")
    if output.name in {".", ".."}:
        raise NoticeError("output must name a file")
    for root in roots:
        if _is_relative_to(resolved_output, root):
            raise NoticeError("output must not be located inside an input source tree")
    try:
        metadata = output.lstat()
    except FileNotFoundError:
        return resolved_output
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise NoticeError("existing output must be a regular file, not a link")
    return resolved_output


def write_atomic(output: Path, data: bytes) -> None:
    if len(data) > MAX_OUTPUT_BYTES:
        raise NoticeError("generated notice file exceeds its output-size limit")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            directory_flags |= os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        directory_descriptor = os.open(output.parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parse_args(arguments: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ffmpeg", required=True, type=Path, help="extracted FFmpeg root")
    parser.add_argument("--x264", required=True, type=Path, help="extracted x264 root")
    parser.add_argument("--lame", required=True, type=Path, help="extracted LAME root")
    parser.add_argument("--musl", required=True, type=Path, help="extracted musl root")
    parser.add_argument(
        "--fortify-headers",
        required=True,
        type=Path,
        help="extracted fortify-headers root",
    )
    parser.add_argument("--output", required=True, type=Path, help="output notice path")
    return parser.parse_args(arguments)


def main(arguments: Optional[list[str]] = None) -> int:
    options = parse_args(arguments)
    try:
        roots = tuple(
            path.resolve(strict=True)
            for path in (
                options.ffmpeg,
                options.x264,
                options.lame,
                options.musl,
                options.fortify_headers,
            )
        )
        output = _validate_output(options.output, roots)
        result = generate(
            options.ffmpeg,
            options.x264,
            options.lame,
            options.musl,
            options.fortify_headers,
        )
        write_atomic(output, result.data)
    except (NoticeError, OSError) as error:
        print(f"generate-third-party-notices: {error}", file=sys.stderr)
        return 2
    summary = {
        "bytes": len(result.data),
        "glumpyBlocks": result.stats.glumpy_blocks,
        "ijgBlocks": result.stats.ijg_blocks,
        "iscBlocks": result.stats.isc_blocks,
        "noticeOccurrences": result.stats.occurrences,
        "output": str(output),
        "sha256": result.sha256,
        "sourceBytes": result.stats.input_bytes,
        "sourceFiles": result.stats.source_files,
        "uniqueNoticeBlocks": result.stats.unique_blocks,
    }
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
