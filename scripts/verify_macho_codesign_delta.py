#!/usr/bin/env python3
"""Prove that macOS signing changed only the Mach-O code-signature region."""

from __future__ import annotations

import argparse
import stat
import struct
from pathlib import Path
from typing import NamedTuple


MAX_BINARY_BYTES = 256 * 1024 * 1024
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CSSLOT_CODEDIRECTORY = 0
CSSLOT_SIGNATURESLOT = 0x10000
CS_ADHOC = 0x2
CS_RUNTIME = 0x10000


class DeltaError(ValueError):
    """The signed Mach-O is not the bound unsigned program plus a signature."""


class MachLayout(NamedTuple):
    signature_offset: int
    signature_size: int
    signature_size_field: int
    linkedit_vm_size_field: int
    linkedit_file_size_field: int
    linkedit_file_offset: int
    code_directory_flags: int
    has_cms_signature: bool


def _u32le(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise DeltaError("truncated Mach-O field")
    return struct.unpack_from("<I", data, offset)[0]


def _u64le(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise DeltaError("truncated Mach-O field")
    return struct.unpack_from("<Q", data, offset)[0]


def _u32be(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise DeltaError("truncated code-signing field")
    return struct.unpack_from(">I", data, offset)[0]


def _parse_superblob(data: bytes, offset: int, size: int) -> tuple[int, bool]:
    if size < 20 or offset < 0 or offset + size != len(data):
        raise DeltaError("invalid Mach-O code-signature extent")
    if _u32be(data, offset) != CSMAGIC_EMBEDDED_SIGNATURE:
        raise DeltaError("code-signature region is not an embedded SuperBlob")
    length = _u32be(data, offset + 4)
    count = _u32be(data, offset + 8)
    if count < 1 or count > 64 or length < 12 + count * 8 or length > size:
        raise DeltaError("invalid embedded SuperBlob header")
    slots: dict[int, tuple[int, int, int]] = {}
    spans: list[tuple[int, int]] = []
    for index in range(count):
        slot_type = _u32be(data, offset + 12 + index * 8)
        relative = _u32be(data, offset + 16 + index * 8)
        if slot_type in slots or relative < 12 + count * 8 or relative + 8 > length:
            raise DeltaError("invalid or duplicate embedded signature slot")
        blob_magic = _u32be(data, offset + relative)
        blob_length = _u32be(data, offset + relative + 4)
        if blob_length < 8 or relative + blob_length > length:
            raise DeltaError("embedded signature slot exceeds the SuperBlob")
        slots[slot_type] = (relative, blob_length, blob_magic)
        spans.append((relative, relative + blob_length))
    spans.sort()
    if any(right_start < left_end for (_, left_end), (right_start, _) in zip(spans, spans[1:])):
        raise DeltaError("embedded signature slots overlap")
    primary = slots.get(CSSLOT_CODEDIRECTORY)
    if primary is None or primary[2] != CSMAGIC_CODEDIRECTORY or primary[1] < 16:
        raise DeltaError("embedded signature has no primary CodeDirectory")
    flags = _u32be(data, offset + primary[0] + 12)
    cms = slots.get(CSSLOT_SIGNATURESLOT)
    if cms is not None and cms[2] != CSMAGIC_BLOBWRAPPER:
        raise DeltaError("CMS signature slot is not a BlobWrapper")
    return flags, cms is not None


def parse_macho(data: bytes) -> MachLayout:
    if len(data) < 32 or _u32le(data, 0) != MH_MAGIC_64:
        raise DeltaError("input is not a thin little-endian 64-bit Mach-O")
    ncmds = _u32le(data, 16)
    sizeofcmds = _u32le(data, 20)
    commands_end = 32 + sizeofcmds
    if ncmds < 1 or ncmds > 4096 or commands_end > len(data):
        raise DeltaError("invalid Mach-O load-command table")
    cursor = 32
    signature_commands: list[tuple[int, int, int]] = []
    linkedit_commands: list[tuple[int, int, int, int]] = []
    for _index in range(ncmds):
        command = _u32le(data, cursor)
        command_size = _u32le(data, cursor + 4)
        if command_size < 8 or command_size % 8 or cursor + command_size > commands_end:
            raise DeltaError("invalid Mach-O load command")
        if command == LC_CODE_SIGNATURE:
            if command_size != 16:
                raise DeltaError("LC_CODE_SIGNATURE has an invalid size")
            signature_commands.append(
                (_u32le(data, cursor + 8), _u32le(data, cursor + 12), cursor + 12)
            )
        elif command == LC_SEGMENT_64:
            if command_size < 72:
                raise DeltaError("LC_SEGMENT_64 is truncated")
            section_count = _u32le(data, cursor + 64)
            if command_size != 72 + section_count * 80:
                raise DeltaError("LC_SEGMENT_64 section table size is inconsistent")
            segment_name = data[cursor + 8 : cursor + 24].rstrip(b"\0")
            if segment_name == b"__LINKEDIT":
                linkedit_commands.append(
                    (
                        _u64le(data, cursor + 40),
                        _u64le(data, cursor + 48),
                        cursor + 32,
                        cursor + 48,
                    )
                )
        cursor += command_size
    if cursor != commands_end:
        raise DeltaError("Mach-O load commands do not fill sizeofcmds")
    if len(signature_commands) != 1 or len(linkedit_commands) != 1:
        raise DeltaError("Mach-O must have one code signature and one __LINKEDIT segment")
    signature_offset, signature_size, signature_size_field = signature_commands[0]
    linkedit_file_offset, linkedit_file_size, vm_size_field, file_size_field = (
        linkedit_commands[0]
    )
    linkedit_vm_size = _u64le(data, vm_size_field)
    if (
        signature_offset % 16
        or signature_offset < linkedit_file_offset
        or signature_offset + signature_size != len(data)
        or linkedit_file_offset + linkedit_file_size != len(data)
        or linkedit_vm_size < linkedit_file_size
    ):
        raise DeltaError("Mach-O signature is not the exact __LINKEDIT file suffix")
    flags, has_cms = _parse_superblob(data, signature_offset, signature_size)
    return MachLayout(
        signature_offset,
        signature_size,
        signature_size_field,
        vm_size_field,
        file_size_field,
        linkedit_file_offset,
        flags,
        has_cms,
    )


def _normalized_prefix(data: bytes, layout: MachLayout) -> bytes:
    normalized = bytearray(data[: layout.signature_offset])
    normalized[layout.signature_size_field : layout.signature_size_field + 4] = b"\0" * 4
    normalized[
        layout.linkedit_vm_size_field : layout.linkedit_vm_size_field + 8
    ] = b"\0" * 8
    normalized[
        layout.linkedit_file_size_field : layout.linkedit_file_size_field + 8
    ] = b"\0" * 8
    return bytes(normalized)


def verify_delta(unsigned: bytes, signed: bytes) -> None:
    unsigned_layout = parse_macho(unsigned)
    signed_layout = parse_macho(signed)
    if unsigned_layout.signature_offset != signed_layout.signature_offset:
        raise DeltaError("LC_CODE_SIGNATURE data offset changed during signing")
    if unsigned_layout.linkedit_file_offset != signed_layout.linkedit_file_offset:
        raise DeltaError("__LINKEDIT file offset changed during signing")
    if not unsigned_layout.code_directory_flags & CS_ADHOC or unsigned_layout.has_cms_signature:
        raise DeltaError("pre-signing Mach-O is not an ad-hoc-only build output")
    if (
        signed_layout.code_directory_flags & CS_ADHOC
        or not signed_layout.code_directory_flags & CS_RUNTIME
        or not signed_layout.has_cms_signature
    ):
        raise DeltaError("signed Mach-O lacks Developer ID CMS or hardened-runtime flags")
    if _normalized_prefix(unsigned, unsigned_layout) != _normalized_prefix(
        signed, signed_layout
    ):
        raise DeltaError("bytes outside code-signature bookkeeping changed during signing")


def verify_unsigned(data: bytes) -> None:
    layout = parse_macho(data)
    if not layout.code_directory_flags & CS_ADHOC or layout.has_cms_signature:
        raise DeltaError("pre-signing Mach-O is not an ad-hoc-only build output")


def read_regular(path: Path) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise DeltaError(f"not a non-empty regular file: {path}")
    if metadata.st_size > MAX_BINARY_BYTES:
        raise DeltaError(f"binary exceeds {MAX_BINARY_BYTES} bytes: {path}")
    with path.open("rb") as handle:
        data = handle.read(MAX_BINARY_BYTES + 1)
    current = path.lstat()
    if (
        current.st_dev != metadata.st_dev
        or current.st_ino != metadata.st_ino
        or current.st_size != metadata.st_size
        or current.st_mtime_ns != metadata.st_mtime_ns
    ):
        raise DeltaError(f"binary changed while being read: {path}")
    if len(data) != metadata.st_size:
        raise DeltaError(f"short or oversized read: {path}")
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--unsigned-only", action="store_true")
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        if args.unsigned_only:
            if len(args.paths) != 1:
                raise DeltaError("--unsigned-only requires exactly one Mach-O path")
            verify_unsigned(read_regular(args.paths[0]))
        else:
            if len(args.paths) != 2:
                raise DeltaError("signature delta verification requires unsigned and signed paths")
            verify_delta(read_regular(args.paths[0]), read_regular(args.paths[1]))
    except (DeltaError, OSError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
