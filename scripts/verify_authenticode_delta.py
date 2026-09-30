#!/usr/bin/env python3
"""Prove that Authenticode signing changed only PE signature bookkeeping.

This is intentionally independent of certificate-chain verification.  The
Windows smoke job performs that check with SignTool; this verifier compares the
bound pre-signing executable with the signed release executable byte for byte,
allowing only CheckSum, the Certificate Table directory entry, alignment
padding, and well-formed appended WIN_CERTIFICATE records.
"""

from __future__ import annotations

import argparse
import os
import stat
import struct
from pathlib import Path
from typing import NamedTuple


MAX_BINARY_BYTES = 256 * 1024 * 1024


class DeltaError(ValueError):
    """The signed image is not an append-only Authenticode transformation."""


class PeLayout(NamedTuple):
    checksum_offset: int
    security_directory_offset: int
    certificate_offset: int
    certificate_size: int
    mapped_file_end: int


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise DeltaError("truncated PE field")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise DeltaError("truncated PE field")
    return struct.unpack_from("<I", data, offset)[0]


def parse_pe(data: bytes) -> PeLayout:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise DeltaError("input is not a DOS/PE image")
    pe_offset = _u32(data, 0x3C)
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise DeltaError("invalid PE header offset")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise DeltaError("missing PE signature")
    coff = pe_offset + 4
    section_count = _u16(data, coff + 2)
    optional_size = _u16(data, coff + 16)
    optional = coff + 20
    optional_end = optional + optional_size
    if optional_end > len(data):
        raise DeltaError("truncated PE optional header")
    magic = _u16(data, optional)
    if magic == 0x10B:
        number_of_directories_offset = optional + 92
        directories = optional + 96
    elif magic == 0x20B:
        number_of_directories_offset = optional + 108
        directories = optional + 112
    else:
        raise DeltaError(f"unsupported PE optional-header magic: 0x{magic:04x}")
    checksum = optional + 64
    if _u32(data, number_of_directories_offset) < 5:
        raise DeltaError("PE image has no Certificate Table directory")
    security_directory = directories + 4 * 8
    if checksum + 4 > optional_end or security_directory + 8 > optional_end:
        raise DeltaError("PE optional header does not contain required fields")
    certificate_offset = _u32(data, security_directory)
    certificate_size = _u32(data, security_directory + 4)

    section_table = optional_end
    section_table_end = section_table + section_count * 40
    if section_table_end > len(data):
        raise DeltaError("truncated PE section table")
    mapped_end = section_table_end
    size_of_headers = _u32(data, optional + 60)
    if size_of_headers > len(data):
        raise DeltaError("PE SizeOfHeaders is beyond end of file")
    mapped_end = max(mapped_end, size_of_headers)
    for index in range(section_count):
        section = section_table + index * 40
        raw_size = _u32(data, section + 16)
        raw_offset = _u32(data, section + 20)
        if raw_size:
            raw_end = raw_offset + raw_size
            if raw_end < raw_offset or raw_end > len(data):
                raise DeltaError("PE section raw data is outside the file")
            mapped_end = max(mapped_end, raw_end)
    return PeLayout(
        checksum,
        security_directory,
        certificate_offset,
        certificate_size,
        mapped_end,
    )


def _normalize_header_fields(data: bytes, layout: PeLayout, prefix_size: int) -> bytes:
    normalized = bytearray(data[:prefix_size])
    normalized[layout.checksum_offset : layout.checksum_offset + 4] = b"\0" * 4
    normalized[
        layout.security_directory_offset : layout.security_directory_offset + 8
    ] = b"\0" * 8
    return bytes(normalized)


def _validate_certificates(data: bytes, offset: int, size: int) -> None:
    end = offset + size
    cursor = offset
    count = 0
    while cursor < end:
        if cursor + 8 > end:
            raise DeltaError("truncated WIN_CERTIFICATE header")
        length, revision, certificate_type = struct.unpack_from("<IHH", data, cursor)
        if length < 9:
            raise DeltaError("WIN_CERTIFICATE record is empty or truncated")
        padded_length = (length + 7) & ~7
        if cursor + padded_length > end:
            raise DeltaError("WIN_CERTIFICATE record exceeds Certificate Table")
        if revision != 0x0200 or certificate_type != 0x0002:
            raise DeltaError("WIN_CERTIFICATE is not a PKCS#7 Authenticode record")
        if data[cursor + 8] != 0x30:
            raise DeltaError("WIN_CERTIFICATE payload is not an ASN.1 SEQUENCE")
        if any(data[cursor + length : cursor + padded_length]):
            raise DeltaError("WIN_CERTIFICATE alignment padding is not zero")
        cursor += padded_length
        count += 1
    if cursor != end or count != 1:
        raise DeltaError("Certificate Table must contain exactly one PKCS#7 record")


def verify_delta(unsigned: bytes, signed: bytes) -> None:
    unsigned_layout = parse_pe(unsigned)
    signed_layout = parse_pe(signed)
    if unsigned_layout.certificate_offset or unsigned_layout.certificate_size:
        raise DeltaError("pre-signing image already contains a Certificate Table")
    if (
        unsigned_layout.checksum_offset != signed_layout.checksum_offset
        or unsigned_layout.security_directory_offset
        != signed_layout.security_directory_offset
        or unsigned_layout.mapped_file_end != signed_layout.mapped_file_end
    ):
        raise DeltaError("PE layout changed during signing")
    certificate_offset = signed_layout.certificate_offset
    certificate_size = signed_layout.certificate_size
    if not certificate_offset or not certificate_size:
        raise DeltaError("signed image has no Certificate Table")
    expected_offset = (len(unsigned) + 7) & ~7
    if certificate_offset != expected_offset or certificate_offset % 8:
        raise DeltaError("Certificate Table was not appended at the aligned unsigned EOF")
    if certificate_offset < signed_layout.mapped_file_end:
        raise DeltaError("Certificate Table overlaps mapped PE content")
    if certificate_offset + certificate_size != len(signed):
        raise DeltaError("Certificate Table does not cover the exact signed-file suffix")
    if len(signed) <= len(unsigned):
        raise DeltaError("signed image did not grow")
    if _normalize_header_fields(unsigned, unsigned_layout, len(unsigned)) != (
        _normalize_header_fields(signed, signed_layout, len(unsigned))
    ):
        raise DeltaError("bytes outside Authenticode header fields changed during signing")
    if any(signed[len(unsigned) : certificate_offset]):
        raise DeltaError("non-zero data was inserted before the Certificate Table")
    _validate_certificates(signed, certificate_offset, certificate_size)


def verify_unsigned(data: bytes) -> None:
    layout = parse_pe(data)
    if layout.certificate_offset or layout.certificate_size:
        raise DeltaError("pre-signing image already contains a Certificate Table")
    if any(data[layout.mapped_file_end :]):
        raise DeltaError("pre-signing image contains a non-zero unmapped overlay")


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
                raise DeltaError("--unsigned-only requires exactly one PE path")
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
