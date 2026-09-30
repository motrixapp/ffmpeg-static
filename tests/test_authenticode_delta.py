from __future__ import annotations

import importlib.util
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_authenticode_delta", ROOT / "scripts" / "verify_authenticode_delta.py"
)
assert SPEC and SPEC.loader
DELTA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DELTA)


def unsigned_pe() -> bytes:
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<H", data, coff, 0x8664)
    struct.pack_into("<H", data, coff + 2, 0)
    struct.pack_into("<H", data, coff + 16, 240)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 64, 0x12345678)
    struct.pack_into("<I", data, optional + 108, 16)
    return bytes(data)


def sign(data: bytes) -> bytes:
    result = bytearray(data)
    layout = DELTA.parse_pe(data)
    certificate = struct.pack("<IHH", 9, 0x0200, 0x0002) + b"\x30" + b"\0" * 7
    struct.pack_into("<I", result, layout.checksum_offset, 0xAABBCCDD)
    struct.pack_into("<II", result, layout.security_directory_offset, len(result), len(certificate))
    result.extend(certificate)
    return bytes(result)


class AuthenticodeDeltaTests(unittest.TestCase):
    def test_accepts_exact_append_only_signature_delta(self) -> None:
        unsigned = unsigned_pe()
        DELTA.verify_unsigned(unsigned)
        DELTA.verify_delta(unsigned, sign(unsigned))

    def test_unsigned_only_rejects_certificate_or_overlay(self) -> None:
        unsigned = unsigned_pe()
        for candidate in (sign(unsigned), unsigned + b"overlay"):
            with self.assertRaises(DELTA.DeltaError):
                DELTA.verify_unsigned(candidate)

    def test_rejects_change_outside_authenticode_fields(self) -> None:
        unsigned = unsigned_pe()
        signed = bytearray(sign(unsigned))
        signed[0x20] ^= 1
        with self.assertRaises(DELTA.DeltaError):
            DELTA.verify_delta(unsigned, bytes(signed))

    def test_rejects_previously_signed_input(self) -> None:
        signed = sign(unsigned_pe())
        with self.assertRaises(DELTA.DeltaError):
            DELTA.verify_delta(signed, sign(signed))

    def test_rejects_nonzero_alignment_gap(self) -> None:
        unsigned = unsigned_pe() + b"x"
        signed = bytearray(unsigned)
        layout = DELTA.parse_pe(unsigned)
        certificate_offset = (len(unsigned) + 7) & ~7
        signed.extend(b"\0" * (certificate_offset - len(signed)))
        certificate = struct.pack("<IHH", 9, 0x0200, 0x0002) + b"\x30" + b"\0" * 7
        struct.pack_into("<II", signed, layout.security_directory_offset, certificate_offset, 16)
        signed[len(unsigned)] = 1
        signed.extend(certificate)
        with self.assertRaises(DELTA.DeltaError):
            DELTA.verify_delta(unsigned, bytes(signed))

    def test_rejects_malformed_win_certificate(self) -> None:
        unsigned = unsigned_pe()
        signed = bytearray(sign(unsigned))
        struct.pack_into("<H", signed, len(unsigned) + 6, 1)
        with self.assertRaises(DELTA.DeltaError):
            DELTA.verify_delta(unsigned, bytes(signed))

    def test_rejects_multiple_primary_signature_records(self) -> None:
        unsigned = unsigned_pe()
        signed = bytearray(sign(unsigned))
        layout = DELTA.parse_pe(bytes(signed))
        certificate = bytes(signed[layout.certificate_offset :])
        struct.pack_into(
            "<I", signed, layout.security_directory_offset + 4, len(certificate) * 2
        )
        signed.extend(certificate)
        with self.assertRaisesRegex(DELTA.DeltaError, "exactly one"):
            DELTA.verify_delta(unsigned, bytes(signed))


if __name__ == "__main__":
    unittest.main()
