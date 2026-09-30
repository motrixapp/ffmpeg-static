from __future__ import annotations

import importlib.util
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_macho_codesign_delta",
    ROOT / "scripts" / "verify_macho_codesign_delta.py",
)
assert SPEC and SPEC.loader
DELTA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DELTA)


def superblob(flags: int, cms: bool) -> bytes:
    code_directory = struct.pack(
        ">IIII", DELTA.CSMAGIC_CODEDIRECTORY, 16, 0x20400, flags
    )
    records = [(DELTA.CSSLOT_CODEDIRECTORY, code_directory)]
    if cms:
        records.append(
            (
                DELTA.CSSLOT_SIGNATURESLOT,
                struct.pack(">II", DELTA.CSMAGIC_BLOBWRAPPER, 8),
            )
        )
    header_size = 12 + 8 * len(records)
    offsets = []
    cursor = header_size
    for slot_type, blob in records:
        offsets.append((slot_type, cursor))
        cursor += len(blob)
    body = b"".join(blob for _slot_type, blob in records)
    result = (
        struct.pack(">III", DELTA.CSMAGIC_EMBEDDED_SIGNATURE, cursor, len(records))
        + b"".join(struct.pack(">II", *entry) for entry in offsets)
        + body
    )
    return result + b"\0" * ((16 - len(result) % 16) % 16)


def macho(flags: int, cms: bool, code_byte: int = 0x41) -> bytes:
    signature = superblob(flags, cms)
    signature_offset = 0x1000
    linkedit_offset = 0x800
    total_size = signature_offset + len(signature)
    linkedit_size = total_size - linkedit_offset
    linkedit_vm_size = (linkedit_size + 0xFFF) & ~0xFFF
    header = struct.pack(
        "<IiiIIIII",
        DELTA.MH_MAGIC_64,
        0x0100000C,
        0,
        2,
        2,
        88,
        0x200085,
        0,
    )
    segment = struct.pack(
        "<II16sQQQQiiII",
        DELTA.LC_SEGMENT_64,
        72,
        b"__LINKEDIT".ljust(16, b"\0"),
        0x100008000,
        linkedit_vm_size,
        linkedit_offset,
        linkedit_size,
        1,
        1,
        0,
        0,
    )
    signature_command = struct.pack(
        "<IIII", DELTA.LC_CODE_SIGNATURE, 16, signature_offset, len(signature)
    )
    prefix = bytearray(header + segment + signature_command)
    prefix.extend(bytes([code_byte]) * (signature_offset - len(prefix)))
    return bytes(prefix) + signature


class MachOCodesignDeltaTests(unittest.TestCase):
    def test_accepts_signature_only_developer_id_transition(self) -> None:
        unsigned = macho(DELTA.CS_ADHOC, False)
        DELTA.verify_unsigned(unsigned)
        signed = macho(DELTA.CS_RUNTIME, True)
        DELTA.verify_delta(unsigned, signed)

    def test_unsigned_only_rejects_cms_or_non_adhoc_input(self) -> None:
        for candidate in (
            macho(DELTA.CS_ADHOC, True),
            macho(DELTA.CS_RUNTIME, False),
        ):
            with self.assertRaises(DELTA.DeltaError):
                DELTA.verify_unsigned(candidate)

    def test_rejects_code_or_load_command_mutation(self) -> None:
        unsigned = macho(DELTA.CS_ADHOC, False)
        for signed in (
            macho(DELTA.CS_RUNTIME, True, code_byte=0x42),
            bytearray(macho(DELTA.CS_RUNTIME, True)),
        ):
            if isinstance(signed, bytearray):
                signed[12] ^= 1
                signed = bytes(signed)
            with self.assertRaises(DELTA.DeltaError):
                DELTA.verify_delta(unsigned, signed)

    def test_rejects_ad_hoc_or_missing_cms_final_signature(self) -> None:
        unsigned = macho(DELTA.CS_ADHOC, False)
        for signed in (
            macho(DELTA.CS_ADHOC | DELTA.CS_RUNTIME, True),
            macho(DELTA.CS_RUNTIME, False),
            macho(0, True),
        ):
            with self.assertRaises(DELTA.DeltaError):
                DELTA.verify_delta(unsigned, signed)

    def test_rejects_signature_offset_or_superblob_corruption(self) -> None:
        unsigned = macho(DELTA.CS_ADHOC, False)
        signed = bytearray(macho(DELTA.CS_RUNTIME, True))
        struct.pack_into("<I", signed, 32 + 72 + 8, 0xFF0)
        with self.assertRaises(DELTA.DeltaError):
            DELTA.verify_delta(unsigned, bytes(signed))
        signed = bytearray(macho(DELTA.CS_RUNTIME, True))
        signed[0x1000] = 0
        with self.assertRaises(DELTA.DeltaError):
            DELTA.verify_delta(unsigned, bytes(signed))


if __name__ == "__main__":
    unittest.main()
