from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def load_reader_module(filename: str):
    spec = importlib.util.spec_from_file_location(
        "reader_test_" + filename.replace("-", "_").replace(".", "_"), SCRIPTS / filename
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


signing = load_reader_module("validate_signing_input.py")
grant = load_reader_module("finalize_signing_grant.py")
notices = load_reader_module("generate-third-party-notices.py")


class BinaryFileReaderTests(unittest.TestCase):
    def test_windows_notice_stat_semantics_preserve_all_mutation_guards(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture"
            data = b"locked source\r\n\x1a\0bytes"
            path.write_bytes(data)
            metadata = path.lstat()
            fields = {
                name: getattr(metadata, name)
                for name in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
            }
            expected = SimpleNamespace(**fields, st_ctime_ns=10, st_birthtime_ns=10)
            opened = SimpleNamespace(**fields, st_ctime_ns=20, st_birthtime_ns=10)
            with mock.patch.object(os, "name", "nt"), mock.patch.object(
                os, "fstat", side_effect=[opened, opened]
            ):
                self.assertEqual(notices._read_regular_file(path, expected), data)

            for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_birthtime_ns"):
                changed = SimpleNamespace(**vars(opened))
                setattr(changed, field, getattr(changed, field) + 1)
                with self.subTest(opening=field), mock.patch.object(os, "name", "nt"), mock.patch.object(
                    os, "fstat", return_value=changed
                ), self.assertRaisesRegex(notices.NoticeError, "while being opened"):
                    notices._read_regular_file(path, expected)

            for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"):
                changed = SimpleNamespace(**vars(opened))
                setattr(changed, field, getattr(changed, field) + 1)
                with self.subTest(reading=field), mock.patch.object(os, "name", "nt"), mock.patch.object(
                    os, "fstat", side_effect=[opened, changed]
                ), self.assertRaisesRegex(notices.NoticeError, "while being read"):
                    notices._read_regular_file(path, expected)

    def readers(self, path: Path, data: bytes):
        yield signing._read_regular(path, len(data))
        yield grant._read_regular(path, len(data))
        yield notices._read_regular_file(path, path.lstat())

    def test_actual_crlf_ctrl_z_and_arbitrary_bytes_are_not_translated(self) -> None:
        # Run this on native Windows x64 and ARM64, not just POSIX mocks.
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "PE-byte-fixture"
            data = b"MZ\r\n\x1a\xff\0\r\nbytes after Ctrl-Z"
            path.write_bytes(data)
            for result in self.readers(path, data):
                self.assertEqual(result, data)

    def test_low_level_open_explicitly_selects_binary_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture"
            data = b"raw\r\n\x1a\0bytes"
            path.write_bytes(data)
            actual_open = os.open
            binary_flag = getattr(os, "O_BINARY", 0x8000)

            def checked_open(name, flags):
                self.assertTrue(flags & binary_flag)
                native_flags = flags if os.name == "nt" else flags & ~binary_flag
                return actual_open(name, native_flags)

            with mock.patch.object(os, "O_BINARY", binary_flag, create=True), mock.patch.object(
                os, "open", side_effect=checked_open
            ):
                for result in self.readers(path, data):
                    self.assertEqual(result, data)


if __name__ == "__main__":
    unittest.main()
