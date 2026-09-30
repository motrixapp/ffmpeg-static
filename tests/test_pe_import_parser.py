from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "parse_pe_imports", ROOT / "scripts" / "parse_pe_imports.py"
)
assert SPEC and SPEC.loader
PARSER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PARSER)


class PeImportParserTests(unittest.TestCase):
    def test_parses_every_ordinary_import(self) -> None:
        output = """
        Import {
          Name: KERNEL32.dll
          Symbol: CreateFileW (1)
        }
        Import {
          Name: api-ms-win-crt-stdio-l1-1-0.dll
          ImportLookupTableRVA: 0x1234
        }
        """
        self.assertEqual(
            PARSER.parse_imports(output),
            ["kernel32.dll", "api-ms-win-crt-stdio-l1-1-0.dll"],
        )

    def test_rejects_delay_import_even_with_ordinary_imports(self) -> None:
        output = """
        Import {
          Name: kernel32.dll
        }
        DelayImport {
          Name: untrusted.dll
        }
        """
        with self.assertRaisesRegex(PARSER.ImportError, "delay-load"):
            PARSER.parse_imports(output)

    def test_rejects_malformed_empty_duplicate_and_unsafe_imports(self) -> None:
        cases = (
            "Import {\n}\n",
            "Import {\n Name: ../evil.dll\n}\n",
            "Import {\n Name: a.dll\n}\nImport {\n Name: A.DLL\n}\n",
            "Import: a.dll\n",
            "Import {\n Name: a.dll\n",
            "header only\n",
        )
        for output in cases:
            with self.subTest(output=output), self.assertRaises(PARSER.ImportError):
                PARSER.parse_imports(output)

    def test_rejects_brace_smuggling_between_import_blocks(self) -> None:
        output = """Import {
 Name: kernel32.dll
 Symbol: crafted{
}
Import {
 Name: evil.dll
}
 Symbol: crafted}
}
"""
        with self.assertRaisesRegex(PARSER.ImportError, "brace"):
            PARSER.parse_imports(output)


if __name__ == "__main__":
    unittest.main()
