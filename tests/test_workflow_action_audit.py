from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "audit_workflow_actions", ROOT / "scripts" / "audit_workflow_actions.py"
)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class WorkflowActionAuditTests(unittest.TestCase):
    def audit(self, text: str, suffix: str = ".yml") -> set[str]:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / f"workflow{suffix}"
            path.write_text(text, encoding="utf-8")
            return AUDIT.audit_workflow(path)

    def test_accepts_only_full_sha_block_action(self) -> None:
        sha = "a" * 40
        self.assertEqual(
            self.audit(f"jobs:\n  test:\n    steps:\n      - uses: actions/checkout@{sha} # pin\n"),
            {f"actions/checkout@{sha}"},
        )

    def test_ignores_uses_text_inside_block_scalar(self) -> None:
        self.assertEqual(
            self.audit("jobs:\n  test:\n    steps:\n      - run: |\n          echo 'uses: evil/a@v1'\n"),
            set(),
        )

    def test_rejects_mutable_or_non_github_action(self) -> None:
        for reference in (
            "actions/checkout@v4",
            "vendor/action@" + "b" * 40,
            "actions/checkout@" + "b" * 40 + "#suffix",
        ):
            with self.subTest(reference=reference), self.assertRaises(AUDIT.AuditError):
                self.audit(f"steps:\n  - uses: {reference}\n")

    def test_rejects_flow_quoted_anchor_and_alias_bypasses(self) -> None:
        cases = (
            "steps: [{uses: evil/action@v1}]\n",
            "steps:\n  - 'uses': evil/action@v1\n",
            'steps:\n  - "u\\u0073es": evil/action@v1\n',
            "defaults: &action {uses: evil/action@v1}\nsteps:\n  - *action\n",
            "steps:\n  - uses: *action\n",
        )
        for text in cases:
            with self.subTest(text=text), self.assertRaises(AUDIT.AuditError):
                self.audit(text)

    def test_discovers_both_workflow_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "a.yml").write_text("name: a\n", encoding="utf-8")
            (directory / "b.yaml").write_text("name: b\n", encoding="utf-8")
            self.assertEqual(len(AUDIT.workflow_paths([directory])), 2)

    def test_rejects_multiline_flow_explicit_key_escape(self) -> None:
        text = """steps:
  - {? "us\\
        es" : "evil/action@v1"}
"""
        with self.assertRaisesRegex(AUDIT.AuditError, "flow collections"):
            self.audit(text)

    def test_rejects_yaml_tagged_uses_key(self) -> None:
        cases = (
            'steps:\n  - !!str "uses": evil/action@v1\n',
            'steps:\n  - != "uses": evil/action@v1\n',
            'steps:\n  - !local "uses": evil/action@v1\n',
            'steps:\n  - !<tag:yaml.org,2002:str> "uses": evil/action@v1\n',
            'steps:\n  - ! "uses": evil/action@v1\n',
        )
        for text in cases:
            with self.subTest(text=text), self.assertRaisesRegex(
                AUDIT.AuditError, "YAML tags"
            ):
                self.audit(text)

    def test_rejects_uses_block_scalar(self) -> None:
        for indicator in ("|-", ">-"):
            text = f"steps:\n  - uses: {indicator}\n      evil/action@v1\n"
            with self.subTest(indicator=indicator), self.assertRaisesRegex(
                AUDIT.AuditError, "uses value must not be a block scalar"
            ):
                self.audit(text)

    def test_allows_github_expression_braces(self) -> None:
        self.assertEqual(
            self.audit("jobs:\n  test:\n    name: ${{ matrix.target }}\n"), set()
        )


if __name__ == "__main__":
    unittest.main()
