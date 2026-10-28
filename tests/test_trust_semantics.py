"""Offline regression: public TDO metadata only; no LDAP/network calls."""
import ast
import unittest
from pathlib import Path
from typing import Any

source = Path(__file__).resolve().parents[1] / "app/modules/ldap_audit.py"
tree = ast.parse(source.read_text())
function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_trust_assessment")
namespace = {"Any": Any}
exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
assess = namespace["_trust_assessment"]

class TrustSemanticsTests(unittest.TestCase):
    def codes(self, value):
        return {issue["code"] for issue in value["assessment"]}

    def test_within_forest_not_external(self):
        result = assess(0x20, 2, 3)
        self.assertIsNone(result["sid_filter"])
        self.assertNotIn("trust_sid_filter", self.codes(result))

    def test_forest_boundary_not_disabled(self):
        result = assess(0x8, 2, 3)
        self.assertEqual(result["sid_filter_mode"], "forest_boundary")
        self.assertIsNone(result["sid_filter"])

    def test_external_no_quarantine(self):
        result = assess(0, 2, 2)
        self.assertIs(result["sid_filter"], False)
        self.assertIn("trust_sid_filter", self.codes(result))

    def test_quarantine(self):
        self.assertIs(assess(4, 2, 3)["sid_filter"], True)

    def test_missing_or_bad_attributes(self):
        for value in (None, "", "bad", -1, True):
            result = assess(value, 2, 3)
            self.assertEqual(result["sid_filter_mode"], "unknown")
            self.assertNotIn("trust_sid_filter", self.codes(result))

    def test_missing_type_unknown(self):
        self.assertEqual(assess(0, None, 3)["sid_filter_mode"], "unknown")

    def test_rc4_flag_not_ad_crypto_proof(self):
        self.assertNotIn("trust_rc4", self.codes(assess(0x80, 2, 3)))
        self.assertIn("trust_mit_rc4", self.codes(assess(0x80, 3, 3)))

    def test_encryption_mask(self):
        self.assertIn("trust_rc4", self.codes(assess(4, 2, 3, 4)))
        self.assertNotIn("trust_rc4", self.codes(assess(4, 2, 3, 28)))
        self.assertNotIn("trust_rc4", self.codes(assess(4, 2, 3, None)))

    def test_tgt_requires_explicit_enable(self):
        self.assertNotIn("trust_tgt", self.codes(assess(0x10, 2, 3)))
        self.assertIn("trust_tgt", self.codes(assess(0x810, 2, 3)))

    def test_selective_not_cancelled_by_within_forest(self):
        self.assertIs(assess(0x30, 2, 3)["selective"], True)

    def test_contradictory_flags(self):
        result = assess(0x28, 2, 3)
        self.assertEqual(result["sid_filter_mode"], "unknown")
        self.assertIn("trust_metadata", self.codes(result))

    def test_treat_as_external(self):
        self.assertIn("trust_treat_external", self.codes(assess(0x48, 2, 3)))

class TrustScannerIntegrationTests(unittest.TestCase):
    def test_scanner_uses_metadata_not_quarantine_shortcut(self):
        from datetime import datetime
        from unittest.mock import Mock
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "scan_trusts_ldap")
        connection = Mock()
        rows = [{"cn": "child.example", "trustAttributes": 32, "trustType": 2, "trustDirection": 3},
                {"cn": "forest.example", "trustAttributes": 8, "trustType": 2, "trustDirection": 3},
                {"cn": "external.example", "trustAttributes": 0, "trustType": 2, "trustDirection": 2}]
        context = {"Any": Any, "datetime": datetime, "LDAPException": RuntimeError,
                   "connect": lambda _: (connection, "DC=example"), "_search": lambda *args: rows,
                   "_first": lambda entry, key: entry.get(key), "_trust_assessment": assess}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), context)
        result = context["scan_trusts_ldap"]({})
        sid = [r for r in result["findings"] if r["vuln_id"] == "trust_sid_filter"]
        self.assertEqual([r["hostname"] for r in sid], ["external.example"])
        self.assertNotIn("critical", [r["severity"] for r in result["findings"]])
        connection.unbind.assert_called_once()

if __name__ == "__main__":
    unittest.main()
