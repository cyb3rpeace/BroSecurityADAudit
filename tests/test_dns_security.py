import ast
import unittest
from pathlib import Path
from typing import Any

source = Path(__file__).resolve().parents[1] / "app/modules/software_scan.py"
tree = ast.parse(source.read_text())
names = {"_dns_advanced_assessment", "_dns_zone_assessment", "dns_zones"}
functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
context = {"Any": Any, "_DNS_ZONE_PS": "offline"}
exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), context)
assess = context["_dns_zone_assessment"]

class DnsSecurityTests(unittest.TestCase):
    def parse(self, output):
        context["run_remote"] = lambda *a, **k: {"stdout": output}
        return context["dns_zones"](dict(host="test", username="x", password="x", transport="ssh", winrm_port=0, ssh_port=22))
    def test_module_failure_not_success(self):
        self.assertFalse(self.parse("DNS_FAIL\nDNS_DONE")["ok"])
    def test_missing_success_marker(self):
        self.assertFalse(self.parse("DNS_DONE")["ok"])
    def test_incomplete_script(self):
        self.assertFalse(self.parse("DNS_ZONES_OK")["ok"])
    def test_empty_success(self):
        result = self.parse("DNS_ZONES_OK\nDNS_DONE")
        self.assertTrue(result["ok"])
        self.assertIsNone(result["wildcard"])
        self.assertIsNone(result["scavenging"]["enabled"])
        self.assertFalse(result["forwarders_collected"])
    def test_unknown_zone_properties(self):
        result = self.parse("DNS_ZONES_OK\nZONE|test|Primary|Domain|Secure|NoTransfer|?|0|?\nDNS_DONE")
        self.assertIsNone(result["zones"][0]["signed"])
        self.assertIsNone(result["zones"][0]["aging"])
    def test_truncation(self):
        self.assertEqual(self.parse("DNS_ZONES_OK\nDNS_TRUNCATED\nDNS_DONE")["collection_state"], "partial")
    def test_nonsecure_updates(self):
        self.assertEqual(assess([{"name":"test", "dynamic":"NonsecureAndSecure"}])[0]["code"], "dns_nonsecure_updates")
    def test_transfer_enum_variants(self):
        for value in ("TransferAnyServer", "NoSecurity", "Any"):
            self.assertEqual(assess([{"name":"test", "transfer":value}])[0]["code"], "dns_open_transfer")
    def test_safe_or_unknown_not_vulnerable(self):
        for row in ({}, {"dynamic":"Secure", "transfer":"NoTransfer"}, {"dynamic":"None", "transfer":"TransferToZoneNameServer"}):
            self.assertEqual(assess([row]), [])
    def test_forwarders_collected_empty(self):
        self.assertTrue(self.parse("DNS_ZONES_OK\nFWD|\nDNS_DONE")["forwarders_collected"])
    def test_scavenging_unknown(self):
        self.assertIsNone(self.parse("DNS_ZONES_OK\nSCAV|?|||\nDNS_DONE")["scavenging"]["enabled"])

if __name__ == "__main__":
    unittest.main()
