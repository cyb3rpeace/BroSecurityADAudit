import ast
import base64
import json
import re
import unittest
from pathlib import Path
from typing import Any

source = Path(__file__).resolve().parents[1] / "app/modules/software_scan.py"
tree = ast.parse(source.read_text())
functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {"_gpo_numeric_baseline", "gpo_conflicts", "_friendly", "_gpo_link_metadata", "_gpo_inherited_links"}]
assigns = [n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in {"_BASELINE", "_FRIENDLY", "_GPO_SAFE_NUMERIC", "_SECRET_KEY"} for t in n.targets)]
ctx = {"Any": Any, "re": re, "base64": base64, "_GPO_DIFF_PS": "offline"}
exec(compile(ast.Module(body=assigns+functions,type_ignores=[]),str(source),"exec"),ctx)

class GpoSecurityTests(unittest.TestCase):
    def parse(self, output, names=None):
        ctx["run_remote"] = lambda *a, **k: {"stdout": output}
        return ctx["gpo_conflicts"](dict(host="test",username="test",password="test",transport="ssh",winrm_port=0,ssh_port=22), names or {})
    def test_no_root_false_success(self):
        self.assertFalse(self.parse("GPO_DONE")["ok"])
        self.assertFalse(self.parse("GPO_FAIL\nGPO_DONE")["ok"])
    def test_incomplete(self):
        self.assertFalse(self.parse("GPO_ROOT_OK")["ok"])
    def test_empty_not_effective(self):
        result=self.parse("GPO_ROOT_OK\nGPO_DONE")
        self.assertTrue(result["ok"])
        self.assertFalse(result["effective_policy_verified"])
        self.assertEqual(result["collection_state"],"partial")
    def test_aes_bitmask(self):
        fn=ctx["_gpo_numeric_baseline"]
        for value in [8,16,24,28]: self.assertTrue(fn(value,24,"aes_mask"))
        for value in [0,4,32,64,-1]: self.assertFalse(fn(value,24,"aes_mask"))
    def test_supported_enum(self):
        fn=ctx["_gpo_numeric_baseline"]
        for value in [1,2]: self.assertTrue(fn(value,1,"one_or_two"))
        for value in [0,3,99]: self.assertFalse(fn(value,1,"one_or_two"))
    def test_numeric_password_setting_visible(self):
        result=self.parse("GPO_ROOT_OK\nINF|{a}|MinimumPasswordLength|8\nGPO_DONE")
        self.assertEqual(result["baseline"][0]["value"],"8")
        self.assertFalse(result["baseline"][0]["ok"])
    def test_secret_not_compared(self):
        result=self.parse("GPO_ROOT_OK\nINF|{a}|Password|secret1\nINF|{b}|Password|secret2\nGPO_DONE")
        self.assertEqual(result["conflicts"],[])
        self.assertEqual(result["collection"]["settings_compared"],0)
    def test_same_display_names_do_not_collapse(self):
        result=self.parse("GPO_ROOT_OK\nINF|{a}|MinimumPasswordLength|8\nINF|{b}|MinimumPasswordLength|14\nGPO_DONE", {"{a}":"same", "{b}":"same"})
        self.assertEqual(len(result["conflicts"]),1)
        self.assertEqual(len(result["baseline"]),2)
    def test_counts_and_limits(self):
        result=self.parse("GPO_ROOT_OK\nGPO_INF_OK|{a}\nGPO_POL_READ|{a}|Machine\nGPO_ERROR|POL|{b}\nGPO_LIMIT\nGPO_DONE")
        self.assertEqual(result["collection"]["inf_files_read"],1)
        self.assertEqual(result["collection"]["registry_files_read"],1)
        self.assertEqual(result["collection"]["read_or_parse_errors"],1)
        self.assertTrue(result["collection"]["limits_reached"])

class GpoLinkMetadataTests(unittest.TestCase):
    def scope(self, links="", options=0):
        return "GPO_SCOPE|" + base64.b64encode(json.dumps({"dn":"OU=Test,DC=example,DC=com", "links":links,"options":options}).encode()).decode()
    def parse(self, text):
        return ctx["_gpo_link_metadata"](text, {})
    def test_flags_order_and_block(self):
        target="CN={12345678-1234-1234-1234-123456789abc},CN=Policies,CN=System,DC=example,DC=com"
        r=self.parse(self.scope("[LDAP://"+target+";2][LDAP://"+target+";1]",1)+"\nGPO_LINK_OK")
        self.assertEqual(r["state"],"collected")
        scope=r["scopes"][0]
        self.assertTrue(scope["block_inheritance"])
        self.assertTrue(scope["links"][0]["enforced"])
        self.assertTrue(scope["links"][0]["enabled"])
        self.assertFalse(scope["links"][1]["enabled"])
        self.assertEqual(scope["links"][0]["order"],2)
        self.assertEqual(scope["links"][1]["order"],1)
        self.assertFalse(r["effective_policy_verified"])
    def test_collector_targets_local_dc(self):
        text=source.read_text()
        self.assertIn("Get-ADObject -Server $env:COMPUTERNAME -SearchBase $domainDn",text)
        self.assertNotIn("$results = $search.FindAll()",text)
    def test_empty_scope_is_not_unlinked_gpo_claim(self):
        r=self.parse(self.scope()+"\nGPO_LINK_OK")
        self.assertEqual(r["scopes"][0]["links"],[])
    def test_missing_marker_partial(self):
        self.assertEqual(self.parse(self.scope())["state"],"partial")
    def test_no_data_unavailable(self):
        self.assertEqual(self.parse("GPO_LINK_OK")["state"],"unavailable")
    def test_limit_partial(self):
        self.assertEqual(self.parse(self.scope()+"\nGPO_LINK_OK\nGPO_LINK_LIMIT")["state"],"partial")
    def test_malformed(self):
        for text in ["GPO_SCOPE|invalid",self.scope("broken"), self.scope("[LDAP://CN=x;4]")]:
            r=self.parse(text+"\nGPO_LINK_OK")
            self.assertEqual(r["state"],"unavailable")
            self.assertEqual(r["parse_errors"],1)

class GpoInheritanceTests(unittest.TestCase):
    def link(self, name, enforced=False, enabled=True):
        return dict(name=name, enforced=enforced, enabled=enabled, order=1)
    def scope(self, dn, links=None, block=False):
        return dict(dn=dn, links=links or [], block_inheritance=block)
    def run_model(self, rows):
        return ctx["_gpo_inherited_links"](rows)[-1]["structural_inheritance"]
    def test_block_preserves_enforced_and_local(self):
        r=self.run_model([self.scope("DC=x,DC=com",[self.link("normal"),self.link("forced",True)]), self.scope("OU=A,DC=x,DC=com",[self.link("local"),self.link("off",enabled=False)],True)])
        self.assertEqual([x["name"] for x in r["candidate_links"]],["forced","local"])
        self.assertEqual(r["blocked_links"][0]["name"],"normal")
        self.assertEqual(r["state"],"collected")
        self.assertFalse(r["effective_policy_verified"])
    def test_missing_parent_partial(self):
        r=self.run_model([self.scope("DC=x,DC=com"),self.scope("OU=B,OU=A,DC=x,DC=com")])
        self.assertEqual(r["state"],"partial")
        self.assertEqual(r["missing_ancestors"],["OU=A,DC=x,DC=com"])
    def test_escaped_comma_and_case(self):
        r=self.run_model([self.scope("dc=X,dc=com",[self.link("root")]),self.scope(r"OU=A\,B,DC=x,DC=com")])
        self.assertEqual(r["state"],"collected")
        self.assertEqual(r["candidate_links"][0]["name"],"root")
    def test_block_at_parent_applies_to_child(self):
        r=self.run_model([self.scope("DC=x,DC=com",[self.link("root")]),self.scope("OU=A,DC=x,DC=com",[self.link("parent")],True),self.scope("OU=B,OU=A,DC=x,DC=com")])
        self.assertEqual([x["name"] for x in r["candidate_links"]],["parent"])

if __name__ == "__main__": unittest.main()
