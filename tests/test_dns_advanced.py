import ast, unittest
from pathlib import Path
from typing import Any
source=Path(__file__).resolve().parents[1]/"app/modules/software_scan.py"
tree=ast.parse(source.read_text())
need={"_dns_advanced_assessment","_dns_zone_assessment","dns_zones"}
func=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in need]
ctx={"Any":Any,"_DNS_ZONE_PS":"offline"}
exec(compile(ast.Module(body=func,type_ignores=[]),str(source),"exec"),ctx)
class DnsAdvancedTests(unittest.TestCase):
 def parse(self,text):
  ctx["run_remote"]=lambda *a,**k:{"stdout":text}
  return ctx["dns_zones"]({"host":"x","username":"x","password":"x","transport":"ssh","winrm_port":0,"ssh_port":22})
 def test_acl_marker(self):
  r=self.parse("DNS_ZONES_OK\nACL|collected|10|2|0|4|0\nDNS_DONE")
  self.assertEqual(r["acl"]["broad_write_principals"],2)
  self.assertEqual(r["acl"]["unresolved_aces"],0)
  self.assertEqual(r["advanced_assessment"][0]["code"],"adidns_broad_write")
 def test_resolver_order(self):
  r=self.parse("DNS_ZONES_OK\nRES|10.0.0.1|0|1|1\nRES|8.8.8.8|1|0|1\nDNS_DONE")
  self.assertEqual(r["resolvers"][1]["position"],1)
  self.assertNotIn("dns_resolver_self_not_first",[x["code"] for x in r["advanced_assessment"]])
 def test_self_not_first(self):
  r=self.parse("DNS_ZONES_OK\nRES|8.8.8.8|0|0|1\nRES|10.0.0.1|1|1|1\nDNS_DONE")
  self.assertNotIn("dns_resolver_self_not_first",[x["code"] for x in r["advanced_assessment"]])
 def test_forwarder_probe(self):
  r=self.parse("DNS_ZONES_OK\nFWDPROBE|forwarder|10.0.0.2|0\nDNS_DONE")
  self.assertIn("dns_forwarder_unreachable",[x["code"] for x in r["advanced_assessment"]])
 def test_failed_sources_partial(self):
  r=self.parse("DNS_ZONES_OK\nACL_FAIL\nRES_FAIL\nFWDPROBE_FAIL\nDNS_DONE")
  self.assertEqual(r["collection_state"],"partial")
 def test_zero_read_is_not_clean_acl(self):
  r=self.parse("DNS_ZONES_OK\nACL|unavailable|0|0|0|0|3\nDNS_DONE")
  self.assertEqual(r["collection_state"],"partial")
  self.assertEqual(r["acl"]["state"],"unavailable")
 def test_conditional_probe(self):
  r=self.parse("DNS_ZONES_OK\nFWDPROBE|conditional|10.0.0.2|0\nDNS_DONE")
  self.assertEqual(r["forwarder_probes"][0]["kind"],"conditional")
  self.assertIn("dns_conditional_forwarder_unreachable",[x["code"] for x in r["advanced_assessment"]])
 def test_unknown_probe_not_failed(self):
  r=self.parse("DNS_ZONES_OK\nRES|10.0.0.1|0|?|?|5\nDNS_DONE")
  self.assertIsNone(r["resolvers"][0]["reachable"])
  self.assertEqual(r["advanced_assessment"],[])
 def test_acl_limit_is_partial(self):
  r=self.parse("DNS_ZONES_OK\nACL|collected|1600|0|0|40|0\nACL_LIMIT\nDNS_DONE")
  self.assertEqual(r["acl"]["state"],"partial")
 def test_winrm_temp_file_is_unique_and_cleaned(self):
  import os, sys, types
  from unittest.mock import patch
  module=ast.parse(source.read_text())
  funcs=[n for n in module.body if isinstance(n,ast.FunctionDef) and n.name == "_run_winrm"]
  context={"Any":Any,"os":os,"base64":__import__("base64"),"_decode_output":lambda b:b.decode(),"_redact":lambda s,p:s}
  exec(compile(ast.Module(body=funcs,type_ignores=[]),str(source),"exec"),context)
  sessions=[]
  class FakeSession:
   def __init__(self,*a,**k): self.commands=[];sessions.append(self)
   def run_cmd(self,*a): self.commands.append(a)
   def run_ps(self,script):
    self.script=script
    return types.SimpleNamespace(status_code=0,std_out=b"ok",std_err=b"")
  with patch.dict(sys.modules,{"winrm":types.SimpleNamespace(Session=FakeSession)}):
   for _ in range(2): context["_run_winrm"]("dc",5985,"u","p","#"*10000,30)
  paths=[session.commands[0][1][-1] for session in sessions]
  self.assertNotEqual(paths[0],paths[1])
  for path,session in zip(paths,sessions):
   self.assertIn(path,session.script)
   self.assertIn("finally { Remove-Item -LiteralPath",session.script)
 def test_directoryentry_uses_psbase_for_dacl(self):
  text=Path(source).read_text()
  self.assertIn("$entry.psbase.Options.SecurityMasks",text)
  self.assertIn("$entry.psbase.ObjectSecurity.GetAccessRules",text)
  self.assertNotIn("$entry.Options.SecurityMasks",text)
 def test_no_acl_names_or_records(self):
  text=Path(source).read_text()
  collector=text[text.index("_DNS_ZONE_PS"):text.index("_TRUST_REACH_PS")]
  self.assertIn("IdentityReference", collector)
  self.assertNotIn("Write-Output $sid", collector)
  self.assertNotIn("Write-Output $ace", collector)
if __name__=="__main__": unittest.main()
