import hashlib, json, os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from app.modules.external_analysis import build_sanitized_evidence, fixed_command, run_aift, cleanup_staging, staging_root

class ExternalAnalysisTests(unittest.TestCase):
 def analysis(self):
  return {'verdict':'review','matched_rules':2,'ruleset':'v1','rows_reviewed':{'PowerShell':3},'limitations':['partial'],'findings':[{'title':'x','source':'safe','row_number':1}], 'source_coverage':[{'source':'safe','rows':1}], 'triage_summary':{'timeline':[{'source':'safe','row_number':1}]}}
 def test_sanitized_input_excludes_raw_archive(self):
  with tempfile.TemporaryDirectory() as d:
   out,digest=build_sanitized_evidence(Path(d)/'evidence',self.analysis(),['summary','findings'])
   data=json.loads(out.read_text())
   self.assertFalse(data['provenance']['raw_evidence_included']); self.assertNotIn('zip',out.read_text()); self.assertEqual(digest,hashlib.sha256(out.read_bytes()).hexdigest())
 def test_unavailable_is_explicit_failure(self):
  with tempfile.TemporaryDirectory() as d, patch.dict(os.environ,{'AIFT_EXECUTABLE':''}):
   result=run_aift(Path(d),'job',self.analysis(),'triage',['summary'])
   self.assertEqual(result['status'],'failed'); self.assertIn('unavailable',result['error'])
 def test_command_contract_and_allowlist(self):
  argv=fixed_command('/opt/aift/aift_cli.py','triage',Path('/tmp/evidence'),Path('/tmp/output'))
  self.assertIn('--evidence' if '--evidence' in argv else '-e',argv); self.assertIn('--profile',argv)
  with self.assertRaises(ValueError): fixed_command('/opt/aift/aift_cli.py','../../evil',Path('/tmp/i'),Path('/tmp/o'))
  with self.assertRaises(ValueError): fixed_command('aift','triage',Path('/tmp/i'),Path('/tmp/o'))
 def test_staging_permissions_and_ttl(self):
  with tempfile.TemporaryDirectory() as d:
   root=staging_root(Path(d)); old=root/'old'; old.mkdir(); os.utime(old,(1,1))
   self.assertEqual(cleanup_staging(Path(d),ttl=1),1); self.assertFalse(old.exists())
   if os.name!='nt': self.assertEqual(root.stat().st_mode & 0o777,0o700)
if __name__=='__main__': unittest.main()
