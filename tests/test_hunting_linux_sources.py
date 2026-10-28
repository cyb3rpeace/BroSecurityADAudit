import json
import unittest
from app.modules.hunting_builder import compile_config, LINUX_QUERIES
from app.modules.hunting_ingest import collection_provenance
from tests.test_hunting_builder import BuilderTests

class LinuxSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        BuilderTests.setUpClass()

    def test_compile_fixed_bounded_sources_without_active_plugins(self):
        profile=dict(id='b'*32, platform='linux', artifacts=['host',*LINUX_QUERIES],timeout_seconds=600,event_days=7)
        data,manifest=compile_config(profile,BuilderTests.pem)
        baseline=json.loads(data)['autoexec']['artifact_definitions'][0]
        self.assertEqual([s['name'] for s in baseline['sources']],['Host','LinuxServices','LinuxCrontab','LinuxSUID'])
        for query in LINUX_QUERIES.values():
            for forbidden in ['execve(', 'upload(', '/**', 'Artifact.Linux']:
                self.assertNotIn(forbidden,query[1])
        self.assertEqual(manifest['collection_contract']['configured_source_row_limits']['linux_crontab'],1000)
        self.assertEqual(manifest['collection_contract']['configured_source_row_limits']['linux_services'],1000)

    def test_linux_evidence_provenance_reports_missing_and_caps(self):
        metadata={'CollectionContract':{'configured_source_row_limits':{'linux_crontab':1000,'linux_suid':10000}}}
        sources=[{'source':'results/BroSec.Offline.Baseline%2FLinuxCrontab.json','rows':1000,'bytes':3000}]
        p=collection_provenance(metadata,sources)
        self.assertTrue(p['requested_sources'][0]['limit_reached'])
        self.assertEqual(p['requested_sources'][1]['observed_status'],'missing')

    def test_windows_rejects_linux_sources(self):
        for source in LINUX_QUERIES:
            profile=dict(id='b'*32, platform='windows',artifacts=['host',source],timeout_seconds=600,event_days=7)
            with self.assertRaises(ValueError): compile_config(profile,BuilderTests.pem)
