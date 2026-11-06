import datetime
import hashlib
import json
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from app.modules.hunting_builder import compile_config


class BuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Unit test only')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cls.pem = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(cls.key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(minutes=1))
                   .not_valid_after(now + datetime.timedelta(days=1))
                   .sign(cls.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())

    def profile(self, **kwargs):
        return dict(id='a'*32, platform='windows', artifacts=['host', 'processes', 'network'], timeout_seconds=600, event_days=7, **kwargs)

    def test_allowlisted_config_and_hash(self):
        for platform in ['windows', 'linux']:
            profile = self.profile()
            profile['platform'] = platform
            data, manifest = compile_config(profile, self.pem)
            config = json.loads(data)
            self.assertEqual(manifest['config_sha256'], hashlib.sha256(data).hexdigest())
            self.assertNotIn(b'PRIVATE KEY', data)
            self.assertNotIn(b'hard_memory_limit', data)
            self.assertEqual(len(config['autoexec']['artifact_definitions'][0]['sources']), 3)
            self.assertIn('password=Password', config['autoexec']['artifact_definitions'][1]['sources'][0]['query'])

    def test_unsupported_collection_fails_closed(self):
        profile = self.profile()
        profile['artifacts'] = ['host', 'security_events']
        with self.assertRaisesRegex(ValueError, 'ещё не проверена'):
            compile_config(profile, self.pem)

    def test_reject_private_key_or_multiple_certificates(self):
        private = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        for pem in [private, self.pem + private, self.pem + self.pem, 'not a certificate']:
            with self.subTest(pem=pem[:25]), self.assertRaises(ValueError):
                compile_config(self.profile(), pem)

    def test_no_client_query_or_credentials_in_config(self):
        profile = self.profile()
        profile.update(password='NEVER_EXPORT', query='SELECT execve(argv=["bad"])', name='NEVER_EXPORT')
        data, _ = compile_config(profile, self.pem)
        self.assertNotIn(b'NEVER_EXPORT', data)
        self.assertNotIn(b'execve', data)

    def test_metadata_states_actual_window_and_completeness(self):
        data, manifest = compile_config(self.profile(), self.pem)
        contract = manifest['collection_contract']
        self.assertFalse(contract['event_window']['applied'])
        self.assertEqual(contract['event_window']['requested_days'], 7)
        self.assertEqual(contract['configured_source_row_limits']['processes'], 10000)
        self.assertEqual(contract['completeness'], 'unknown_until_result_inspection')
        self.assertFalse(contract['windows_event_execution_verified'])
        query = json.loads(data)['autoexec']['artifact_definitions'][1]['sources'][0]['query']
        self.assertIn('CaptureStartedUTC=CaptureStartedUTC', query)
        self.assertIn('CollectionContract=CollectionContract', query)
        self.assertNotIn('upload(', query)
        self.assertNotIn('process_memory(', query)

    def test_event_pilot_compiles_only_with_explicit_server_flag(self):
        from app.modules.hunting_builder import EVENT_METADATA_SPECS
        profile = self.profile(windows_event_pilot=True); profile['artifacts'] = ['host', 'security_events']
        data, manifest = compile_config(profile, self.pem)
        names = [item['name'] for item in json.loads(data)['autoexec']['artifact_definitions'][0]['sources']]
        self.assertEqual(names, ['Host', 'SecurityEvents'])
        self.assertIn('metadata-only', ' '.join(manifest['limitations']))

    def test_all_experimental_event_compilations_rejected(self):
        from app.modules.hunting_builder import EVENT_METADATA_SPECS
        for event in EVENT_METADATA_SPECS:
            profile = self.profile()
            profile['artifacts'] = ['host', event]
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, 'ещё не проверена'):
                compile_config(profile, self.pem)

    def test_windows_persistence_compilation_contract(self):
        profile = self.profile()
        profile['artifacts'] = ['host', 'processes', 'network', 'services', 'tasks', 'startup']
        data, manifest = compile_config(profile, self.pem)
        config = json.loads(data)
        baseline, collector = config['autoexec']['artifact_definitions']
        self.assertEqual([s['name'] for s in baseline['sources']],
                         ['Host', 'Processes', 'Network', 'Services', 'Tasks', 'Startup'])
        queries = {s['name']: s['query'] for s in baseline['sources']}
        self.assertIn('Calculate_hashes=FALSE, CertificateInfo=FALSE', queries['Services'])
        self.assertIn('AlsoUpload=FALSE, UploadCommands=FALSE', queries['Tasks'])
        self.assertIn('AlsoUpload=FALSE', queries['Startup'])
        for name in ['Services', 'Tasks', 'Startup']:
            self.assertTrue(queries[name].endswith('LIMIT 10000'))
        query = collector['sources'][0]['query']
        for artifact in ['Windows.System.Services', 'Windows.System.TaskScheduler', 'Windows.Sys.StartupItems']:
            self.assertIn(artifact, query)
        self.assertIn('--require_admin', config['autoexec']['argv'])
        self.assertEqual(manifest['artifacts'], profile['artifacts'])
        for forbidden in ['upload(', 'execve(', 'process_memory(']:
            self.assertNotIn(forbidden, data.decode())

    def test_linux_rejects_each_windows_persistence_source(self):
        for artifact in ['services', 'tasks', 'startup']:
            profile = self.profile()
            profile.update(platform='linux', artifacts=['host', artifact])
            with self.subTest(artifact=artifact), self.assertRaises(ValueError):
                compile_config(profile, self.pem)

    def test_reject_identifier_injection(self):
        profile = self.profile()
        profile['id'] = '../../etc'
        with self.assertRaises(ValueError):
            compile_config(profile, self.pem)


class ProcessCollectorContractTests(unittest.TestCase):
    def test_command_line_and_creation_time_are_preserved(self):
        from app.modules.hunting_builder import QUERIES
        self.assertIn('CommandLine', QUERIES['processes'][1])
        self.assertIn('CreateTime', QUERIES['processes'][1])
        self.assertIn('LIMIT 10000', QUERIES['processes'][1])


class NetworkCollectorContractTests(unittest.TestCase):
    def test_network_query_keeps_schema_for_field_drift(self):
        from app.modules.hunting_builder import QUERIES
        self.assertIn('SELECT * FROM netstat()',QUERIES['network'][1])

class EventMetadataContractTests(unittest.TestCase):
    def test_window_precedes_limit_and_has_upper_bound(self):
        from app.modules.hunting_builder import EVENT_METADATA_SPECS, event_metadata_query
        for key, spec in EVENT_METADATA_SPECS.items():
            for days in (1, 7, 30):
                query = event_metadata_query(key, days)
                self.assertIn(f'CaptureEpoch - {days * 86400}', query)
                self.assertIn('StartDate=WindowStart, EndDate=WindowEnd', query)
                self.assertIn('WHERE TimeCreated >= WindowStart AND TimeCreated <= WindowEnd', query)
                self.assertLess(query.index('WHERE TimeCreated'), query.index('LIMIT '))
                self.assertTrue(query.endswith(f'LIMIT {spec[4]}'))
                self.assertIn('VSSAnalysisAge=0', query)
                self.assertIn('EvtxGlob=', query)
                self.assertNotIn('Glob="C:', query)

    def test_fixed_metadata_projection_excludes_sensitive_payloads(self):
        from app.modules.hunting_builder import EVENT_METADATA_SPECS, event_metadata_query
        for key in EVENT_METADATA_SPECS:
            query = event_metadata_query(key, 7)
            for forbidden in ('SELECT *', 'Message', 'EventData', 'ScriptBlock',
                              'upload(', 'execve(', 'read_file(', 'process_memory(',
                              'ntfs_vss', 'UserData'):
                self.assertNotIn(forbidden, query)
            self.assertIn('System.Computer AS Computer', query)
            self.assertIn('IDRegex="^(', query)
            self.assertIn('ChannelRegex="^', query)
        for days in (0, 31, True, 1.5, '7'):
            with self.subTest(days=days), self.assertRaises(ValueError):
                event_metadata_query('security_events', days)
        with self.assertRaises(ValueError):
            event_metadata_query('arbitrary_path', 7)

    def test_extended_source_caps_and_linux_contract(self):
        from app.modules.hunting_builder import EXTENDED_QUERIES
        expected = {"windows_evtx": 50000, "windows_prefetch": 20000, "windows_amcache": 1,
                    "windows_lnk_jumplists": 20000, "windows_srum": 2000, "windows_mft_usn": 2,
                    "linux_journal": 1000, "linux_auth_logs": 1000, "linux_audit_logs": 1000}
        self.assertEqual(set(expected), set(EXTENDED_QUERIES))
        for key, cap in expected.items():
            self.assertIn(f"LIMIT {cap}", EXTENDED_QUERIES[key][1])
        self.assertIn('length=65536', EXTENDED_QUERIES['linux_journal'][1])

    def test_events_remain_fail_closed(self):
        from app.modules.hunting_builder import EVENT_METADATA_SPECS, SUPPORTED
        self.assertFalse(set(EVENT_METADATA_SPECS) & SUPPORTED)


class InstalledEventEngineTests(unittest.TestCase):
    def test_synthetic_utc_cutoff_before_row_limit(self):
        import os
        import re
        import subprocess
        from app.modules.hunting_builder import event_metadata_query
        engine = os.environ.get('HUNTING_VQL_ENGINE')
        if not engine:
            self.skipTest('Set HUNTING_VQL_ENGINE for server-only synthetic validation')
        # One stale record precedes two in-window records, followed by a future
        # record. LIMIT 1 must return the first in-window record, not zero rows.
        query = event_metadata_query('security_events', 1)
        query = query.replace('LET CaptureEpoch <= now()', 'LET CaptureEpoch <= 2000000000')
        synthetic = '''foreach(row=[
 dict(TimeCreated=timestamp(epoch=1999913599), EventID=4624, EventRecordID=1),
 dict(TimeCreated=timestamp(epoch=1999913600), EventID=4624, EventRecordID=2),
 dict(TimeCreated=timestamp(epoch=2000000000), EventID=4624, EventRecordID=3),
 dict(TimeCreated=timestamp(epoch=2000000001), EventID=4624, EventRecordID=4)],
 query={ SELECT TimeCreated, EventID, EventRecordID, "Security" AS Channel,
 dict(Computer="fixture", Provider=dict(Name="fixture"), Level=4) AS System
 FROM scope() })'''
        query = re.sub(r'Artifact\.Windows\.EventLogs\.Evtx\(.*?\)\nWHERE',
                       lambda _: synthetic + '\nWHERE', query, flags=re.S)
        for cap, expected in ((1, [2]), (10, [2, 3])):
            bounded = query.replace('LIMIT 50000', f'LIMIT {cap}')
            result = subprocess.run([engine, 'query', '--format=json', bounded],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = json.loads(result.stdout)
            self.assertEqual([row['EventRecordID'] for row in rows], expected)
            self.assertNotIn('ERROR', result.stderr)


if __name__ == '__main__':
    unittest.main()


    def test_extended_sources_are_opt_in(self):
        from app.modules.hunting_builder import compile_config
        profile = {"id": "0123456789abcdef0123456789abcdef", "campaign_id": "pilot", "platform": "windows", "artifacts": ["host", "windows_prefetch"], "timeout_seconds": 600, "event_days": 7}
        with self.assertRaises(ValueError):
            compile_config(profile, self.cert)
        profile["extended_pilot"] = True
        config, _ = compile_config(profile, self.cert)
        self.assertIn("WindowsPrefetch", str(config))
