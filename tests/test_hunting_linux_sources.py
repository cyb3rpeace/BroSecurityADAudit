import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from app.modules.hunting_builder import compile_config, LINUX_QUERIES, linux_config_query, linux_suid_query
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
        self.assertIn('Systemd drop-ins are not collected', '\n'.join(manifest['limitations']))
        self.assertIn('Symlinked parent directories are skipped', '\n'.join(manifest['limitations']))

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


class LinuxQueryExecutionTests(unittest.TestCase):
    """Only synthetic tmpdir paths are queried, never the production globs.

    Set HUNTING_TEST_ENGINE to the pinned installed engine mounted read-only.
    """
    @classmethod
    def setUpClass(cls):
        cls.engine = os.environ.get('HUNTING_TEST_ENGINE')
        if not cls.engine:
            raise unittest.SkipTest('HUNTING_TEST_ENGINE is required for engine tests')
        if not Path(cls.engine).is_file():
            raise RuntimeError('Configured execution engine is missing')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='linux-query-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def query(self, query):
        result = subprocess.run([self.engine, '--nobanner', 'query', '--format', 'jsonl', query],
                                capture_output=True, text=True, timeout=20, check=True)
        self.assertEqual(result.stderr.strip(), '', result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]

    def test_content_rejects_final_and_intermediate_links(self):
        safe = self.root / 'safe'
        safe.mkdir()
        (safe / 'ok.conf').write_text('safe fixture')
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'escape.conf').write_text('outside fixture')
        (safe / 'linked.conf').symlink_to(outside / 'escape.conf')
        linked = self.root / 'linked'
        linked.symlink_to(outside, target_is_directory=True)
        rows = self.query(linux_config_query([str(safe / '*'), str(linked / '*')]))
        self.assertEqual([r['OSPath'] for r in rows], [str(safe / 'ok.conf')])
        self.assertEqual(rows[0]['Content'], 'safe fixture')
        # Also reject a link above the immediate parent directory.
        (outside / 'nested').mkdir()
        (outside / 'nested' / 'escape.conf').write_text('outside fixture')
        self.assertEqual(self.query(linux_config_query([str(linked / 'nested' / '*')])), [])

    def test_wildcard_parents_rejected_and_dropins_not_advertised_in_query(self):
        with self.assertRaises(ValueError):
            linux_config_query([str(self.root / '*.service.d' / '*.conf')])
        self.assertNotIn('*.service.d', LINUX_QUERIES['linux_services'][1])

    def test_content_regular_files_byte_cap_and_truncation(self):
        (self.root / 'exact').write_text('x' * 65536)
        (self.root / 'large').write_text('y' * 65537)
        (self.root / 'directory').mkdir()
        os.mkfifo(self.root / 'fifo')
        rows = self.query(linux_config_query([str(self.root / '*')]))
        by_name = {Path(r['OSPath']).name: r for r in rows}
        self.assertEqual(set(by_name), {'exact', 'large'})
        self.assertEqual(len(by_name['exact']['Content']), 65536)
        self.assertFalse(by_name['exact']['ContentTruncated'])
        self.assertEqual(len(by_name['large']['Content']), 65536)
        self.assertTrue(by_name['large']['ContentTruncated'])

    def test_config_row_cap(self):
        for i in range(1001):
            (self.root / f'{i:04}.conf').write_text('fixture')
        self.assertEqual(len(self.query(linux_config_query([str(self.root / '*')]))), 1000)

    def test_suid_modes_and_numeric_ownership(self):
        for name, mode in [('suid', 0o4755), ('sgid', 0o2755), ('both', 0o6755), ('normal', 0o755)]:
            p = self.root / name
            p.write_text('fixture')
            if os.geteuid() == 0:
                os.chown(p, 12345, 23456)
            p.chmod(mode)
        (self.root / 'link').symlink_to(self.root / 'suid')
        directory = self.root / 'directory'
        directory.mkdir()
        directory.chmod(0o2755)
        rows = self.query(linux_suid_query([str(self.root / '*')]))
        self.assertEqual({Path(r['OSPath']).name for r in rows}, {'suid', 'sgid', 'both'})
        for row in rows:
            st = Path(row['OSPath']).stat()
            self.assertIs(type(row['OwnerID']), int)
            self.assertIs(type(row['GroupID']), int)
            self.assertEqual((row['OwnerID'], row['GroupID']), (st.st_uid, st.st_gid))
        linked = self.root / 'linked-directory'
        linked.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.query(linux_suid_query([str(linked / '*')])), [])

    def test_terminal_telemetry_empty_present_and_cap(self):
        from app.modules.hunting_builder import outcome_query
        for count, cap, outcome in [(0, 10, 'empty'), (2, 10, 'present'), (10, 10, 'cap_reached')]:
            rows = self.query(outcome_query('processes', f'SELECT _value AS Pid FROM range(end={count}) LIMIT {cap}', cap))
            self.assertEqual(len(rows), count + 1)
            claim = rows[-1]['_BroSecCollectionStatus']
            self.assertEqual(claim['rows'], count)
            self.assertEqual(claim['outcome'], outcome)
            self.assertEqual(claim['status'], 'unknown')

    def test_logged_plugin_failure_is_not_success_or_empty_success(self):
        from app.modules.hunting_builder import outcome_query
        # A real plugin error is observable in stderr, not a reliable per-source
        # success signal exposed by VQL. Preserve unknown rather than guessing.
        query = outcome_query('host', 'SELECT * FROM brosec_nonexistent_plugin()', 1)
        run = subprocess.run([self.engine, '--nobanner', 'query', '--format', 'jsonl', query], capture_output=True, text=True, timeout=20)
        self.assertTrue(run.stderr.strip())
        rows = [json.loads(line) for line in run.stdout.splitlines() if line.strip()]
        for row in rows:
            if '_BroSecCollectionStatus' in row:
                self.assertEqual(row['_BroSecCollectionStatus']['status'], 'unknown')

    def test_suid_row_cap(self):
        for i in range(10001):
            p = self.root / f'{i:05}'
            p.write_text('fixture')
            p.chmod(0o4755)
        self.assertEqual(len(self.query(linux_suid_query([str(self.root / '*')]))), 10000)
