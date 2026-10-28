import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.modules import hunting_correlation as correlation
from app.modules.hunting_results import save_result

PREFIX = 'results/BroSec.Offline.Baseline/'
HASH = 'a' * 64


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.rows = {}

    def add(self, host='alpha', processes=None, network=None, company=1, extra=None):
        rows = [(PREFIX + 'Host.json', {'Hostname': host})] if host else []
        rows += [(PREFIX + 'Processes.json', row) for row in (processes or [])]
        rows += [(PREFIX + 'Network.json', row) for row in (network or [])]
        rows += extra or []
        data = ('archive-' + str(len(self.rows))).encode()
        counts = {}
        for source, row in rows:
            counts[source] = counts.get(source, 0) + 1
        summary = {'sources': [{'source': source, 'rows': count} for source, count in counts.items()],
                   'total_rows': len(rows)}
        item = save_result(self.base, company, data, summary)
        self.rows[data] = (rows, summary)
        return item['id']

    def parse(self, data, keys, company, row_callback=None):
        rows, summary = self.rows[data]
        counts = {}
        for source, row in rows:
            index = counts.get(source, 0)
            counts[source] = index + 1
            if row_callback:
                row_callback(source, index, row)
        return copy.deepcopy(summary)

    def run_correlation(self, ids, company=1):
        with patch('app.modules.hunting_results.summarize_container', side_effect=self.parse), \
             patch.object(correlation, 'summarize_container', side_effect=self.parse):
            return correlation.correlate_results(self.base, self.base / 'keys', company, ids)

    def test_tenant_preflight_all_ids_before_analysis(self):
        own = self.add()
        foreign = self.add(company=2)
        for ids in ([foreign], [own, foreign], ['f' * 32]):
            with patch.object(correlation, 'analyze_result') as analyzer:
                with self.assertRaisesRegex(KeyError, 'Result not found'):
                    correlation.correlate_results(self.base, self.base, 1, ids)
                analyzer.assert_not_called()

    def test_duplicate_oversized_and_invalid_input(self):
        rid = self.add()
        for ids in ([], [rid] * 21, [rid, rid], ['../escape'], 'bad', [None]):
            with self.assertRaises(ValueError):
                self.run_correlation(ids)
        for company in (True, 0, -1, '1'):
            with self.assertRaises(ValueError):
                self.run_correlation([rid], company)

    def test_shared_ip_never_links_or_resolves_hosts(self):
        a = self.add('alpha', network=[{'RemoteIP': '8.8.8.8', 'Pid': 1}])
        b = self.add('beta', network=[{'LocalIP': '8.8.8.8', 'Pid': 1}])
        result = self.run_correlation([a, b])
        self.assertEqual(result['graph']['edges'], [])
        self.assertEqual(len([n for n in result['graph']['nodes'] if n['kind'] == 'host']), 2)

    def test_explicit_shared_hash_identity_and_determinism(self):
        rows = [{'Pid': 1, 'Exe': '/bin/tool', 'SHA256': HASH, 'Username': r'DOMAIN\alice'}]
        a = self.add('alpha', processes=rows)
        b = self.add('beta', processes=rows)
        first = self.run_correlation([a, b])
        self.assertEqual(first, self.run_correlation([b, a]))
        self.assertEqual({e['relation'] for e in first['graph']['edges']},
                         {'shared_sha256', 'shared_qualified_identity'})
        for edge in first['graph']['edges']:
            self.assertEqual(edge['confidence'], 'explicit_shared_evidence')
            self.assertEqual({r['result_id'] for r in edge['evidence_refs']}, {a, b})
            self.assertEqual({r['result_id'] for r in edge['host_evidence_refs']}, {a, b})
            self.assertTrue(all(r['source'] == PREFIX + 'Processes.json' and r['row_number'] == 1
                                for r in edge['evidence_refs']))
        self.assertNotIn('verdict', first)

    def test_unqualified_user_and_same_host_do_not_link(self):
        a = self.add('alpha', processes=[{'Username': 'alice'}])
        b = self.add('beta', processes=[{'Username': 'alice'}])
        self.assertEqual(self.run_correlation([a, b])['graph']['edges'], [])
        c = self.add('ALPHA.', processes=[{'SHA256': HASH}])
        d = self.add('alpha', processes=[{'SHA256': HASH}])
        self.assertEqual(self.run_correlation([c, d])['graph']['edges'], [])

    def test_builtin_and_local_identities_never_link_hosts(self):
        for identity in [r'NT AUTHORITY\SYSTEM', r'NT SERVICE\TrustedInstaller',
                         r'BUILTIN\Administrators', r'.\alice', r'localhost\alice',
                         r'Window Manager\DWM-1', r'Font Driver Host\UMFD-0',
                         r'ALPHA\alice', r'alpha.example.test\alice']:
            with self.subTest(identity=identity):
                a = self.add('alpha.example.test', processes=[{'Username': identity}])
                b = self.add('beta.example.test', processes=[{'Username': identity}])
                self.assertEqual(self.run_correlation([a, b])['graph']['edges'], [])

    def test_domain_and_upn_identities_keep_bilateral_evidence(self):
        for identity in [r'CORP\alice', 'alice@corp.example.test']:
            a = self.add('alpha.example.test', processes=[{'Username': identity}])
            b = self.add('beta.example.test', processes=[{'Username': identity}])
            edges = self.run_correlation([a, b])['graph']['edges']
            self.assertEqual(len(edges), 1)
            self.assertEqual(edges[0]['relation'], 'shared_qualified_identity')
            self.assertEqual({ref['result_id'] for ref in edges[0]['evidence_refs']}, {a, b})

    def test_missing_ambiguous_host_and_unsupported_sources(self):
        a = self.add('alpha', processes=[{'SHA256': HASH}])
        for host, extra in ((None, []), ('beta', [(PREFIX + 'Host.json', {'Hostname': 'gamma'})]),
                            ('beta', [('results/arbitrary.json', {'SHA256': HASH})])):
            b = self.add(host, processes=[{'SHA256': HASH}] if host != 'beta' or extra[0][0].endswith('Host.json') else [], extra=extra)
            self.assertEqual(self.run_correlation([a, b])['graph']['edges'], [])

    def test_missing_tampered_and_symlink_archives(self):
        rid = self.add()
        path = self.base / 'archives' / '1' / (rid + '.zip')
        original = path.read_bytes()
        path.write_bytes(b'x' * len(original))
        with self.assertRaises(ValueError):
            self.run_correlation([rid])
        path.unlink()
        with self.assertRaises(ValueError):
            self.run_correlation([rid])
        target = self.base / 'target'
        target.write_bytes(original)
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            self.run_correlation([rid])

    def test_hard_byte_row_budgets_and_metadata_understatement(self):
        rid = self.add()
        for limit in ('MAX_TOTAL_BYTES', 'MAX_TOTAL_ROWS'):
            with patch.object(correlation, limit, 0):
                with self.assertRaises(correlation.CorrelationLimitError):
                    self.run_correlation([rid])
        from app.modules.hunting_results import connection
        import json
        with connection(self.base) as db:
            db.execute('UPDATE imports SET summary=? WHERE id=?',
                       (json.dumps({'sources': [], 'total_rows': 0}), rid))
        with self.assertRaises(ValueError):
            self.run_correlation([rid])

    def test_soft_output_limits_and_retained_hosts(self):
        a = self.add('alpha', processes=[{'SHA256': HASH, 'Username': 'a@domain'}] * 16)
        b = self.add('beta', processes=[{'SHA256': HASH, 'Username': 'a@domain'}])
        with patch.object(correlation, 'MAX_NODES', 22), patch.object(correlation, 'MAX_EDGES', 1), \
             patch.object(correlation, 'MAX_INDICATORS', 1):
            result = self.run_correlation([a, b])
        self.assertTrue(result['truncated'])
        self.assertLessEqual(len(result['graph']['nodes']), 22)
        self.assertLessEqual(len(result['graph']['edges']), 1)
        self.assertEqual(len([x for x in result['graph']['nodes'] if x['kind'] == 'host']), 2)
        self.assertLessEqual(len(result['graph']['edges'][0]['evidence_refs']), 24)

    def test_twenty_results_and_persistence_nodes(self):
        ids = [self.add('host-' + str(i), processes=[{'Pid': 1}],
                        extra=[(PREFIX + 'Services.json', {'Name': 'service'})]) for i in range(20)]
        result = self.run_correlation(ids)
        self.assertEqual(len(result['result_ids']), 20)
        self.assertEqual(len([n for n in result['graph']['nodes'] if n['kind'] == 'persistence']), 20)
        self.assertEqual(result['graph']['edges'], [])

    def test_real_encrypted_container(self):
        from tests.test_hunting_ingest import IngestTests
        from app.modules.hunting_ingest import summarize_container
        fixture = IngestTests()
        fixture.setUp()
        try:
            ids = []
            import json
            for hostname in ('alpha', 'beta'):
                # Existing fixture emits one source; Host rows also carry no hash links.
                data = fixture.container(PREFIX + 'Host.json',
                                         (json.dumps({'Hostname': hostname}) + '\n').encode())
                summary = summarize_container(data, fixture.root, 1)
                ids.append(save_result(self.base, 1, data, summary)['id'])
            result = correlation.correlate_results(self.base, fixture.root, 1, ids)
            self.assertEqual(len(result['graph']['nodes']), 2)
            self.assertEqual(result['graph']['edges'], [])
        finally:
            fixture.doCleanups()


if __name__ == '__main__':
    unittest.main()
