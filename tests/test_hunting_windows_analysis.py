"""Synthetic anonymized schemas; no endpoint evidence or key material."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from app.modules.hunting_analysis import BaselineReview, MAX_FINDINGS
from app.modules.hunting_results import save_result, analyze_result, read_page

PREFIX = 'results/BroSec.Acceptance.WindowsCandidates%2F'
COUNTS = {'WMIPersistence': 1, 'RegistryRunKeys': 21, 'SecurityEvents': 10000,
          'PowerShellEvents': 3522, 'DefenderEvents': 0, 'RDPEvents': 2}

def source(kind):
    return PREFIX + kind + '.json'

def summaries():
    return [{'source': source(k), 'rows': v, 'status': 'present' if v else 'empty',
             'completeness': 'unknown'} for k, v in COUNTS.items()]

class WindowsAnalysisTests(unittest.TestCase):
    def test_exact_source_contract(self):
        for kind in COUNTS:
            self.assertEqual(BaselineReview.source_kind(source(kind)), kind)
            self.assertEqual(BaselineReview.source_kind(source(kind).replace('%2F', '/')), kind)
        self.assertIsNone(BaselineReview.source_kind('results/untrusted/SecurityEvents.json'))
        self.assertIsNone(BaselineReview.source_kind(source('Unknown')))

    def test_wmi_nullable_types_and_run_literal_citations(self):
        r = BaselineReview()
        r.consume(source('WMIPersistence'), 0, {'Namespace': 'root/subscription',
            'ConsumerName': 'synthetic-consumer', 'ConsumerType': None,
            'FilterName': 'synthetic-filter', 'FilterType': None})
        r.consume(source('RegistryRunKeys'), 20, {'Name': 'synthetic-value',
            'OSPath': 'synthetic-path', 'Details': 'powershell.exe -EncodedCommand ' + 'A' * 40})
        out = r.result(summaries())
        self.assertEqual(out['verdict'], 'not_determined')
        self.assertEqual(out['findings'][0]['classification'], 'observation')
        f = next(x for x in out['findings'] if x['rule_id'] == 'persistence.registry_run_suspicious_invocation')
        self.assertEqual(f['evidence_refs'], [{'source': source('RegistryRunKeys'), 'row_number': 21, 'relation': 'rule_match'}])
        self.assertEqual(f['evidence']['Name'], 'synthetic-value')
        self.assertFalse(any(x['triage_level'] == 'high' for x in out['findings']))

    def test_benign_and_malformed_values_not_behavior(self):
        for value in [None, ['powershell.exe'], {'Details': 'bad'}, 'powershell.exe -Command Get-Date',
                      'cmd.exe /c echo powershell.exe -EncodedCommand ' + 'A' * 40]:
            r = BaselineReview()
            r.consume(source('RegistryRunKeys'), 0, {'Details': value})
            self.assertFalse(r.result([])['findings'])

    def test_channel_and_event_id_fail_closed(self):
        for row in [{'EventID': 4698, 'Channel': 'Application'}, {'EventID': True, 'Channel': 'Security'},
                    {'EventID': ['4698'], 'Channel': 'Security'}, {'EventID': 9999, 'Channel': 'Security'},
                    {'EventID': 4698, 'Channel': ['Security']}, {}]:
            r = BaselineReview(); r.consume(source('SecurityEvents'), 0, row)
            self.assertFalse(r.result([])['findings'])

    def test_late_event_evidence_and_bounded_output(self):
        r = BaselineReview()
        for i in range(6000):
            r.consume(source('SecurityEvents'), i, {'EventID': 4688, 'Channel': 'Security'})
        for i in range(MAX_FINDINGS + 2):
            r.consume(source('SecurityEvents'), 6000 + i, {'EventID': 4698, 'Channel': 'Security', 'EventRecordID': i + 1})
        out = r.result(summaries())
        self.assertTrue(out['truncated'])
        self.assertEqual(out['findings'][0]['evidence']['EventID'], 4698)
        self.assertEqual(out['findings'][0]['row_number'], 6001)
        self.assertEqual(len(out['findings']), MAX_FINDINGS)
        self.assertEqual(out['windows_event_counts'][0]['rows'] + out['windows_event_counts'][1]['rows'], 6000 + MAX_FINDINGS + 2)

    def test_fixture_summary(self):
        out = BaselineReview().result(summaries())
        self.assertEqual(sum(x['rows'] for x in out['source_coverage']), 13546)
        self.assertEqual(out['unsupported_sources'], [])
        self.assertTrue(all(x['supported'] and x['completeness'] == 'unknown' for x in out['source_coverage']))
        self.assertEqual(out['source_statuses']['SecurityEvents']['status'], 'cap_reached')
        self.assertEqual(out['source_statuses']['DefenderEvents']['status'], 'empty')
        self.assertTrue(any('SecurityEvents' in x for x in out['source_quality_warnings']))
        self.assertTrue(any('DefenderEvents' in x for x in out['source_quality_warnings']))

    def test_analyze_and_resolve_exact_evidence(self):
        rows = [{'EventID': 4688, 'Channel': 'Security'}, {'EventID': 4698, 'Channel': 'Security'}]
        def parser(data, key_root, company_id, row_callback=None):
            if row_callback:
                for i, row in enumerate(rows): row_callback(source('SecurityEvents'), i, row)
            return {'sources': [{'source': source('SecurityEvents'), 'rows': 2}],
                    'collection_provenance': {'status': 'endpoint_claims', 'claims_trusted': False},
                    'collection_quality_warnings': []}
        with tempfile.TemporaryDirectory() as temp, patch('app.modules.hunting_results.summarize_container', side_effect=parser):
            base = Path(temp); item = save_result(base, 1, b'synthetic-encrypted', parser(None, None, 1))
            out = analyze_result(base, base, 1, item['id']); f = out['findings'][0]
            page = read_page(base, base, 1, item['id'], f['source'], f['row_number'] - 1, 1)
            self.assertEqual(page['rows'], [rows[1]])
            self.assertFalse(out['collection_provenance']['claims_trusted'])

if __name__ == '__main__':
    unittest.main()
