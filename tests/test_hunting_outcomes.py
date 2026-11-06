"""Endpoint measurements remain claims, not verified collection success."""
import json
import unittest
from app.modules.hunting_ingest import collection_provenance, strict_object
from app.modules.hunting_builder import outcome_query


class EndpointOutcomeTests(unittest.TestCase):
    def provenance(self, rows, outcome, claimed_rows=None, status='unknown'):
        return collection_provenance(
            {'CollectionContract': {'configured_source_row_limits': {'processes': 10}},
             'CollectionStatus': {'version': 1, 'sources': {'processes': {'status': status}}}},
            [] if rows is None else [{'source': 'results/BroSec.Offline.Baseline/Processes.json', 'rows': rows}],
            {'processes': [{'version': 1, 'source': 'processes', 'status': 'unknown',
                            'measurement': 'bounded_output_only', 'outcome': outcome,
                            'rows': rows if claimed_rows is None else claimed_rows}]})

    def test_present_empty_and_cap_are_measurements_only(self):
        for rows, outcome in [(0, 'empty'), (3, 'present'), (10, 'cap_reached')]:
            result = self.provenance(rows, outcome)
            source = result['requested_sources'][0]
            self.assertEqual(source['claimed_status'], 'unknown')
            self.assertEqual(source['claimed_outcome'], outcome)
            self.assertEqual(source['claim_discrepancies'], [])
            self.assertFalse(result['claims_verified'])
            self.assertFalse(result['claims_trusted'])

    def test_mismatch_and_duplicate_do_not_change_observation(self):
        result = self.provenance(0, 'present', 2)
        source = result['requested_sources'][0]
        self.assertEqual(source['observed_status'], 'empty')
        self.assertTrue(source['claim_discrepancies'])
        result = collection_provenance({'CollectionContract': {'configured_source_row_limits': {'host': 1}}}, [], {'host': [{}, {}]})
        self.assertEqual(result['requested_sources'][0]['claimed_outcome'], 'unknown')
        self.assertTrue(result['requested_sources'][0]['claim_discrepancies'])

    def test_failures_are_untrusted_limitations_not_verified(self):
        for status in ['failed', 'blocked', 'skipped', 'truncated']:
            result = collection_provenance({'CollectionContract': {'configured_source_row_limits': {'host': 1}}, 'CollectionStatus': {'version': 1, 'sources': {'host': {'status': status, 'error': 'SECRET'}}}}, [])
            self.assertEqual(result['requested_sources'][0]['claimed_status'], status)
            self.assertTrue(result['warnings'])
            self.assertNotIn('SECRET', json.dumps(result))
            self.assertFalse(result['claims_verified'])

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"version":1,"version":1}', object_pairs_hook=strict_object)

    def test_legacy_missing_remains_unknown(self):
        result = collection_provenance({'CollectionContract': {'configured_source_row_limits': {'host': 1}}}, [])
        source = result['requested_sources'][0]
        self.assertIsNone(source['claimed_status'])
        self.assertEqual(source['claimed_outcome'], 'unknown')
        self.assertEqual(source['observed_status'], 'missing')

    def test_query_single_bounded_evaluation_no_success_claim(self):
        query = outcome_query('processes', 'SELECT Pid FROM pslist() LIMIT 10', 10)
        self.assertEqual(query.count('pslist()'), 1)
        self.assertIn('LET BroSecRows <=', query)
        self.assertIn('status="unknown"', query)
        self.assertNotIn('status="success"', query)
