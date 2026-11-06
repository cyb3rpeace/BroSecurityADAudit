import unittest
from app.modules.hunting_profiles import profile_row_budget, validate_profile, collection_contract

class ProfileRowBudgetTests(unittest.TestCase):
    def test_combined_event_sources_rejected(self):
        sources=['security_events','powershell_events','defender_events','rdp_events']
        self.assertEqual(profile_row_budget(sources)['configured_rows'],115000)
        with self.assertRaisesRegex(ValueError,'90000'):
            validate_profile('windows',sources,600,7)

    def test_snapshot_and_linux_profiles_fit(self):
        for platform,sources in [('windows',['host','processes','network','services','tasks','startup']),('linux',['host','processes','network','linux_services','linux_crontab','linux_suid'])]:
            validate_profile(platform,sources,600,7)
            budget=collection_contract(dict(artifacts=sources,timeout_seconds=600,event_days=7))['row_budget']
            self.assertTrue(budget['within_budget'])
            self.assertLess(budget['configured_rows'],budget['importer_maximum_rows'])

    def test_budget_counts_unique_sources(self):
        self.assertEqual(profile_row_budget(['host','host'])['configured_rows'],1)
        with self.assertRaises(ValueError): validate_profile('windows',['host','host'],600,7)
