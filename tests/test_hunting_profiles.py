import json
import tempfile
import unittest
from pathlib import Path
from app.modules import hunting_profiles as hp


class HuntingProfilesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def create(self, company=1, **kwargs):
        fields = dict(name='Проверка', platform='windows', artifacts=['host', 'processes'], timeout_seconds=600, event_days=7)
        fields.update(kwargs)
        return hp.create_profile(self.base, company, **fields)

    def test_tenant_isolation(self):
        first = self.create(1)
        second = self.create(2)
        self.assertEqual([p['id'] for p in hp.list_profiles(self.base, 1)], [first['id']])
        self.assertIsNone(hp.get_profile(self.base, 2, first['id']))
        self.assertEqual(hp.get_profile(self.base, 2, second['id']), second)

    def test_platform_allowlist(self):
        for kwargs in [dict(platform='macos'), dict(platform='linux', artifacts=['services']), dict(artifacts=['arbitrary_vql']), dict(artifacts=[]), dict(artifacts=['host', 'host'])]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.create(**kwargs)
        self.assertEqual(self.create(platform='linux')['platform'], 'linux')

    def test_limits_and_name(self):
        for kwargs in [dict(timeout_seconds=59), dict(timeout_seconds=3601), dict(event_days=0), dict(event_days=31), dict(name=' '), dict(name='a\nb'), dict(name='x'*121)]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.create(**kwargs)
        self.create(timeout_seconds=60, event_days=1)
        self.create(timeout_seconds=3600, event_days=30)

    def test_spec_has_no_tenant_credentials_or_executable(self):
        profile = self.create()
        spec = hp.export_spec({**profile, 'password': 'DO_NOT_EXPORT', 'private_key': 'DO_NOT_EXPORT'})
        text = json.dumps(spec)
        self.assertNotIn('DO_NOT_EXPORT', text)
        self.assertNotIn('company_id', spec)
        self.assertFalse(spec['executable'])
        self.assertTrue(spec['encryption_required'])

    def test_offline_verified_sources_are_supported_and_events_remain_gated(self):
        for source_id in ("accounts", "wmi_persistence", "registry_run_keys"):
            item = next(x for x in hp.CATALOG if x["id"] == source_id)
            self.assertEqual(item["status"], "analysis_supported")
        for item in hp.CATALOG:
            if item["id"] in hp.EVENT_SOURCE_IDS:
                self.assertIn(item["status"], {"verified_bounded", "candidate_no_telemetry", "candidate"})
                if item["status"] == "candidate": self.assertFalse(item["execution_verified"])
                self.assertTrue(item["metadata_only"])

    def test_export_explicitly_reports_unapplied_days(self):
        for artifacts, reason in [(['host'], 'snapshot_sources_have_no_event_window'),
                                  (['security_events'], 'event_sources_candidate_not_packaged')]:
            spec = hp.export_spec(self.create(artifacts=artifacts, event_days=3))
            window = spec['collection_contract']['event_window']
            self.assertEqual(window, dict(requested_days=3, applied=False, reason=reason))
            self.assertEqual(spec['collection_contract']['windows_event_execution_verified'], artifacts == ['security_events'])

    def test_limits_reject_boolean_fractional_and_string(self):
        for kwargs in (dict(event_days=True), dict(event_days=1.5), dict(event_days='7'),
                       dict(timeout_seconds=True), dict(timeout_seconds=60.5)):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.create(**kwargs)

    def test_list_bounded(self):
        for _ in range(102):
            self.create()
        self.assertEqual(len(hp.list_profiles(self.base, 1)), 100)


    def test_delete_profile_is_tenant_scoped_and_idempotent(self):
        row = self.create()
        self.assertFalse(hp.delete_profile(self.base, 2, row["id"]))
        self.assertIsNotNone(hp.get_profile(self.base, 1, row["id"]))
        self.assertTrue(hp.delete_profile(self.base, 1, row["id"]))
        self.assertFalse(hp.delete_profile(self.base, 1, row["id"]))
        self.assertIsNone(hp.get_profile(self.base, 1, row["id"]))


if __name__ == '__main__':
    unittest.main()
