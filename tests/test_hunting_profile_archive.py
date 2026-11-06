import tempfile
import unittest
from pathlib import Path
from app.modules import hunting_profiles as hp

class ProfileArchiveTests(unittest.TestCase):
    def test_deleted_profile_hidden_but_retained_for_existing_campaign(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d)
            row=hp.create_profile(base,1,'Campaign profile','linux',['host'],600,7)
            self.assertTrue(hp.delete_profile(base,1,row['id']))
            self.assertEqual(hp.list_profiles(base,1),[])
            self.assertIsNone(hp.get_profile(base,1,row['id']))
            archived=hp.get_profile(base,1,row['id'],include_deleted=True)
            self.assertEqual(archived['artifacts'],['host'])
            self.assertTrue(archived['deleted_at'])
            self.assertIsNone(hp.get_profile(base,2,row['id'],include_deleted=True))
            self.assertFalse(hp.delete_profile(base,1,row['id']))
