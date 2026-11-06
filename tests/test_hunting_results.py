import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from app.modules.hunting_results import save_result, history, get_result, read_page


class ResultTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.summary={'sources':[{'source':'results/test.json','rows':3}],'total_rows':3}

    def test_persistence_deduplication_and_tenant_isolation(self):
        one=save_result(self.base,1,b'encrypted',self.summary)
        self.assertFalse(one['duplicate'])
        self.assertTrue(save_result(self.base,1,b'encrypted',self.summary)['duplicate'])
        self.assertEqual(history(self.base,1)['total'],1)
        self.assertEqual(history(self.base,2)['total'],0)
        self.assertIsNone(get_result(self.base,2,one['id']))
        self.assertEqual((self.base/'archives/1'/ (one['id']+'.zip')).read_bytes(),b'encrypted')

    def test_pagination_and_integrity(self):
        item=save_result(self.base,1,b'encrypted',self.summary)
        def parser(data,keys,company,row_callback):
            for i in range(3):row_callback('results/test.json',i,{'n':i})
        with patch('app.modules.hunting_results.summarize_container',side_effect=parser):
            page=read_page(self.base,self.base/'keys',1,item['id'],'results/test.json',1,1)
            self.assertEqual(page['rows'],[{'n':1}])
        (self.base/'archives/1'/(item['id']+'.zip')).write_bytes(b'tamper')
        with self.assertRaises(ValueError):read_page(self.base,self.base/'keys',1,item['id'],'results/test.json')

    def test_quota_and_invalid_page(self):
        with patch('app.modules.hunting_results.MAX_TENANT_BYTES',1):
            with self.assertRaises(ValueError):save_result(self.base,1,b'large',self.summary)
        self.assertEqual(history(self.base,1)['total'],0)
        with self.assertRaises(ValueError):history(self.base,1,-1)
        with self.assertRaises(KeyError):read_page(self.base,self.base/'keys',2,'missing','anything')


    def test_delete_cleans_owned_artifacts_and_allows_reimport(self):
        from app.modules.hunting_results import delete_result, review_finding, finding_reviews
        from app.modules.hunting_pipeline import create_job, advance, list_jobs, events
        one = save_result(self.base, 1, b'encrypted', self.summary)
        other = save_result(self.base, 2, b'encrypted', self.summary)
        review_finding(self.base, 1, one['id'], {'source': 'results/test.json', 'row_number': 1}, 'confirmed', 'reviewed', 1)
        job = create_job(self.base, 1, None, None, one['id'])
        advance(self.base, 1, job['id'], 'completed', 'done', payload={'cached': 'analysis'})
        foreign = create_job(self.base, 2, None, None, one['id'])
        for extension in ('pdf', 'xlsx'):
            path = self.base / 'exports' / '1' / (one['id'] + '-forensic.' + extension)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'export')
        self.assertEqual(delete_result(self.base, 1, one['id']), {'deleted': True, 'id': one['id']})
        self.assertEqual(history(self.base, 1)['total'], 0)
        self.assertEqual(finding_reviews(self.base, 1, one['id']), [])
        self.assertEqual(list_jobs(self.base, 1)['total'], 0)
        self.assertEqual(events(self.base, 1, job['id']), [])
        self.assertEqual(list_jobs(self.base, 2)['items'][0]['id'], foreign['id'])
        self.assertIsNotNone(get_result(self.base, 2, other['id']))
        self.assertFalse((self.base / 'archives' / '1' / (one['id'] + '.zip')).exists())
        self.assertEqual(list((self.base / 'exports' / '1').iterdir()), [])
        self.assertFalse(save_result(self.base, 1, b'encrypted', self.summary)['duplicate'])
        with self.assertRaises(KeyError):
            delete_result(self.base, 1, one['id'])

    def test_delete_missing_and_foreign_results_do_not_touch_evidence(self):
        from app.modules.hunting_results import delete_result
        one = save_result(self.base, 1, b'encrypted', self.summary)
        for company, identifier in [(2, one['id']), (1, 'a' * 32), (1, '../escape'), (1, 'missing')]:
            with self.assertRaises(KeyError):
                delete_result(self.base, company, identifier)
        self.assertIsNotNone(get_result(self.base, 1, one['id']))
        self.assertEqual((self.base / 'archives' / '1' / (one['id'] + '.zip')).read_bytes(), b'encrypted')

    def test_delete_active_job_conflicts_and_failed_job_is_removed(self):
        from app.modules.hunting_results import delete_result, ResultInUseError
        from app.modules.hunting_pipeline import create_job, fail, list_jobs
        one = save_result(self.base, 1, b'encrypted', self.summary)
        job = create_job(self.base, 1, None, None, one['id'])
        with self.assertRaises(ResultInUseError):
            delete_result(self.base, 1, one['id'])
        self.assertIsNotNone(get_result(self.base, 1, one['id']))
        fail(self.base, 1, job['id'], 'test', 'failed')
        delete_result(self.base, 1, one['id'])
        self.assertEqual(list_jobs(self.base, 1)['total'], 0)

    def test_delete_handles_missing_archive_and_rejects_symlink_paths(self):
        from app.modules.hunting_results import delete_result
        one = save_result(self.base, 1, b'encrypted', self.summary)
        archive = self.base / 'archives' / '1' / (one['id'] + '.zip')
        archive.unlink()
        target = self.base / 'untouched'
        target.write_bytes(b'private')
        archive.symlink_to(target)
        with self.assertRaises(ValueError):
            delete_result(self.base, 1, one['id'])
        self.assertEqual(target.read_bytes(), b'private')
        self.assertIsNotNone(get_result(self.base, 1, one['id']))
        archive.unlink()
        directory = archive.parent
        directory.rmdir()
        directory.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError):
            delete_result(self.base, 1, one['id'])
        directory.unlink()
        delete_result(self.base, 1, one['id'])
        self.assertEqual(target.read_bytes(), b'private')

    def test_delete_export_symlink_rejected_before_moving_archive(self):
        from app.modules.hunting_results import delete_result
        one = save_result(self.base, 1, b'encrypted', self.summary)
        export = self.base / 'exports' / '1' / (one['id'] + '-forensic.pdf')
        export.parent.mkdir(parents=True)
        target = self.base / 'private.pdf'
        target.write_bytes(b'foreign report')
        export.symlink_to(target)
        with self.assertRaises(ValueError):
            delete_result(self.base, 1, one['id'])
        self.assertEqual(target.read_bytes(), b'foreign report')
        self.assertEqual((self.base / 'archives' / '1' / (one['id'] + '.zip')).read_bytes(), b'encrypted')
        self.assertIsNotNone(get_result(self.base, 1, one['id']))

    def test_delete_rolls_back_files_and_index_on_database_failure(self):
        import sqlite3
        from app.modules.hunting_results import delete_result, connection
        one = save_result(self.base, 1, b'encrypted', self.summary)
        with connection(self.base) as db:
            db.execute("CREATE TRIGGER reject_delete BEFORE DELETE ON imports BEGIN SELECT RAISE(ABORT, 'test'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            delete_result(self.base, 1, one['id'])
        self.assertIsNotNone(get_result(self.base, 1, one['id']))
        self.assertEqual((self.base / 'archives' / '1' / (one['id'] + '.zip')).read_bytes(), b'encrypted')

    def test_delete_campaign_task_active_guard_and_terminal_unlink(self):
        from app.modules.hunting_results import delete_result, ResultInUseError
        from app.modules.hunting_campaigns import connection
        one = save_result(self.base, 1, b'encrypted', self.summary)
        with connection(self.base) as db:
            db.execute("INSERT INTO campaigns VALUES ('campaign',1,'profile','running','idempotency',1,1,'now',NULL,NULL,'now')")
            db.execute("INSERT INTO tasks (id,campaign_id,company_id,hostname,normalized_hostname,status,task_key,next_attempt_at,result_id,created_at,updated_at) VALUES ('task','campaign',1,'host','host','analyzing','task-key','now',?,'now','now')", (one['id'],))
        with self.assertRaises(ResultInUseError):
            delete_result(self.base, 1, one['id'])
        with connection(self.base) as db:
            db.execute("UPDATE tasks SET status='analyzed'")
        delete_result(self.base, 1, one['id'])
        with connection(self.base) as db:
            task = db.execute("SELECT * FROM tasks WHERE id='task'").fetchone()
            self.assertIsNone(task['result_id'])
            self.assertEqual(task['status'], 'analyzed')


    def test_retention_purge_uses_transactional_delete_and_rolls_back(self):
        import sqlite3
        from app.modules.hunting_results import purge_retention_candidates, connection
        one = save_result(self.base, 1, b'encrypted', self.summary)
        candidate = {'id': one['id'], 'protected': False}
        with patch('app.modules.hunting_results.retention_candidates', return_value=[candidate]):
            preview = purge_retention_candidates(self.base, 1, dry_run=True)
            self.assertTrue(preview['dry_run'])
            self.assertEqual((self.base / 'archives' / '1' / (one['id'] + '.zip')).read_bytes(), b'encrypted')
            with connection(self.base) as db:
                db.execute("CREATE TRIGGER reject_retention_delete BEFORE DELETE ON imports BEGIN SELECT RAISE(ABORT, 'test'); END")
            with self.assertRaises(sqlite3.IntegrityError):
                purge_retention_candidates(self.base, 1, dry_run=False)
        self.assertIsNotNone(get_result(self.base, 1, one['id']))
        self.assertEqual((self.base / 'archives' / '1' / (one['id'] + '.zip')).read_bytes(), b'encrypted')


if __name__=='__main__':unittest.main()
