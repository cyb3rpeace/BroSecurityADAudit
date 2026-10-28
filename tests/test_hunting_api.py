"""Route integration tests using actual route and authorization definitions.

Load only the relevant AST nodes to avoid starting the application's scheduler
or opening its production database. Run in the application's dependency image.
"""
import ast
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field
from app.modules import hunting_profiles


class HuntingApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.user = None
        self.company = SimpleNamespace(id=1)
        self.db = SimpleNamespace(get=lambda model, key: self.company if key == 1 else None, commit=lambda: None)
        def get_user():
            if self.user is None:
                raise HTTPException(401, 'Требуется вход')
            return self.user
        def get_db():
            return self.db
        app = FastAPI()
        scope = dict(HUNTING_BUILD_LOCK=__import__('threading').BoundedSemaphore(1), json=__import__('json'), app=app, Depends=Depends, HTTPException=HTTPException, JSONResponse=JSONResponse,
                     Form=__import__('fastapi').Form, File=__import__('fastapi').File, UploadFile=__import__('fastapi').UploadFile, hashlib=__import__('hashlib'), BaseModel=BaseModel, Field=Field, Path=Path, User=object, Session=object, Company=object,
                     get_user=get_user, get_db=get_db, hunting_profiles=hunting_profiles,
                     BASE_DIR=Path(self.tmp.name), write_audit=lambda *args: None)
        names = {'resolve_company', 'HuntingProfileIn', 'hunting_store', 'hunting_external_worker_enabled', 'hunting_catalog', 'hunting_list', 'hunting_create', 'hunting_spec', 'HuntingConfigIn', 'hunting_compile', 'HuntingBuildIn', 'hunting_package', 'hunting_import', 'hunting_history', 'hunting_result_delete', 'hunting_profile_delete', 'hunting_rows', 'hunting_analysis'}
        source = Path(__file__).resolve().parents[1] / 'app' / 'main.py'
        tree = ast.parse(source.read_text(encoding='utf-8'))
        nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
        self.assertEqual(len(nodes), len(names))
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), scope)
        self.client = TestClient(app)
        self.payload = dict(company_id=1, name='API test', platform='windows', artifacts=['host'], timeout_seconds=600, event_days=7)

    def login(self):
        self.user = SimpleNamespace(role='company_admin', company_id=1)

    def test_auth_required(self):
        for url in ['/api/threat-hunting/catalog', '/api/threat-hunting/profiles?company_id=1', '/api/threat-hunting/profiles/missing/spec?company_id=1']:
            self.assertEqual(self.client.get(url).status_code, 401)
        self.assertEqual(self.client.post('/api/threat-hunting/profiles', json=self.payload).status_code, 401)

    def test_create_list_export(self):
        self.login()
        result = self.client.post('/api/threat-hunting/profiles', json=self.payload)
        self.assertEqual(result.status_code, 201)
        row = result.json()
        self.assertEqual(self.client.get('/api/threat-hunting/profiles?company_id=1').json(), [row])
        spec = self.client.get('/api/threat-hunting/profiles/' + row['id'] + '/spec?company_id=1')
        self.assertEqual(spec.status_code, 200)
        self.assertEqual(spec.headers['cache-control'], 'no-store')
        self.assertFalse(spec.json()['executable'])
        self.assertNotIn('company_id', spec.json())

    def test_cross_tenant_denied(self):
        self.login()
        row = self.client.post('/api/threat-hunting/profiles', json=self.payload).json()
        self.assertEqual(self.client.get('/api/threat-hunting/profiles?company_id=2').status_code, 403)
        self.assertEqual(self.client.post('/api/threat-hunting/profiles', json={**self.payload, 'company_id': 2}).status_code, 403)
        self.assertEqual(self.client.get('/api/threat-hunting/profiles/' + row['id'] + '/spec?company_id=2').status_code, 403)

    def test_compile_config_and_tenant_checks(self):
        from test_hunting_builder import BuilderTests
        BuilderTests.setUpClass()
        self.login()
        row = self.client.post('/api/threat-hunting/profiles', json=self.payload).json()
        url = '/api/threat-hunting/profiles/' + row['id'] + '/config'
        payload = {'company_id': 1, 'public_certificate': BuilderTests.pem}
        response = self.client.post(url, json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['manifest']['config_only'])
        self.assertEqual(self.client.post(url, json={**payload, 'company_id': 2}).status_code, 403)
        self.assertEqual(self.client.post(url, json={**payload, 'public_certificate': 'invalid'*30}).status_code, 422)
        self.user = None
        self.assertEqual(self.client.post(url, json=payload).status_code, 401)

    def test_package_auth_and_zip(self):
        from unittest.mock import patch
        import io, zipfile
        self.login()
        row = self.client.post('/api/threat-hunting/profiles', json=self.payload).json()
        url = '/api/threat-hunting/profiles/' + row['id'] + '/package'
        with patch('app.modules.hunting_runtime.trusted_tools', return_value=(None,None,'a','b')), patch('app.modules.hunting_packager.build_package', return_value=(b'test-binary', {'executable_sha256':'abc'})):
            response = self.client.post(url, json={'company_id':1})
            self.assertEqual(response.status_code,200)
            with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                self.assertEqual(archive.read('BroSec-Collector.exe'),b'test-binary')
            self.assertEqual(self.client.post(url,json={'company_id':2}).status_code,403)
            self.user = None
            self.assertEqual(self.client.post(url,json={'company_id':1}).status_code,401)

    def test_archived_profile_package_requires_matching_existing_campaign(self):
        from unittest.mock import patch
        self.login()
        row = self.client.post('/api/threat-hunting/profiles', json=self.payload).json()
        url = '/api/threat-hunting/profiles/' + row['id']
        self.assertEqual(self.client.delete(url + '?company_id=1').status_code, 200)
        with patch('app.modules.hunting_runtime.trusted_tools', return_value=(None,None,'a','b')), patch('app.modules.hunting_packager.build_package', return_value=(b'test-binary', {'executable_sha256':'abc'})), patch('app.modules.hunting_campaigns.get_campaign') as campaign:
            self.assertEqual(self.client.post(url + '/package', json={'company_id':1}).status_code, 404)
            campaign.return_value = {'profile_id': row['id']}
            self.assertEqual(self.client.post(url + '/package', json={'company_id':1, 'campaign_id':'a'*32}).status_code, 200)
            campaign.return_value = {'profile_id': 'different'}
            self.assertEqual(self.client.post(url + '/package', json={'company_id':1, 'campaign_id':'a'*32}).status_code, 409)
            campaign.return_value = None
            self.assertEqual(self.client.post(url + '/package', json={'company_id':1, 'campaign_id':'a'*32}).status_code, 404)

    def test_import_auth_and_summary(self):
        from unittest.mock import patch
        url = '/api/threat-hunting/import'
        self.assertEqual(self.client.post(url,data={'company_id':1},files={'file':('result.zip',b'test')}).status_code,401)
        self.login()
        with patch.dict(__import__('os').environ, {'HUNTING_EXTERNAL_WORKER': '1'}), patch('app.modules.hunting_ingest.summarize_container',return_value={'total_rows':1,'sources':[],'limitations':[]}):
            response=self.client.post(url,data={'company_id':1},files={'file':('result.zip',b'test')})
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.json()['total_rows'],1)
            self.assertEqual(self.client.post(url,data={'company_id':2},files={'file':('result.zip',b'test')}).status_code,403)
        with patch('app.modules.hunting_ingest.summarize_container',side_effect=ValueError('Rejected')):
            self.assertEqual(self.client.post(url,data={'company_id':1},files={'file':('result.zip',b'test')}).status_code,422)

    def test_history_and_rows_tenant_guards(self):
        self.assertEqual(self.client.get('/api/threat-hunting/results?company_id=1').status_code,401)
        self.login()
        self.assertEqual(self.client.get('/api/threat-hunting/results?company_id=1').json()['total'],0)
        self.assertEqual(self.client.get('/api/threat-hunting/results?company_id=2').status_code,403)
        self.assertEqual(self.client.get('/api/threat-hunting/results/missing/rows?company_id=1&source=x').status_code,404)
        self.assertEqual(self.client.get('/api/threat-hunting/results/missing/rows?company_id=2&source=x').status_code,403)

    def test_analysis_authorization_lock_and_response(self):
        from unittest.mock import patch
        url = '/api/threat-hunting/results/missing/analysis?company_id='
        self.assertEqual(self.client.post(url + '1').status_code, 401)
        self.login()
        self.assertEqual(self.client.post(url + '2').status_code, 403)
        self.assertEqual(self.client.post(url + '1').status_code, 404)
        result = {'ruleset': 'test', 'matched_rules': 0, 'findings': []}
        with patch('app.modules.hunting_results.analyze_result', return_value=result):
            response = self.client.post(url + '1')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['cache-control'], 'no-store')
            self.assertEqual(response.json(), result)
        with patch('app.modules.hunting_results.analyze_result', side_effect=ValueError('corrupt')):
            self.assertEqual(self.client.post(url + '1').status_code, 422)
        with patch('app.modules.hunting_results.analyze_result', return_value=result):
            self.assertEqual(self.client.post(url + '1').status_code, 200)

    def test_delete_result_authorization_missing_and_success(self):
        from app.modules.hunting_results import save_result, get_result
        base = Path(self.tmp.name) / 'data' / 'threat-hunting'
        item = save_result(base, 1, b'encrypted', {'sources': []})
        foreign = save_result(base, 2, b'foreign', {'sources': []})
        url = '/api/threat-hunting/results/' + item['id']
        self.assertEqual(self.client.delete(url + '?company_id=1').status_code, 401)
        self.login()
        self.user.id = 1
        self.assertEqual(self.client.delete(url + '?company_id=2').status_code, 403)
        self.assertEqual(self.client.delete('/api/threat-hunting/results/' + foreign['id'] + '?company_id=1').status_code, 404)
        self.assertEqual(self.client.delete(url).status_code, 422)
        self.user.role = 'viewer'
        self.assertEqual(self.client.delete(url + '?company_id=1').status_code, 403)
        self.user.role = 'company_admin'
        response = self.client.delete(url + '?company_id=1')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'deleted': True, 'id': item['id']})
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(self.client.delete(url + '?company_id=1').status_code, 404)
        self.assertIsNotNone(get_result(base, 2, foreign['id']))

    def test_delete_result_active_job_conflict_and_superadmin(self):
        from app.modules.hunting_results import save_result, get_result
        from app.modules.hunting_pipeline import create_job
        base = Path(self.tmp.name) / 'data' / 'threat-hunting'
        item = save_result(base, 1, b'encrypted', {'sources': []})
        create_job(base, 1, None, None, item['id'])
        self.login()
        self.user.role = 'superadmin'
        self.user.id = 1
        url = '/api/threat-hunting/results/' + item['id'] + '?company_id=1'
        self.assertEqual(self.client.delete(url).status_code, 409)
        self.assertIsNotNone(get_result(base, 1, item['id']))

    def test_validation_and_missing_profile(self):
        self.login()
        for delta in [{'platform': 'linux', 'artifacts': ['services']}, {'artifacts': ['host', 'host']}, {'timeout_seconds': 0}, {'name': ' '}]:
            self.assertEqual(self.client.post('/api/threat-hunting/profiles', json={**self.payload, **delta}).status_code, 422)
        self.assertEqual(self.client.get('/api/threat-hunting/profiles/missing/spec?company_id=1').status_code, 404)


    def test_delete_profile_authorization_and_success(self):
        self.login()
        row = self.client.post("/api/threat-hunting/profiles", json=self.payload).json()
        url = "/api/threat-hunting/profiles/" + row["id"]
        self.assertEqual(self.client.delete(url + "?company_id=2").status_code, 403)
        self.assertEqual(self.client.delete(url + "?company_id=1").status_code, 200)
        self.assertEqual(self.client.delete(url + "?company_id=1").status_code, 404)


if __name__ == '__main__':
    unittest.main()
