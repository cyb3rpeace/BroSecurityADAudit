import ast
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from app.modules.hunting_ai_reports import register_ai_report_routes
from app.modules.hunting_results import save_result


class AIReportEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.user = None
        company = SimpleNamespace(id=1)
        self.db = SimpleNamespace(get=lambda model, key: company if key == 1 else None, commit=lambda: None)
        source = Path(__file__).resolve().parents[1]/"app/main.py"
        nodes = [n for n in ast.parse(source.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == "resolve_company"]
        scope = {"User": object, "Session": object, "Company": object, "HTTPException": HTTPException}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), scope)
        def get_user():
            if self.user is None:
                raise HTTPException(401, "login")
            return self.user
        self.audit = []
        app = FastAPI()
        register_ai_report_routes(app, get_user=get_user, get_db=lambda: self.db, resolve_company=scope["resolve_company"], hunting_store=lambda: self.base, write_audit=lambda *args: self.audit.append(args))
        self.client = TestClient(app)
        self.item = save_result(self.base, 1, b"encrypted", {"hostnames": ["host"], "sources": []})
        self.foreign = save_result(self.base, 2, b"foreign", {"sources": []})
        self.url = "/api/threat-hunting/results/" + self.item["id"] + "/ai-report?company_id=1&format="
        self.analysis = {"ruleset": "test", "findings": [], "triage_summary": {}}

    def login(self):
        self.user = SimpleNamespace(id=1, role="company_admin", company_id=1)

    def test_auth_and_tenant(self):
        self.assertEqual(self.client.post(self.url+"md", json={"answer":"ok"}).status_code, 401)
        self.login()
        self.assertEqual(self.client.post(self.url.replace("company_id=1", "company_id=2")+"md", json={"answer":"ok"}).status_code, 403)
        self.assertEqual(self.client.post(self.url.replace(self.item["id"], self.foreign["id"])+"md", json={"answer":"ok"}).status_code, 404)
        self.assertEqual(self.client.post(self.url.replace(self.item["id"], "missing")+"md", json={"answer":"ok"}).status_code, 404)

    def test_correlation_auth_tenant_and_validation(self):
        url = "/api/threat-hunting/correlations?company_id=1"
        payload = {"result_ids": [self.item["id"]]}
        self.assertEqual(self.client.post(url, json=payload).status_code, 401)
        self.login()
        self.assertEqual(self.client.post(url.replace("=1", "=2"), json=payload).status_code, 403)
        self.assertEqual(self.client.post(url, json={"result_ids": [self.foreign["id"]]}).status_code, 404)
        for ids in [[], [self.item["id"]]*21, [self.item["id"]]*2, ["../bad"], [123]]:
            self.assertEqual(self.client.post(url, json={"result_ids": ids}).status_code, 422)

    def test_correlation_budget_integrity_and_no_store(self):
        from app.modules.hunting_correlation import CorrelationLimitError
        self.login()
        url = "/api/threat-hunting/correlations?company_id=1"
        payload = {"result_ids": [self.item["id"]]}
        for error, code in [(CorrelationLimitError("budget"),413), (ValueError("SECRET"),422), (KeyError("SECRET"),404)]:
            with patch("app.modules.hunting_correlation.correlate_results", side_effect=error):
                response = self.client.post(url, json=payload)
                self.assertEqual(response.status_code, code)
                self.assertNotIn("SECRET", response.text)
        with patch("app.modules.hunting_correlation.correlate_results", return_value={"graph":{"nodes":[],"edges":[]}, "truncated":False}) as call:
            response = self.client.post(url, json=payload)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertEqual(call.call_args.args[2], 1)
            self.assertEqual(call.call_args.args[3], payload["result_ids"])

    def test_formats_and_no_report_persistence(self):
        self.login()
        before = {str(p) for p in self.base.rglob("*")}
        with patch("app.modules.hunting_results.analyze_result", return_value=self.analysis):
            for fmt, media in [("md", "text/markdown"), ("pdf", "application/pdf")]:
                response = self.client.post(self.url+fmt, json={"answer":"\u041f\u0440\u0438\u0432\u0435\u0442 <img src='https://example.com/'>"})
                self.assertEqual(response.status_code, 200, response.text[:100])
                self.assertTrue(response.headers["content-type"].startswith(media))
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertIn("attachment", response.headers["content-disposition"])
        self.assertEqual(before, {str(p) for p in self.base.rglob("*")})
        self.assertEqual(len(self.audit), 2)

    def test_invalid_answers_formats_and_missing_query(self):
        self.login()
        for payload in [{}, {"answer":""}, {"answer":"  "}, {"answer":"x"*100001}, {"answer":123}, {"answer":None}]:
            self.assertEqual(self.client.post(self.url+"md", json=payload).status_code, 422)
        for fmt in ["html", "xlsx", "PDF", ""]:
            self.assertEqual(self.client.post(self.url+fmt, json={"answer":"ok"}).status_code, 422)
        self.assertEqual(self.client.post(self.url.split("?")[0], json={"answer":"ok"}).status_code, 422)

    def test_actual_tamper_check_not_tenant_scan(self):
        self.login()
        archive = self.base/"archives/1"/(self.item["id"]+".zip")
        archive.write_bytes(b"tampered")
        response = self.client.post(self.url+"md", json={"answer":"ok"})
        self.assertEqual(response.status_code, 409)
        self.assertFalse(self.audit)

    def test_actual_analysis_and_summary_aliases_are_not_host_identity(self):
        self.login()
        def parse(data, keys, company_id, row_callback):
            row_callback("host.jsonl", 0, {"hostname":"host"})
            return {"sources":[{"source":"host.jsonl", "rows":1}]}
        with patch("app.modules.hunting_results.summarize_container", side_effect=parse):
            response = self.client.post(self.url+"md", json={"answer":"ok"})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn("host.jsonl", response.text)
        with patch("app.modules.hunting_results.get_result", return_value={**self.item, "summary":{"hostnames":["host", "host.docker.internal"]}}), patch("app.modules.hunting_results.analyze_result", return_value=self.analysis):
            self.assertEqual(self.client.post(self.url+"md", json={"answer":"ok"}).status_code, 200)

    def test_maximum_answer_and_no_external_network(self):
        self.login()
        answer = "x"*99997 + "END"
        with patch("app.modules.hunting_results.analyze_result", return_value=self.analysis), patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
            response = self.client.post(self.url+"md", json={"answer":answer})
            self.assertEqual(response.status_code, 200)
            self.assertIn(answer, response.text)

    def test_main_registers_export_with_existing_dependencies(self):
        source = Path(__file__).resolve().parents[1]/"app/main.py"
        tree = ast.parse(source.read_text())
        calls = [node for node in tree.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "register_ai_report_routes"]
        self.assertEqual(len(calls), 1)
        self.assertEqual({k.arg for k in calls[0].value.keywords}, {"get_user", "get_db", "resolve_company", "hunting_store", "write_audit"})

    def test_real_encrypted_archive_md_pdf(self):
        from test_hunting_ingest import IngestTests
        from app.modules.hunting_packager import tenant_certificate
        from app.modules.hunting_ingest import summarize_container
        fixture = IngestTests()
        fixture.cert = tenant_certificate(self.base/"keys", 1)
        data = fixture.container("results/Host.json", b'{"Hostname":"host"}\n')
        summary = summarize_container(data, self.base/"keys", 1)
        item = save_result(self.base, 1, data, summary)
        self.login()
        url = self.url.replace(self.item["id"], item["id"])
        for fmt in ["md", "pdf"]:
            response = self.client.post(url+fmt, json={"answer":"Verified archive, unreviewed answer"})
            self.assertEqual(response.status_code, 200, response.text[:100])
        fixture.cert = tenant_certificate(self.base/"keys", 2)
        foreign_key_data = fixture.container("results/Host.json", b'{"Hostname":"other"}\n')
        wrong = save_result(self.base, 1, foreign_key_data, summary)
        url = url.replace(item["id"], wrong["id"])
        self.assertEqual(self.client.post(url+"md", json={"answer":"ok"}).status_code, 409)
