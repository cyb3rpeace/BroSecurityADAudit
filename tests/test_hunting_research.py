import json
import unittest
from unittest.mock import Mock, patch

import requests
from app.modules.hunting_research import research_question, research_ioc, sanitized_question, safe_url, MAX_BYTES, SEARCH_ENDPOINT
from app.modules.hunting_ai import ask_hunting, audit_answer_citations


class PublicResearchTests(unittest.TestCase):
    def response(self, html, status=200):
        response = Mock(status_code=status)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.iter_content.return_value = [html.encode()]
        return response

    @patch('app.modules.hunting_research.requests.get')
    def test_no_network_without_opt_in_or_supported_concept(self, get):
        self.assertEqual(research_question('PowerShell')['status'], 'not_requested')
        self.assertEqual(research_question('internal-host password=secret', opt_in=True)['status'], 'not_supported')
        get.assert_not_called()

    @patch('app.modules.hunting_research.requests.get')
    def test_concept_only_disclosure_and_fixed_endpoint(self, get):
        get.return_value = self.response('<a href="https://attack.mitre.org/techniques/T1059/" class="result__a">PowerShell</a>')
        question = 'Explain PowerShell on SECRET-HOST.internal for Alice token=abcdef 10.0.0.1 https://private/x'
        result = research_question(question, opt_in=True)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['sanitized_question'], 'PowerShell security detection')
        args, kwargs = get.call_args
        self.assertEqual(args, (SEARCH_ENDPOINT,))
        self.assertFalse(kwargs['allow_redirects'])
        self.assertTrue(kwargs['stream'])
        outbound = json.dumps(kwargs)
        for secret in ('SECRET-HOST', 'Alice', 'abcdef', '10.0.0.1', 'private'):
            self.assertNotIn(secret, outbound)

    def test_safe_urls(self):
        for url in ('http://attack.mitre.org/x', 'https://attack.mitre.org.evil.test/x', 'https://127.0.0.1/x', 'https://user:pass@attack.mitre.org/x', 'https://attack.mitre.org:444/x', 'javascript:alert(1)'):
            self.assertIsNone(safe_url(url))
        self.assertEqual(safe_url('//duckduckgo.com/l/?uddg=https%3A%2F%2Fattack.mitre.org%2Fx'), 'https://attack.mitre.org/x')

    @patch('app.modules.hunting_research.requests.get')
    def test_results_bounded_deduplicated_allowlisted(self, get):
        html = '<a class="result__a" href="https://evil.test/">Bad</a>'
        html += ''.join(f'<a class="result__a" href="https://learn.microsoft.com/{i}">Article {i}</a>' for i in range(12))
        get.return_value = self.response(html + html)
        result = research_question('persistence', opt_in=True)
        self.assertEqual(len(result['results']), 5)
        self.assertTrue(all(r['host'] == 'learn.microsoft.com' for r in result['results']))
        self.assertEqual(get.call_count, 1)

    @patch('app.modules.hunting_research.requests.get')
    def test_fail_closed(self, get):
        for status in (302, 429, 500):
            get.return_value = self.response('', status)
            self.assertEqual(research_question('PowerShell', opt_in=True)['status'], 'unavailable')
        get.return_value = self.response('x' * (MAX_BYTES + 1))
        self.assertEqual(research_question('PowerShell', opt_in=True)['status'], 'response_too_large')
        get.return_value = self.response('captcha')
        self.assertEqual(research_question('PowerShell', opt_in=True)['status'], 'no_results')
        get.side_effect = requests.Timeout()
        self.assertEqual(research_question('PowerShell', opt_in=True)['status'], 'unavailable')

    @patch('app.modules.hunting_research.requests.get')
    def test_private_invalid_ioc_never_sent(self, get):
        for ioc in ('10.0.0.1', '127.0.0.1', '192.168.1.1', '169.254.169.254', '999.999.999.999', 'host.internal'):
            self.assertEqual(research_ioc(ioc)['status'], 'not_supported')
        get.assert_not_called()

    @patch('app.modules.hunting_ai.requests.post')
    def test_prompt_receives_research_and_exact_citations(self, post):
        source = 'results/Windows.System.Services.json'
        answer = f'Observed [evidence:{source}#298] https://attack.mitre.org/techniques/T1059/'
        post.return_value.json.return_value = {'choices': [{'message': {'content': answer}}]}
        analysis = {'findings': [{'source': source, 'row_number': 298}]}
        research = {'status': 'completed', 'results': [{'url': 'https://attack.mitre.org/techniques/T1059/'}]}
        self.assertEqual(ask_hunting({'api_url': 'https://model.test/v1'}, 'Explain persistence', analysis, research), answer)
        messages = post.call_args.kwargs['json']['messages']
        self.assertIn(json.dumps(research), messages[1]['content'])
        self.assertIn('цитируй точные предоставленные URL', messages[0]['content'])
        self.assertEqual(audit_answer_citations(answer, analysis)['status'], 'references_present')
        self.assertEqual(audit_answer_citations('[evidence:Windows.System.Services.json#298]', analysis)['status'], 'invalid_references')


class ResearchEndpointTests(unittest.TestCase):
    def setUp(self):
        import ast
        from pathlib import Path
        from types import SimpleNamespace
        from typing import Any
        from fastapi import FastAPI, Depends, HTTPException
        from fastapi.testclient import TestClient
        from pydantic import BaseModel, Field
        self.user = SimpleNamespace(role='company_admin', company_id=1)
        def get_user():
            if self.user is None:
                raise HTTPException(401)
            return self.user
        def resolve_company(user, db, company_id):
            if company_id != user.company_id:
                raise HTTPException(403)
            return SimpleNamespace(id=1)
        app = FastAPI()
        scope = dict(app=app, Depends=Depends, HTTPException=HTTPException, BaseModel=BaseModel, Field=Field,
                     Any=Any, User=object, Session=object, get_user=get_user, get_db=lambda: None,
                     resolve_company=resolve_company, assistant_runtime=lambda row: {'enabled': True},
                     assistant_row=lambda db: None, hunting_store=lambda: Path('/tmp/research-test'))
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'app/main.py').read_text())
        nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in {'ChatTurn', 'ChatIn', 'hunting_ai_investigate'}]
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<routes>', 'exec'), scope)
        self.client = TestClient(app)
        self.payload = {'company_id': 1, 'hunting_result_id': 'result', 'message': 'Explain PowerShell', 'public_research': True}

    @patch('app.modules.hunting_results.analyze_result')
    @patch('app.modules.hunting_research.research_question')
    @patch('app.modules.hunting_ai.ask_hunting')
    def test_research_status_returned_and_passed_to_model(self, ask, research, analyze):
        analyze.return_value = {'ruleset': 'test', 'findings': [{'source': 'results/a.json', 'row_number': 1}]}
        ask.return_value = 'Fact [evidence:results/a.json#1]'
        research.return_value = {'status': 'completed', 'results': [{'url': 'https://attack.mitre.org/'}]}
        result = self.client.post('/api/threat-hunting/ai-investigate', json=self.payload)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()['research'], research.return_value)
        self.assertEqual(result.json()['citation_validation']['status'], 'references_present')
        research.assert_called_once_with('Explain PowerShell', opt_in=True)
        self.assertEqual(ask.call_args.kwargs['research'], research.return_value)

    @patch('app.modules.hunting_research.research_question')
    def test_auth_and_tenant_checks_precede_research(self, research):
        self.assertEqual(self.client.post('/api/threat-hunting/ai-investigate', json={**self.payload, 'company_id': 2}).status_code, 403)
        self.user = None
        self.assertEqual(self.client.post('/api/threat-hunting/ai-investigate', json=self.payload).status_code, 401)
        research.assert_not_called()


if __name__ == '__main__':
    unittest.main()
