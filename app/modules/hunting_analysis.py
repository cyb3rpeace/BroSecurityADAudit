"""Deterministic baseline review, not malware attribution or an incident verdict."""
import ipaddress
import json
import re
import shlex
from datetime import datetime, timezone
from urllib.parse import unquote

VERSION = 'forensic-triage-7-windows-candidates'
MAX_FINDINGS = 200

TRIAGE = {
    # Rule matches are triage signals, not confirmed compromise. Reserve high priority
    # for corroborated evidence added by analyst review or downstream validation.
    'review': {'level': 'medium', 'confidence': 0.72, 'score': 55},
    'observation': {'level': 'low', 'confidence': 0.45, 'score': 25},
}


class BaselineReview:
    def __init__(self):
        self.findings = []
        # Compact metadata for every rule match; detailed evidence remains bounded.
        self.finding_inventory = []
        self.matches = 0
        self.counts = {'Host': 0, 'Processes': 0, 'Network': 0, 'Services': 0, 'Tasks': 0, 'Startup': 0, 'LinuxServices': 0, 'LinuxCrontab': 0, 'LinuxSUID': 0, 'WMIPersistence': 0, 'RegistryRunKeys': 0, 'SecurityEvents': 0, 'PowerShellEvents': 0, 'DefenderEvents': 0, 'RDPEvents': 0}
        self.windows_event_counts = {}
        self.sources = set()
        self.unsupported = set()
        self.processes = {}
        self.process_refs = {}
        self.ambiguous_pids = set()
        self.evidence_rows = {}
        self.persistence = []
        self.network = []
        self.correlated = False
        self.process_network = []
        self.graph_nodes = {}
        self.graph_edges = []
        self.iocs = {}
        self.timeline = []
        self.timeline_rows_seen = 0
        self.host_rows = []
        self.linux_commands = {}
        self.linux_gaps = set()

    @staticmethod
    def _number(row: dict, *keys, maximum=2**32 - 1):
        for key in keys:
            value = row.get(key)
            if type(value) is int and 0 <= value <= maximum:
                return value
            if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value.lstrip('0')) <= 10:
                number = int(value.lstrip('0') or '0')
                if 0 <= number <= maximum:
                    return number
        return None

    @staticmethod
    def _text(row: dict, *keys):
        for key in keys:
            value = row.get(key)
            if isinstance(value, str) and value.strip() and value.strip().lower() not in {"null", "<nil>"}:
                return value.strip()
        return None

    @staticmethod
    def _executable(command):
        """Extract an executable without guessing unquoted paths containing spaces."""
        if not isinstance(command, str) or not command.strip():
            return None
        text = command.strip()
        if text.startswith('"'):
            end = text.find('"', 1)
            return text[1:end] if end > 1 else None
        if ' ' in text:
            first = text.split()[0]
            if not first.lower().endswith(('.exe', '.com')):
                return None
            return first
        return text

    @classmethod
    def _persistence_commands(cls, kind, row):
        """Normalize profile fields and built-in task Exec actions, never arbitrary JSON."""
        if kind == 'Services':
            command = cls._text(row, 'PathName', 'AbsoluteExePath', 'ServiceDll')
            return [command] if command else []
        if kind in {'Startup', 'RegistryRunKeys'}:
            command = cls._text(row, 'Details')
            return [command] if command else []
        if kind in {'LinuxServices', 'LinuxCrontab'}:
            # Do not path-correlate Linux shells or untrusted extra JSON fields.
            return []
        commands = []
        def collect(action, depth=0):
            if depth > 4 or len(commands) >= 100:
                return
            if isinstance(action, list):
                for item in action[:100]:
                    collect(item, depth + 1)
            elif isinstance(action, dict):
                command = cls._text(action, 'Command', 'Execute')
                if command:
                    # A separate Command field is an executable, even with path spaces.
                    if not command.startswith('"') and ' ' in command and command.lower().endswith(('.exe', '.com')):
                        command = '"' + command + '"'
                    arguments = cls._text(action, 'Arguments')
                    commands.append(command + (' ' + arguments if arguments else ''))
                for key in ('Actions', 'Exec'):
                    if key in action:
                        collect(action[key], depth + 1)
            elif isinstance(action, str) and len(action) <= 65536:
                try:
                    decoded = json.loads(action)
                except (ValueError, RecursionError):
                    return
                if isinstance(decoded, (dict, list)):
                    collect(decoded, depth + 1)
        collect(row)
        return list(dict.fromkeys(commands))

    @staticmethod
    def _invocation_signal(exe, command):
        """Review specific execution arguments, not an interpreter's mere presence."""
        basename = exe.replace('\\', '/').casefold().rsplit('/', 1)[-1]
        powershell = {'powershell.exe', 'pwsh.exe', 'powershell', 'pwsh'}
        if basename in {'cmd.exe', 'cmd'}:
            nested = re.search(r'(?i)(?:^|\s)/[ck]\s+"?((?:"[^"\r\n]+[\\/])?powershell(?:\.exe)?|(?:pwsh(?:\.exe)?))"?\s+(.+)', command)
            if nested:
                return BaselineReview._invocation_signal('powershell.exe', nested.group(2))
        if basename in powershell:
            if re.search(r'(?i)(?:^|\s)-(?:enc|encodedcommand)\s+[a-z0-9+/]{20,}={0,2}(?=\s|$)', command):
                return 'encoded_powershell'
            remote = re.search(r'(?i)https?://', command)
            download = re.search(r'(?i)\b(?:downloadstring|downloadfile|invoke-webrequest|iwr|invoke-restmethod|irm)\b', command)
            execute = re.search(r'(?i)\b(?:iex|invoke-expression)\b', command)
            if remote and download and execute:
                return 'remote_script_execution'
        if basename == 'mshta.exe' and re.search(r'(?i)(?:^|[\s"])(?:https?://|javascript:|vbscript:)', command):
            return 'remote_or_inline_script'
        if basename == 'regsvr32.exe' and re.search(r'(?i)/i:https?://', command) and re.search(r'(?i)\bscrobj\.dll\b', command):
            return 'remote_scriptlet'
        if basename == 'rundll32.exe' and re.search(r'(?i)javascript:', command):
            return 'inline_script'
        return None

    @staticmethod
    def _linux_invocation(command, shell=True, depth=0):
        """Recognize narrow invocation shapes; never evaluate, expand or decode input."""
        if depth > 3 or len(command) > 65536:
            return None
        try:
            lexer = shlex.shlex(command, posix=False, punctuation_chars='|;&()')
            lexer.whitespace_split = True
            lexer.commenters = '#'
            tokens = list(lexer)
            # Preserve quoted operators as data, but unwrap ordinary arguments.
            tokens = [shlex.split(token)[0] if token[:1] in {'"', "'"} and token[1:-1] not in {'|', ';', '&&', '||'} else token for token in tokens]
        except ValueError:
            return None
        if not tokens:
            return None
        basename = lambda value: value.rsplit('/', 1)[-1]
        shells = {'sh', 'bash', 'dash', 'zsh', 'ksh'}
        # Explicit shell command strings are parsed as shell syntax. systemd itself
        # does NOT interpret pipes, substitutions or shell metacharacters.
        exe = basename(tokens[0])
        if exe in shells and len(tokens) == 3 and tokens[1] in {'-c', '-lc'}:
            return BaselineReview._linux_invocation(tokens[2], True, depth + 1)
        if exe in {'python', 'python3', 'python2'} and len(tokens) == 3 and tokens[1] == '-c':
            if re.search(r'\bexec\s*\(\s*(?:base64\.)?b64decode\s*\(\s*["\'][A-Za-z0-9+/]{20,}={0,2}["\']', tokens[2]):
                return 'encoded_interpreter_execution'
        if exe == 'perl' and len(tokens) == 3 and tokens[1] == '-e':
            if re.search(r'\beval\s*\(?\s*decode_base64\s*\(\s*["\'][A-Za-z0-9+/]{20,}={0,2}["\']', tokens[2]):
                return 'encoded_interpreter_execution'
        if not shell:
            return None
        # Only direct pipeline stages are accepted. No substring searching of echo,
        # descriptions, arbitrary quoted strings, variables or command substitutions.
        for i, token in enumerate(tokens):
            if token != '|' or i == 0 or i + 1 >= len(tokens):
                continue
            left_start = max([j + 1 for j in range(i) if tokens[j] in {'|', ';', '&&', '||'}] or [0])
            left = tokens[left_start:i]
            right_end = next((j for j in range(i + 1, len(tokens)) if tokens[j] in {'|', ';', '&&', '||'}), len(tokens))
            right = tokens[i + 1:right_end]
            if not left or not right or basename(right[0]) not in shells:
                continue
            # A shell script filename after sh is not stdin execution.
            if any(arg not in {'-s', '--', '-e', '-u', '-x', '-eu'} for arg in right[1:]):
                continue
            tool = basename(left[0])
            urls = [arg for arg in left[1:] if re.fullmatch(r'https?://[^\s]+', arg)]
            if tool == 'curl' and urls and not any(arg in {'-o', '--output', '-O', '--remote-name'} or arg.startswith(('--output=', '-o')) for arg in left[1:]):
                return 'download_to_shell'
            if tool == 'wget' and urls and ('-O-' in left or any(left[j:j+2] == ['-O', '-'] for j in range(len(left)-1))):
                return 'download_to_shell'
            if tool == 'base64' and any(arg in {'-d', '--decode'} for arg in left[1:]):
                return 'decoded_payload_to_shell'
        return None

    def _linux_persistence(self, kind, row, source, index):
        content, path = row.get('Content'), self._text(row, 'OSPath') or ''
        if not isinstance(content, str):
            self.linux_gaps.add('Linux config Content missing or not text')
            return
        truncated = row.get('ContentTruncated') is True or len(content) > 65536
        content = content[:65536]
        lines = content.splitlines()
        if truncated:
            self.linux_gaps.add('Truncated Linux content: final partial line omitted; unseen content not assessed')
            lines = lines[:-1]
        section = ''
        commands = []
        for number, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith(('#', ';')):
                continue
            if line.endswith('\\'):
                self.linux_gaps.add('Linux multiline continuations unsupported')
                # Fail closed for this file rather than treating continuation lines
                # as independent directives or cron commands.
                break
            if kind == 'LinuxServices':
                if line.startswith('[') and line.endswith(']'):
                    section = line[1:-1]
                    continue
                if '=' not in line:
                    continue
                key, value = line.split('=', 1)
                key, value = key.strip(), value.strip()
                if section != 'Service' or key not in {'ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecReload', 'ExecStop', 'ExecStopPost', 'ExecCondition'}:
                    self.linux_gaps.add('Only literal systemd Service Exec directives are analyzed; other directives unsupported')
                    continue
                if not value:
                    commands = [item for item in commands if item[3] != key]
                    continue
                if value[0] in '-+!:@' or '%' in value or '$' in value:
                    self.linux_gaps.add('Systemd prefixes, specifiers and variable expansion unsupported')
                    continue
                commands.append((number, raw, value, key))
            else:
                system = path == '/etc/crontab' or path.startswith('/etc/cron.d/')
                user = path.startswith('/var/spool/cron/')
                if not (system or user):
                    self.linux_gaps.add('Periodic cron scripts are collected as data, not analyzed as shell programs')
                    break
                if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', line):
                    continue
                parts = line.split(None, (6 if system else 5))
                if line.startswith('@'):
                    parts = line.split(None, (2 if system else 1))
                    valid = parts[0] in {'@reboot', '@yearly', '@annually', '@monthly', '@weekly', '@daily', '@midnight', '@hourly'}
                    needed = 3 if system else 2
                else:
                    valid = len(parts) >= 5 and all(re.fullmatch(r'[0-9*/,:A-Za-z-]+', part) for part in parts[:5])
                    needed = 7 if system else 6
                if valid and len(parts) == needed:
                    command = re.split(r'(?<!\\)%', parts[-1], maxsplit=1)[0]
                    commands.append((number, raw, command, 'cron'))
        self.linux_commands[(source, index)] = [item[2] for item in commands]
        self.persistence.append((kind, row, source, index))
        for number, raw, command, directive in commands:
            signal = self._linux_invocation(command, kind == 'LinuxCrontab')
            if not signal:
                continue
            rule = 'persistence.linux_' + ('systemd' if kind == 'LinuxServices' else 'cron') + '_suspicious_invocation'
            self.add(rule, 'Linux persistence invocation requires review',
                     f'Literal configuration matches {signal}; configuration is not proof of execution or compromise.', source, index,
                     checks=['Review the full original configuration row and owning package/user',
                             'Validate payload offline without executing it',
                             'Corroborate with execution history and approved administration'])
            if self.findings and (self.findings[-1]['source'], self.findings[-1]['row_offset'], self.findings[-1]['rule_id']) == (source, index, rule):
                self.findings[-1]['config_evidence'] = {'field': 'Content', 'line_number': number,
                    'line': raw[:4096], 'line_excerpt_truncated': len(raw) > 4096,
                    'command': command[:4096], 'signal': signal, 'directive': directive,
                    'content_truncated': truncated}

    @classmethod
    def _evidence_value(cls, value, depth=0):
        if isinstance(value, str):
            return value[:2000]
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        if depth < 4 and isinstance(value, list):
            return [cls._evidence_value(item, depth + 1) for item in value[:32]]
        if depth < 4 and isinstance(value, dict):
            return {key: cls._evidence_value(item, depth + 1) for key, item in list(value.items())[:32]}
        return '[complex value]'

    def _timestamp(self, row):
        for key in ('Timestamp', 'Time', 'EventTime', 'CreateTime', 'LastWriteTime'):
            value = row.get(key)
            if isinstance(value, str) and value.strip():
                text = value.strip().replace('Z', '+00:00')
                try:
                    parsed = datetime.fromisoformat(text)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    return parsed.astimezone(timezone.utc).isoformat()
                except ValueError:
                    continue
        return None

    @staticmethod
    def source_kind(source):
        decoded = unquote(source)
        match = re.fullmatch(r'results/BroSec\.Offline\.Baseline/(Host|Processes|Network|Services|Tasks|Startup|LinuxServices|LinuxCrontab|LinuxSUID)\.json', decoded)
        if match:
            return match[1]
        builtin_paths = {
            'results/Windows.System.Services.json': 'Services',
            'results/Windows.System.Services/Analysis.json': 'Services',
            'results/Windows.System.TaskScheduler.json': 'Tasks',
            'results/Windows.System.TaskScheduler/Analysis.json': 'Tasks',
            'results/Windows.Sys.StartupItems.json': 'Startup',
            'results/Windows.Sys.StartupItems/Analysis.json': 'Startup',
            'results/BroSec.Acceptance.WindowsCandidates/WMIPersistence.json': 'WMIPersistence',
            'results/BroSec.Acceptance.WindowsCandidates/RegistryRunKeys.json': 'RegistryRunKeys',
            'results/BroSec.Acceptance.WindowsCandidates/SecurityEvents.json': 'SecurityEvents',
            'results/BroSec.Acceptance.WindowsCandidates/PowerShellEvents.json': 'PowerShellEvents',
            'results/BroSec.Acceptance.WindowsCandidates/DefenderEvents.json': 'DefenderEvents',
            'results/BroSec.Acceptance.WindowsCandidates/RDPEvents.json': 'RDPEvents',
        }
        return builtin_paths.get(decoded)

    def _node(self, node_id: str, kind: str, label: str, source: str | None = None, row: int | None = None) -> None:
        if len(self.graph_nodes) >= 1000 and node_id not in self.graph_nodes:
            return
        self.graph_nodes.setdefault(node_id, {"id": node_id, "kind": kind, "label": label[:180], "evidence_refs": []})
        if source is not None:
            self.graph_nodes[node_id]["label"] = label[:180]
        if source is not None and row is not None and len(self.graph_nodes[node_id]["evidence_refs"]) < 12:
            self.graph_nodes[node_id]["evidence_refs"].append({"source": source, "row_number": row + 1})

    def _edge(self, source: str, target: str, relation: str, confidence: str = "context") -> None:
        if len(self.graph_edges) >= 2000 or source == target:
            return
        item = {"source": source, "target": target, "relation": relation, "confidence": confidence}
        if item not in self.graph_edges:
            self.graph_edges.append(item)

    def _collect_iocs(self, source: str, index: int, row: dict) -> None:
        for key, value in row.items():
            if not isinstance(value, str) or len(value) > 2048:
                continue
            for candidate in re.findall(r"(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])", value):
                try:
                    address = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if not address.is_private and not address.is_loopback and not address.is_reserved:
                    self.iocs.setdefault(candidate, {"type": "ipv4", "value": candidate, "evidence_refs": []})["evidence_refs"].append({"source": source, "row_number": index + 1, "field": key})
            for digest in re.findall(r"(?i)\b[a-f0-9]{64}\b", value):
                self.iocs.setdefault(digest.lower(), {"type": "sha256", "value": digest.lower(), "evidence_refs": []})["evidence_refs"].append({"source": source, "row_number": index + 1, "field": key})

    def add(self, rule, title, reason, source, index, severity='review', checks=None):
        self.matches += 1
        triage = TRIAGE.get(severity, TRIAGE['review'])
        self.finding_inventory.append({'rule_id': rule, 'title': title, 'classification': severity,
                                      'triage_level': triage['level'], 'confidence': triage['confidence'],
                                      'risk_score': triage['score'], 'source': source,
                                      'row_number': index + 1, 'inventory_index': self.matches - 1})
        if len(self.findings) < MAX_FINDINGS:
            self.findings.append({'rule_id': rule, 'title': title, 'reason': reason,
                                  'source': source, 'row_offset': index, 'row_number': index + 1,
                                  'classification': severity, 'triage_level': triage['level'],
                                  'confidence': triage['confidence'], 'risk_score': triage['score'],
                                  'status': 'needs_review', 'recommended_checks': checks or [
                                      'Сохранить исходную строку и проверить временную шкалу',
                                      'Проверить владельца, подпись и хеш связанного файла',
                                      'Сопоставить с изменениями, журналами и активностью пользователя',
                                  ]})

    def consume(self, source, index, row):
        self.sources.add(source)
        self._collect_iocs(source, index, row)
        if len(self.evidence_rows) < 5000:
            self.evidence_rows[(source, index)] = {k: self._evidence_value(row[k]) for k in ('Pid', 'PID', 'pid', 'Ppid', 'PPid', 'ParentPid', 'ParentPID', 'Exe', 'Username', 'Status', 'RemoteIP', 'RemoteAddr', 'RemoteAddress', 'RemoteEndpoint', 'RemotePort', 'RemotePortNumber', 'LocalIP', 'LocalPort', 'Name', 'TaskName', 'PathName', 'AbsoluteExePath', 'ServiceDll', 'Command', 'CommandLine', 'Cmdline', 'Arguments', 'Actions', 'Details', 'OSPath', 'Content', 'ContentTruncated', 'Size', 'Mode', 'OwnerID', 'GroupID', 'Namespace', 'ConsumerName', 'ConsumerType', 'FilterName', 'FilterType', 'Timestamp', 'EventID', 'Channel', 'EventRecordID', 'Provider', 'Level', 'WindowStartUTC', 'WindowEndUTC') if k in row}
        timestamp = self._timestamp(row)
        if timestamp:
            self.timeline_rows_seen += 1
        if timestamp and len(self.timeline) < 5000:
            self.timeline.append({'timestamp': timestamp, 'source': source, 'row_number': index + 1, 'category': self.source_kind(source) or 'Other'})
        # Do not infer telemetry type merely from arbitrary JSON field names.
        kind = self.source_kind(source)
        if kind is None:
            self.unsupported.add(source)
            return
        self.counts[kind] += 1
        before_matches = len(self.findings)
        if kind == 'Host':
            hostname = self._text(row, 'Hostname', 'Fqdn', 'Host') or 'collection scope'
            self.host_rows.append((source, index, hostname))
            self._node('host:scope', 'host', hostname, source, index)
        elif kind == 'Processes':
            pid = self._number(row, 'Pid', 'PID', 'pid')
            if type(pid) is int and pid > 0:
                parent = self._number(row, 'Ppid', 'PPid', 'ParentPid', 'ParentPID')
                if type(parent) is int and parent > 0 and parent != pid:
                    self._node(f"process:{parent}", "process", str(parent))
                    self._edge(f"process:{parent}", f"process:{pid}", "parent_child", "snapshot_pid")
                process_node = f"process:{pid}"
                self._node(process_node, "process", str(row.get('Exe') or row.get('Name') or pid), source, index)
                if pid in self.processes:
                    self.ambiguous_pids.add(pid)
                else:
                    self.processes[pid] = row
                    self.process_refs[pid] = (source, index)
            exe = row.get('Exe')
            if not isinstance(exe, str):
                return
            lower = exe.lower().replace('\\', '/')
            if re.match(r'^[a-z]:/(?:users/[^/]+/(?:appdata/(?:local/temp|roaming)|downloads)|windows/temp|temp)/', lower) or lower.startswith(('/tmp/', '/var/tmp/', '/dev/shm/')):
                self.add('process.transient_path', 'Процесс запущен из временного или пользовательского каталога',
                         'Путь может использоваться для временных инструментов, установщиков или закрепления. Проверьте назначение, владельца, подпись и хеш файла. Права записи не проверены.', source, index)
            if lower.startswith(('/home/', '/root/')) and lower.endswith(' (deleted)'):
                self.add('process.deleted_user_binary', 'Удалённый исполняемый файл процесса в домашнем каталоге',
                         'Суффикс (deleted) требует проверки: это может быть обновление или удаление работающего файла. Сам по себе не доказывает сокрытие.', source, index)
            command = self._text(row, 'CommandLine', 'Cmdline', 'Command', 'Arguments', 'Details') or ''
            basename = lower.rsplit('/', 1)[-1]
            lolbins = {'powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe'}
            signal = self._invocation_signal(exe, command) if command else None
            if basename in lolbins and command:
                self.add('process.lolbin_execution', 'Командный интерпретатор или LOLBin требует проверки',
                         'Обнаружен системный интерпретатор/LOLBin с командной строкой. Это может быть штатная автоматизация; подтверждение требует родителя, пользователя, подписи и конкретных аргументов.', source, index, 'review' if signal else 'observation', [
                             'Проверить parent process и пользователя', 'Проверить подпись и полный путь бинарного файла', 'Сопоставить команду с журналами PowerShell/Security и задачами'
                         ])
            if signal == 'encoded_powershell':
                self.add('process.encoded_powershell', 'PowerShell запущен с закодированной командой',
                         'Командная строка содержит -EncodedCommand и похожий на Base64 payload. Это сильный повод для декодирования и проверки источника, но не доказательство атаки.', source, index, 'review', [
                             'Извлечь и декодировать payload в изолированной среде', 'Проверить родителя, пользователя и ScriptBlock logging', 'Сопоставить хеши и сетевые события по времени'
                         ])
            if signal and signal != 'encoded_powershell':
                self.add('process.suspicious_invocation', 'Аргументы интерпретатора требуют приоритетной проверки',
                         'Обнаружено сочетание загрузки и выполнения скрипта либо удалённый/inline script в аргументах LOLBin. Возможна согласованная автоматизация; это не доказательство компрометации.', source, index)
        elif kind in {'Services', 'Tasks'}:
            self.persistence.append((kind, row, source, index))
            commands = self._persistence_commands(kind, row)
            prefix = 'service' if kind == 'Services' else 'task'
            if any(re.search(r'(?i)(?:^|[\\/\s"])' + r'(?:temp|downloads|appdata|users[\\/][^\\/]+[\\/]desktop)(?:[\\/]|$)', command) for command in commands):
                self.add(f'persistence.{prefix}_transient_path', 'Конфигурация автозапуска указывает на пользовательский или временный каталог',
                         'Путь требует проверки владельца, подписи и необходимости запуска. Это эвристика, а не подтверждение вредоносности.', source, index)
            if any(self._invocation_signal(self._executable(command) or '', command) for command in commands):
                self.add(f'persistence.{prefix}_suspicious_invocation', 'Подозрительные аргументы в конфигурации автозапуска',
                         'Конфигурация содержит закодированную PowerShell-команду либо аргументы удалённого/inline выполнения скрипта. Проверьте payload, владельца и назначение. Конфигурация не доказывает факт запуска или компрометацию.', source, index)
        elif kind in {'LinuxServices', 'LinuxCrontab'}:
            self._linux_persistence(kind, row, source, index)
        elif kind == 'LinuxSUID':
            mode = self._text(row, 'Mode')
            owner = self._number(row, 'OwnerID')
            group = self._number(row, 'GroupID')
            path = self._text(row, 'OSPath')
            if path and mode and owner is not None and group is not None:
                self.add('inventory.linux_suid_sgid', 'Linux SUID/SGID file inventory requires contextual review',
                         'A file with special permission bits was inventoried. This is common for legitimate system utilities and does not establish abuse; validate package ownership, expected path, file integrity and change history.', source, index, 'observation', [
                             'Compare the path and package owner against the approved distribution baseline',
                             'Verify file metadata and hash on a forensic copy; do not execute the file',
                             'Correlate ownership and modification time with change records and execution telemetry'
                         ])
        elif kind == 'Startup':
            self.persistence.append((kind, row, source, index))
            details = row.get('Details')
            if isinstance(details, str) and re.search(r'(?i)(?:temp|downloads|appdata|users\\[^\\/]+\\desktop)', details):
                self.add('persistence.startup_transient_path', 'Элемент автозапуска указывает на пользовательский или временный каталог',
                         'Путь автозапуска требует проверки владельца и подписи. Это эвристика, а не подтверждение вредоносности.', source, index)
            commands = self._persistence_commands(kind, row)
            if any(self._invocation_signal(self._executable(command) or '', command) for command in commands):
                self.add('persistence.startup_suspicious_invocation', 'Подозрительная команда в автозапуске',
                         'Обнаружены аргументы кодированного или удалённого выполнения. Конфигурация не доказывает факт запуска.', source, index, 'review')
        elif kind == 'WMIPersistence':
            if self._text(row, 'ConsumerName') and self._text(row, 'FilterName'):
                self.add('windows.wmi_binding', 'Permanent WMI binding requires review',
                         'A filter/consumer binding was collected from the fixed WMI persistence query. Validate ownership, namespace and payload offline; collection is not proof of execution or compromise.', source, index, 'observation')
        elif kind == 'RegistryRunKeys':
            self.persistence.append((kind, row, source, index))
            command = self._text(row, 'Details')
            exe = self._executable(command or '')
            signal = self._invocation_signal(exe or '', command or '') if exe and command else None
            if signal:
                self.add('persistence.registry_run_suspicious_invocation', 'Run key contains suspicious execution arguments',
                         'The literal Run/RunOnce value matches a narrow encoded or remote-script invocation pattern. Validate the exact value, signer and intended software; persistence is not proof of execution.', source, index, 'review')
            elif command and re.search(r'(?i)(?:\\temp(?:\\|/)|/temp/|\\downloads(?:\\|/)|/downloads/|appdata[\\/])', command):
                self.add('persistence.registry_run_transient_path', 'Run key points to a user or temporary path',
                         'The literal startup value points to a user-controlled or temporary location and requires validation of owner, signer and purpose.', source, index, 'observation')
        elif kind in {'SecurityEvents', 'PowerShellEvents', 'DefenderEvents', 'RDPEvents'}:
            raw_event_id = row.get('EventID')
            event_id = raw_event_id if type(raw_event_id) is int and 0 <= raw_event_id <= 65535 else None
            channel = self._text(row, 'Channel')
            contracts = {
                'SecurityEvents': ('Security', {1102, 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4699, 4700, 4701, 4702, 4720, 4722, 4724, 4728, 4732, 4756, 5140, 5145}),
                'PowerShellEvents': ('Microsoft-Windows-PowerShell/Operational', {4103, 4104}),
                'DefenderEvents': ('Microsoft-Windows-Windows Defender/Operational', {1116, 1117, 5001, 5007}),
                'RDPEvents': ('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', {21, 22, 23, 24, 25}),
            }
            expected_channel, allowed_ids = contracts[kind]
            if channel != expected_channel or event_id not in allowed_ids:
                return
            key = (kind, event_id, channel)
            self.windows_event_counts[key] = self.windows_event_counts.get(key, 0) + 1
            event_rules = {
                ('SecurityEvents', 1102): ('windows.security.log_cleared', 'Security log-clear metadata requires review', 'review'),
                ('DefenderEvents', 1116): ('windows.defender.detection', 'Defender detection metadata requires validation', 'review'),
                ('DefenderEvents', 1117): ('windows.defender.action', 'Defender action metadata requires validation', 'observation'),
                ('DefenderEvents', 5001): ('windows.defender.protection_disabled', 'Defender protection-change metadata requires review', 'review'),
                ('DefenderEvents', 5007): ('windows.defender.configuration_change', 'Defender configuration-change metadata requires review', 'observation'),
                ('SecurityEvents', 4697): ('windows.security.service_install', 'Security 4697 service-install metadata requires review', 'review'),
                ('SecurityEvents', 4698): ('windows.security.scheduled_task_create', 'Security 4698 scheduled-task metadata requires review', 'review'),
                ('SecurityEvents', 4625): ('windows.security.failed_logon', 'Security 4625 failed-logon metadata requires review', 'observation'),
                ('PowerShellEvents', 4104): ('windows.powershell.scriptblock', 'PowerShell 4104 script-block metadata requires review', 'observation'),
                ('RDPEvents', 21): ('windows.rdp.session_logon', 'RDP session-logon metadata was observed', 'observation'),
                ('RDPEvents', 22): ('windows.rdp.session_shell_start', 'RDP shell-start metadata was observed', 'observation'),
            }
            rule = event_rules.get((kind, event_id))
            if rule:
                self.add(rule[0], rule[1], 'Normalized event ID/channel signal only; event payload, identity and causal context were not collected in this schema. This is not evidence of compromise.', source, index, rule[2])
        elif kind == 'Network':
            self.network.append((row, source, index))
            status = str(row.get('Status', '')).upper()
            local = self._text(row, 'LocalIP', 'LocalAddr', 'LocalAddress', 'LocalEndpoint')
            port = self._number(row, 'LocalPort', 'LocalPortNumber', maximum=65535)
            if status == 'LISTEN' and local in ('0.0.0.0', '::') and type(port) is int and port in {22, 3389, 445, 5985, 5986}:
                self.add('network.management_listener', 'Служба удалённого доступа слушает wildcard-интерфейс',
                         f'Локальный порт {port}: проверьте необходимость службы и ограничения firewall. LISTEN не означает доступность из другой сети.', source, index, 'observation')
            remote = self._text(row, 'RemoteIP', 'RemoteAddr', 'RemoteAddress', 'RemoteEndpoint')
            pid = self._number(row, 'Pid', 'PID', 'pid')
            if type(pid) is int and isinstance(remote, str):
                self._node(f"process:{pid}", "process", str(self.processes.get(pid, {}).get('Exe') or pid))
                self._node(f"ip:{remote}", "network", remote, source, index)
                self._edge(f"process:{pid}", f"ip:{remote}", "network_connection", "snapshot_pid")
            if status not in {'ESTAB', 'ESTABLISHED'} or not isinstance(remote, str):
                return
            try:
                address = ipaddress.ip_address(remote)
            except ValueError:
                return
            if address.is_global:
                self.add('network.public_peer', 'Установлено соединение с публичным IP-адресом',
                         'Публичный адрес не является индикатором C2 сам по себе. Проверьте назначение соединения и процесс; DNS, репутация и содержимое трафика не проверялись.', source, index, 'observation')

        if len(self.findings) > before_matches and (source, index) not in self.evidence_rows:
            self.evidence_rows[(source, index)] = {k: self._evidence_value(v) for k, v in row.items()
                if k in {'Name', 'OSPath', 'Details', 'Namespace', 'ConsumerName', 'ConsumerType',
                         'FilterName', 'FilterType', 'Timestamp', 'EventID', 'Channel', 'EventRecordID',
                         'Provider', 'Level', 'WindowStartUTC', 'WindowEndUTC'}}

    @staticmethod
    def _same_executable(left, right):
        if not isinstance(left, str) or not isinstance(right, str):
            return False
        def normalize(value):
            value = value.strip()
            if value.startswith('"'):
                end = value.find('"', 1)
                value = value[1:end] if end > 1 else value
            elif ' ' in value and not value.lower().endswith(('.exe', '.com')):
                return None
            return value.casefold().replace('\\', '/')
        a, b = normalize(left), normalize(right)
        return bool(a and b and a == b)

    def result(self, source_summaries):
        expected = set()
        correlation_count = 0
        process_pids = set(self.processes) - self.ambiguous_pids
        # Correlate the complete inventory, not the bounded detail preview.
        matches_by_row = {}
        for item in self.finding_inventory:
            matches_by_row.setdefault((item['source'], item['row_number']), set()).add(item['rule_id'])
        behavioral_rules = {'process.encoded_powershell', 'process.suspicious_invocation',
                            'persistence.service_suspicious_invocation', 'persistence.task_suspicious_invocation',
                            'persistence.startup_suspicious_invocation', 'persistence.registry_run_suspicious_invocation',
                            'persistence.linux_systemd_suspicious_invocation', 'persistence.linux_cron_suspicious_invocation'}
        behavioral_rows = {key for key, rules in matches_by_row.items() if rules & behavioral_rules}
        for row, source, index in self.network:
            pid = self._number(row, 'Pid', 'PID', 'pid')
            if type(pid) is not int or pid not in process_pids:
                continue
            process = self.processes[pid]
            if str(row.get('Status', '')).upper() not in ('ESTAB', 'ESTABLISHED'):
                continue
            try:
                public = ipaddress.ip_address(self._text(row, 'RemoteIP', 'RemoteAddr', 'RemoteAddress', 'RemoteEndpoint')).is_global
            except (ValueError, TypeError):
                continue
            ps, pi = self.process_refs[pid]
            # A PID edge is contextual evidence, not by itself a high-risk detection.
            suspicious = bool(matches_by_row.get((ps, pi + 1), set()) & {'process.transient_path', 'process.deleted_user_binary', 'process.encoded_powershell', 'process.suspicious_invocation'})
            self.process_network.append({'pid': pid, 'process_source': ps, 'process_row_number': pi + 1,
                'network_source': source, 'network_row_number': index + 1, 'exe': process.get('Exe'),
                'remote_ip': self._text(row, 'RemoteIP', 'RemoteAddr', 'RemoteAddress', 'RemoteEndpoint'), 'association': 'snapshot_pid', 'identity_verified': False})
            if not (public and suspicious):
                continue
            if 'process.transient_path' in matches_by_row.get((ps, pi + 1), set()):
                self.add('network.public_peer_with_process', 'Процесс установил соединение с публичным узлом',
                         'Совместно подтверждены нетипичный путь процесса и публичное соединение по PID снимка. Это не подтверждает C2, периодичность или одновременность сбора.', source, index)
                if self.findings and self.findings[-1]['rule_id'] == 'network.public_peer_with_process' and (self.findings[-1]['source'], self.findings[-1]['row_offset']) == (source, index):
                    self.findings[-1]['related_evidence'] = [{'source': ps, 'row_number': pi + 1, 'relation': 'snapshot_pid'}]
            correlation_count += 1
            self.add('correlation.process_network', 'Процесс с приоритетным наблюдением связан с публичным соединением',
                'В одном архиве совпал PID процесса и установленного соединения. Это связь снимка, не доказательство C2; PID reuse и одновременность сбора не исключены.', source, index)
            if self.findings and self.findings[-1]['rule_id'] == 'correlation.process_network' and (self.findings[-1]['source'], self.findings[-1]['row_offset']) == (source, index):
                self.findings[-1]['related_evidence'] = [{'source': ps, 'row_number': pi + 1, 'relation': 'snapshot_pid'}]
        # Parent-child anomalies are emitted only when both process rows are unambiguous.
        suspicious_children = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe'}
        suspicious_parents = {'svchost.exe', 'spoolsv.exe', 'winlogon.exe', 'services.exe'}
        for pid, process in self.processes.items():
            if pid in self.ambiguous_pids:
                continue
            parent_pid = self._number(process, 'Ppid', 'PPid', 'ParentPid', 'ParentPID')
            parent = self.processes.get(parent_pid)
            if not parent or parent_pid in self.ambiguous_pids:
                continue
            child_exe = str(process.get('Exe') or process.get('Name') or '').replace('\\', '/').casefold().rsplit('/', 1)[-1]
            parent_exe = str(parent.get('Exe') or parent.get('Name') or '').replace('\\', '/').casefold().rsplit('/', 1)[-1]
            if child_exe in suspicious_children and parent_exe in suspicious_parents:
                source, index = self.process_refs[pid]
                self.add('process.anomalous_parent_child', 'Нетипичная цепочка parent-child требует проверки',
                         f'{parent_exe} породил {child_exe}; это может быть штатная служба или признак злоупотребления, поэтому требуется проверка контекста и командной строки.', source, index, 'review', [
                             'Проверить командную строку и пользователя обоих процессов', 'Проверить службу/задачу, породившую родительский процесс', 'Сопоставить с Windows Event Log и временной шкалой'
                         ])
                if self.findings and self.findings[-1]['rule_id'] == 'process.anomalous_parent_child' and (self.findings[-1]['source'], self.findings[-1]['row_offset']) == (source, index):
                    self.findings[-1]['related_evidence'] = [{'source': self.process_refs[parent_pid][0], 'row_number': self.process_refs[parent_pid][1] + 1, 'relation': 'parent_child'}]
        persistence_count = 0
        def executable(command):
            value = self._executable(command)
            return value.casefold().replace('\\', '/') if value else None
        def process_path(process):
            value = self._text(process, 'Exe')
            return value.strip('"').casefold().replace('\\', '/') if value else None
        for kind, row, source, index in self.persistence:
            paths = {executable(command) for command in self._persistence_commands(kind, row)} - {None}
            matches = [(pid, process) for pid, process in self.processes.items()
                       if pid not in self.ambiguous_pids and process_path(process) in paths]
            if not matches:
                continue
            # Normal service/process co-occurrence is context, not suspicious by default.
            suspicious = any(rule.startswith('persistence.') for rule in matches_by_row.get((source, index + 1), set()))
            if not suspicious:
                continue
            persistence_count += 1
            self.add('correlation.process_persistence', 'Конфигурация автозапуска с наблюдением совпала с путём процесса',
                'Совпал нормализованный исполняемый путь, а не подстрока. Связь не подтверждает намерение, подпись или владельца файла.', source, index)
            if self.findings and self.findings[-1]['rule_id'] == 'correlation.process_persistence' and (self.findings[-1]['source'], self.findings[-1]['row_offset']) == (source, index):
                self.findings[-1]['related_evidence'] = [{'source': self.process_refs[pid][0], 'row_number': self.process_refs[pid][1]+1, 'relation': 'executable_path'} for pid, _ in matches[:10]]
        self.correlated = correlation_count > 0 or persistence_count > 0
        # Compact, source-grounded chains survive the detailed-finding cap.
        behavior_chains = []
        for link in self.process_network:
            key = (link['process_source'], link['process_row_number'])
            try:
                public = ipaddress.ip_address(link['remote_ip']).is_global
            except (ValueError, TypeError):
                public = False
            if key in behavioral_rows and public:
                behavior_chains.append({'kind': 'suspicious_execution_public_connection',
                    'assessment': 'hypothesis', 'identity_verified': False,
                    'evidence_refs': [{'source': key[0], 'row_number': key[1]},
                                      {'source': link['network_source'], 'row_number': link['network_row_number']}],
                    'limitations': ['Snapshot PID association; PID reuse and collection-time differences not excluded',
                                    'Public IP is not verified C2']})
        for item in self.finding_inventory:
            key = (item['source'], item['row_number'])
            item['signal_kind'] = 'suspicious_behavior' if key in behavioral_rows else 'context'
            if item['rule_id'] == 'process.anomalous_parent_child':
                item['signal_kind'] = 'suspicious_relationship'
        for finding in self.findings:
            finding['evidence'] = self.evidence_rows.get((finding['source'], finding['row_offset']), {})
            finding['evidence_refs'] = [{'source': finding['source'], 'row_number': finding['row_number'], 'relation': 'rule_match'}] + finding.get('related_evidence', [])
            finding['confidence_kind'] = 'heuristic_strength_not_compromise_probability'
            finding['benign_explanations'] = ['Установщик, обновление или согласованное администрирование', 'Легитимная служба или пользовательское приложение; требуется подтверждение владельца']
            finding['data_gaps'] = ['Подпись/репутация hash не проверены', 'История запуска и бизнес-назначение не подтверждены']
            finding['assessment'] = 'hypothesis' if finding['rule_id'].startswith('correlation.') else 'observation'
        for kind, row, source, index in self.persistence:
            label = str(row.get('Name') or row.get('TaskName') or row.get('DisplayName') or kind)
            persistence_id = f"{kind.lower()}:{source}:{index}"
            self._node(persistence_id, "persistence", label, source, index)
            paths = {executable(command) for command in self._persistence_commands(kind, row)} - {None}
            for pid, process in self.processes.items():
                if pid not in self.ambiguous_pids and process_path(process) in paths:
                    self._edge(persistence_id, f"process:{pid}", "executes", "path_match")
        valid_pids = set(self.processes) - self.ambiguous_pids
        def valid_edge(edge):
            if edge['relation'] not in ('parent_child', 'network_connection'):
                return True
            ids = [edge['source']] + ([edge['target']] if edge['relation'] == 'parent_child' else [])
            if any(int(value.split(':')[1]) not in valid_pids for value in ids):
                return False
            if edge['relation'] == 'parent_child':
                current = int(edge['source'].split(':')[1]); seen = {int(edge['target'].split(':')[1])}
                while current in valid_pids:
                    if current in seen:
                        return False
                    seen.add(current)
                    current = self._number(self.processes[current], 'Ppid', 'PPid', 'ParentPid', 'ParentPID')
                    if type(current) is not int:
                        break
            return edge['source'] in self.graph_nodes and edge['target'] in self.graph_nodes
        self.graph_edges = [edge for edge in self.graph_edges if valid_edge(edge)]

        context_graph = {'nodes': list(self.graph_nodes.values()), 'edges': list(self.graph_edges),
                         'truncated': len(self.graph_nodes) >= 1000 or len(self.graph_edges) >= 2000}

        # The analyst graph is a suspicious-behavior projection, not a process inventory.
        # Keep only strong behavior and the minimum evidence context around it. Public IP,
        # a routine process, or a normal service is never sufficient to enter this graph.
        process_by_ref = {(source, index + 1): pid for pid, (source, index) in self.process_refs.items()
                          if pid not in self.ambiguous_pids}
        graph_rules = {'process.encoded_powershell', 'process.suspicious_invocation',
                       'process.anomalous_parent_child', 'persistence.service_suspicious_invocation',
                       'persistence.task_suspicious_invocation', 'persistence.startup_suspicious_invocation', 'persistence.registry_run_suspicious_invocation', 'persistence.registry_run_suspicious_invocation',
                            'persistence.linux_systemd_suspicious_invocation', 'persistence.linux_cron_suspicious_invocation'}
        row_rules = {}
        for item in self.finding_inventory:
            if item['rule_id'] in graph_rules:
                row_rules.setdefault((item['source'], item['row_number']), set()).add(item['rule_id'])
        suspicious_process_pids = {process_by_ref[key] for key in row_rules if key in process_by_ref}
        suspicious_persistence = {key for key, rules in row_rules.items()
                                  if any(rule.startswith('persistence.') for rule in rules)}
        # Exact persistence-to-process path matches are retained only when the persistence
        # row itself is suspicious or it launches a process already in the focus graph.
        for kind, row, source, index in self.persistence:
            paths = {executable(command) for command in self._persistence_commands(kind, row)} - {None}
            row_key = (source, index + 1)
            for pid, process in self.processes.items():
                if pid in self.ambiguous_pids or process_path(process) not in paths:
                    continue
                if row_key in suspicious_persistence or pid in suspicious_process_pids:
                    suspicious_persistence.add(row_key)
                    suspicious_process_pids.add(pid)
        # Preserve parent context for each suspicious process, bounded by the snapshot PID graph.
        context_process_pids = set(suspicious_process_pids)
        for pid in list(suspicious_process_pids):
            current = pid
            for _ in range(8):
                parent = self._number(self.processes.get(current, {}), 'Ppid', 'PPid', 'ParentPid', 'ParentPID')
                if parent not in process_pids or parent in self.ambiguous_pids: break
                context_process_pids.add(parent); current = parent
        # Build focus graph afresh AFTER signal selection: routine rows cannot consume
        # the graph budget before a late suspicious process, host or endpoint arrives.
        self.graph_nodes, self.graph_edges = {}, []
        if suspicious_process_pids or suspicious_persistence:
            for source, index, hostname in self.host_rows[:12]:
                self._node('host:scope', 'host', hostname, source, index)
        for pid in sorted(context_process_pids, key=lambda value: (value not in suspicious_process_pids, value)):
            if pid not in process_pids:
                continue
            row = self.processes[pid]
            source, index = self.process_refs[pid]
            self._node(f'process:{pid}', 'process', str(row.get('Exe') or row.get('Name') or pid), source, index)
        for pid in sorted(context_process_pids):
            parent = self._number(self.processes.get(pid, {}), 'Ppid', 'PPid', 'ParentPid', 'ParentPID')
            edge = {'source': f'process:{parent}', 'target': f'process:{pid}',
                    'relation': 'parent_child', 'confidence': 'snapshot_pid'}
            if parent in context_process_pids and valid_edge(edge):
                self._edge(edge['source'], edge['target'], edge['relation'], edge['confidence'])
        for kind, row, source, index in self.persistence:
            if (source, index + 1) not in suspicious_persistence:
                continue
            node_id = f'{kind.lower()}:{source}:{index}'
            self._node(node_id, 'persistence', str(row.get('Name') or row.get('TaskName') or kind), source, index)
            paths = {executable(command) for command in self._persistence_commands(kind, row)} - {None}
            for pid in sorted(suspicious_process_pids):
                if process_path(self.processes.get(pid, {})) in paths and f'process:{pid}' in self.graph_nodes:
                    self._edge(node_id, f'process:{pid}', 'executes', 'path_match')
        for row, source, index in self.network:
            pid = self._number(row, 'Pid', 'PID', 'pid')
            if pid not in suspicious_process_pids or pid not in process_pids:
                continue
            if str(row.get('Status', '')).upper() not in ('ESTAB', 'ESTABLISHED'):
                continue
            remote = self._text(row, 'RemoteIP', 'RemoteAddr', 'RemoteAddress', 'RemoteEndpoint')
            try:
                address = ipaddress.ip_address(remote)
                if address.is_unspecified or address.is_multicast:
                    continue
            except (ValueError, TypeError):
                continue
            port = self._number(row, 'RemotePort', 'RemotePortNumber', maximum=65535)
            endpoint = f'[{address}]:{port}' if address.version == 6 and port is not None else f'{address}:{port}' if port is not None else str(address)
            node_id = 'endpoint:' + endpoint
            self._node(node_id, 'network', endpoint, source, index)
            if node_id in self.graph_nodes and f'process:{pid}' in self.graph_nodes:
                self._edge(f'process:{pid}', node_id, 'network_connection', 'snapshot_pid')
        for node_id, node in self.graph_nodes.items():
            rules = sorted({rule for ref in node.get('evidence_refs', [])
                            for rule in row_rules.get((ref['source'], ref['row_number']), set())})
            node['signal_rules'] = rules
            node['role'] = 'signal' if rules else 'context'
            node['reason'] = ('Поведенческий сигнал: ' + ', '.join(rules)) if rules else 'Контекст подозрительного действия; не самостоятельный индикатор атаки'
            if node['kind'] == 'process':
                pid = int(node_id.split(':')[1])
                node['command_line'] = (self._text(self.processes.get(pid, {}), 'CommandLine', 'Cmdline', 'Command', 'Arguments') or '')[:4096]
            elif node['kind'] == 'persistence':
                ref = node['evidence_refs'][0]
                for kind, row, source, index in self.persistence:
                    if (source, index + 1) == (ref['source'], ref['row_number']):
                        node['command_line'] = '\n'.join(self.linux_commands.get((source, index), self._persistence_commands(kind, row)))[:4096]
                        break
            elif node['kind'] == 'network':
                node['reason'] = 'Соединение процесса с поведенческим сигналом по PID снимка; C2 и одновременность не подтверждены'
        # Scope containment is not a causal relationship. Link roots only to avoid
        # obscuring the actual execution/network chain with a host-to-everything star.
        targets = {edge['target'] for edge in self.graph_edges}
        for node_id in sorted(self.graph_nodes):
            if 'host:scope' in self.graph_nodes and node_id != 'host:scope' and node_id not in targets:
                self._edge('host:scope', node_id, 'observed_on', 'collection_scope')
        unsupported = set(self.unsupported)
        for item in source_summaries:
            kind = self.source_kind(item['source'])
            if kind:
                expected.add(kind)
            else:
                unsupported.add(item['source'])
        coverage = []
        windows_caps = {'WMIPersistence': 5000, 'RegistryRunKeys': 10000,
                        'SecurityEvents': 10000, 'PowerShellEvents': 10000,
                        'DefenderEvents': 10000, 'RDPEvents': 10000}
        coverage_warnings = []
        for item in source_summaries:
            kind = self.source_kind(item['source'])
            rows = item.get('rows', 0)
            status = item.get('status', 'present' if rows else 'empty')
            if kind in windows_caps:
                status = 'cap_reached' if rows >= windows_caps[kind] else 'present' if rows else 'empty'
                if status == 'cap_reached':
                    coverage_warnings.append(kind + ' reached the fixed output row cap; unseen rows and collection completeness remain unknown')
                if kind == 'DefenderEvents' and not rows:
                    coverage_warnings.append('DefenderEvents is empty; this does not establish absence of detections or successful collection')
            coverage.append({'source': item['source'], 'rows': rows, 'supported': kind is not None,
                             'status': status, 'completeness': 'unknown'})
        level_counts = {}
        for finding in self.findings:
            level = finding['triage_level']
            level_counts[level] = level_counts.get(level, 0) + 1
        return {'ruleset': VERSION, 'verdict': 'not_determined', 'findings': self.findings, 'finding_inventory': self.finding_inventory,
                'matched_rules': self.matches, 'returned_findings': len(self.findings),
                'triage_summary': {'by_level': level_counts, 'manual_review_required': self.matches > 0,
                                   'max_risk_score': max((x['risk_score'] for x in self.findings), default=0),
                                   'correlations': {'process_network': correlation_count, 'process_persistence': persistence_count, 'active': self.correlated},
                                   'timeline': sorted(self.timeline, key=lambda x: x['timestamp'])[:500],
                                   'timeline_truncated': self.timeline_rows_seen > 500,
                                   'process_network_evidence': self.process_network[:200],
                                   'behavior_chains': behavior_chains[:200],
                                   'behavior_chains_total': len(behavior_chains),
                                   'behavior_chains_truncated': len(behavior_chains) > 200,
                                   'behavioral_rows_total': len(behavioral_rows)},

                'truncated': self.matches > MAX_FINDINGS, 'rows_reviewed': self.counts,
                'source_coverage': coverage,
                'source_statuses': {self.source_kind(x['source']) or x['source']: {k: x[k] for k in ('status', 'rows', 'completeness')} for x in coverage},
                'source_quality_warnings': coverage_warnings,
                'windows_event_counts': [{'source': k[0], 'event_id': k[1], 'channel': k[2], 'rows': v} for k, v in sorted(self.windows_event_counts.items(), key=lambda item: str(item[0]))],
                'ambiguous_process_ids': len(self.ambiguous_pids),
                'context_graph': context_graph,
                'graph': {'nodes': list(self.graph_nodes.values()), 'edges': self.graph_edges,
                          'scope': 'suspicious_behavior',
                          'excluded_context': 'Routine process, public endpoint, and normal persistence rows are omitted; open full evidence for context.',
                          'truncated': len(self.graph_nodes) >= 1000 or len(self.graph_edges) >= 2000},
                'iocs': list(self.iocs.values())[:500],
                'missing_sources': sorted({'Host', 'Processes', 'Network'} - expected),
                'empty_sources': [k for k in sorted(expected & self.counts.keys()) if self.counts[k] == 0],
                'unsupported_sources': sorted(unsupported),
                'limitations': sorted(self.linux_gaps) + coverage_warnings + [
                                'Windows event analysis is metadata-only for fixed event IDs/channels; payload, identity and execution context are not available',
                                'Windows source completeness is unknown; SecurityEvents may be cap-reached and DefenderEvents may be empty',
                                'Linux analysis is literal snapshot config triage, not execution history, enablement or maliciousness attribution',
                                'LinuxSUID is metadata-only inventory; a special permission bit alone does not prove abuse or compromise',
                                'Linux shell analysis is a narrow invocation subset; compound scripts, substitutions, aliases, includes and environment resolution are unsupported',
                                'Systemd effective configuration, drop-ins, timers, generators, dependencies and overridden vendor units are not resolved',
                                'LinuxServices and LinuxCrontab support is partial: literal commands only; unsupported syntax is not a clean bill of health',
                                'Отсутствие срабатываний не подтверждает отсутствие угроз',
                                'Проверяются источники Host, Processes, Network, Services, Tasks, Startup и ограниченное подмножество LinuxServices/LinuxCrontab и метаданные LinuxSUID из точечного сбора; отсутствие persistence-источника не трактуется как отсутствие угроз',
                                'Нет проверки подписей, хешей по репутации, ACL, истории событий и полноты сбора',
                                'Классификация «наблюдение» не является уязвимостью или подтверждённой атакой',
                                'Источник и строки получены из загруженного архива, авторство не подтверждено']}
