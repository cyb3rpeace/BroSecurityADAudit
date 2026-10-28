"""Deterministic baseline review, not malware attribution or an incident verdict."""
import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import unquote

VERSION = 'forensic-triage-4'
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
        self.counts = {'Host': 0, 'Processes': 0, 'Network': 0, 'Services': 0, 'Tasks': 0, 'Startup': 0}
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
        if kind == 'Startup':
            command = cls._text(row, 'Details')
            return [command] if command else []
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
        match = re.fullmatch(r'results/BroSec\.Offline\.Baseline/(Host|Processes|Network|Services|Tasks|Startup)\.json', decoded)
        if match:
            return match[1]
        builtin_paths = {
            'results/Windows.System.Services.json': 'Services',
            'results/Windows.System.Services/Analysis.json': 'Services',
            'results/Windows.System.TaskScheduler.json': 'Tasks',
            'results/Windows.System.TaskScheduler/Analysis.json': 'Tasks',
            'results/Windows.Sys.StartupItems.json': 'Startup',
            'results/Windows.Sys.StartupItems/Analysis.json': 'Startup',
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
            self.evidence_rows[(source, index)] = {k: self._evidence_value(row[k]) for k in ('Pid', 'PID', 'pid', 'Ppid', 'PPid', 'ParentPid', 'ParentPID', 'Exe', 'Username', 'Status', 'RemoteIP', 'RemoteAddr', 'RemoteAddress', 'RemoteEndpoint', 'RemotePort', 'RemotePortNumber', 'LocalIP', 'LocalPort', 'Name', 'TaskName', 'PathName', 'AbsoluteExePath', 'ServiceDll', 'Command', 'CommandLine', 'Cmdline', 'Arguments', 'Actions', 'Details') if k in row}
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
        if kind == 'Processes':
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
        elif kind == 'Startup':
            self.persistence.append((kind, row, source, index))
            details = row.get('Details')
            if isinstance(details, str) and re.search(r'(?i)(?:temp|downloads|appdata|users\\[^\\/]+\\desktop)', details):
                self.add('persistence.startup_transient_path', 'Элемент автозапуска указывает на пользовательский или временный каталог',
                         'Путь автозапуска требует проверки владельца и подписи. Это эвристика, а не подтверждение вредоносности.', source, index)
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
                            'persistence.service_suspicious_invocation', 'persistence.task_suspicious_invocation'}
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
        unsupported = set(self.unsupported)
        for item in source_summaries:
            kind = self.source_kind(item['source'])
            if kind:
                expected.add(kind)
            else:
                unsupported.add(item['source'])
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
                'source_coverage': [{'source': x['source'], 'rows': x.get('rows', 0), 'supported': self.source_kind(x['source']) is not None} for x in source_summaries],
                'ambiguous_process_ids': len(self.ambiguous_pids),
                'graph': {'nodes': list(self.graph_nodes.values()), 'edges': self.graph_edges, 'truncated': len(self.graph_nodes) >= 1000 or len(self.graph_edges) >= 2000},
                'iocs': list(self.iocs.values())[:500],
                'missing_sources': sorted({'Host', 'Processes', 'Network'} - expected),
                'empty_sources': [k for k in sorted(expected & self.counts.keys()) if self.counts[k] == 0],
                'unsupported_sources': sorted(unsupported),
                'limitations': ['Отсутствие срабатываний не подтверждает отсутствие угроз',
                                'Проверяются источники Host, Processes, Network, Services, Tasks и Startup из точечного сбора; отсутствие persistence-источника не трактуется как отсутствие угроз',
                                'Нет проверки подписей, хешей по репутации, ACL, истории событий и полноты сбора',
                                'Классификация «наблюдение» не является уязвимостью или подтверждённой атакой',
                                'Источник и строки получены из загруженного архива, авторство не подтверждено']}
