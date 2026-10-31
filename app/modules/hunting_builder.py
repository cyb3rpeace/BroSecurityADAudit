"""Fail-closed configuration compiler for Velociraptor offline baseline collectors.

Only reviewed built-in queries are emitted. JSON is valid YAML for config repack.
This module does not read environment variables, server config, or private keys.
"""
from __future__ import annotations
import hashlib
import json
import re
from datetime import datetime, timezone

from app.modules.hunting_profiles import validate_profile, collection_contract

BASE_SUPPORTED = frozenset({'host', 'processes', 'network'})
# Exact parameter/projection contract inspected in installed Velociraptor 0.77.3.
# These queries remain fail-closed in compile_config until Windows execution is
# verified. Metadata only: never project Message, EventData or script contents.
EVENT_METADATA_SPECS = {
    'security_events': ('SecurityEvents', 'Security', 'Security',
                        (4624,4625,4672,4688,4697,4698,4699,4700,4701,4702,4720,4722,4724,4728,4732,4738,4740,4768,4769,4771,4776,5140,5145), 50000),
    'powershell_events': ('PowerShellEvents', 'Microsoft-Windows-PowerShell%4Operational',
                          'Microsoft-Windows-PowerShell/Operational', (4103,4104), 25000),
    'defender_events': ('DefenderEvents', 'Microsoft-Windows-Windows Defender%4Operational',
                        'Microsoft-Windows-Windows Defender/Operational', (1000,1001,1002,1116,1117,1118,1119,5001,5007), 20000),
    'rdp_events': ('RDPEvents', 'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational',
                   'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', (21,22,23,24,25), 20000),
}


def event_metadata_query(artifact: str, event_days: int) -> str:
    """Experimental, not admitted to compile_config; UTC window at endpoint start.

    LIMIT bounds output, not bytes parsed or scan work. No ordering guarantee:
    the first matching rows in parser order are returned, not the newest N.
    """
    if artifact not in EVENT_METADATA_SPECS:
        raise ValueError('Unknown fixed event metadata source')
    if type(event_days) is not int or not 1 <= event_days <= 30:
        raise ValueError('Event window must be an integer from 1 to 30 days')
    _, filename, channel, ids, limit = EVENT_METADATA_SPECS[artifact]
    id_regex = '^(' + '|'.join(str(i) for i in ids) + ')$'
    channel_regex = '^' + re.escape(channel) + '$'
    return f'''LET CaptureEpoch <= now()
LET WindowEnd <= timestamp(epoch=CaptureEpoch)
LET WindowStart <= timestamp(epoch=CaptureEpoch - {event_days * 86400})
SELECT TimeCreated AS Timestamp, EventID, Channel, EventRecordID,
       System.Computer AS Computer, System.Provider.Name AS Provider,
       System.Level AS Level, WindowStart AS WindowStartUTC,
       WindowEnd AS WindowEndUTC
FROM Artifact.Windows.EventLogs.Evtx(
  EvtxGlob="%SystemRoot%/System32/winevt/Logs/{filename}.evtx",
  VSSAnalysisAge=0, StartDate=WindowStart, EndDate=WindowEnd,
  ChannelRegex={json.dumps(channel_regex)}, IDRegex="{id_regex}")
WHERE TimeCreated >= WindowStart AND TimeCreated <= WindowEnd
LIMIT {limit}'''


# Historical public mapping retained, but all event entries now use the safe
# metadata projection. The compiler deliberately does not include this mapping.
EVENT_QUERIES = {key: (spec[0], event_metadata_query(key, 7))
                 for key, spec in EVENT_METADATA_SPECS.items()}
PERSISTENCE_QUERIES = {
    'services': ('Services', '''SELECT Name, DisplayName, State, StartMode, Pid, PathName, UserAccount, ServiceDll
FROM Artifact.Windows.System.Services(Calculate_hashes=FALSE, CertificateInfo=FALSE)
LIMIT 10000'''),
    'tasks': ('Tasks', '''SELECT TaskName, Command, Arguments, UserId, RunLevel, LogonType, ComHandler, OSPath
FROM Artifact.Windows.System.TaskScheduler(AlsoUpload=FALSE, UploadCommands=FALSE)
LIMIT 10000'''),
    'startup': ('Startup', '''SELECT Name, OSPath, Details, Enabled
FROM Artifact.Windows.Sys.StartupItems(AlsoUpload=FALSE)
LIMIT 10000'''),
}
# Candidate artifact names and parameter schemas must be verified against the
# installed Velociraptor version before they are admitted to compilation.
QUERIES = {
    'host': ('Host', 'SELECT Hostname, Fqdn, OS, Platform, Architecture FROM info()'),
    'processes': ('Processes', 'SELECT Pid, Ppid, Name, Exe, Username, CommandLine, CreateTime FROM pslist() LIMIT 10000'),
    'network': ('Network', 'SELECT * FROM netstat() LIMIT 20000'),
}
LINUX_SOURCES = {'linux_services': 'LinuxServices', 'linux_crontab': 'LinuxCrontab', 'linux_suid': 'LinuxSUID'}
# Fixed local paths only: no command execution, recursive filesystem walk or uploads.
def _linux_safe_glob(paths):
    """Reject intermediate wildcard components and linked literal directories.

    /lib and /bin aliases are deliberately skipped when linked; their /usr
    counterparts are separately enumerated. This is a snapshot check, not an
    atomic no-follow open against concurrent filesystem replacement.
    """
    queries = []
    for path in paths:
        parts = path.split('/')
        if not path.startswith('/') or any(c in part for part in parts[1:-1] for c in '*?[]{}'):
            raise ValueError('Linux collection requires literal parent directories')
        parents = ['/' + '/'.join(parts[1:i]) for i in range(2, len(parts))]
        checks = [f'(stat(filename={json.dumps(parent)}, accessor="file").IsDir AND NOT stat(filename={json.dumps(parent)}, accessor="file").IsLink)' for parent in parents]
        guard = ' AND '.join(checks) or 'TRUE'
        queries.append('q%d={SELECT * FROM foreach(row={SELECT * FROM scope() WHERE %s}, query={SELECT * FROM glob(globs=%s, accessor="file")})}' % (len(queries), guard, json.dumps(path)))
    return 'chain(' + ',\n'.join(queries) + ')'


def linux_config_query(paths):
    # Read only regular files, at most 64 KiB each, with truncation evidence.
    return '''SELECT OSPath, Size, Mtime, format(format="%s", args=Mode) AS Mode,
       read_file(filename=OSPath, accessor="file", length=65536) AS Content,
       Size > 65536 AS ContentTruncated
FROM __GLOB__
WHERE NOT IsDir AND NOT IsLink AND format(format="%s", args=Mode) =~ "^-" AND Size >= 0
LIMIT 1000'''.replace('__GLOB__', _linux_safe_glob(paths))


def linux_suid_query(paths):
    # glob() has no Sys on the installed engine; stat(file) exposes numeric IDs.
    return '''SELECT OSPath, Size, Mtime, format(format="%s", args=Mode) AS Mode,
       stat(filename=OSPath, accessor="file").Sys.Uid AS OwnerID,
       stat(filename=OSPath, accessor="file").Sys.Gid AS GroupID
FROM __GLOB__
WHERE NOT IsDir AND NOT IsLink AND format(format="%s", args=Mode) =~ "^[ug]"
LIMIT 10000'''.replace('__GLOB__', _linux_safe_glob(paths))


LINUX_QUERIES = {
    'linux_services': ('LinuxServices', linux_config_query([
        '/etc/systemd/system/*.service', '/etc/systemd/system/*.timer',
        # Wildcard drop-in directories are intentionally not collected: glob's
        # final-entry IsLink cannot exclude symlinked intermediate directories.
        '/usr/lib/systemd/system/*.service', '/usr/lib/systemd/system/*.timer',
        '/lib/systemd/system/*.service', '/lib/systemd/system/*.timer'])),
    'linux_crontab': ('LinuxCrontab', linux_config_query([
        '/etc/crontab', '/etc/cron.d/*', '/var/spool/cron/*',
        '/var/spool/cron/crontabs/*', '/etc/cron.hourly/*',
        '/etc/cron.daily/*', '/etc/cron.weekly/*', '/etc/cron.monthly/*'])),
    'linux_suid': ('LinuxSUID', linux_suid_query([
        '/usr/bin/*', '/usr/sbin/*', '/bin/*', '/sbin/*'])),
}

def outcome_query(source_id, query, cap):
    """Terminal output measurement, not plugin success/error inference.

    Materialize only the already capped projection, once. A killed/timed-out
    query has no terminal row and therefore remains unknown. VQL plugins can
    log errors while returning zero rows: never label that verified success.
    """
    return '''LET BroSecRows <= %s
SELECT * FROM chain(
  evidence={SELECT * FROM BroSecRows},
  telemetry={SELECT dict(version=1, source="%s", status="unknown",
    outcome=if(condition=len(list=BroSecRows) >= %d, then="cap_reached",
      else=if(condition=len(list=BroSecRows) = 0, then="empty", else="present")),
    rows=len(list=BroSecRows), measurement="bounded_output_only") AS _BroSecCollectionStatus
    FROM scope()})''' % (query, source_id, cap)


SUPPORTED = BASE_SUPPORTED | frozenset(PERSISTENCE_QUERIES) | frozenset(LINUX_QUERIES)

def certificate_info(pem: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    if not re.fullmatch(r'\s*-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*', pem):
        raise ValueError('Требуется ровно один публичный X509-сертификат без приватного ключа')
    cert = x509.load_pem_x509_certificate(pem.encode('ascii'))
    key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
        raise ValueError('Для шифрования требуется RSA не менее 3072 бит')
    now = datetime.now(timezone.utc)
    # cryptography < 42 exposes naive not_valid_* properties; normalize both
    # APIs to aware UTC before enforcing certificate validity.
    not_before = getattr(cert, 'not_valid_before_utc', None)
    not_after = getattr(cert, 'not_valid_after_utc', None)
    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if not_before > now or now >= not_after:
        raise ValueError('Сертификат ещё не действует или истёк')
    usage = None
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        pass
    if usage is not None and not usage.key_encipherment:
        raise ValueError('Сертификат не разрешает шифрование ключа')
    return cert.public_bytes(serialization.Encoding.PEM).decode('ascii'), cert.fingerprint(hashes.SHA256()).hex()


def validate_compiled_config(config: dict, profile: dict) -> None:
    """Fail closed when generated artifact names/parameters drift from ingestion contracts."""
    autoexec = config.get('autoexec')
    if not isinstance(autoexec, dict):
        raise ValueError('Конфигурация не содержит autoexec')
    definitions = autoexec.get('artifact_definitions')
    if not isinstance(definitions, list) or len(definitions) != 2:
        raise ValueError('Ожидаются ровно два artifact definition: baseline и Collector')
    baseline = next((item for item in definitions if item.get('name') == 'BroSec.Offline.Baseline'), None)
    collector = next((item for item in definitions if item.get('name') == 'Collector'), None)
    if not baseline or not collector:
        raise ValueError('Отсутствует baseline или Collector artifact')
    expected_sources = {'host': 'Host', 'processes': 'Processes', 'network': 'Network',
                        'services': 'Services', 'tasks': 'Tasks', 'startup': 'Startup', **LINUX_SOURCES}
    sources = baseline.get('sources')
    if not isinstance(sources, list) or {item.get('name') for item in sources} != {expected_sources[item] for item in profile['artifacts'] if item in expected_sources}:
        raise ValueError('Список baseline sources не соответствует профилю')
    builtin = {'services': 'Windows.System.Services', 'tasks': 'Windows.System.TaskScheduler', 'startup': 'Windows.Sys.StartupItems'}
    collector_text = json.dumps(collector, ensure_ascii=False)
    for artifact in profile['artifacts']:
        if artifact in builtin and builtin[artifact] not in collector_text:
            raise ValueError(f'В Collector отсутствует встроенный artifact: {builtin[artifact]}')
    if 'password=Password' not in collector_text or 'metadata=Metadata' not in collector_text:
        raise ValueError('Collector не содержит обязательный encrypted metadata contract')


def compile_config(profile: dict, public_certificate: str):
    campaign_id = profile.get('campaign_id', 'manual')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,120}', campaign_id):
        raise ValueError('Некорректный идентификатор кампании')
    validate_profile(profile['platform'], profile['artifacts'], profile['timeout_seconds'], profile['event_days'])
    supported = (BASE_SUPPORTED | PERSISTENCE_QUERIES.keys()) if profile['platform'] == 'windows' else (BASE_SUPPORTED | LINUX_QUERIES.keys())
    unsupported = sorted(set(profile['artifacts']) - supported)
    if unsupported:
        raise ValueError('Упаковка этих сборов ещё не проверена: ' + ', '.join(unsupported))
    if not re.fullmatch('[a-f0-9]{32}', profile['id']):
        raise ValueError('Некорректный идентификатор профиля')
    pem, fingerprint = certificate_info(public_certificate)
    artifact_name = 'BroSec.Offline.Baseline'
    platform = profile['platform']
    definitions = QUERIES | PERSISTENCE_QUERIES | LINUX_QUERIES
    artifact = {
        'name': artifact_name, 'type': 'CLIENT',
        'description': 'Read-only bounded baseline. Row limits may truncate evidence. Linux skips symlinked parent directories and systemd drop-ins; checks are not atomic against concurrent path replacement.',
        'precondition': "SELECT OS FROM info() WHERE OS = '" + platform + "'",
        'sources': [{'name': definitions[a][0], 'query': outcome_query(
            a, definitions[a][1], collection_contract(profile)['configured_source_row_limits'][a])
            if platform == 'linux' else definitions[a][1]}
            for a in profile['artifacts'] if a in definitions],
    }
    builtin_artifacts = {
        'services': 'Windows.System.Services',
        'tasks': 'Windows.System.TaskScheduler',
        'startup': 'Windows.Sys.StartupItems',
    }
    collected_artifacts = json.dumps([artifact_name] + [
        builtin_artifacts[a] for a in profile['artifacts'] if a in builtin_artifacts
    ], ensure_ascii=False)
    contract = collection_contract(profile)
    collector_query = '''LET Host <= SELECT Hostname FROM info()
LET Parameters <= dict(
  `Windows.System.Services`=dict(Calculate_hashes=FALSE, CertificateInfo=FALSE),
  `Windows.System.TaskScheduler`=dict(AlsoUpload=FALSE, UploadCommands=FALSE),
  `Windows.Sys.StartupItems`=dict(AlsoUpload=FALSE))
LET RandomPassword <= SELECT format(format="%02x", args=rand(range=255)) AS A FROM range(end=50)
LET Password <= join(array=RandomPassword.A)
LET CampaignId <= "__CAMPAIGN_ID__"
LET CaptureStartedUTC <= timestamp(epoch=now())
LET CollectionContract <= parse_json(data=__CONTRACT__)
LET CollectionStatus <= parse_json(data=__STATUS__)
LET Metadata <= dict(CollectionStatus=CollectionStatus, CaptureStartedUTC=CaptureStartedUTC, CollectionContract=CollectionContract, EncryptedPass=pk_encrypt(data=Password, public_key=PublicCertificate, scheme="X509"), Scheme="X509", PublicKey=PublicCertificate, CampaignId=CampaignId, CollectorSchema="brosec.result.v1")
LET Destination <= format(format="BroSec-%s-%d.zip", args=[Host[0].Hostname, now()])
    SELECT * FROM collect(artifacts=__ARTIFACTS__, args=Parameters, output=Destination,
 password=Password, metadata=Metadata, timeout=Timeout, progress_timeout=120,
 cpu_limit=20, concurrency=1, level=5, format="jsonl")'''.replace('__ARTIFACTS__', collected_artifacts).replace('__CAMPAIGN_ID__', campaign_id).replace('__CONTRACT__', json.dumps(json.dumps(contract, ensure_ascii=False))).replace('__STATUS__', json.dumps(json.dumps({'version': 1, 'sources': {a: {'status': 'unknown'} for a in profile['artifacts']}})))
    # Random-password and X509 metadata format follow Velociraptor's offline Collector.
    # No plaintext password is emitted as a result row or embedded in the config.
    collector = {
        'name': 'Collector',
        'required_permissions': ['SERVER_ADMIN', 'FILESYSTEM_WRITE'],
        'parameters': [
            {'name': 'PublicCertificate', 'default': pem},
            {'name': 'Timeout', 'type': 'int', 'default': str(profile['timeout_seconds'])},
        ],
        'sources': [{'query': collector_query}],
    }
    argv = ['artifacts', 'collect', 'Collector', '--nobanner']
    if platform == 'windows':
        argv.append('--require_admin')
    config = {'autoexec': {'argv': argv, 'artifact_definitions': [artifact, collector]}}
    validate_compiled_config(config, profile)
    encoded = json.dumps(config, ensure_ascii=False, indent=2).encode('utf-8')
    if b'PRIVATE KEY' in encoded or b'hard_memory_limit' in encoded:
        raise ValueError('Запрещённые данные в конфигурации')
    manifest = {
        'schema': 'brosec.collector-config.v1', 'profile_id': profile['id'],
        'campaign_id': campaign_id, 'transport': 'offline_result_upload',
        'platform': platform, 'artifacts': list(profile['artifacts']),
        'certificate_sha256': fingerprint, 'config_sha256': hashlib.sha256(encoded).hexdigest(),
        'encryption': 'X509', 'config_only': True,
        'collection_contract': contract,
        'limitations': ['Моментальный снимок, не история активности',
                        'Лимиты строк: процессы 10000, соединения 20000',
                        'Синтаксис и выполнение требуют проверки целевой версией Velociraptor'],
    }
    if platform == 'linux':
        manifest['limitations'].extend([
            'Systemd drop-ins are not collected; wildcard parent directories are forbidden',
            'Symlinked parent directories are skipped, including /lib, /bin and /sbin aliases; explicit /usr paths are queried separately',
            'Path checks are snapshots, not atomic no-follow opens against concurrent filesystem replacement',
        ])
    return encoded, manifest
