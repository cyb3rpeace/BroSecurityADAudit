"""Bounded, non-extracting reader for X509 Velociraptor containers.

Uploaded filenames and certificate metadata never select a tenant or key path.
No uploaded scripts or artifacts are executed.
"""
import base64
import hashlib
import io
import json
import stat
import zipfile
from pathlib import PurePosixPath, Path

MAX_UPLOAD = 128 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_FILES = 2000
MAX_ROWS = 100000
MAX_LINE = 1024 * 1024


def checked_members(archive):
    members = archive.infolist()
    if len(members) > MAX_FILES or sum(x.file_size for x in members) > MAX_EXPANDED:
        raise ValueError('Превышен лимит файлов или распакованного размера')
    seen = set()
    for member in members:
        name = member.filename
        path = PurePosixPath(name)
        if name in seen or '\\' in name or ':' in name or path.is_absolute() or '..' in path.parts or '\x00' in name:
            raise ValueError('Небезопасный или повторяющийся путь в архиве')
        if stat.S_ISLNK(member.external_attr >> 16):
            raise ValueError('Ссылки в архиве запрещены')
        seen.add(name)
    return {m.filename: m for m in members}


def collection_provenance(metadata, sources):
    """Assess observed archive sources and optional untrusted endpoint claims.

    Optional metadata CollectionStatus schema (claims only, never verified):
    {"version": 1, "sources": {"host": {"status": "success"}}}.
    Allowed source ids are host/processes/network/services/tasks/startup and
    statuses are failed/blocked/truncated/empty/success/skipped. Unknown,
    duplicate, malformed, and raw error fields are ignored.
    """
    from urllib.parse import unquote
    known = {'host': 'Host', 'processes': 'Processes', 'network': 'Network',
             'services': 'Services', 'tasks': 'Tasks', 'startup': 'Startup',
             'linux_services': 'LinuxServices', 'linux_crontab': 'LinuxCrontab',
             'linux_suid': 'LinuxSUID'}
    warnings = []
    contract = metadata.get('CollectionContract') if isinstance(metadata, dict) else None
    if not isinstance(contract, dict):
        contract = {}
    limits = contract.get('configured_source_row_limits')
    requested = []
    observed_by_id = {}
    seen_paths = set()
    for item in sources if isinstance(sources, list) else []:
        if not isinstance(item, dict):
            continue
        path = item.get('source')
        if not isinstance(path, str) or path in seen_paths:
            continue
        seen_paths.add(path)
        decoded = unquote(path)
        source_id = next((key for key, label in known.items()
                          if decoded.endswith('/' + label + '.json')), None)
        if source_id is None:
            continue
        rows = item.get('rows')
        if type(rows) is not int or rows < 0 or rows > MAX_ROWS:
            continue
        byte_count = item.get('bytes')
        if type(byte_count) is not int or byte_count < 0 or byte_count > MAX_EXPANDED:
            byte_count = None
        previous = observed_by_id.get(source_id, {'rows': 0, 'bytes': 0, 'bytes_known': True})
        previous['rows'] += rows
        if byte_count is None:
            previous['bytes_known'] = False
        else:
            previous['bytes'] += byte_count
        observed_by_id[source_id] = previous
    if isinstance(limits, dict):
        for key, label in known.items():
            cap = limits.get(key)
            if type(cap) is not int or not 1 <= cap <= MAX_ROWS:
                continue
            observation = observed_by_id.get(key, {'rows': 0, 'bytes': 0, 'bytes_known': True})
            rows = observation['rows']
            observed_status = 'missing' if key not in observed_by_id else ('empty' if rows == 0 else 'present')
            possibly_truncated = rows >= cap
            requested.append({'id': key, 'configured_row_limit': cap,
                              'observed_rows': rows,
                              'observed_bytes': observation['bytes'] if observation['bytes_known'] else None,
                              'observed_bytes_status': 'present' if observation['bytes_known'] else 'unknown',
                              'observed_status': observed_status,
                              'status': observed_status, 'limit_reached': possibly_truncated,
                              'completeness': 'possibly_truncated' if possibly_truncated else 'unknown'})
            if observed_status in {'missing', 'empty'}:
                warnings.append(f'{key} is {observed_status}; absence of rows does not establish a clean result')
            if possibly_truncated:
                warnings.append(f'{key} reached its configured collection cap; archive may be truncated')
    claims = {}
    status_manifest = metadata.get('CollectionStatus') if isinstance(metadata, dict) else None
    entries = status_manifest.get('sources') if isinstance(status_manifest, dict) and type(status_manifest.get('version')) is int and status_manifest.get('version') == 1 else None
    if isinstance(entries, dict):
        for source_id, claim in entries.items():
            if source_id not in known or not isinstance(claim, dict) or source_id in claims:
                continue
            status = claim.get('status')
            if isinstance(status, str) and status in {'failed', 'blocked', 'truncated', 'empty', 'success', 'skipped'}:
                claims[source_id] = status
    for item in requested:
        item['claimed_status'] = claims.get(item['id'])
    capture = metadata.get('CaptureStartedUTC') if isinstance(metadata, dict) else None
    if not isinstance(capture, str) or len(capture) > 80 or any(ord(c) < 32 for c in capture):
        capture = None
    window = contract.get('event_window')
    return {'status': 'endpoint_claims' if contract else 'legacy_or_missing',
            'claims_verified': False, 'claims_trusted': False,
            'capture_started_utc_claim': capture,
            'event_window_applied_claim': isinstance(window, dict) and window.get('applied') is True,
            'requested_sources': requested, 'completeness': 'possibly_truncated' if any(
                x['completeness'] == 'possibly_truncated' for x in requested) else 'unknown',
            'warnings': warnings}


def summarize_container(data: bytes | Path, key_root: Path, company_id: int, row_callback=None):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    import pyzipper
    if type(company_id) is not int or company_id <= 0:
        raise ValueError('Некорректная компания')
    if isinstance(data, (str, Path)):
        data = Path(data)
        if data.is_symlink() or not data.is_file():
            raise ValueError('Файл архива недоступен')
        if data.stat().st_size > MAX_UPLOAD:
            raise ValueError('Архив превышает 128 МиБ')
        source = data
    else:
        if len(data) > MAX_UPLOAD:
            raise ValueError('Архив превышает 128 МиБ')
        source = io.BytesIO(data)
    key_path = key_root / str(company_id) / 'offline-keypair.pem'
    if not key_path.is_file() or key_path.is_symlink():
        raise ValueError('Ключ компании не найден; сначала создайте сборщик')
    try:
        with pyzipper.AESZipFile(source) as outer:
            members = checked_members(outer)
            if 'metadata.json' not in members or 'data.zip' not in members:
                raise ValueError('Ожидается зашифрованный контейнер Velociraptor')
            if not members['data.zip'].flag_bits & 1:
                raise ValueError('data.zip должен быть зашифрован')
            if members['metadata.json'].file_size > 65536:
                raise ValueError('Слишком большой metadata.json')
            metadata = json.loads(outer.read('metadata.json'))
            if isinstance(metadata, list) and len(metadata) == 1:
                metadata = metadata[0]
            if not isinstance(metadata, dict):
                raise ValueError('Некорректные метаданные контейнера')
            if str(metadata.get('Scheme', '')).lower() != 'x509':
                raise ValueError('Поддерживается только X509-контейнер')
            campaign_id = metadata.get('CampaignId', 'manual')
            if not isinstance(campaign_id, str) or len(campaign_id) > 120:
                raise ValueError('Некорректная кампания в метаданных контейнера')
            encrypted = base64.b64decode(metadata['EncryptedPass'], validate=True)
            key_data = key_path.read_bytes().split(b'-----BEGIN CERTIFICATE-----')[0]
            key = serialization.load_pem_private_key(key_data, password=None)
            password = key.decrypt(encrypted, padding.OAEP(mgf=padding.MGF1(hashes.SHA512()), algorithm=hashes.SHA512(), label=None))
            outer.setpassword(password)
            inner_data = outer.read('data.zip')
        results = []; total = 0; hostnames = set()
        with pyzipper.AESZipFile(io.BytesIO(inner_data)) as inner:
            members = checked_members(inner)
            inner.setpassword(password)
            # Read all members to validate CRC/authentication, but never extract to disk.
            for name, member in members.items():
                if member.is_dir():
                    continue
                is_result = name.startswith('results/') and name.endswith('.json')
                count = 0
                digest = hashlib.sha256()
                bytes_read = 0
                with inner.open(name) as stream:
                    if is_result:
                        for line in iter(lambda: stream.readline(MAX_LINE + 1), b''):
                            digest.update(line)
                            bytes_read += len(line)
                            if len(line) > MAX_LINE:
                                raise ValueError('Слишком длинная строка результата')
                            if line.strip():
                                row = json.loads(line)
                                if not isinstance(row, dict):
                                    raise ValueError('Ожидаются JSON-объекты результатов')
                                if row_callback is not None:
                                    row_callback(name, count, row)
                                for key in ('Hostname', 'Host', 'Fqdn'):
                                    value = row.get(key)
                                    if isinstance(value, str) and value.strip() and len(value) <= 253:
                                        hostnames.add(value.strip())
                                total += 1; count += 1
                                if total > MAX_ROWS:
                                    raise ValueError('Превышен лимит строк результатов')
                    else:
                        while stream.read(1024 * 1024):
                            pass
                if is_result:
                    results.append({'source': name, 'rows': count, 'sha256': digest.hexdigest(),
                                    'bytes': bytes_read, 'status': 'present' if count else 'empty',
                                    'completeness': 'unknown'})
        if not results:
            raise ValueError('В контейнере нет JSONL-результатов')
        provenance = collection_provenance(metadata, results)
        return {'status': 'parsed', 'sources': results, 'total_rows': total,
                'campaign_id': campaign_id,
                'collector_schema': metadata.get('CollectorSchema', 'legacy'),
                'hostnames': sorted(hostnames),
                'collection_provenance': provenance,
                'collection_quality_warnings': provenance.get('warnings', []),
                'limitations': ['Успешная расшифровка не подтверждает авторство или подлинность данных',
                                'Полнота сбора и журналы ошибок ещё не оценены',
                                'Это сводка импорта, не заключение об отсутствии угроз']}
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, zipfile.BadZipFile, pyzipper.BadZipFile, NotImplementedError) as exc:
        raise ValueError('Контейнер не принят: неверный формат, ключ компании или повреждённые данные') from exc
