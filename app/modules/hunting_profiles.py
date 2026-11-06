"""Offline collection profiles. No credentials, VQL, or executable code from clients."""
from __future__ import annotations
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

CATALOG = [
    {"id": "host", "title": "Сведения об ОС", "platforms": ["windows", "linux"], "source": "Host", "status": "analysis_supported", "max_rows": 1, "privacy": "low", "note": "Имя узла, версия и архитектура ОС."},
    {"id": "processes", "title": "Процессы", "platforms": ["windows", "linux"], "source": "Processes", "status": "analysis_supported", "max_rows": 10000, "privacy": "high", "note": "Снимок процессов; командные строки могут содержать чувствительные данные."},
    {"id": "network", "title": "Сетевые соединения", "platforms": ["windows", "linux"], "source": "Network", "status": "analysis_supported", "max_rows": 20000, "privacy": "high", "note": "Моментальный снимок, не история сетевой активности."},
    {"id": "linux_services", "title": "Службы Linux", "platforms": ["linux"], "source": "LinuxServices", "status": "collection_supported", "max_rows": 1000, "privacy": "high", "note": "Фиксированные systemd service/timer пути: до 1000 файлов, первые 64 КБ; без systemctl. Drop-in и каталоги-ссылки пропускаются. Не инвентарь активных служб."},
    {"id": "linux_crontab", "title": "Cron и планировщик Linux", "platforms": ["linux"], "source": "LinuxCrontab", "status": "collection_supported", "max_rows": 1000, "privacy": "high", "note": "Системные и пользовательские crontab, cron-скрипты: до 1000 файлов, первые 64 КБ. Содержимое может включать секреты; усечение отмечается."},
    {"id": "linux_suid", "title": "SUID/SGID-файлы", "platforms": ["linux"], "source": "LinuxSUID", "status": "collection_supported", "max_rows": 10000, "privacy": "moderate", "note": "Метаданные SUID/SGID и числовые UID/GID только /usr/bin, /usr/sbin, /bin, /sbin; каталоги-ссылки пропускаются. Не полный обход диска; без содержимого."},

    {"id": "linux_ssh_pam", "title": "SSH и PAM", "platforms": ["linux"], "source": "LinuxSSHPAM", "status": "collection_supported", "max_rows": 1000, "privacy": "high", "note": "Фиксированные SSH/PAM конфигурации, read-only bounded текст с отметкой усечения."},
    {"id": "linux_file_timeline", "title": "Ограниченная file timeline", "platforms": ["linux"], "source": "LinuxFileTimeline", "status": "collection_supported", "max_rows": 10000, "privacy": "high", "note": "Метаданные файлов фиксированных каталогов; не полная история и не восстановление удалённых файлов."},
    {"id": "linux_capabilities", "title": "Linux capabilities", "platforms": ["linux"], "source": "LinuxCapabilities", "status": "collection_supported", "max_rows": 10000, "privacy": "moderate", "note": "Метаданные файлов системных каталогов; без полного обхода диска."},
    {"id": "linux_package_integrity", "title": "Целостность пакетов", "platforms": ["linux"], "source": "LinuxPackageIntegrity", "status": "collection_supported", "max_rows": 2000, "privacy": "moderate", "note": "Фиксированные package manifest/checksum файлы; пакетный менеджер не запускается."},    {"id": "services", "title": "Службы", "platforms": ["windows"], "source": "Services", "status": "analysis_supported", "max_rows": 10000, "privacy": "high", "note": "Состояние и конфигурация служб Windows."},
    {"id": "tasks", "title": "Задания планировщика", "platforms": ["windows"], "source": "Tasks", "status": "analysis_supported", "max_rows": 10000, "privacy": "high", "note": "Действия и учётные записи задач; аргументы могут содержать секреты."},
    {"id": "startup", "title": "Автозапуск", "platforms": ["windows"], "source": "Startup", "status": "analysis_supported", "max_rows": 10000, "privacy": "moderate", "note": "Нормализованный снимок Run-ключей и папок автозагрузки; покрытие пользовательских ульев ограничено."},
    {"id": "accounts", "title": "Локальные пользователи и администраторы", "platforms": ["windows"], "source": "Accounts", "status": "analysis_supported", "max_rows": 2000, "privacy": "moderate", "note": "Метаданные локальных записей и Administrators, без обхода доменных групп."},
    {"id": "security_events", "title": "События безопасности", "platforms": ["windows"], "source": "SecurityEvents", "status": "verified_bounded", "execution_verified": True, "metadata_only": True, "max_rows": 50000, "privacy": "high", "note": "Подтверждено Windows-пилотом SIT-2222; 50 000 строк достигли лимита, поэтому полнота ограничена."},
    {"id": "powershell_events", "title": "События PowerShell", "platforms": ["windows"], "source": "PowerShellEvents", "status": "verified_bounded", "execution_verified": True, "metadata_only": True, "max_rows": 25000, "privacy": "high", "note": "Подтверждено Windows-пилотом SIT-2222; metadata-only без ScriptBlock и EventData."},
    {"id": "defender_events", "title": "События Microsoft Defender", "platforms": ["windows"], "source": "DefenderEvents", "status": "candidate_no_telemetry", "execution_verified": False, "metadata_only": True, "max_rows": 20000, "privacy": "high", "note": "Runner и импорт проверены, но в фактическом архиве 0 событий; отсутствие строк не подтверждает telemetry."},
    {"id": "rdp_events", "title": "События RDP", "platforms": ["windows"], "source": "RDPEvents", "status": "verified_bounded", "execution_verified": True, "metadata_only": True, "max_rows": 20000, "privacy": "high", "note": "Подтверждено Windows-пилотом SIT-2222; 30 metadata-событий за UTC-окно."},
    {"id": "wmi_persistence", "title": "WMI-постоянство", "platforms": ["windows"], "source": "WMIPersistence", "status": "analysis_supported", "max_rows": 5000, "privacy": "high", "note": "Метаданные постоянных WMI-подписок без выполнения команд."},
    {"id": "registry_run_keys", "title": "Registry Run/RunOnce", "platforms": ["windows"], "source": "RegistryRunKeys", "status": "analysis_supported", "max_rows": 10000, "privacy": "high", "note": "Фиксированный набор Run/RunOnce путей без произвольного Registry-доступа."},
    {"id": "windows_evtx", "title": "Расширенные EVTX", "platforms": ["windows"], "source": "WindowsEVTX", "status": "candidate", "execution_verified": False, "metadata_only": False, "max_rows": 50000, "privacy": "high", "note": "Пилотный bounded raw EVTX: только ограниченное окно и лимит строк; статус не подтверждён до Windows-пилота."},
    {"id": "windows_prefetch", "title": "Prefetch", "platforms": ["windows"], "source": "WindowsPrefetch", "status": "candidate", "execution_verified": False, "metadata_only": True, "max_rows": 20000, "privacy": "moderate", "note": "Только метаданные файлов Prefetch из фиксированного пути; без полного парсинга."},
    {"id": "windows_amcache", "title": "Amcache", "platforms": ["windows"], "source": "WindowsAmcache", "status": "candidate", "execution_verified": False, "metadata_only": True, "max_rows": 1, "privacy": "high", "note": "Только bounded metadata-файл; формат hive и доступность требуют пилота."},
    {"id": "windows_lnk_jumplists", "title": "LNK и Jump Lists", "platforms": ["windows"], "source": "WindowsLnkJumpLists", "status": "candidate", "execution_verified": False, "metadata_only": True, "max_rows": 20000, "privacy": "moderate", "note": "Ограниченный список файлов из Recent; содержимое и полный парсинг не выполняются."},
    {"id": "windows_srum", "title": "SRUM", "platforms": ["windows"], "source": "WindowsSRUM", "status": "candidate", "execution_verified": False, "metadata_only": True, "max_rows": 2000, "privacy": "high", "note": "Только metadata файлов SRUM; база и записи не парсятся до подтверждения пилотом."},
    {"id": "windows_mft_usn", "title": "MFT/USN", "platforms": ["windows"], "source": "WindowsMFTUSN", "status": "candidate", "execution_verified": False, "metadata_only": True, "max_rows": 2, "privacy": "high", "note": "Только bounded metadata специальных файлов; полноценная timeline не заявляется."},
    {"id": "linux_journal", "title": "Linux journal", "platforms": ["linux"], "source": "LinuxJournal", "status": "verified_bounded", "execution_verified": True, "metadata_only": False, "max_rows": 1000, "privacy": "high", "note": "Ограниченное чтение journal-файлов до 64 КБ на файл; без journalctl и полного журнала."},
    {"id": "linux_auth_logs", "title": "Linux auth/secure logs", "platforms": ["linux"], "source": "LinuxAuthLogs", "status": "verified_bounded", "execution_verified": True, "metadata_only": False, "max_rows": 1000, "privacy": "high", "note": "Фиксированный набор auth/secure/messages, до 64 КБ на файл."},
    {"id": "linux_audit_logs", "title": "Linux audit logs", "platforms": ["linux"], "source": "LinuxAuditLogs", "status": "candidate_no_telemetry", "execution_verified": False, "metadata_only": False, "max_rows": 1000, "privacy": "high", "note": "Только /var/log/audit/audit.log с bounded read; auditd не запускается."},
]

EVENT_SOURCE_IDS = frozenset({'security_events', 'powershell_events', 'defender_events', 'rdp_events'})

# Event sources are qualified individually from the SIT-2222 acceptance archives.
# Status means schema/analysis support, not proof that a Windows endpoint succeeded.
for _item in CATALOG:
    if _item['id'] in EVENT_SOURCE_IDS and _item.get('status') not in {'verified_bounded'}:
        _item.update(status='candidate_no_telemetry' if _item['id'] == 'defender_events' else 'candidate', execution_verified=_item.get('execution_verified', False), metadata_only=True,
                     note='Экспериментальные метаданные EVTX: UTC-окно до LIMIT; без Message/EventData/ScriptBlock. Исполнение Windows не проверено; упаковка запрещена.')


MAX_PROFILE_ROWS = 90000  # Reserve 10000 rows below the importer hard cap.


def profile_row_budget(artifacts):
    """Budget wrapper output only; legacy duplicate built-ins are not bounded."""
    selected = set(artifacts)
    total = sum(item['max_rows'] for item in CATALOG if item['id'] in selected)
    return {'configured_rows': total, 'maximum_rows': MAX_PROFILE_ROWS,
            'importer_maximum_rows': 100000, 'reserved_rows': 10000,
            'within_budget': total <= MAX_PROFILE_ROWS,
            'scope': 'normalized_source_output_not_legacy_builtin_scan_or_bytes'}


def collection_contract(profile):
    """Configured coverage, never a claim that a source succeeded or was complete."""
    selected = set(profile['artifacts'])
    rows = {item['id']: item['max_rows'] for item in CATALOG if item['id'] in selected}
    return {
        'schema': 'brosec.collection-contract.v1',
        'collector_schema': 'brosec.result.v1',
        'capture_clock': 'endpoint_utc',
        'collection_status': {
            'version': 1, 'transport': 'source_terminal_row',
            'marker': '_BroSecCollectionStatus',
            'measurement': 'bounded_output_only_not_plugin_success',
            'missing_terminal_status': 'unknown',
            'claims_verified': False,
        },
        'configured_source_row_limits': rows,
        'row_budget': profile_row_budget(profile['artifacts']),
        'timeout_seconds': profile['timeout_seconds'],
        'event_window': {
            'requested_days': profile['event_days'],
            'applied': bool(selected & EVENT_SOURCE_IDS and profile.get('windows_event_pilot') is True),
            'reason': ('endpoint_utc_window_applied' if selected & EVENT_SOURCE_IDS and profile.get('windows_event_pilot') is True else 'event_sources_candidate_not_packaged' if selected & EVENT_SOURCE_IDS else 'snapshot_sources_have_no_event_window'),
        },
        'completeness': 'unknown_until_result_inspection',
        'row_limit_semantics': 'per_query_output_cap_not_scan_bound_or_success_proof',
        'builtin_persistence_duplicates': sorted(selected & {'services', 'tasks', 'startup'}),
        'builtin_persistence_row_limits_enforced': False,
        'windows_event_execution_verified': bool(selected & EVENT_SOURCE_IDS) and all(next(item for item in CATALOG if item['id'] == source)['execution_verified'] for source in selected & EVENT_SOURCE_IDS),
        'event_payload_policy': 'metadata_only_no_message_eventdata_scriptblock',
    }


def validate_profile(platform, artifacts, timeout_seconds, event_days):
    if platform not in {"windows", "linux"}:
        raise ValueError("Поддерживаются Windows и Linux")
    allowed = {x["id"] for x in CATALOG if platform in x["platforms"]}
    if not artifacts or len(artifacts) != len(set(artifacts)) or not set(artifacts) <= allowed:
        raise ValueError("Выберите неповторяющиеся сборы, совместимые с ОС")
    if not profile_row_budget(artifacts)['within_budget']:
        raise ValueError("Суммарный лимит источников превышает 90000 строк; разделите сбор на профили")
    if (type(timeout_seconds) is not int or type(event_days) is not int
            or not 60 <= timeout_seconds <= 3600 or not 1 <= event_days <= 30):
        raise ValueError("Лимит времени: 60–3600 секунд; окно событий: 1–30 дней")

@contextmanager
def connection(base: Path):
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(base / "hunting-profiles.sqlite", timeout=15)
    try:
        with db:
            db.execute("CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, company_id INTEGER NOT NULL, created_at TEXT NOT NULL, body TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS profiles_tenant_created ON profiles(company_id, created_at)")
            yield db
    finally:
        db.close()

def create_profile(base, company_id, name, platform, artifacts, timeout_seconds, event_days):
    validate_profile(platform, artifacts, timeout_seconds, event_days)
    name = name.strip()
    if not name or len(name) > 120 or any(ord(c) < 32 for c in name):
        raise ValueError("Название должно содержать 1–120 символов без управляющих знаков")
    row = {"id": uuid.uuid4().hex, "company_id": company_id, "name": name,
           "platform": platform, "artifacts": artifacts, "timeout_seconds": timeout_seconds,
           "event_days": event_days, "created_at": datetime.now(timezone.utc).isoformat(),
           "status": "profile_saved", "encryption_required": True}
    with connection(base) as db:
        db.execute("INSERT INTO profiles VALUES (?, ?, ?, ?)", (row["id"], company_id, row["created_at"], json.dumps(row, ensure_ascii=False)))
    return row

def list_profiles(base, company_id):
    with connection(base) as db:
        return [json.loads(x[0]) for x in db.execute("SELECT body FROM profiles WHERE company_id=? AND json_extract(body, '$.deleted_at') IS NULL ORDER BY created_at DESC LIMIT 100", (company_id,))]

def delete_profile(base, company_id, profile_id):
    if not isinstance(profile_id, str) or not profile_id or len(profile_id) > 120:
        return False
    with connection(base) as db:
        row = db.execute("SELECT body FROM profiles WHERE company_id=? AND id=?", (company_id, profile_id)).fetchone()
        if row is None:
            return False
        # Keep the immutable configuration for campaigns already holding this id.
        body = json.loads(row[0])
        if body.get('deleted_at'):
            return False
        body['deleted_at'] = datetime.now(timezone.utc).isoformat()
        db.execute("UPDATE profiles SET body=? WHERE company_id=? AND id=?",
                   (json.dumps(body, ensure_ascii=False), company_id, profile_id))
    return True

def get_profile(base, company_id, profile_id, include_deleted=False):
    with connection(base) as db:
        row = db.execute("SELECT body FROM profiles WHERE company_id=? AND id=?", (company_id, profile_id)).fetchone()
    body = json.loads(row[0]) if row else None
    return body if body and (include_deleted or not body.get('deleted_at')) else None

def export_spec(profile):
    return {"schema": "brosec.offline-profile.v1", "profile_id": profile["id"],
            "platform": profile["platform"], "artifacts": profile["artifacts"],
            "limits": {"timeout_seconds": profile["timeout_seconds"], "event_days": profile["event_days"]},
            "collection_contract": collection_contract(profile),
            "encryption_required": True, "executable": False,
            "note": "Это спецификация профиля, не готовый сборщик. Запуск и развёртывание не выполняются."}
