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
    {"id": "linux_services", "title": "Службы Linux", "platforms": ["linux"], "source": "LinuxServices", "status": "collection_supported", "max_rows": 1000, "privacy": "high", "note": "Фиксированные systemd service/timer и drop-in пути: до 1000 файлов, первые 64 КиБ; без запуска systemctl. Не инвентарь активных служб."},
    {"id": "linux_crontab", "title": "Cron и планировщик Linux", "platforms": ["linux"], "source": "LinuxCrontab", "status": "collection_supported", "max_rows": 1000, "privacy": "high", "note": "Системные и пользовательские crontab, cron-скрипты: до 1000 файлов, первые 64 КиБ. Содержимое может включать секреты; усечение отмечается."},
    {"id": "linux_suid", "title": "SUID/SGID-файлы", "platforms": ["linux"], "source": "LinuxSUID", "status": "collection_supported", "max_rows": 10000, "privacy": "moderate", "note": "Метаданные SUID/SGID только /usr/bin, /usr/sbin, /bin, /sbin; не полный обход диска. Содержимое не выгружается."},
    {"id": "services", "title": "Службы", "platforms": ["windows"], "source": "Services", "status": "analysis_supported", "max_rows": 10000, "privacy": "high", "note": "Состояние и конфигурация служб Windows."},
    {"id": "tasks", "title": "Задания планировщика", "platforms": ["windows"], "source": "Tasks", "status": "analysis_supported", "max_rows": 10000, "privacy": "high", "note": "Действия и учётные записи задач; аргументы могут содержать секреты."},
    {"id": "startup", "title": "Автозапуск", "platforms": ["windows"], "source": "Startup", "status": "analysis_supported", "max_rows": 10000, "privacy": "moderate", "note": "Нормализованный снимок Run-ключей и папок автозагрузки; покрытие пользовательских ульев ограничено."},
    {"id": "accounts", "title": "Локальные пользователи и администраторы", "platforms": ["windows"], "source": "Accounts", "status": "candidate", "max_rows": 2000, "privacy": "moderate", "note": "Метаданные локальных записей и Administrators, без обхода доменных групп."},
    {"id": "security_events", "title": "События безопасности", "platforms": ["windows"], "source": "SecurityEvents", "status": "candidate", "max_rows": 50000, "privacy": "high", "note": "Нормализованная выборка Security за ограниченное окно, только утверждённые event IDs."},
    {"id": "powershell_events", "title": "События PowerShell", "platforms": ["windows"], "source": "PowerShellEvents", "status": "candidate", "max_rows": 25000, "privacy": "high", "note": "Операционные события PowerShell; ScriptBlock может содержать чувствительные данные."},
    {"id": "defender_events", "title": "События Microsoft Defender", "platforms": ["windows"], "source": "DefenderEvents", "status": "candidate", "max_rows": 20000, "privacy": "high", "note": "Детектирования и изменения состояния Defender без выгрузки сырых файлов."},
    {"id": "rdp_events", "title": "События RDP", "platforms": ["windows"], "source": "RDPEvents", "status": "candidate", "max_rows": 20000, "privacy": "high", "note": "Сессии и подключения RDP за ограниченное окно."},
    {"id": "wmi_persistence", "title": "WMI-постоянство", "platforms": ["windows"], "source": "WMIPersistence", "status": "candidate", "max_rows": 5000, "privacy": "high", "note": "Метаданные постоянных WMI-подписок без выполнения команд."},
    {"id": "registry_run_keys", "title": "Registry Run/RunOnce", "platforms": ["windows"], "source": "RegistryRunKeys", "status": "candidate", "max_rows": 10000, "privacy": "high", "note": "Фиксированный набор Run/RunOnce путей без произвольного Registry-доступа."},
]

EVENT_SOURCE_IDS = frozenset({'security_events', 'powershell_events', 'defender_events', 'rdp_events'})

# Catalog status is not execution verification. Preserve candidate gating until
# the new metadata queries have actually run on Windows.
for _item in CATALOG:
    if _item['id'] in EVENT_SOURCE_IDS:
        _item.update(status='candidate', execution_verified=False, metadata_only=True,
                     note='Экспериментальные метаданные EVTX: UTC-окно до LIMIT; без Message/EventData/ScriptBlock. Исполнение Windows не проверено; упаковка запрещена.')


def collection_contract(profile):
    """Configured coverage, never a claim that a source succeeded or was complete."""
    selected = set(profile['artifacts'])
    rows = {item['id']: item['max_rows'] for item in CATALOG if item['id'] in selected}
    return {
        'schema': 'brosec.collection-contract.v1',
        'collector_schema': 'brosec.result.v1',
        'capture_clock': 'endpoint_utc',
        'configured_source_row_limits': rows,
        'timeout_seconds': profile['timeout_seconds'],
        'event_window': {
            'requested_days': profile['event_days'],
            'applied': False,
            'reason': ('event_sources_candidate_not_packaged' if selected & EVENT_SOURCE_IDS
                       else 'snapshot_sources_have_no_event_window'),
        },
        'completeness': 'unknown_until_result_inspection',
        'row_limit_semantics': 'per_query_output_cap_not_scan_bound_or_success_proof',
        'builtin_persistence_duplicates': sorted(selected & {'services', 'tasks', 'startup'}),
        'builtin_persistence_row_limits_enforced': False,
        'windows_event_execution_verified': False,
    }


def validate_profile(platform, artifacts, timeout_seconds, event_days):
    if platform not in {"windows", "linux"}:
        raise ValueError("Поддерживаются Windows и Linux")
    allowed = {x["id"] for x in CATALOG if platform in x["platforms"]}
    if not artifacts or len(artifacts) != len(set(artifacts)) or not set(artifacts) <= allowed:
        raise ValueError("Выберите неповторяющиеся сборы, совместимые с ОС")
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
        return [json.loads(x[0]) for x in db.execute("SELECT body FROM profiles WHERE company_id=? ORDER BY created_at DESC LIMIT 100", (company_id,))]

def delete_profile(base, company_id, profile_id):
    if not isinstance(profile_id, str) or not profile_id or len(profile_id) > 120:
        return False
    with connection(base) as db:
        row = db.execute("SELECT body FROM profiles WHERE company_id=? AND id=?", (company_id, profile_id)).fetchone()
        if row is None:
            return False
        db.execute("DELETE FROM profiles WHERE company_id=? AND id=?", (company_id, profile_id))
    return True

def get_profile(base, company_id, profile_id):
    with connection(base) as db:
        row = db.execute("SELECT body FROM profiles WHERE company_id=? AND id=?", (company_id, profile_id)).fetchone()
    return json.loads(row[0]) if row else None

def export_spec(profile):
    return {"schema": "brosec.offline-profile.v1", "profile_id": profile["id"],
            "platform": profile["platform"], "artifacts": profile["artifacts"],
            "limits": {"timeout_seconds": profile["timeout_seconds"], "event_days": profile["event_days"]},
            "collection_contract": collection_contract(profile),
            "encryption_required": True, "executable": False,
            "note": "Это спецификация профиля, не готовый сборщик. Запуск и развёртывание не выполняются."}
