"""Durable, tenant-scoped campaign orchestration for mass host collection.

This layer deliberately does not require a resident agent: hosts can run a signed
offline collector and submit one result per task. A future agent can use the same
campaign/task protocol without changing the domain model.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path


STATUSES = {
    "pending", "leased", "running", "uploading", "uploaded", "validating",
    "analyzing", "succeeded", "analyzed", "failed", "expired", "cancelled",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connection(base: Path):
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(base / "campaigns.sqlite", timeout=15)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA busy_timeout=15000")
        with db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS campaigns (
                    id TEXT PRIMARY KEY, company_id INTEGER NOT NULL,
                    profile_id TEXT NOT NULL, status TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL, requested_by INTEGER,
                    total_hosts INTEGER NOT NULL, created_at TEXT NOT NULL,
                    started_at TEXT, finished_at TEXT, updated_at TEXT NOT NULL,
                    UNIQUE(company_id, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS campaigns_company_time
                    ON campaigns(company_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS campaigns_company_status
                    ON campaigns(company_id, status, created_at DESC);
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL,
                    company_id INTEGER NOT NULL, hostname TEXT NOT NULL,
                    normalized_hostname TEXT NOT NULL, status TEXT NOT NULL,
                    attempt INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 5,
                    task_key TEXT NOT NULL, lease_owner TEXT, lease_expires_at TEXT,
                    next_attempt_at TEXT NOT NULL, progress_percent INTEGER NOT NULL DEFAULT 0,
                    bytes_received INTEGER NOT NULL DEFAULT 0, rows_received INTEGER NOT NULL DEFAULT 0,
                    result_id TEXT, last_error_code TEXT, last_error_message TEXT,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    UNIQUE(company_id, task_key), FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
                );
                CREATE INDEX IF NOT EXISTS tasks_campaign_status ON tasks(campaign_id, status);
                CREATE INDEX IF NOT EXISTS tasks_claimable ON tasks(status, next_attempt_at, lease_expires_at);
                """
            )
            yield db
    finally:
        db.close()


def _row(row):
    return dict(row) if row else None


def reconcile_all(base: Path, company_id: int):
    """Reconcile all campaigns for a tenant after restart or scheduled recovery."""
    return reconcile_campaign(base, company_id, None)


def reconcile_campaign(base: Path, company_id: int, campaign_id: str | None = None):
    """Repair terminal campaign state after crashes or out-of-band imports."""
    stamp = now()
    repaired = []
    with connection(base) as db:
        db.execute('BEGIN IMMEDIATE')
        where = 'company_id=?'
        args: list[object] = [company_id]
        if campaign_id:
            where += ' AND id=?'; args.append(campaign_id)
        rows = db.execute(f'SELECT id,status FROM campaigns WHERE {where}', args).fetchall()
        for row in rows:
            before = row['status']
            _expire_exhausted(db, company_id, stamp)
            _finish_campaign(db, row['id'], stamp)
            after = db.execute('SELECT status FROM campaigns WHERE id=?', (row['id'],)).fetchone()['status']
            if before != after:
                repaired.append({'campaign_id': row['id'], 'from': before, 'to': after})
    return repaired


def _finish_campaign(db, campaign_id: str, stamp: str):
    """Finalize only after analysis (not merely archive acceptance)."""
    remaining = db.execute(
        "SELECT COUNT(*) FROM tasks WHERE campaign_id=? AND status NOT IN ('analyzed','failed','cancelled','expired')",
        (campaign_id,),
    ).fetchone()[0]
    if remaining:
        return
    failures = db.execute(
        "SELECT COUNT(*) FROM tasks WHERE campaign_id=? AND status IN ('failed','expired')",
        (campaign_id,),
    ).fetchone()[0]
    db.execute(
        "UPDATE campaigns SET status=?, finished_at=?, updated_at=? WHERE id=? AND status NOT IN ('cancelled','paused')",
        ('partial' if failures else 'completed', stamp, stamp, campaign_id),
    )


def _campaign(db, row):
    item = _row(row)
    if item:
        counts = db.execute(
            "SELECT status, COUNT(*) n FROM tasks WHERE campaign_id=? GROUP BY status",
            (item["id"],),
        ).fetchall()
        item["counts"] = {r["status"]: r["n"] for r in counts}
        item["completed_hosts"] = sum(item["counts"].get(s, 0) for s in ("analyzed", "failed", "cancelled", "expired"))
        item["progress_percent"] = round(item["completed_hosts"] * 100 / item["total_hosts"]) if item["total_hosts"] else 100
        item["collection_completed"] = item["counts"].get("succeeded", 0) + item["counts"].get("analyzed", 0)
        item["analysis_completed"] = item["counts"].get("analyzed", 0)
        item["analysis_pending"] = max(0, item["collection_completed"] - item["analysis_completed"])
    return item


def create_campaign(base: Path, company_id: int, profile_id: str, hostnames: list[str], idempotency_key: str, requested_by: int | None = None):
    if not hostnames or len(hostnames) > 5000:
        raise ValueError("Кампания должна содержать от 1 до 5000 хостов")
    key = idempotency_key.strip()[:160]
    if len(key) < 8:
        raise ValueError("Idempotency-Key должен содержать не менее 8 символов")
    normalized = []
    for hostname in hostnames:
        value = hostname.strip()
        if not value or len(value) > 253 or any(c in value for c in "\r\n/\\"):
            raise ValueError(f"Некорректное имя хоста: {hostname}")
        normalized.append((value, value.casefold().rstrip(".")))
    if len({x[1] for x in normalized}) != len(normalized):
        raise ValueError("Список хостов содержит дубликаты")
    created = now()
    campaign_id = uuid.uuid4().hex
    with connection(base) as db:
        existing = db.execute("SELECT * FROM campaigns WHERE company_id=? AND idempotency_key=?", (company_id, key)).fetchone()
        if existing:
            return _campaign(db, existing)
        db.execute(
            "INSERT INTO campaigns VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (campaign_id, company_id, profile_id, "pending", key, requested_by, len(normalized), created, None, None, created),
        )
        for hostname, normalized_name in normalized:
            task_id = uuid.uuid4().hex
            task_key = f"{campaign_id}:{normalized_name}"
            db.execute(
                "INSERT INTO tasks (id,campaign_id,company_id,hostname,normalized_hostname,status,task_key,next_attempt_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (task_id, campaign_id, company_id, hostname, normalized_name, "pending", task_key, created, created, created),
            )
        return _campaign(db, db.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone())


def get_campaign(base: Path, company_id: int, campaign_id: str):
    with connection(base) as db:
        return _campaign(db, db.execute("SELECT * FROM campaigns WHERE company_id=? AND id=?", (company_id, campaign_id)).fetchone())


def list_campaigns(base: Path, company_id: int, offset=0, limit=20):
    if offset < 0 or not 1 <= limit <= 100:
        raise ValueError("Некорректная страница")
    with connection(base) as db:
        total = db.execute("SELECT COUNT(*) FROM campaigns WHERE company_id=?", (company_id,)).fetchone()[0]
        rows = db.execute("SELECT * FROM campaigns WHERE company_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?", (company_id, limit, offset)).fetchall()
        return {"total": total, "items": [_campaign(db, r) for r in rows], "offset": offset, "limit": limit}


def list_tasks(base: Path, company_id: int, campaign_id: str, status: str | None = None, offset=0, limit=100):
    if offset < 0 or not 1 <= limit <= 500:
        raise ValueError("Некорректная страница")
    with connection(base) as db:
        where = "company_id=? AND campaign_id=?"
        args: list[object] = [company_id, campaign_id]
        if status:
            if status not in STATUSES:
                raise ValueError("Некорректный статус задания")
            where += " AND status=?"; args.append(status)
        total = db.execute(f"SELECT COUNT(*) FROM tasks WHERE {where}", args).fetchone()[0]
        rows = db.execute(f"SELECT * FROM tasks WHERE {where} ORDER BY created_at LIMIT ? OFFSET ?", [*args, limit, offset]).fetchall()
        return {"total": total, "items": [_row(r) for r in rows], "offset": offset, "limit": limit}


def _expire_exhausted(db, company_id: int, stamp: str):
    rows = db.execute(
        "SELECT t.id,t.campaign_id FROM tasks t JOIN campaigns c ON c.id=t.campaign_id "
        "WHERE t.company_id=? AND c.status IN ('pending','running') "
        "AND t.result_id IS NULL AND t.attempt>=t.max_attempts "
        "AND (t.status IN ('pending','failed') OR "
        "(t.status IN ('leased','running','uploading','uploaded') AND t.lease_expires_at<=?))",
        (company_id, stamp),
    ).fetchall()
    for row in rows:
        db.execute(
            "UPDATE tasks SET status='expired',lease_owner=NULL,lease_expires_at=NULL,"
            "last_error_code='attempts_exhausted',last_error_message=?,updated_at=? WHERE id=?",
            ('Исчерпан лимит попыток сбора', stamp, row['id']),
        )
    for campaign_id in {row['campaign_id'] for row in rows}:
        _finish_campaign(db, campaign_id, stamp)
    return len(rows)


def claim_task(base: Path, company_id: int, worker_id: str, lease_seconds: int = 300):
    """Atomically lease one pending/retryable task for an optional collector transport."""
    if not worker_id or len(worker_id) > 120:
        raise ValueError("Некорректный идентификатор worker")
    lease_seconds = max(30, min(3600, int(lease_seconds)))
    stamp = now()
    expires = (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).isoformat()
    with connection(base) as db:
        db.execute("BEGIN IMMEDIATE")
        _expire_exhausted(db, company_id, stamp)
        row = db.execute(
            "SELECT t.* FROM tasks t JOIN campaigns c ON c.id=t.campaign_id "
            "WHERE t.company_id=? AND c.status IN ('pending','running') AND t.attempt<t.max_attempts AND t.result_id IS NULL "
            "AND ((t.status IN ('pending','failed') AND t.next_attempt_at<=?) "
            "OR (t.status IN ('leased','running','uploading','uploaded') AND t.lease_expires_at<?)) "
            "ORDER BY t.next_attempt_at, t.created_at LIMIT 1",
            (company_id, stamp, stamp),
        ).fetchone()
        if row is None:
            return None
        db.execute(
            "UPDATE tasks SET status='leased', attempt=attempt+1, lease_owner=?, lease_expires_at=?, updated_at=? WHERE id=?",
            (worker_id, expires, stamp, row["id"]),
        )
        db.execute("UPDATE campaigns SET status='running', started_at=COALESCE(started_at,?), updated_at=? WHERE id=?", (stamp, stamp, row["campaign_id"]))
        return _row(db.execute("SELECT * FROM tasks WHERE id=?", (row["id"],)).fetchone())


def heartbeat_task(base: Path, company_id: int, task_id: str, worker_id: str, lease_seconds: int = 300):
    """Renew an active collection lease without changing its state or progress."""
    stamp = now()
    expires = (datetime.now(timezone.utc) + timedelta(seconds=max(30, min(3600, int(lease_seconds))))).isoformat()
    with connection(base) as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM tasks WHERE company_id=? AND id=?', (company_id, task_id)).fetchone()
        if row is None:
            return None
        if row['lease_owner'] != worker_id or not row['lease_expires_at'] or row['lease_expires_at'] <= stamp:
            raise PermissionError('Lease задания истёк или принадлежит другому worker')
        if row['status'] not in ('leased', 'running', 'uploading', 'uploaded'):
            raise ValueError('Heartbeat недоступен для закрытого задания')
        db.execute('UPDATE tasks SET lease_expires_at=?,updated_at=? WHERE id=?', (expires, stamp, task_id))
        return _row(db.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone())


def update_task(base: Path, company_id: int, task_id: str, worker_id: str, status: str, progress_percent: int = 0, bytes_received: int = 0, rows_received: int = 0, result_id: str | None = None, error_code: str | None = None, error_message: str | None = None):
    if status not in ('leased', 'running', 'uploading', 'uploaded', 'failed'):
        raise ValueError("Worker не может выставлять серверный статус задания")
    if result_id is not None:
        raise ValueError("Результат привязывается только после проверки архива сервером")
    progress_percent = max(0, min(100, int(progress_percent)))
    stamp = now()
    with connection(base) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM tasks WHERE company_id=? AND id=?", (company_id, task_id)).fetchone()
        if row is None:
            return None
        if row["lease_owner"] != worker_id or not row['lease_expires_at'] or row['lease_expires_at'] <= stamp:
            raise PermissionError("Lease задания истёк или принадлежит другому worker")
        campaign = db.execute("SELECT status FROM campaigns WHERE id=?", (row['campaign_id'],)).fetchone()
        if campaign['status'] not in ('pending', 'running', 'paused') or row['status'] not in ('leased', 'running', 'uploading', 'uploaded'):
            raise ValueError("Задание уже закрыто или кампания отменена")
        order = {'leased': 0, 'running': 1, 'uploading': 2, 'uploaded': 3}
        if status != 'failed' and order[status] < order[row['status']]:
            raise ValueError("Worker не может возвращать задание на предыдущую стадию")
        progress_percent = max(progress_percent, row['progress_percent'])
        next_attempt = (datetime.now(timezone.utc) + timedelta(minutes=min(30, 2 ** min(row["attempt"], 5)))).isoformat() if status == "failed" else stamp
        db.execute(
            "UPDATE tasks SET status=?, progress_percent=?, bytes_received=?, rows_received=?, result_id=COALESCE(?,result_id), last_error_code=?, last_error_message=?, next_attempt_at=?, lease_expires_at=?, updated_at=? WHERE id=?",
            (status, progress_percent, max(0, int(bytes_received)), max(0, int(rows_received)), result_id, error_code, error_message, next_attempt, None if status in ('succeeded','failed','cancelled','expired') else (datetime.now(timezone.utc) + timedelta(seconds=300)).isoformat(), stamp, task_id),
        )
        _finish_campaign(db, row['campaign_id'], stamp)
        return _row(db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())


def bind_result(base: Path, company_id: int, task_id: str, campaign_id: str, hostnames: list[str], result_id: str, rows_received: int):
    """Bind an accepted archive to its assigned host task."""
    names = {str(x).strip().casefold().rstrip('.') for x in hostnames if isinstance(x, str)}
    stamp = now()
    with connection(base) as db:
        row = db.execute("SELECT * FROM tasks WHERE company_id=? AND id=? AND campaign_id=?", (company_id, task_id, campaign_id)).fetchone()
        if row is None:
            raise ValueError('Задание не найдено в указанной кампании')
        if row['normalized_hostname'] not in names:
            raise ValueError('Имя хоста архива не совпадает с назначенным хостом')
        if row['result_id'] == result_id and row['status'] in ('succeeded', 'analyzed', 'failed'):
            return _row(row)
        if row['result_id'] and row['result_id'] != result_id:
            raise ValueError('Задание уже связано с другим результатом')
        if row['status'] in ('cancelled', 'expired'):
            raise ValueError('Задание уже закрыто и не принимает результат')
        db.execute("UPDATE tasks SET status='succeeded', progress_percent=100, rows_received=?, result_id=?, lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE id=?", (max(0, int(rows_received)), result_id, stamp, task_id))
        _finish_campaign(db, campaign_id, stamp)
        return _row(db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())


def mark_result_analyzed(base: Path, company_id: int, result_id: str, success: bool = True):
    """Attach durable analysis outcome to the collector task without a worker lease."""
    stamp = now()
    with connection(base) as db:
        row = db.execute("SELECT * FROM tasks WHERE company_id=? AND result_id=?", (company_id, result_id)).fetchone()
        if row is None:
            return None
        if row['status'] in ('cancelled', 'expired', 'analyzed'):
            return _row(row)
        status = "analyzed" if success else "failed"
        db.execute("UPDATE tasks SET status=?, last_error_code=?, last_error_message=?, updated_at=? WHERE id=?", (status, None if success else "analysis_failed", None if success else "Pipeline analysis failed", stamp, row["id"]))
        _finish_campaign(db, row["campaign_id"], stamp)
        return _row(db.execute("SELECT * FROM tasks WHERE id=?", (row["id"],)).fetchone())


def prepare_analysis_retry(base: Path, company_id: int, task_id: str, result_id: str):
    """Reopen analysis only; never reset collection attempts or evidence identity."""
    stamp = now()
    with connection(base) as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM tasks WHERE company_id=? AND id=? AND result_id=?', (company_id, task_id, result_id)).fetchone()
        if row is None:
            raise ValueError('Задание не связано с результатом')
        campaign = db.execute('SELECT status FROM campaigns WHERE id=?', (row['campaign_id'],)).fetchone()
        if campaign['status'] in ('cancelled', 'paused') or row['status'] != 'failed':
            raise ValueError('Повтор анализа недоступен в текущем состоянии кампании/задания')
        db.execute("UPDATE tasks SET status='analyzing',last_error_code=NULL,last_error_message=NULL,updated_at=? WHERE id=?", (stamp, task_id))
        db.execute("UPDATE campaigns SET status='running',finished_at=NULL,updated_at=? WHERE id=?", (stamp, row['campaign_id']))
        return _row(db.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone())


def retry_task(base: Path, company_id: int, task_id: str):
    stamp = now()
    with connection(base) as db:
        row = db.execute("SELECT * FROM tasks WHERE company_id=? AND id=?", (company_id, task_id)).fetchone()
        if row is None:
            return None
        if row['status'] not in ('failed', 'expired'):
            raise ValueError('Повторить можно только неуспешное задание')
        campaign = db.execute("SELECT status FROM campaigns WHERE id=?", (row['campaign_id'],)).fetchone()
        if campaign['status'] == 'cancelled':
            raise ValueError('Нельзя повторять задание отменённой кампании')
        if row['result_id']:
            raise ValueError('Архив уже принят: требуется повтор серверного анализа, а не сбора')
        if row['attempt'] >= row['max_attempts']:
            raise ValueError('Исчерпан лимит попыток задания')
        db.execute("UPDATE tasks SET status='pending', next_attempt_at=?, lease_owner=NULL, lease_expires_at=NULL, progress_percent=0, bytes_received=0, rows_received=0, last_error_code=NULL, last_error_message=NULL, updated_at=? WHERE id=?", (stamp, stamp, task_id))
        db.execute("UPDATE campaigns SET status='running', finished_at=NULL, updated_at=? WHERE id=?", (stamp, row['campaign_id']))
        return _row(db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())


def change_campaign(base: Path, company_id: int, campaign_id: str, action: str):
    transitions = {"pause": "paused", "resume": "running", "cancel": "cancelled"}
    if action not in transitions:
        raise ValueError("Недопустимое действие кампании")
    with connection(base) as db:
        row = db.execute("SELECT * FROM campaigns WHERE company_id=? AND id=?", (company_id, campaign_id)).fetchone()
        if not row:
            return None
        target = transitions[action]
        if target == "paused" and row["status"] not in ("pending", "running"):
            raise ValueError("Кампанию нельзя приостановить в текущем состоянии")
        if target == "running" and row["status"] not in ("paused", "pending"):
            raise ValueError("Кампанию нельзя возобновить в текущем состоянии")
        if target == "cancelled" and row["status"] in ("completed", "cancelled"):
            raise ValueError("Кампания уже завершена")
        stamp = now()
        db.execute("UPDATE campaigns SET status=?, started_at=COALESCE(started_at,?), updated_at=? WHERE id=?", (target, stamp if target == "running" else None, stamp, campaign_id))
        if target == "cancelled":
            db.execute("UPDATE tasks SET status='cancelled', updated_at=? WHERE campaign_id=? AND status NOT IN ('succeeded','analyzed','failed','cancelled')", (stamp, campaign_id))
        return _campaign(db, db.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone())
