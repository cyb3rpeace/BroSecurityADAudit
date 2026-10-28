"""Durable archive-processing stages and progress events.

The current deployment uses SQLite as a durable coordination store. The API can
later move these tables to PostgreSQL/Redis workers without changing the stage
contract exposed to the GUI.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

STAGES = ("received", "validating", "decrypting", "parsing", "indexing", "triage", "correlation", "completed")
STAGE_PERCENT = {name: round(i * 100 / (len(STAGES) - 1)) for i, name in enumerate(STAGES)}


def stamp():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connection(base: Path):
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(base / "pipeline.sqlite", timeout=15)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA busy_timeout=15000")
        with db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, company_id INTEGER NOT NULL, campaign_id TEXT,
                task_id TEXT, result_id TEXT, stage TEXT NOT NULL, percent INTEGER NOT NULL,
                status TEXT NOT NULL, message TEXT NOT NULL, rows_processed INTEGER NOT NULL DEFAULT 0,
                findings_count INTEGER NOT NULL DEFAULT 0, error_code TEXT, error_message TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT
            );
            CREATE INDEX IF NOT EXISTS jobs_company_time ON jobs(company_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS jobs_campaign_time ON jobs(campaign_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, company_id INTEGER NOT NULL,
                stage TEXT NOT NULL, percent INTEGER NOT NULL, message TEXT NOT NULL,
                payload TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_job_time ON events(job_id, id);
            """)
            yield db
    finally:
        db.close()


def _job(row):
    if row is None:
        return None
    item = dict(row)
    item["payload"] = json.loads(item.pop("payload")) if "payload" in item else None
    return item


def create_job(base: Path, company_id: int, campaign_id: str | None, task_id: str | None, result_id: str | None):
    now = stamp()
    with connection(base) as db:
        db.execute("BEGIN IMMEDIATE")
        if result_id:
            existing = db.execute("SELECT * FROM jobs WHERE company_id=? AND result_id=? ORDER BY created_at DESC LIMIT 1", (company_id, result_id)).fetchone()
            if existing:
                return _job(existing)
        job_id = uuid.uuid4().hex
        db.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (job_id, company_id, campaign_id, task_id, result_id, "received", 0, "queued", "Результат принят", 0, 0, None, None, now, now, None))
        db.execute("INSERT INTO events (job_id,company_id,stage,percent,message,payload,created_at) VALUES (?,?,?,?,?,?,?)", (job_id, company_id, "received", 0, "Результат принят", "{}", now))
    return get_job(base, company_id, job_id)


def queue_job(base: Path, company_id: int, job_id: str):
    """Place a durable job in the external-worker queue after archive indexing."""
    now = stamp()
    with connection(base) as db:
        row = db.execute('SELECT * FROM jobs WHERE company_id=? AND id=?', (company_id, job_id)).fetchone()
        if row is None:
            raise KeyError('Pipeline job не найден')
        if row['status'] == 'completed':
            return _job(row)
        if row['status'] not in ('received', 'running', 'failed', 'queued'):
            raise ValueError('Job нельзя поставить во внешнюю очередь из текущего состояния')
        db.execute("UPDATE jobs SET status='queued', message=?, updated_at=? WHERE id=?", ('Ожидает внешнего pipeline worker', now, job_id))
    return get_job(base, company_id, job_id)


def get_job(base: Path, company_id: int, job_id: str):
    with connection(base) as db:
        row = db.execute("SELECT * FROM jobs WHERE company_id=? AND id=?", (company_id, job_id)).fetchone()
        return _job(row)


def list_jobs(base: Path, company_id: int, campaign_id: str | None = None, offset=0, limit=50):
    if offset < 0 or not 1 <= limit <= 500:
        raise ValueError("Некорректная страница")
    with connection(base) as db:
        where = "company_id=?"; args: list[object] = [company_id]
        if campaign_id:
            where += " AND campaign_id=?"; args.append(campaign_id)
        total = db.execute(f"SELECT COUNT(*) FROM jobs WHERE {where}", args).fetchone()[0]
        rows = db.execute(f"SELECT * FROM jobs WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?", [*args, limit, offset]).fetchall()
        return {"total": total, "items": [_job(r) for r in rows], "offset": offset, "limit": limit}


def advance(base: Path, company_id: int, job_id: str, stage: str, message: str, rows_processed=0, findings_count=0, payload=None):
    if stage not in STAGES:
        raise ValueError("Некорректная стадия pipeline")
    now = stamp(); percent = STAGE_PERCENT[stage]
    status = "completed" if stage == "completed" else "running"
    with connection(base) as db:
        row = db.execute("SELECT * FROM jobs WHERE company_id=? AND id=?", (company_id, job_id)).fetchone()
        if row is None:
            raise KeyError("Pipeline job не найден")
        db.execute("UPDATE jobs SET stage=?, percent=?, status=?, message=?, rows_processed=?, findings_count=?, updated_at=?, completed_at=? WHERE id=?", (stage, percent, status, message, max(0, int(rows_processed)), max(0, int(findings_count)), now, now if stage == "completed" else None, job_id))
        db.execute("INSERT INTO events (job_id,company_id,stage,percent,message,payload,created_at) VALUES (?,?,?,?,?,?,?)", (job_id, company_id, stage, percent, message, json.dumps(payload or {}, ensure_ascii=False), now))
    return get_job(base, company_id, job_id)


def fail(base: Path, company_id: int, job_id: str, error_code: str, error_message: str):
    now = stamp()
    with connection(base) as db:
        row = db.execute("SELECT * FROM jobs WHERE company_id=? AND id=?", (company_id, job_id)).fetchone()
        if row is None:
            raise KeyError("Pipeline job не найден")
        db.execute("UPDATE jobs SET status='failed', error_code=?, error_message=?, message=?, updated_at=? WHERE id=?", (error_code, error_message, "Обработка завершилась ошибкой", now, job_id))
        db.execute("INSERT INTO events (job_id,company_id,stage,percent,message,payload,created_at) VALUES (?,?,?,?,?,?,?)", (job_id, company_id, row["stage"], row["percent"], "Обработка завершилась ошибкой", json.dumps({"error_code": error_code}, ensure_ascii=False), now))
    return get_job(base, company_id, job_id)


def operational_stats(base: Path, company_id: int | None = None, stale_seconds: int = 1800):
    """Return bounded, tenant-scoped job counters for readiness/operations."""
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max(60, int(stale_seconds)))).isoformat()
    with connection(base) as db:
        where = ''
        args: list[object] = []
        if company_id is not None:
            where = ' WHERE company_id=?'
            args.append(company_id)
        rows = db.execute(f'SELECT status, COUNT(*) AS count FROM jobs{where} GROUP BY status', args).fetchall()
        stale = db.execute(f"SELECT COUNT(*) FROM jobs{where}{' AND' if where else ' WHERE'} status='running' AND updated_at<?", [*args, cutoff]).fetchone()[0]
    return {'by_status': {row['status']: row['count'] for row in rows}, 'stale_running': stale}


def events(base: Path, company_id: int, job_id: str, limit=100):
    with connection(base) as db:
        rows = db.execute("SELECT stage,percent,message,payload,created_at FROM events WHERE company_id=? AND job_id=? ORDER BY id LIMIT ?", (company_id, job_id, min(500, max(1, limit)))).fetchall()
        return [{**dict(r), "payload": json.loads(r["payload"])} for r in rows]


def retry_analysis(base: Path, company_id: int, job_id: str):
    """Reserve a failed analysis job atomically; retain its evidence and timeline."""
    now = stamp()
    with connection(base) as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM jobs WHERE company_id=? AND id=?', (company_id, job_id)).fetchone()
        if row is None:
            raise KeyError('Pipeline job не найден')
        if row['status'] != 'failed' or not row['result_id']:
            raise ValueError('Повтор доступен только для неуспешного анализа принятого архива')
        db.execute("UPDATE jobs SET status='running',stage='triage',percent=?,message=?,error_code=NULL,error_message=NULL,completed_at=NULL,updated_at=? WHERE id=?", (STAGE_PERCENT['triage'], 'Повтор серверного анализа', now, job_id))
        db.execute('INSERT INTO events (job_id,company_id,stage,percent,message,payload,created_at) VALUES (?,?,?,?,?,?,?)', (job_id, company_id, 'triage', STAGE_PERCENT['triage'], 'Повтор серверного анализа', json.dumps({'previous_error_code': row['error_code'], 'previous_error_message': row['error_message']}, ensure_ascii=False), now))
        return _job(db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone())


def recover_stale_jobs(base: Path, timeout_seconds: int = 1800, company_id: int | None = None):
    """Fail jobs left running after a worker/process crash.

    This is intentionally conservative: only jobs whose updated_at is older
    than the timeout are recovered, and the original stage is preserved.
    """
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max(60, int(timeout_seconds)))).isoformat()
    recovered = []
    with connection(base) as db:
        db.execute('BEGIN IMMEDIATE')
        query = "SELECT id, company_id, stage, percent FROM jobs WHERE status='running' AND updated_at<?"
        args: list[object] = [cutoff]
        if company_id is not None:
            query += ' AND company_id=?'; args.append(company_id)
        rows = db.execute(query, args).fetchall()
        for row in rows:
            now = stamp()
            code = "worker_timeout"
            message = "Pipeline остановлен после истечения времени ожидания worker"
            db.execute("UPDATE jobs SET status='failed', error_code=?, error_message=?, message=?, updated_at=? WHERE id=?", (code, message, message, now, row['id']))
            db.execute("INSERT INTO events (job_id,company_id,stage,percent,message,payload,created_at) VALUES (?,?,?,?,?,?,?)", (row['id'], row['company_id'], row['stage'], row['percent'], message, json.dumps({'error_code': code}, ensure_ascii=False), now))
            recovered.append(row['id'])
    return recovered
