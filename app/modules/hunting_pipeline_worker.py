"""Small durable worker entrypoint for deployments without Redis/Celery yet."""
from __future__ import annotations

from pathlib import Path
from app.modules.hunting_pipeline import advance, fail, get_job, recover_stale_jobs
from app.modules.hunting_results import analyze_result


def run_pending_once(base: Path, key_root: Path, company_id: int | None = None, worker_id: str = 'pipeline-worker'):
    """Atomically claim one queued analysis job for one external worker."""
    from app.modules.hunting_pipeline import connection, stamp
    with connection(base) as db:
        db.execute('BEGIN IMMEDIATE')
        where = "status='queued'"
        args = []
        if company_id is not None:
            where += ' AND company_id=?'; args.append(company_id)
        row = db.execute(f'SELECT * FROM jobs WHERE {where} ORDER BY created_at LIMIT 1', args).fetchone()
        if row is None:
            return None
        now = stamp()
        message = f'Worker начал forensic triage: {worker_id}'
        changed = db.execute("UPDATE jobs SET status='running',stage='triage',percent=?,message=?,updated_at=? WHERE id=? AND status='queued'", (50, message, now, row['id'])).rowcount
        if changed != 1:
            return None
    return run_analysis(base, key_root, row['company_id'], row['id'], row['result_id'])


def main():
    import os
    import time
    base = Path(os.getenv('HUNTING_STORE', '/opt/ad-audit/data/threat-hunting'))
    key_root = base / 'keys'
    company_id = os.getenv('HUNTING_COMPANY_ID')
    company = int(company_id) if company_id else None
    worker_id = os.getenv('HUNTING_WORKER_ID', 'pipeline-worker')
    recovery_interval = max(10.0, float(os.getenv('HUNTING_WORKER_RECOVERY_SECONDS', '60')))
    last_recovery = 0.0
    while True:
        now = time.monotonic()
        if now - last_recovery >= recovery_interval:
            recover_stale_jobs(base, int(os.getenv('HUNTING_WORKER_STALE_SECONDS', '1800')), company)
            last_recovery = now
        job = run_pending_once(base, key_root, company, worker_id)
        if job is None:
            time.sleep(float(os.getenv('HUNTING_WORKER_IDLE_SECONDS', '2')))


def run_analysis(base: Path, key_root: Path, company_id: int, job_id: str, result_id: str):
    """Run one bounded analysis job; safe to call from a process worker."""
    try:
        advance(base, company_id, job_id, "triage", "Запущен forensic triage")
        result = analyze_result(base, key_root, company_id, result_id)
        advance(base, company_id, job_id, "correlation", "Выполнены корреляции", result.get("rows_reviewed", {}).get("Processes", 0), result.get("matched_rules", 0), {"ruleset": result.get("ruleset"), "triage_summary": result.get("triage_summary", {})})
        from app.modules.hunting_campaigns import mark_result_analyzed
        mark_result_analyzed(base, company_id, result_id, True)
        return advance(base, company_id, job_id, "completed", "Анализ завершён", sum(result.get("rows_reviewed", {}).values()), result.get("matched_rules", 0))
    except Exception as exc:
        from app.modules.hunting_campaigns import mark_result_analyzed
        mark_result_analyzed(base, company_id, result_id, False)
        return fail(base, company_id, job_id, "analysis_failed", str(exc)[:500])


if __name__ == '__main__':
    main()
