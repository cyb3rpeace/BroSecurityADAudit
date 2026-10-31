"""Tenant-scoped immutable encrypted evidence and indexed import history."""
import hashlib
import json
import os
import sqlite3
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from app.modules.hunting_ingest import summarize_container

MAX_TENANT_BYTES = 2 * 1024**3
DEFAULT_RETENTION_DAYS = 90
FINDING_STATUSES = {'needs_review', 'confirmed', 'benign', 'insufficient_evidence'}


@contextmanager
def connection(base):
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(base / 'results.sqlite', timeout=15)
    db.row_factory = sqlite3.Row
    try:
        with db:
            db.execute('CREATE TABLE IF NOT EXISTS imports (id TEXT PRIMARY KEY, company_id INTEGER NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, created_at TEXT NOT NULL, summary TEXT NOT NULL, UNIQUE(company_id, sha256))')
            db.execute('CREATE INDEX IF NOT EXISTS imports_tenant_time ON imports(company_id, created_at)')
            yield db
    finally:
        db.close()


def tenant_dir(base, company_id):
    if type(company_id) is not int or company_id <= 0:
        raise ValueError('Некорректная компания')
    path = base / 'archives' / str(company_id)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def public(row):
    return {**{k: row[k] for k in ['id', 'sha256', 'size', 'created_at']}, 'summary': json.loads(row['summary'])}


def save_result(base: Path, company_id: int, data: bytes | Path, summary: dict):
    """Persist evidence without requiring a second full archive buffer."""
    source_path = data if isinstance(data, Path) else None
    if source_path is not None:
        if source_path.is_symlink() or not source_path.is_file():
            raise ValueError('Файл архива недоступен')
        size = source_path.stat().st_size
        if size < 0:
            raise ValueError('Некорректный размер архива')
        digest_builder = hashlib.sha256()
        with source_path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest_builder.update(chunk)
        digest = digest_builder.hexdigest()
    else:
        size = len(data)
        digest = hashlib.sha256(data).hexdigest()
    directory = tenant_dir(base, company_id)
    with connection(base) as db:
        db.execute('BEGIN IMMEDIATE')
        previous = db.execute('SELECT * FROM imports WHERE company_id=? AND sha256=?', (company_id, digest)).fetchone()
        if previous:
            return {**public(previous), 'duplicate': True}
        used = db.execute('SELECT COALESCE(SUM(size),0) FROM imports WHERE company_id=?', (company_id,)).fetchone()[0]
        if used + size > MAX_TENANT_BYTES:
            raise ValueError('Достигнута квота архива компании: 2 ГиБ')
        identifier = uuid.uuid4().hex
        destination = directory / (identifier + '.zip')
        fd, temp = tempfile.mkstemp(prefix='.upload-', dir=directory)
        try:
            with os.fdopen(fd, 'wb') as stream:
                if source_path is not None:
                    with source_path.open('rb') as source:
                        for chunk in iter(lambda: source.read(1024 * 1024), b''):
                            stream.write(chunk)
                else:
                    stream.write(data)
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temp, destination)
            db.execute('INSERT INTO imports VALUES (?,?,?,?,?,?)', (identifier, company_id, digest, size, datetime.now(timezone.utc).isoformat(), json.dumps(summary, ensure_ascii=False)))
            row = db.execute('SELECT * FROM imports WHERE id=?', (identifier,)).fetchone()
            # Commit before returning; a failed commit removes the unindexed archive.
            db.commit()
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        finally:
            Path(temp).unlink(missing_ok=True)
    return {**public(row), 'duplicate': False}


def retention_candidates(base: Path, company_id: int, retention_days: int = DEFAULT_RETENTION_DAYS):
    """List old evidence candidates without deleting anything.

    Evidence referenced by a non-terminal pipeline job is protected from purge.
    """
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, min(3650, int(retention_days))))).isoformat()
    with connection(base) as db:
        rows = db.execute('SELECT id, size, created_at FROM imports WHERE company_id=? AND created_at<? ORDER BY created_at LIMIT 1000', (company_id, cutoff)).fetchall()
    protected = set()
    pipeline_db = base / 'pipeline.sqlite'
    if pipeline_db.exists():
        import sqlite3
        pipeline = sqlite3.connect(pipeline_db)
        try:
            try:
                protected = {row[0] for row in pipeline.execute("SELECT result_id FROM jobs WHERE company_id=? AND result_id IS NOT NULL AND status NOT IN ('completed','failed')", (company_id,)).fetchall()}
            except sqlite3.OperationalError:
                protected = set()
        finally:
            pipeline.close()
    return [{**dict(row), 'protected': row['id'] in protected} for row in rows]


def purge_retention_candidates(base: Path, company_id: int, retention_days: int = DEFAULT_RETENTION_DAYS, dry_run: bool = True):
    """Safely purge expired tenant results through the transactional delete path."""
    candidates = retention_candidates(base, company_id, retention_days)
    protected = [item['id'] for item in candidates if item.get('protected')]
    deletable = [item['id'] for item in candidates if not item.get('protected')]
    if dry_run or not candidates:
        return {'dry_run': True, 'deleted': [], 'skipped_protected': protected, 'candidates': candidates}

    deleted = []
    for identifier in deletable:
        try:
            delete_result(base, company_id, identifier)
        except KeyError:
            # Concurrent removal is safe and idempotent for a retention sweep.
            continue
        except ResultInUseError:
            # A job may have started since the candidate scan; never remove its evidence.
            protected.append(identifier)
            continue
        deleted.append(identifier)
    return {'dry_run': False, 'deleted': deleted, 'skipped_protected': protected, 'candidates': candidates}



class ResultInUseError(ValueError):
    """Evidence is still referenced by an active analysis/collection job."""


def delete_result(base: Path, company_id: int, identifier: str):
    """Remove one owned import, evidence, exports, reviews and pipeline caches.

    Attached SQLite databases share one write transaction, so a worker cannot
    claim/retry an existing job between the active-job check and deletion.
    Campaign tasks remain as operational history, but lose the deleted link.
    Files are staged by rename and restored if the database transaction fails.
    """
    import re
    if type(company_id) is not int or company_id <= 0:
        raise ValueError('Invalid company')
    # A malformed/missing/foreign identifier has the same not-found behavior.
    if not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{32}', identifier):
        raise KeyError('Result not found')
    base = Path(base).resolve()
    # Check ownership before inspecting any related storage paths. Recheck under
    # the write lock below to cover concurrent deletion.
    if get_result(base, company_id, identifier) is None:
        raise KeyError('Result not found')

    def safe_path(relative):
        path = base / relative
        current = base
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise ValueError('Unsafe result storage path')
        if path.exists() and not path.is_file():
            raise ValueError('Unsafe result storage path')
        return path

    staged = []
    committed = False
    try:
        with connection(base) as db:
            attached = set()
            for alias, filename in [('pipeline', 'pipeline.sqlite'), ('campaigns', 'campaigns.sqlite'), ('reviews', 'finding_reviews.sqlite')]:
                path = safe_path(Path(filename))
                if path.exists():
                    db.execute(f'ATTACH DATABASE ? AS {alias}', (str(path),))
                    attached.add(alias)
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM imports WHERE company_id=? AND id=?', (company_id, identifier)).fetchone() is None:
                raise KeyError('Result not found')
            args = (company_id, identifier)
            if 'pipeline' in attached:
                active = db.execute("SELECT 1 FROM pipeline.jobs WHERE company_id=? AND result_id=? AND status NOT IN ('completed','failed') LIMIT 1", args).fetchone()
                if active:
                    raise ResultInUseError('Result has an active pipeline job')
            if 'campaigns' in attached:
                active = db.execute("SELECT 1 FROM campaigns.tasks WHERE company_id=? AND result_id=? AND status NOT IN ('succeeded','analyzed','failed','expired','cancelled') LIMIT 1", args).fetchone()
                if active:
                    raise ResultInUseError('Result has an active collection task')
            paths = [safe_path(Path('archives') / str(company_id) / (identifier + '.zip'))]
            paths += [safe_path(Path('exports') / str(company_id) / (identifier + '-forensic.' + extension)) for extension in ('pdf', 'xlsx')]
            # Validate every path before moving anything; never follow symlinks.
            for path in paths:
                if path.exists():
                    temporary = path.with_name('.delete-' + uuid.uuid4().hex)
                    path.rename(temporary)
                    staged.append((path, temporary))
            if 'reviews' in attached:
                db.execute('DELETE FROM reviews.reviews WHERE company_id=? AND result_id=?', args)
            if 'pipeline' in attached:
                db.execute('DELETE FROM pipeline.events WHERE company_id=? AND job_id IN (SELECT id FROM pipeline.jobs WHERE company_id=? AND result_id=?)', (company_id, *args))
                db.execute('DELETE FROM pipeline.jobs WHERE company_id=? AND result_id=?', args)
            if 'campaigns' in attached:
                db.execute('UPDATE campaigns.tasks SET result_id=NULL WHERE company_id=? AND result_id=?', args)
            db.execute('DELETE FROM imports WHERE company_id=? AND id=?', args)
            db.commit()
            committed = True
    finally:
        for original, temporary in reversed(staged):
            if committed:
                temporary.unlink(missing_ok=True)
            else:
                temporary.rename(original)
    return {'deleted': True, 'id': identifier}


def history(base, company_id, offset=0, limit=20):
    if offset < 0 or not 1 <= limit <= 100:
        raise ValueError('Некорректная страница')
    with connection(base) as db:
        total = db.execute('SELECT COUNT(*) FROM imports WHERE company_id=?', (company_id,)).fetchone()[0]
        rows = db.execute('SELECT * FROM imports WHERE company_id=? ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?', (company_id, limit, offset)).fetchall()
    return {'total': total, 'items': [public(r) for r in rows], 'offset': offset, 'limit': limit}


def _finding_db(base: Path):
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(base / 'finding_reviews.sqlite', timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA busy_timeout=15000')
    db.execute('CREATE TABLE IF NOT EXISTS reviews (company_id INTEGER NOT NULL, result_id TEXT NOT NULL, finding_key TEXT NOT NULL, status TEXT NOT NULL, note TEXT NOT NULL, updated_by INTEGER, updated_at TEXT NOT NULL, PRIMARY KEY(company_id, result_id, finding_key))')
    db.execute('CREATE INDEX IF NOT EXISTS reviews_result ON reviews(company_id, result_id)')
    return db


def finding_key(finding: dict):
    return '|'.join(str(finding.get(key, '')) for key in ('rule_id', 'source', 'row_number'))


def review_finding(base: Path, company_id: int, result_id: str, finding: dict, status: str, note: str, user_id: int | None = None):
    if status not in FINDING_STATUSES:
        raise ValueError('Недопустимый статус finding')
    note = note.strip()
    if len(note) < 3 or len(note) > 4000:
        raise ValueError('Заметка аналитика должна содержать от 3 до 4000 символов')
    key = finding_key(finding)
    if not key.strip('|'):
        raise ValueError('Finding не содержит citation identity')
    result = get_result(base, company_id, result_id)
    if result is None:
        raise KeyError('Результат не найден')
    source = finding.get('source')
    try:
        row_number = int(finding.get('row_number'))
    except (TypeError, ValueError) as exc:
        raise ValueError('Некорректный номер строки evidence') from exc
    source_rows = {item.get('source'): int(item.get('rows', 0)) for item in result['summary'].get('sources', [])}
    if source not in source_rows or row_number < 1 or row_number > source_rows[source]:
        raise ValueError('Citation finding не соответствует evidence результата')
    db = _finding_db(base)
    try:
        now = datetime.now(timezone.utc).isoformat()
        db.execute('BEGIN IMMEDIATE')
        db.execute('INSERT INTO reviews VALUES (?,?,?,?,?,?,?) ON CONFLICT(company_id,result_id,finding_key) DO UPDATE SET status=excluded.status,note=excluded.note,updated_by=excluded.updated_by,updated_at=excluded.updated_at', (company_id, result_id, key, status, note, user_id, now))
        db.commit()
        return {'company_id': company_id, 'result_id': result_id, 'finding_key': key, 'status': status, 'note': note, 'updated_by': user_id, 'updated_at': now}
    finally:
        db.close()


def finding_reviews(base: Path, company_id: int, result_id: str):
    db = _finding_db(base)
    try:
        return [dict(row) for row in db.execute('SELECT * FROM reviews WHERE company_id=? AND result_id=? ORDER BY updated_at', (company_id, result_id)).fetchall()]
    finally:
        db.close()


def verify_integrity(base: Path, company_id: int, limit: int = 1000):
    """Verify tenant evidence metadata against on-disk archives without mutation."""
    if not 1 <= int(limit) <= 5000:
        raise ValueError('Некорректный лимит проверки')
    directory = tenant_dir(base, company_id)
    checked = []
    with connection(base) as db:
        rows = db.execute('SELECT id, sha256, size FROM imports WHERE company_id=? ORDER BY created_at DESC LIMIT ?', (company_id, int(limit))).fetchall()
    for row in rows:
        path = directory / (row['id'] + '.zip')
        issue = None
        if path.is_symlink() or (path.exists() and not path.is_file()):
            issue = 'invalid_path'
        elif not path.exists():
            issue = 'missing_archive'
        elif path.stat().st_size != row['size']:
            issue = 'size_mismatch'
        else:
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            if digest.hexdigest() != row['sha256']:
                issue = 'sha256_mismatch'
        checked.append({'id': row['id'], 'ok': issue is None, 'issue': issue})
    return {'company_id': company_id, 'checked': len(checked), 'valid': sum(item['ok'] for item in checked), 'invalid': [item for item in checked if not item['ok']]}


def get_result(base, company_id, identifier):
    with connection(base) as db:
        row = db.execute('SELECT * FROM imports WHERE company_id=? AND id=?', (company_id, identifier)).fetchone()
    if row is None:
        return None
    return public(row)


def analyze_result(base, key_root, company_id, identifier):
    from app.modules.hunting_analysis import BaselineReview
    item = get_result(base, company_id, identifier)
    if item is None:
        raise KeyError('Результат не найден')
    path = tenant_dir(base, company_id) / (item['id'] + '.zip')
    if path.is_symlink():
        raise ValueError('Недопустимый путь архива')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError('Контрольная сумма сохранённого архива не совпадает')
    review = BaselineReview()
    summary = summarize_container(data, key_root, company_id, row_callback=review.consume)
    result = review.result(summary['sources'])
    result['collection_provenance'] = summary.get('collection_provenance', {'status': 'legacy_or_missing', 'claims_verified': False, 'claims_trusted': False})
    result['collection_quality_warnings'] = list(dict.fromkeys(summary.get('collection_quality_warnings', []) + result.get('source_quality_warnings', [])))
    result['limitations'] += result['collection_quality_warnings'] + [
        'Endpoint collection status is untrusted; output presence/counts do not verify plugin success or completeness',
        'Missing terminal telemetry, cancellation and plugin errors without reliable error signals remain unknown',
    ]
    decisions = {item['finding_key']: item for item in finding_reviews(base, company_id, identifier)}
    result['findings'] = [{**finding, 'review': decisions.get(finding_key(finding))} for finding in result['findings']]
    return {**result, 'import_id': item['id'], 'sha256': item['sha256']}


def read_page(base, key_root, company_id, identifier, source, offset=0, limit=25):
    if offset < 0 or not 1 <= limit <= 100:
        raise ValueError('Некорректная страница')
    item = get_result(base, company_id, identifier)
    if item is None:
        raise KeyError('Результат не найден')
    sources = {x['source']: x['rows'] for x in item['summary']['sources']}
    if source not in sources:
        raise ValueError('Источник не найден')
    path = tenant_dir(base, company_id) / (item['id'] + '.zip')
    if path.is_symlink():
        raise ValueError('Недопустимый путь архива')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError('Контрольная сумма сохранённого архива не совпадает')
    rows = []
    def capture(name, index, row):
        if name == source and offset <= index < offset + limit:
            rows.append(row)
    summarize_container(data, key_root, company_id, row_callback=capture)
    return {'rows': rows, 'total': sources[source], 'offset': offset, 'limit': limit, 'source': source}
