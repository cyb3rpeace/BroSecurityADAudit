"""SQLite-схема и стартовые профили тенантов."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime
from pathlib import Path

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, create_engine, event, text
from sqlalchemy.orm import declarative_base, sessionmaker

BASE_DIR = Path(os.getenv("APP_BASE", "/opt/ad-audit"))
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    f"sqlite:///{DATA_DIR / 'ad_audit.db'}",
    connect_args={"check_same_thread": False, "timeout": 30},
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
Base = declarative_base()


class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), default="")
    dc_host = Column(String(255), default="")
    dc_user = Column(String(255), default="")
    dc_password = Column(String(255), default="")
    transport = Column(String(16), default="winrm")
    winrm_port = Column(Integer, default=5985)
    ssh_port = Column(Integer, default=22)
    ldap_port = Column(Integer, default=636)
    ldap_ssl = Column(Boolean, default=True)
    directory_mode = Column(String(16), default="ldaps")
    runner_host = Column(String(255), default="")
    collector_hash = Column(String(128), default="")
    scan_hosts = Column(Text, default="")
    notify_email = Column(String(255), default="")
    telegram_chat = Column(String(64), default="")
    schedule = Column(String(16), default="weekly")
    scheduler_enabled = Column(Boolean, default=False)
    risk_index = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class NotifyChannel(Base):
    """Один корпоративный канал почты и один бот Telegram на всю установку."""

    __tablename__ = "notify_channel"

    id = Column(Integer, primary_key=True)
    smtp_server = Column(String(255), default="")
    smtp_port = Column(Integer, default=587)
    smtp_security = Column(String(16), default="starttls")
    smtp_user = Column(String(255), default="")
    smtp_password = Column(String(255), default="")
    smtp_from = Column(String(255), default="")
    telegram_token = Column(String(255), default="")
    telegram_chat = Column(String(64), default="")
    telegram_proxy = Column(String(128), default="")
    prefs = Column(Text, default="")


class TenantNotifyChannel(Base):
    """Изолированные каналы уведомлений выбранной компании."""

    __tablename__ = "tenant_notify_channels"

    id = Column(Integer, ForeignKey("companies.id", ondelete="CASCADE"), primary_key=True)
    smtp_server = Column(String(255), default="")
    smtp_port = Column(Integer, default=587)
    smtp_security = Column(String(16), default="starttls")
    smtp_user = Column(String(255), default="")
    smtp_password = Column(String(255), default="")
    smtp_from = Column(String(255), default="")
    telegram_token = Column(String(255), default="")
    telegram_chat = Column(String(64), default="")
    telegram_proxy = Column(String(128), default="")
    prefs = Column(Text, default="")


class AssistantSettings(Base):
    """Подключение внешней модели для ассистента. Ключ в браузер не отдается."""

    __tablename__ = "assistant_settings"

    id = Column(Integer, primary_key=True)
    enabled = Column(Boolean, default=False)
    api_url = Column(String(512), default="")
    model_name = Column(String(128), default="")
    api_key = Column(Text, default="")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    full_name = Column(String(255), default="")
    email = Column(String(255), default="")
    phone = Column(String(32), default="")
    locale = Column(String(8), default="ru")
    totp_secret = Column(String(64), default="")
    totp_enabled = Column(Integer, default=0)


class AuthSession(Base):
    """Сеанс входа в консоль. Пароль и код приложения сюда не пишутся."""

    __tablename__ = "auth_sessions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    ip = Column(String(64), default="")
    device = Column(String(255), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    seen_at = Column(DateTime, default=datetime.utcnow)
    revoked = Column(Integer, default=0)


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("companies.id"), index=True, nullable=False)
    module = Column(String(255), nullable=False)
    target_dc = Column(String(255), default="")
    status = Column(String(32), default="queued")
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    summary = Column(Text, default="")
    report_html_path = Column(String(512), default="")
    risk_score = Column(Integer, nullable=True)
    log = Column(Text, default="")
    actor = Column(String(128), default="")


class Inventory(Base):
    __tablename__ = "inventory"

    id = Column(Integer, primary_key=True)
    company_id = Column(Integer, ForeignKey("companies.id"), index=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False)
    title = Column(String(512), nullable=False)
    severity = Column(String(16), nullable=False)
    detail = Column(Text, default="")
    tags = Column(String(512), default="")
    vuln_id = Column(String(64), default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(32), default="open")


class AuditEvent(Base):
    """Входы в консоль и изменения настроек. Пароли и ключи сюда не пишутся."""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String(64), default="")
    company_id = Column(Integer, nullable=True, index=True)
    action = Column(String(64), nullable=False)
    detail = Column(Text, default="")


class ConsoleNotice(Base):
    """Уведомления колокольчика. Отдельно от почты и Telegram."""

    __tablename__ = "console_notices"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    company_id = Column(Integer, nullable=True)
    kind = Column(String(32), default="info")
    title = Column(String(200), nullable=False)
    body = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    read_at = Column(DateTime, nullable=True)


def hash_password(password: str, salt: str | None = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    check = hash_password(password, salt).split("$", 1)[1]
    return secrets.compare_digest(check, digest)


def _inventory(company_id: int, rows: list[tuple]) -> list[Inventory]:
    detected = datetime(2026, 10, 10, 9, 0)
    items = []
    for hostname, category, title, severity, detail, tags, vuln_id in rows:
        items.append(
            Inventory(
                company_id=company_id,
                hostname=hostname,
                category=category,
                title=title,
                severity=severity,
                detail=detail,
                tags=tags,
                vuln_id=vuln_id,
                detected_at=detected,
                status="baseline",
            )
        )
    return items


def _seed(db) -> None:
    """Пустая установка: только суперадминистратор. Пароль в репозиторий не входит."""
    password = os.getenv("INITIAL_ADMIN_PASSWORD") or secrets.token_urlsafe(18)
    note = DATA_DIR / "initial-admin.txt"
    if not os.getenv("INITIAL_ADMIN_PASSWORD"):
        note.write_text(password + "\n", encoding="utf-8")
        try:
            note.chmod(0o600)
        except OSError:
            pass
    db.add(
        User(
            username="admin",
            password_hash=hash_password(password),
            role="superadmin",
            company_id=None,
            full_name="Суперадминистратор",
        )
    )
    db.commit()


def _ensure_columns() -> None:
    with engine.begin() as conn:
        rows = conn.execute(text("PRAGMA table_info(companies)")).fetchall()
        names = {row[1] for row in rows}
        if "ldap_port" not in names:
            conn.execute(text("ALTER TABLE companies ADD COLUMN ldap_port INTEGER DEFAULT 636"))
        if "ldap_ssl" not in names:
            conn.execute(text("ALTER TABLE companies ADD COLUMN ldap_ssl INTEGER DEFAULT 1"))
        if "directory_mode" not in names:
            conn.execute(text("ALTER TABLE companies ADD COLUMN directory_mode VARCHAR(16) DEFAULT 'ldaps'"))
        if "runner_host" not in names:
            conn.execute(text("ALTER TABLE companies ADD COLUMN runner_host VARCHAR(255) DEFAULT ''"))
        if "collector_hash" not in names:
            conn.execute(text("ALTER TABLE companies ADD COLUMN collector_hash VARCHAR(128) DEFAULT ''"))
        if "telegram_chat" not in names:
            conn.execute(text("ALTER TABLE companies ADD COLUMN telegram_chat VARCHAR(64) DEFAULT ''"))
        scan_names = {row[1] for row in conn.execute(text("PRAGMA table_info(scan_history)")).fetchall()}
        if scan_names and "actor" not in scan_names:
            conn.execute(text("ALTER TABLE scan_history ADD COLUMN actor VARCHAR(128) DEFAULT ''"))
        notify_names = {row[1] for row in conn.execute(text("PRAGMA table_info(notify_channel)")).fetchall()}
        if notify_names and "prefs" not in notify_names:
            conn.execute(text("ALTER TABLE notify_channel ADD COLUMN prefs TEXT DEFAULT ''"))
        if notify_names and "telegram_proxy" not in notify_names:
            conn.execute(text("ALTER TABLE notify_channel ADD COLUMN telegram_proxy VARCHAR(128) DEFAULT ''"))
        user_names = {row[1] for row in conn.execute(text("PRAGMA table_info(users)")).fetchall()}
        for name, ddl in (
            ("email", "VARCHAR(255) DEFAULT ''"),
            ("phone", "VARCHAR(32) DEFAULT ''"),
            ("locale", "VARCHAR(8) DEFAULT 'ru'"),
            ("totp_secret", "VARCHAR(64) DEFAULT ''"),
            ("totp_enabled", "INTEGER DEFAULT 0"),
        ):
            if user_names and name not in user_names:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN {name} {ddl}"))


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_columns()
    with SessionLocal() as db:
        if db.query(User).filter(User.username == "admin").first():
            return
        _seed(db)
