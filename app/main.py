"""AD Identity Guard v2.0 — ядро, изоляция тенантов, отчеты и копилот."""

from __future__ import annotations

import hashlib
import html
import json
import logging
import os
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote
from zoneinfo import ZoneInfo

import pandas as pd
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import or_
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.database import (
    BASE_DIR,
    REPORTS_DIR,
    AuditEvent,
    Company,
    ConsoleNotice,
    Inventory,
    AssistantSettings,
    ExternalAnalysisJob,
    NotifyChannel,
    TenantNotifyChannel,
    ScanHistory,
    AuthSession,
    SessionLocal,
    User,
    hash_password,
    init_db,
    verify_password,
)
from app.modules.account_auth import device_label, new_secret, otpauth_uri, qr_svg, totp_ok
from app.modules.dc_hardening import scan_hardening
from app.modules.ldap_audit import directory_picture, list_computer_names, lookup_asset, probe_directory, scan_adcs_ldap, scan_hardening_ldap, scan_hygiene_ldap, scan_trusts_ldap
from app.modules.mitre import card as mitre_card
from app.modules.mitre import tactics_of
from app.modules.protocols import scan_protocols_ldap, scan_protocols_windows
from app.modules.notifier_mail import send_report
from app.modules.notifier_tg import send_summary
from app.modules.posture import scan_hygiene, scan_time, scan_trusts
from app.modules.software_scan import controller_extra, dns_zones, gpo_conflicts, last_interactive_user, repair_caption, scan_gpp, scan_software, trust_reach, validate_host

load_dotenv(BASE_DIR / ".env")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("adguard")

try:
    TZ = ZoneInfo("Europe/Moscow")
except Exception:
    TZ = ZoneInfo("UTC")

PRODUCT_VERSION = "2.6.25"

ALLOWED_MODULES = (
    "ad_cs",
    "software_audit",
    "gpp_passwords",
    "dc_hardening",
    "trusts",
    "time_sync",
    "baseline_hygiene",
    "protocols",
)
MODULE_TITLES = {
    "ad_cs": "AD CS",
    "software_audit": "Аудит ПО",
    "gpp_passwords": "Пароли в GPO",
    "dc_hardening": "Харденинг контроллера",
    "trusts": "Доверия и фильтрация SID",
    "time_sync": "Время контроллеров",
    "baseline_hygiene": "Базовая гигиена",
    "protocols": "Опасные протоколы",
}
SEVERITY_RU = {
    "critical": "Критический",
    "high": "Высокий",
    "medium": "Средний",
    "low": "Низкий",
    "info": "Информация",
}
STANDARDS = {
    "gpp_password": (
        "CIS Windows Server — запрет хранения паролей в предпочтениях GPO; бюллетень MS14-025",
        "ГОСТ Р 57580.1 — управление аутентификационной информацией",
    ),
    "kerberoasting": (
        "CIS Control 5.2 — длинные уникальные пароли служебных учетных записей, переход на gMSA",
        "ГОСТ Р 57580.1 — средства аутентификации",
    ),
    "active_smbv1": (
        "CIS Windows Server — отключение протокола SMB v1",
        "ГОСТ Р 56939 — безопасная конфигурация",
    ),
    "anydesk_detected": (
        "CIS Control 2 — учет и контроль программного обеспечения",
        "ГОСТ Р 57580.1 — контроль состава ПО",
    ),
    "teamviewer_detected": (
        "CIS Control 2 — учет и контроль программного обеспечения",
        "ГОСТ Р 57580.1 — контроль состава ПО",
    ),
    "rustdesk_detected": (
        "CIS Control 2 — учет и контроль программного обеспечения",
        "ГОСТ Р 57580.1 — контроль состава ПО",
    ),
    "vnc_detected": (
        "CIS Control 2 и CIS Control 4 — запрет неуправляемого удаленного доступа",
        "ГОСТ Р 57580.1 — контроль удаленного доступа",
    ),
    "vpn_unauthorized": (
        "CIS Control 4 — контроль сетевых каналов",
        "ГОСТ Р 57580.1 — управление сетевыми потоками",
    ),
    "obsolete_os": (
        "CIS Control 2 — поддерживаемые версии ОС",
        "ГОСТ Р 56939 — управление уязвимостями и обновлениями",
    ),
    "adcs_enrollee_san": (
        "Microsoft — усиление шаблонов AD CS, запрет SAN от заявителя без согласования",
        "ГОСТ Р 57580.1 — управление сертификатами и ключами",
    ),
    "unconstrained_delegation": (
        "CIS — ограничение доверенного делегирования Kerberos",
        "ГОСТ Р 57580.1 — разграничение полномочий",
    ),
    "asrep_preauth": (
        "CIS — предварительная проверка подлинности Kerberos включена",
        "ГОСТ Р 57580.1 — средства аутентификации",
    ),
    "krbtgt_old": (
        "Microsoft — двукратная смена пароля krbtgt с интервалом не менее 10 часов",
        "ГОСТ Р 57580.1 — управление ключевой информацией",
    ),
    "honeytoken": (
        "MITRE D3-DUC — обманные учетные данные как контроль обнаружения",
        "ГОСТ Р 57580.1 — мониторинг событий безопасности",
    ),
    "print_spooler_on_dc": (
        "CIS Windows Server — служба Print Spooler на контроллере отключена",
        "ГОСТ Р 56939 — минимизация функций узла",
    ),
    "ldap_signing_not_required": (
        "CIS — LDAP signing required",
        "ГОСТ Р 57580.1 — защита каналов администрирования",
    ),
    "recycle_bin_disabled": (
        "Microsoft — AD Recycle Bin для восстановления объектов",
        "ГОСТ Р 57580.1 — обеспечение доступности",
    ),
    "priv_password_never_expires": (
        "CIS — пароли привилегированных учетных записей имеют срок действия",
        "ГОСТ Р 57580.1 — управление аутентификацией",
    ),
    "not_in_protected_users": (
        "Microsoft — группа Protected Users для интерактивных администраторов",
        "ГОСТ Р 57580.1 — усиленная аутентификация",
    ),
    "laps_missing": (
        "CIS — Windows LAPS для паролей локальных администраторов",
        "ГОСТ Р 57580.1 — уникальные секреты учетных записей",
    ),
    "ad_module_missing": (
        "Средство удаленного администрирования Active Directory",
        "ГОСТ Р 57580.1 — полнота контроля",
    ),
    "trust_sid_filter": (
        "Microsoft — фильтрация SID (карантин) на внешних и лесных довериях",
        "ГОСТ Р 57580.1 — разграничение контуров",
    ),
    "time_skew": (
        "Kerberos — расхождение часов контроллеров не больше 5 минут",
        "ГОСТ Р 57580.1 — синхронизация времени средств аутентификации",
    ),
    "ordinary_privileged": (
        "Выделенные административные учетные записи, отдельные от повседневных",
        "ГОСТ Р 57580.1 — разграничение полномочий",
    ),
    "stale_password": (
        "CIS — срок действия пароля и ротация служебных учетных записей",
        "ГОСТ Р 57580.1 — управление аутентификационной информацией",
    ),
    "inactive_stale": (
        "CIS Control 5 — отключение неиспользуемых учетных записей",
        "ГОСТ Р 57580.1 — жизненный цикл учетных записей",
    ),
    "guest_enabled": (
        "CIS — встроенная учетная запись Guest отключена",
        "ГОСТ Р 57580.1 — запрет анонимного доступа",
    ),
}

app = FastAPI(title="BroSec Audit AD", version=PRODUCT_VERSION, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET") or "ad-identity-guard-change-me",
    max_age=60 * 60 * 12,
    same_site="lax",
    https_only=True,
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")
_spa_assets = BASE_DIR / "app" / "spa" / "assets"
if _spa_assets.is_dir():
    app.mount("/assets", StaticFiles(directory=str(_spa_assets)), name="spa-assets")
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))
scheduler = BackgroundScheduler(timezone=TZ)
_locks: dict[int, threading.Lock] = {}
_locks_guard = threading.Lock()
_fonts_ready = False


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    host = forwarded.split(",")[0].strip() if forwarded else ""
    if not host and request.client:
        host = request.client.host or ""
    return host[:64]


def open_console_session(db: Session, request: Request, user: User) -> AuthSession:
    row = AuthSession(user_id=user.id, ip=client_ip(request), device=device_label(request.headers.get("user-agent", "")))
    db.add(row)
    db.flush()
    request.session["uid"] = user.id
    request.session["sid"] = row.id
    return row


def get_user(request: Request, db: Session = Depends(get_db)) -> User:
    uid = request.session.get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Требуется вход")
    user = db.get(User, int(uid))
    if user is None:
        raise HTTPException(status_code=401, detail="Сессия недействительна")
    sid = request.session.get("sid")
    if sid:
        row = db.get(AuthSession, int(sid))
        if row is None or row.revoked or row.user_id != user.id:
            request.session.clear()
            raise HTTPException(status_code=401, detail="Сессия завершена")
        if row.seen_at is None or (datetime.utcnow() - row.seen_at).total_seconds() > 60:
            row.seen_at = datetime.utcnow()
            row.ip = client_ip(request) or row.ip
            db.commit()
    else:
        open_console_session(db, request, user)
        db.commit()
    return user


def resolve_company(user: User, db: Session, company_id: int | None) -> Company:
    if user.role == "company_admin":
        company = db.get(Company, user.company_id)
        if company is None:
            raise HTTPException(status_code=403, detail="Компания администратора не найдена")
        if company_id is not None and int(company_id) != company.id:
            raise HTTPException(status_code=403, detail="Доступ к данным другой компании запрещен")
        return company
    if user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Недостаточно прав")
    if not company_id:
        raise HTTPException(status_code=400, detail="Выберите компанию")
    company = db.get(Company, int(company_id))
    if company is None:
        raise HTTPException(status_code=404, detail="Компания не найдена")
    return company


def company_public(company: Company) -> dict[str, Any]:
    return {
        "id": company.id,
        "name": company.name,
        "domain": company.domain or "",
        "dc_host": company.dc_host or "",
        "dc_user": company.dc_user or "",
        "dc_password_set": bool(company.dc_password),
        "transport": company.transport or "winrm",
        "winrm_port": company.winrm_port or 5985,
        "ssh_port": company.ssh_port or 22,
        "ldap_port": company.ldap_port or 636,
        "ldap_ssl": bool(company.ldap_ssl) if company.ldap_ssl is not None else True,
        "directory_mode": directory_mode_of(company),
        "windows_mode": windows_mode_of(company),
        "runner_host": company.runner_host or "",
        "scan_hosts": company.scan_hosts or "",
        "notify_email": company.notify_email or "",
        "telegram_chat": company.telegram_chat or "",
        "schedule": company.schedule or "weekly",
        "scheduler_enabled": bool(company.scheduler_enabled),
        "risk_index": company.risk_index or 0,
    }


def clean_proxy(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    match = re.fullmatch(r"([A-Za-z0-9.-]{1,253}):(\d{1,5})", raw)
    if not match or not 1 <= int(match.group(2)) <= 65535:
        raise HTTPException(status_code=400, detail="Прокси Telegram: укажите адрес и порт, например 203.0.113.10:3128")
    return raw


def channel_row(db: Session, company_id: int) -> TenantNotifyChannel:
    row = db.get(TenantNotifyChannel, company_id)
    if row is None:
        row = TenantNotifyChannel(id=company_id)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def mail_channel(row: NotifyChannel) -> dict[str, Any]:
    return {
        "tenant_scoped": True,
        "server": row.smtp_server or "",
        "port": row.smtp_port or 587,
        "security": row.smtp_security or "starttls",
        "username": row.smtp_user or "",
        "password": row.smtp_password or "",
        "sender": row.smtp_from or row.smtp_user or "",
    }


def channel_public(row: NotifyChannel) -> dict[str, Any]:
    return {
        "smtp_server": row.smtp_server or "",
        "smtp_port": row.smtp_port or 587,
        "smtp_security": row.smtp_security or "starttls",
        "smtp_user": row.smtp_user or "",
        "smtp_from": row.smtp_from or "",
        "smtp_password_set": bool(row.smtp_password),
        "telegram_chat": row.telegram_chat or "",
        "telegram_token_set": bool(row.telegram_token),
        "telegram_proxy": row.telegram_proxy or "",
    }


def assistant_row(db: Session) -> AssistantSettings:
    row = db.get(AssistantSettings, 1)
    if row is None:
        row = AssistantSettings(
            id=1,
            enabled=(os.getenv("USE_LOCAL_LLM") or "false").lower() == "true",
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def assistant_runtime(row: AssistantSettings) -> dict[str, Any]:
    return {
        "enabled": bool(row.enabled),
        "api_url": (row.api_url or os.getenv("LLM_API_URL") or "").strip(),
        "model_name": (row.model_name or os.getenv("LLM_MODEL_NAME") or "").strip(),
        "api_key": (row.api_key or os.getenv("LLM_API_KEY") or "").strip(),
    }


def assistant_public(row: AssistantSettings) -> dict[str, Any]:
    runtime = assistant_runtime(row)
    if row.api_key:
        source = "saved"
    elif os.getenv("LLM_API_KEY"):
        source = "env"
    else:
        source = "none"
    return {
        "enabled": runtime["enabled"],
        "api_url": runtime["api_url"],
        "model_name": runtime["model_name"],
        "api_key_set": bool(runtime["api_key"]),
        "api_key_source": source,
    }


def inventory_public(row: Inventory) -> dict[str, Any]:
    moment = row.detected_at
    return {
        "id": row.id,
        "hostname": row.hostname,
        "category": row.category,
        "title": repair_caption(row.title or ""),
        "severity": row.severity,
        "severity_label": SEVERITY_RU.get(row.severity, row.severity),
        "detail": row.detail or "",
        "tags": row.tags or "",
        "vuln_id": row.vuln_id or "",
        "mitre": mitre_card(row.vuln_id or "")["id"],
        "tactic": mitre_card(row.vuln_id or "")["tactic"],
        "impact": mitre_card(row.vuln_id or "")["impact"],
        "detected_at": moment.strftime("%d.%m.%Y %H:%M") if moment else "",
        "status": row.status,
    }


_DAY_RU = {"mon": "пн", "tue": "вт", "wed": "ср", "thu": "чт", "fri": "пт", "sat": "сб", "sun": "вс"}
_DAY_ORDER = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def parse_schedule(raw: str) -> tuple[list[str], int, int]:
    text = (raw or "weekly").strip()
    legacy = {"daily": list(_DAY_ORDER), "weekly": ["mon"], "monthly": ["mon"]}
    if text in legacy:
        return legacy[text], 2, 0
    match = re.fullmatch(r"([a-z]{3}(?:,[a-z]{3})*)@(\d{2}):(\d{2})", text)
    if not match:
        return ["mon"], 2, 0
    days = [part for part in match.group(1).split(",") if part in _DAY_RU]
    hour, minute = int(match.group(2)), int(match.group(3))
    if not days or hour > 23 or minute > 59:
        return ["mon"], 2, 0
    return days, hour, minute


def schedule_phrase(raw: str) -> str:
    text = (raw or "").strip()
    hourly = re.fullmatch(r"hourly@(\d{2})", text)
    if hourly:
        minute = int(hourly.group(1))
        if minute > 59:
            minute = 0
        return f"каждый час, на минуте {minute:02d}"
    if text == "monthly":
        return "1-го числа в 02:00"
    days, hour, minute = parse_schedule(raw or "")
    names = ", ".join(_DAY_RU[day] for day in _DAY_ORDER if day in days)
    return f"{names} в {hour:02d}:{minute:02d}"


def scheduler_view(company: Company) -> dict[str, Any]:
    job = scheduler.get_job(f"scan-{company.id}")
    next_run = None
    if job and job.next_run_time:
        next_run = job.next_run_time.astimezone(TZ).strftime("%d.%m.%Y %H:%M")
    if company.scheduler_enabled:
        label = "Включен, " + schedule_phrase(company.schedule or "")
        if next_run:
            label += f", следующий запуск {next_run}"
    else:
        label = "Остановлен"
    return {
        "enabled": bool(company.scheduler_enabled),
        "interval": company.schedule or "weekly",
        "next_run": next_run,
        "label": label,
    }


def timeline_for(db: Session, company_id: int) -> list[dict[str, Any]]:
    months = "янв фев мар апр май июн июл авг сен окт ноя дек".split()
    scans = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.company_id == company_id,
            ScanHistory.risk_score.isnot(None),
            ScanHistory.status.in_(("success", "partial")),
        )
        .order_by(ScanHistory.finished_at.asc(), ScanHistory.id.asc())
        .all()
    )
    points = []
    for scan in scans[-6:]:
        moment = scan.finished_at or scan.started_at or datetime.utcnow()
        points.append(
            {
                "label": f"{months[moment.month - 1]} {moment.year}",
                "when": stamp(moment),
                "score": scan.risk_score,
                "scan_id": scan.id,
                "module": scan.module or "",
                "kind": "platform",
                "actor": scan.actor or "",
            }
        )
    return points


def shadow_hosts(rows: list[Inventory]) -> int:
    hosts = {row.hostname for row in rows if "shadow_it" in (row.tags or "")}
    return len(hosts)


def connection_from(company: Company, host: str) -> dict[str, Any]:
    return {
        "host": host,
        "username": company.dc_user or "",
        "password": company.dc_password or "",
        "transport": company.transport or "winrm",
        "winrm_port": int(company.winrm_port or 5985),
        "ssh_port": int(company.ssh_port or 22),
        "ldap_port": int(company.ldap_port or 636),
        "ldap_ssl": company.transport in {"ldaps", "both"} or bool(company.ldap_ssl),
        "domain": company.domain or "",
    }


def directory_mode_of(company: Company) -> str:
    mode = (getattr(company, "directory_mode", None) or "").strip()
    if mode in {"ldap", "ldaps"}:
        return mode
    if (company.transport or "") == "ldap" or int(company.ldap_port or 636) == 389:
        return "ldap"
    return "ldaps"


def windows_mode_of(company: Company) -> str:
    transport = (company.transport or "winrm").strip()
    if transport in {"winrm", "ssh", "none"}:
        return transport
    if transport == "both":
        return "winrm"
    if transport in {"ldap", "ldaps"}:
        return "none"
    return "winrm"


def uses_windows(connection: dict[str, Any]) -> bool:
    return connection.get("transport") in {"winrm", "ssh", "both"}


def uses_ldap(connection: dict[str, Any]) -> bool:
    return connection.get("transport") in {"ldap", "ldaps", "both"}


def windows_connection(connection: dict[str, Any]) -> dict[str, Any]:
    copied = dict(connection)
    if copied.get("transport") == "both":
        copied["transport"] = "winrm"
    return copied


def windows_required(module: str) -> dict[str, Any]:
    hints = {
        "protocols": "Реестр SMB, LLMNR, NetBIOS, WDigest и подписи LDAP читается на контроллере по WinRM. Типы шифрования Kerberos при этом уже читаются по LDAP.",
        "software_audit": "Список программ читается из реестра Windows. Нужен WinRM или SSH. Одного LDAPS недостаточно.",
        "gpp_passwords": "SYSVOL читается скриптом на контроллере. Нужен WinRM или SSH. Значение cpassword не расшифровывается.",
        "ad_cs": "Шаблоны AD CS читаются по LDAP из раздела конфигурации. WinRM для этой проверки не нужен.",
        "time_sync": "Сдвиг часов снимается командой w32tm на контроллере. Нужен WinRM или SSH.",
    }
    return {
        "ok": False,
        "findings": [],
        "score": None,
        "message": hints.get(module, "Этот модуль выполняется на Windows. Выберите WinRM, SSH или «LDAPS и WinRM»."),
    }


def company_lock(company_id: int) -> threading.Lock:
    with _locks_guard:
        if company_id not in _locks:
            _locks[company_id] = threading.Lock()
        return _locks[company_id]


def replace_findings(db: Session, company_id: int, module: str, findings: list[dict[str, Any]]) -> None:
    marker = f"%module:{module}%"
    db.query(Inventory).filter(
        Inventory.company_id == company_id,
        Inventory.status != "baseline",
        Inventory.tags.like(marker),
    ).delete(synchronize_session=False)
    now = datetime.utcnow()
    for item in findings:
        db.add(
            Inventory(
                company_id=company_id,
                hostname=str(item.get("hostname") or "")[:255],
                category=str(item.get("category") or "Проверка")[:64],
                title=repair_caption(str(item.get("title") or "Находка"))[:512],
                severity=str(item.get("severity") or "medium")[:16],
                detail=str(item.get("detail") or ""),
                tags=str(item.get("tags") or f"module:{module}")[:512],
                vuln_id=str(item.get("vuln_id") or "")[:64],
                detected_at=now,
                status="open",
            )
        )


def score_from_rows(rows: list[Inventory]) -> int:
    weights = {"critical": 16, "high": 8, "medium": 3, "low": 1}
    return min(100, sum(weights.get(row.severity, 0) for row in rows))


def render_report_html(company_name: str, domain: str, score: int | None, summary: str, findings: list[dict], kind: str = "Паспорт сканирования") -> str:
    body = []
    for item in findings:
        body.append(
            "<tr>"
            f"<td>{html.escape(SEVERITY_RU.get(item.get('severity', ''), item.get('severity', '')))}</td>"
            f"<td>{html.escape(item.get('hostname', ''))}</td>"
            f"<td>{html.escape(item.get('title', ''))}</td>"
            f"<td>{html.escape(item.get('detail', ''))}</td>"
            "</tr>"
        )
    if not body:
        body.append("<tr><td colspan='4'>В этом срезе нет детального перечня. Индекс сохранен для тренда.</td></tr>")
    safe_score = "—" if score is None else str(score)
    title = kind or "Паспорт сканирования"
    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><title>{html.escape(title)} — {html.escape(company_name)}</title>
<style>
body {{ margin:0; background:#09090b; color:#fafafa; font-family:Segoe UI,sans-serif; }}
main {{ max-width:1100px; margin:0 auto; padding:32px 20px 64px; }}
h1 {{ font-size:28px; font-weight:650; letter-spacing:-.02em; }}
.muted {{ color:#a1a1aa; }}
.card {{ background:#18181b; border:1px solid #27272a; border-radius:16px; padding:20px; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ border-bottom:1px solid #27272a; text-align:left; padding:10px 8px; vertical-align:top; }}
th {{ color:#a1a1aa; font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
</style></head><body><main>
<p class="muted">BroSec Audit AD · {html.escape(title)}</p>
<h1>{html.escape(title)}</h1>
<div class="card">
<p><b>Компания:</b> {html.escape(company_name)}<br>
<b>Домен:</b> {html.escape(domain or "не указан")}<br>
<b>Индекс риска платформы:</b> {safe_score}</p>
<p class="muted">{html.escape(summary or "")}</p>
<table><thead><tr><th>Критичность</th><th>Узел</th><th>Находка</th><th>Описание</th></tr></thead>
<tbody>{''.join(body)}</tbody></table>
</div></main></body></html>"""


def write_report_file(scan: ScanHistory, company: Company) -> None:
    if not scan.report_html_path:
        scan.report_html_path = str(REPORTS_DIR / str(company.id) / f"{scan.id}.html")
    try:
        payload = json.loads(scan.log or "{}")
    except json.JSONDecodeError:
        payload = {}
    path = Path(scan.report_html_path)
    if REPORTS_DIR.resolve() not in path.resolve().parents:
        raise ValueError("Путь отчета вне каталога reports")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_report_html(
            company.name,
            company.domain or "",
            scan.risk_score,
            scan.summary or "",
            payload.get("findings") or [],
            "Паспорт сканирования",
        ),
        encoding="utf-8",
    )


def ensure_fonts() -> tuple[str, str]:
    global _fonts_ready
    regular = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    bold = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    if not _fonts_ready:
        pdfmetrics.registerFont(TTFont("DejaVu", regular))
        pdfmetrics.registerFont(TTFont("DejaVuBold", bold))
        _fonts_ready = True
    return "DejaVu", "DejaVuBold"


def build_pdf(path: Path, company: Company, rows: list[Inventory], score: int) -> None:
    from reportlab.graphics.shapes import Drawing, Rect, String

    font, font_bold = ensure_fonts()
    styles = getSampleStyleSheet()
    title = ParagraphStyle("RuTitle", parent=styles["Title"], fontName=font_bold, fontSize=16, leading=20, textColor=colors.HexColor("#0b1220"))
    body = ParagraphStyle("RuBody", parent=styles["Normal"], fontName=font, fontSize=9, leading=12, textColor=colors.HexColor("#1f2937"))
    small = ParagraphStyle("RuSmall", parent=styles["Normal"], fontName=font, fontSize=7.5, leading=9, textColor=colors.HexColor("#1f2937"))
    head = ParagraphStyle("RuHead", parent=styles["Normal"], fontName=font_bold, fontSize=7.5, leading=9, textColor=colors.white)
    visible = [row for row in rows if row.severity != "info"]
    counts = {key: sum(1 for row in visible if row.severity == key) for key in ("critical", "high", "medium", "low")}
    peak = max(list(counts.values()) or [1]) or 1
    drawing = Drawing(460, 110)
    palette = {"critical": "#ef4444", "high": "#f59e0b", "medium": "#3b82f6", "low": "#10b981"}
    labels = {"critical": "Критические", "high": "Высокие", "medium": "Средние", "low": "Низкие"}
    for index, key in enumerate(("critical", "high", "medium", "low")):
        height = 70 * counts[key] / peak
        drawing.add(Rect(24 + index * 110, 18, 28, height, fillColor=colors.HexColor(palette[key]), strokeColor=None))
        drawing.add(String(24 + index * 110, 4, f"{labels[key]}: {counts[key]}", fontName=font, fontSize=8, fillColor=colors.HexColor("#111827")))
    story = [
        Paragraph("Паспорт безопасности домена", title),
        Paragraph("BroSec Audit AD", body),
        Spacer(1, 4),
        Paragraph(f"Компания: {html.escape(company.name)}. Домен: {html.escape(company.domain or 'не указан')}.", body),
        Paragraph(f"Дата: {datetime.now(TZ).strftime('%d.%m.%Y %H:%M')} (Москва). Индекс риска AD: {score}.", body),
        Spacer(1, 4),
        Paragraph("Сколько находок каждого уровня", body),
        drawing,
        Spacer(1, 6),
        Paragraph("По каждой проблеме: что не так, на что это влияет, как закрыть и номер MITRE ATT&CK.", body),
    ]
    table_data = [[
        Paragraph("Уровень", head),
        Paragraph("Проблема", head),
        Paragraph("На что влияет", head),
        Paragraph("Как закрыть", head),
        Paragraph("MITRE", head),
    ]]
    for row in visible[:250]:
        meta = mitre_card(row.vuln_id or "")
        table_data.append([
            Paragraph(html.escape(SEVERITY_RU.get(row.severity, row.severity)), small),
            Paragraph(html.escape(f"{row.title}. Объект: {row.hostname}"), small),
            Paragraph(html.escape(meta["impact"]), small),
            Paragraph(html.escape(meta["closure"]), small),
            Paragraph(html.escape(f"{meta['id']} {meta['tactic']}"), small),
        ])
    table = Table(table_data, colWidths=[22 * mm, 42 * mm, 42 * mm, 42 * mm, 28 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    story.append(table)
    story.append(Spacer(1, 8))
    story.append(Paragraph("Документ конфиденциален и предназначен только для службы ИБ выбранной компании. Номера MITRE нужны для приоритизации, это не инструкция по атаке.", body))
    path.parent.mkdir(parents=True, exist_ok=True)
    SimpleDocTemplate(
        str(path),
        pagesize=A4,
        title="Паспорт безопасности домена",
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
    ).build(story)


def excel_cell(value: object) -> str:
    text = "" if value is None else str(value)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    return text[:32000]


def build_excel(path: Path, company: Company, rows: list[Inventory], scans: list[ScanHistory], score: int, note: str = "") -> None:
    findings = pd.DataFrame([
        {
            "Критичность": excel_cell(SEVERITY_RU.get(row.severity, row.severity)),
            "Узел": excel_cell(row.hostname),
            "Категория": excel_cell(row.category),
            "Находка": excel_cell(row.title),
            "Описание": excel_cell(row.detail),
            "Теги": excel_cell(row.tags),
            "На что влияет": excel_cell(mitre_card(row.vuln_id or "")["impact"]),
            "Как закрыть": excel_cell(mitre_card(row.vuln_id or "")["closure"]),
            "MITRE": excel_cell(mitre_card(row.vuln_id or "")["id"]),
            "Тактика MITRE": excel_cell(mitre_card(row.vuln_id or "")["tactic"]),
            "Техника MITRE": excel_cell(mitre_card(row.vuln_id or "")["name"]),
            "Стандарт CIS": excel_cell(STANDARDS.get(row.vuln_id, ("", ""))[0]),
            "ГОСТ": excel_cell(STANDARDS.get(row.vuln_id, ("", ""))[1]),
            "Обнаружено": row.detected_at.strftime("%d.%m.%Y %H:%M") if row.detected_at else "",
            "Статус": excel_cell(row.status),
        }
        for row in rows
    ])
    if findings.empty:
        findings = pd.DataFrame(columns=["Критичность", "Узел", "Категория", "Находка", "Описание", "Теги", "На что влияет", "Как закрыть", "MITRE", "Тактика MITRE", "Техника MITRE", "Стандарт CIS", "ГОСТ", "Обнаружено", "Статус"])
    history = pd.DataFrame([
        {
            "Дата": (scan.finished_at or scan.started_at).strftime("%d.%m.%Y %H:%M") if (scan.finished_at or scan.started_at) else "",
            "Модули": excel_cell(scan.module),
            "Контроллер": excel_cell(scan.target_dc),
            "Статус": excel_cell(scan.status),
            "Индекс": scan.risk_score if scan.risk_score is not None else "",
            "Сводка": excel_cell(scan.summary),
        }
        for scan in scans
    ])
    summary = pd.DataFrame([
        {"Показатель": "Компания", "Значение": excel_cell(company.name)},
        {"Показатель": "Домен", "Значение": excel_cell(company.domain or "")},
        {"Показатель": "Индекс риска AD", "Значение": score},
        {"Показатель": "Хостов с Shadow IT", "Значение": shadow_hosts(rows)},
        {"Показатель": "Ловушек", "Значение": sum(1 for row in rows if row.vuln_id == "honeytoken")},
        {"Показатель": "Строк в файле", "Значение": len(rows)},
        {"Показатель": "Отбор", "Значение": note or "Весь текущий каталог"},
    ])
    path.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        summary.to_excel(writer, sheet_name="Сводка", index=False)
        findings.to_excel(writer, sheet_name="Находки", index=False)
        history.to_excel(writer, sheet_name="История", index=False)
        tactics = tactics_of(rows)
        pd.DataFrame(tactics or [{"tactic": "нет", "count": 0}]).to_excel(writer, sheet_name="MITRE", index=False)
        book = writer.book
        sheet = book["MITRE"]
        if tactics:
            try:
                from openpyxl.chart import BarChart, Reference

                chart = BarChart()
                chart.title = "Находки по тактикам MITRE ATT&CK"
                chart.y_axis.title = "Находки"
                chart.x_axis.title = None
                data = Reference(sheet, min_col=2, min_row=1, max_row=len(tactics) + 1)
                cats = Reference(sheet, min_col=1, min_row=2, max_row=len(tactics) + 1)
                chart.add_data(data, titles_from_data=True)
                chart.set_categories(cats)
                chart.shape = 4
                chart.height = 8
                chart.width = 18
                sheet.add_chart(chart, "D2")
            except Exception:
                log.exception("excel chart")
        from openpyxl.styles import Font, PatternFill

        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill("solid", fgColor="111827")
        for name in ("Сводка", "Находки", "История", "MITRE"):
            page = book[name]
            page.auto_filter.ref = page.dimensions
            page.freeze_panes = "A2"
            for cell in page[1]:
                cell.font = header_font
                cell.fill = header_fill


def attachment(path: Path, download_name: str, media_type: str) -> FileResponse:
    response = FileResponse(path, media_type=media_type, filename="report.bin")
    response.headers["Content-Disposition"] = (
        f"attachment; filename=report.bin; filename*=UTF-8''{quote(download_name)}"
    )
    return response


def stamp(moment: datetime | None) -> str:
    if moment is None:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=ZoneInfo("UTC"))
    return moment.astimezone(TZ).strftime("%d.%m.%Y %H:%M")


def write_audit(db: Session, user: User | None, action: str, detail: str, company_id: int | None = None, username: str = "") -> None:
    db.add(
        AuditEvent(
            created_at=datetime.utcnow(),
            user_id=user.id if user else None,
            username=((user.username if user else username) or "")[:64],
            company_id=company_id,
            action=action[:64],
            detail=(detail or "")[:1000],
        )
    )


def publish_notice(db: Session, company_id: int | None, title: str, body: str, kind: str) -> None:
    query = db.query(User).filter(User.role == "superadmin")
    if company_id:
        query = db.query(User).filter(or_(User.role == "superadmin", User.company_id == company_id))
    now = datetime.utcnow()
    for person in query.all():
        db.add(
            ConsoleNotice(
                user_id=person.id,
                company_id=company_id,
                kind=kind[:32],
                title=title[:200],
                body=(body or "")[:1000],
                created_at=now,
            )
        )


def publish_scan_notice(db: Session, scan: ScanHistory, company: Company) -> None:
    actor = scan.actor or "система"
    critical = 0
    try:
        payload = json.loads(scan.log or "{}")
        findings = payload.get("findings") if isinstance(payload, dict) else []
        critical = sum(1 for item in findings or [] if isinstance(item, dict) and item.get("severity") == "critical")
    except json.JSONDecodeError:
        critical = 0
    title = "Сканирование завершено" if scan.status == "success" else "Сканирование завершилось с оговоркой" if scan.status == "partial" else "Сканирование не выполнено"
    body = f"{company.name}. Запустил: {actor}. Статус: {scan.status}. Индекс: {scan.risk_score if scan.risk_score is not None else '—'}."
    if critical:
        body += f" Новых критических в этом запуске: {critical}."
    publish_notice(db, company.id, title, body, "scan")


_MODULE_SHORT = {
    "ad_cs": "AD CS",
    "software_audit": "Аудит ПО",
    "gpp_passwords": "Пароли в GPO",
    "dc_hardening": "Харденинг",
    "trusts": "Доверия и SID",
    "time_sync": "Время",
    "baseline_hygiene": "Гигиена",
    "protocols": "Протоколы",
}


def progress_document(modules: list[str], states: dict[str, str], notes: dict[str, str], times: dict[str, str], hosts: dict[str, int] | None) -> dict[str, Any]:
    return {
        "kind": "progress",
        "modules": [
            {
                "id": module,
                "title": _MODULE_SHORT.get(module, MODULE_TITLES.get(module, module)),
                "state": states.get(module, "wait"),
                "note": notes.get(module) or ("ждёт" if states.get(module, "wait") == "wait" else ""),
                "at": times.get(module, ""),
            }
            for module in modules
        ],
        "hosts": hosts,
    }


def read_progress(scan: ScanHistory) -> dict[str, Any] | None:
    try:
        parsed = json.loads(scan.log or "")
    except (TypeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    progress = parsed.get("progress") if parsed.get("kind") == "live" else parsed if parsed.get("kind") == "progress" else None
    if not isinstance(progress, dict):
        return None
    end = scan.finished_at or datetime.utcnow()
    start = scan.started_at or end
    view = dict(progress)
    view["elapsed_sec"] = max(0, int((end - start).total_seconds()))
    view["status"] = scan.status
    return view


def execute_scan(scan_id: int) -> None:
    db = SessionLocal()
    scan = db.get(ScanHistory, scan_id)
    if scan is None:
        db.close()
        return
    lock = company_lock(scan.company_id)
    if not lock.acquire(blocking=False):
        scan.status = "failed"
        scan.summary = "Проверка этой компании уже выполняется."
        scan.finished_at = datetime.utcnow()
        db.commit()
        db.close()
        return
    try:
        company = db.get(Company, scan.company_id)
        scan.status = "running"
        db.commit()
        modules = [item for item in (scan.module or "").split(",") if item in ALLOWED_MODULES]
        host = scan.target_dc or company.dc_host
        connection = connection_from(company, host) if host else None
        if connection:
            connection["transport"] = directory_mode_of(company)
            connection["ldap_ssl"] = connection["transport"] == "ldaps"
            connection["ldap_port"] = 636 if connection["ldap_ssl"] else int(company.ldap_port or 389)
        win_mode = windows_mode_of(company)
        runner = (company.runner_host or "").strip() or host
        win_connection = connection_from(company, runner) if runner and win_mode in {"winrm", "ssh"} else None
        if win_connection:
            win_connection["transport"] = win_mode
        dc_windows = connection_from(company, host) if host and win_mode in {"winrm", "ssh"} else None
        if dc_windows:
            dc_windows["transport"] = win_mode
        notes: list[str] = []
        collected: list[dict[str, Any]] = []
        score = None
        ok_count = 0
        states = {module: "wait" for module in modules}
        note_map: dict[str, str] = {}
        time_map: dict[str, str] = {}
        hosts_progress: dict[str, int] | None = None

        def save_progress() -> None:
            scan.log = json.dumps(progress_document(modules, states, note_map, time_map, hosts_progress), ensure_ascii=False)
            db.commit()

        if modules:
            states[modules[0]] = "now"
            time_map[modules[0]] = datetime.now(TZ).strftime("%H:%M")
        save_progress()
        for module in modules:
            states[module] = "now"
            time_map.setdefault(module, datetime.now(TZ).strftime("%H:%M"))
            save_progress()
            try:
                if not connection or not connection["username"] or not connection["password"]:
                    result = {
                        "ok": False,
                        "findings": [],
                        "score": None,
                        "message": "Не заданы учетные данные. Для каталога достаточно служебной учетной записи домена с правом чтения.",
                    }
                elif module == "protocols":
                    findings: list[dict[str, Any]] = []
                    bits: list[str] = []
                    ldap_part = scan_protocols_ldap(connection)
                    findings.extend(ldap_part.get("findings") or [])
                    bits.append(str(ldap_part.get("message") or ""))
                    if dc_windows:
                        win_part = scan_protocols_windows(windows_connection(dc_windows))
                        findings.extend(win_part.get("findings") or [])
                        bits.append(str(win_part.get("message") or ""))
                    else:
                        bits.append("Реестр контроллера не читался. Для SMB, LLMNR, NetBIOS и WDigest нужен WinRM именно на контроллер.")
                    result = {"ok": bool(ldap_part.get("ok") or findings), "findings": findings, "score": None, "message": " ".join(bits)}
                elif module == "ad_cs":
                    result = scan_adcs_ldap(connection)
                elif module in {"trusts", "baseline_hygiene"}:
                    result = scan_trusts_ldap(connection) if module == "trusts" else scan_hygiene_ldap(connection)
                elif module == "dc_hardening" and not dc_windows:
                    result = scan_hardening_ldap(connection)
                elif module == "software_audit" and not win_connection:
                    result = windows_required(module)
                elif module not in {"software_audit", "dc_hardening"} and not dc_windows and module not in {"trusts", "baseline_hygiene", "protocols"}:
                    result = windows_required(module)
                else:
                    remote_tools = windows_connection(win_connection) if win_connection else None
                    remote_dc = windows_connection(dc_windows) if dc_windows else None
                    if module == "software_audit":
                        extra = company.scan_hosts or ""
                        catalog_note = ""
                        try:
                            discovered = list_computer_names(connection)
                            if discovered:
                                extra = "\n".join(part for part in (extra, "\n".join(discovered)) if part)
                                catalog_note = f"Компьютеров в каталоге: {len(discovered)}. "
                        except Exception as exc:
                            catalog_note = f"Список компьютеров каталога не прочитан: {exc}. "
                        def on_hosts(payload: dict[str, int]) -> None:
                            nonlocal hosts_progress
                            hosts_progress = payload
                            note_map[module] = f"{payload.get('seen', 0)} из {payload.get('total', 0)}"
                            save_progress()

                        result = scan_software(remote_tools, extra, on_hosts)
                        if catalog_note:
                            result["message"] = catalog_note + str(result.get("message") or "")
                    elif module == "gpp_passwords":
                        result = scan_gpp(remote_dc)
                    elif module == "dc_hardening":
                        result = scan_hardening(remote_dc)
                    elif module == "trusts":
                        result = scan_trusts(remote_dc)
                    elif module == "time_sync":
                        result = scan_time(remote_dc)
                    elif module == "baseline_hygiene":
                        result = scan_hygiene(remote_dc)
                    else:
                        result = {"ok": False, "findings": [], "score": None, "message": "Неизвестный модуль"}
            except Exception as exc:
                log.exception("module %s failed", module)
                result = {"ok": False, "findings": [], "score": None, "message": str(exc)}
            message = str(result.get("message") or "")
            if company.dc_password:
                message = message.replace(company.dc_password, "[скрыто]")
            notes.append(f"{MODULE_TITLES.get(module, module)}: {message}")
            short = message.split("\n", 1)[0][:160]
            if result.get("ok"):
                ok_count += 1
                states[module] = "done"
                note_map[module] = short or "готово"
                replace_findings(db, company.id, module, result.get("findings") or [])
                collected.extend(result.get("findings") or [])
                if result.get("score") is not None:
                    score = int(result["score"])
            else:
                states[module] = "error"
                note_map[module] = short or "ошибка"
            save_progress()
        rows = db.query(Inventory).filter(Inventory.company_id == company.id).all()
        if score is None:
            score = score_from_rows(rows)
        company.risk_index = score
        scan.risk_score = score
        scan.summary = "\n".join(notes)[:8000]
        scan.log = json.dumps(
            {"kind": "live", "progress": progress_document(modules, states, note_map, time_map, hosts_progress), "findings": collected},
            ensure_ascii=False,
        )
        scan.finished_at = datetime.utcnow()
        if ok_count == 0:
            scan.status = "failed"
        elif ok_count < len(modules):
            scan.status = "partial"
        else:
            scan.status = "success"
        scan.report_html_path = str(REPORTS_DIR / str(company.id) / f"{scan.id}.html")
        write_report_file(scan, company)
        pdf_path = REPORTS_DIR / str(company.id) / f"passport-{scan.id}.pdf"
        try:
            build_pdf(pdf_path, company, rows, score)
        except Exception as exc:
            log.exception("pdf failed")
            notes.append(f"PDF не собран: {exc}")
            pdf_path = None
        db.commit()
        text = (
            f"BroSec Audit AD\nКомпания: {company.name}\nКонтроллер: {host}\n"
            f"Индекс риска: {score}\nСтатус: {scan.status}\n\n{scan.summary}"
        )
        try:
            extra = dispatch_notifications(db, company, scan, text, collected, str(pdf_path) if pdf_path else None)
            if extra:
                scan.summary = (scan.summary + "\n" + "\n".join(extra))[:8000]
            publish_scan_notice(db, scan, company)
            if extra:
                publish_notice(db, company.id, "Почта или Telegram не доставили сообщение", "\n".join(extra)[:900], "error")
            db.commit()
        except Exception:
            log.exception("notice")
    except Exception as exc:
        log.exception("scan %s failed", scan_id)
        scan.status = "failed"
        scan.summary = f"Проверка прервана: {exc}"
        scan.finished_at = datetime.utcnow()
        db.commit()
        try:
            failed_company = db.get(Company, scan.company_id)
            if failed_company is not None:
                reason = scan.summary or "Проверка прервана."
                extra = dispatch_notifications(db, failed_company, scan, reason, [], None)
                publish_scan_notice(db, scan, failed_company)
                if extra:
                    publish_notice(db, failed_company.id, "Почта или Telegram не доставили сообщение", "\n".join(extra)[:900], "error")
                db.commit()
        except Exception:
            log.exception("notice")
    finally:
        lock.release()
        db.close()


NOTIFY_TOPICS = ("scan_done", "scan_failed", "software_danger", "adcs", "gpp", "trust", "critical")
SOFTWARE_ALERTS = {"rat_detected", "remote_access_detected", "vpn_unauthorized"}
TOPIC_TITLES = {
    "software_danger": "Опасное ПО на хосте",
    "adcs": "Шаблон сертификатов",
    "gpp": "Пароль в групповой политике",
    "trust": "Доверие без фильтрации SID",
    "critical": "Критичные и высокие находки",
}


def default_notify_prefs() -> dict[str, dict[str, bool]]:
    return {key: {"mail": True, "telegram": True} for key in NOTIFY_TOPICS}


def read_notify_prefs(row: NotifyChannel) -> dict[str, dict[str, bool]]:
    data = default_notify_prefs()
    raw = getattr(row, "prefs", "") or ""
    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {}
    if not isinstance(parsed, dict):
        return data
    for key in NOTIFY_TOPICS:
        item = parsed.get(key)
        if isinstance(item, dict):
            if "mail" in item:
                data[key]["mail"] = bool(item["mail"])
            if "telegram" in item:
                data[key]["telegram"] = bool(item["telegram"])
    return data


def finding_topics(item: dict) -> list[str]:
    vid = str(item.get("vuln_id") or "")
    topics: list[str] = []
    if vid in SOFTWARE_ALERTS:
        topics.append("software_danger")
    if vid.startswith("adcs"):
        topics.append("adcs")
    if vid == "gpp_password":
        topics.append("gpp")
    if vid == "trust_sid_filter":
        topics.append("trust")
    if str(item.get("severity") or "") in {"critical", "high"}:
        topics.append("critical")
    return topics


def alert_body(prefs: dict, channel: str, status_key: str, summary_text: str, collected: list) -> str:
    parts: list[str] = []
    if prefs.get(status_key, {}).get(channel):
        parts.append(summary_text)
    buckets: dict[str, list] = {key: [] for key in TOPIC_TITLES}
    for item in collected:
        if not isinstance(item, dict):
            continue
        for topic in finding_topics(item):
            if topic in buckets:
                buckets[topic].append(item)
    used: set[tuple[str, str, str]] = set()
    for key in ("software_danger", "adcs", "gpp", "trust", "critical"):
        if not prefs.get(key, {}).get(channel):
            continue
        lines = []
        for item in buckets[key]:
            marker = (str(item.get("vuln_id") or ""), str(item.get("hostname") or ""), str(item.get("title") or ""))
            if key == "critical" and marker in used:
                continue
            used.add(marker)
            lines.append(f"- {item.get('hostname') or 'объект'}: {item.get('title') or ''}")
        if lines:
            parts.append(TOPIC_TITLES[key] + "\n" + "\n".join(lines[:8]))
    return "\n\n".join(part for part in parts if part).strip()


def _mail_finding(item: dict, topic: str) -> dict:
    if topic == "gpp":
        return {
            "severity": item.get("severity") or "critical",
            "hostname": item.get("hostname") or "объект",
            "title": "В предпочтении групповой политики есть атрибут cpassword. Значение пароля не читалось и в письмо не входит.",
            "vuln_id": "gpp_password",
        }
    return {
        "severity": item.get("severity") or "",
        "hostname": item.get("hostname") or "объект",
        "title": item.get("title") or "",
        "vuln_id": item.get("vuln_id") or "",
    }


def _redact_delivery(lines: list[str], secrets: list[str]) -> list[str]:
    clean = list(lines)
    for secret in secrets:
        if secret:
            clean = [line.replace(secret, "***") for line in clean]
    return clean


def _compact_delivery_errors(errors: list[str]) -> list[str]:
    """Collapse identical channel errors so one scan creates one actionable notice."""
    counts: dict[str, int] = {}
    order: list[str] = []
    for raw in errors:
        text = str(raw).strip()
        if not text:
            continue
        if text not in counts:
            order.append(text)
            counts[text] = 0
        counts[text] += 1
    compact: list[str] = []
    for text in order:
        count = counts[text]
        compact.append(f"{text} (повторено {count} раз)" if count > 1 else text)
    return compact


def dispatch_notifications(db: Session, company: Company, scan: ScanHistory, summary_text: str, collected: list, pdf_path: str | None) -> list[str]:
    """Каждая включённая почтовая тема уходит отдельным письмом. Telegram остаётся одной сводкой."""
    channel = channel_row(db, company.id)
    prefs = read_notify_prefs(channel)
    chat = (company.telegram_chat or channel.telegram_chat or "").strip()
    status_key = "scan_failed" if scan.status == "failed" else "scan_done"
    errors: list[str] = []
    tg_text = alert_body(prefs, "telegram", status_key, summary_text, collected)
    if tg_text and not (channel.telegram_token and chat):
        errors.append("Telegram выбранной компании не настроен.")
    elif tg_text:
        telegram = send_summary(tg_text, pdf_path if status_key == "scan_done" else None, channel.telegram_token, chat, channel.telegram_proxy)
        if not telegram.get("ok"):
            errors.append(str(telegram.get("error") or "Telegram не доставил сводку."))
    if prefs.get(status_key, {}).get("mail"):
        headline = "Сканирование остановилось с ошибкой" if status_key == "scan_failed" else "Сканирование завершилось"
        mail = send_report(
            company.name,
            summary_text,
            [],
            pdf_path if status_key == "scan_done" else None,
            company.notify_email,
            mail_channel(channel),
            subject=f"{headline} — {company.name}",
            headline=headline,
            include_findings=False,
        )
        if not mail.get("ok"):
            errors.append(str(mail.get("error") or "Письмо об итоге не ушло."))
    buckets: dict[str, list] = {key: [] for key in TOPIC_TITLES}
    for item in collected:
        if isinstance(item, dict):
            for topic in finding_topics(item):
                if topic in buckets:
                    buckets[topic].append(item)
    used: set[tuple[str, str, str]] = set()
    for key in ("software_danger", "adcs", "gpp", "trust", "critical"):
        if not prefs.get(key, {}).get("mail"):
            continue
        rows = []
        for item in buckets[key]:
            marker = (str(item.get("vuln_id") or ""), str(item.get("hostname") or ""), str(item.get("title") or ""))
            if key == "critical" and marker in used:
                continue
            used.add(marker)
            rows.append(_mail_finding(item, "gpp" if str(item.get("vuln_id") or "") == "gpp_password" else key))
        if not rows:
            continue
        mail = send_report(
            company.name,
            TOPIC_TITLES[key] + ". Строки ниже относятся только к этой теме.",
            rows,
            None,
            company.notify_email,
            mail_channel(channel),
            subject=f"{TOPIC_TITLES[key]} — {company.name}",
            headline=TOPIC_TITLES[key],
        )
        if not mail.get("ok"):
            errors.append(str(mail.get("error") or f"Письмо «{TOPIC_TITLES[key]}» не ушло."))
    redacted = _redact_delivery(errors, [channel.smtp_password or "", channel.telegram_token or ""])
    return _compact_delivery_errors(redacted)


def apply_company_schedule(company: Company) -> None:
    job_id = f"scan-{company.id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    if not company.scheduler_enabled:
        return
    if (company.schedule or "") == "monthly":
        trigger = CronTrigger(day=1, hour=2, minute=0, timezone=TZ)
    elif re.fullmatch(r"hourly@\d{2}", company.schedule or ""):
        minute = int((company.schedule or "hourly@00").split("@", 1)[1])
        if minute > 59:
            minute = 0
        trigger = CronTrigger(minute=minute, timezone=TZ)
    else:
        days, hour, minute = parse_schedule(company.schedule or "")
        trigger = CronTrigger(day_of_week=",".join(days), hour=hour, minute=minute, timezone=TZ)
    scheduler.add_job(
        scheduled_scan,
        trigger,
        id=job_id,
        args=[company.id],
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )


def scheduled_scan(company_id: int) -> None:
    db = SessionLocal()
    try:
        company = db.get(Company, company_id)
        if company is None or not company.scheduler_enabled:
            return
        scan = ScanHistory(
            company_id=company.id,
            module=",".join(ALLOWED_MODULES),
            target_dc=company.dc_host or company.domain or "",
            status="queued",
            started_at=datetime.utcnow(),
            actor="Расписание",
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()
    execute_scan(scan_id)


def reload_schedules() -> None:
    db = SessionLocal()
    try:
        for company in db.query(Company).all():
            apply_company_schedule(company)
    finally:
        db.close()


def _scan_findings(scan: ScanHistory) -> list[dict[str, Any]]:
    try:
        payload = json.loads(scan.log or "{}")
    except json.JSONDecodeError:
        return []
    findings = payload.get("findings") if isinstance(payload, dict) else None
    return findings if isinstance(findings, list) else []


def _finding_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(item.get("vuln_id") or ""),
        str(item.get("hostname") or ""),
        str(item.get("title") or ""),
    )


def compare_scans(db: Session, company_id: int) -> dict[str, Any]:
    scans = (
        db.query(ScanHistory)
        .filter(
            ScanHistory.company_id == company_id,
            ScanHistory.status.in_(("success", "partial")),
        )
        .order_by(ScanHistory.finished_at.asc(), ScanHistory.id.asc())
        .all()
    )
    packed = [(scan, _scan_findings(scan)) for scan in scans]
    packed = [(scan, findings) for scan, findings in packed if findings and (scan.module or "") != "pingcastle"]
    if len(packed) < 2:
        return {
            "ready": False,
            "message": "Два сканирования ещё не завершены. Этот блок сравнивает последние запуски платформы.",
            "added": [],
            "removed": [],
        }
    left_scan, left_findings = packed[-2]
    right_scan, right_findings = packed[-1]
    left_map = {_finding_key(item): item for item in left_findings}
    right_map = {_finding_key(item): item for item in right_findings}
    added = [right_map[key] for key in right_map if key not in left_map]
    removed = [left_map[key] for key in left_map if key not in right_map]

    def label(scan: ScanHistory) -> str:
        moment = scan.finished_at or scan.started_at
        stamp = moment.strftime("%d.%m.%Y %H:%M") if moment else "без даты"
        return f"{stamp}, индекс {scan.risk_score if scan.risk_score is not None else '—'}"

    return {
        "ready": True,
        "message": f"Сравнение двух последних сканирований. Появилось {len(added)}, исчезло {len(removed)}.",
        "left": {"id": left_scan.id, "label": label(left_scan), "score": left_scan.risk_score},
        "right": {"id": right_scan.id, "label": label(right_scan), "score": right_scan.risk_score},
        "added": added,
        "removed": removed,
    }


def ensure_brosec_samples() -> None:
    """Демонстрационные базовые находки. Реальные учетные записи заказчика сюда не копируются."""
    samples = [
        {
            "hostname": "partner.holding.local",
            "category": "Доверительные отношения",
            "title": "Фильтрация SID выключена: partner.holding.local",
            "severity": "critical",
            "detail": "Внешнее двустороннее доверие, карантин SID не включен. Выборочная проверка подлинности выключена.",
            "tags": "trust,sid-filter,baseline,module:trusts",
            "vuln_id": "trust_sid_filter",
        },
        {
            "hostname": "hq.internal",
            "category": "Доверительные отношения",
            "title": "Доверие hq.internal: фильтрация SID включена",
            "severity": "info",
            "detail": "Лесное доверие, карантин SID включен.",
            "tags": "trust,sid-filter,baseline,module:trusts",
            "vuln_id": "trust_ok",
        },
        {
            "hostname": "dc02",
            "category": "Время контроллеров",
            "title": "Расхождение времени 412 с — Kerberos уже ненадежен",
            "severity": "critical",
            "detail": "Смещение dc02 относительно PDC больше порога Kerberos в 300 секунд.",
            "tags": "time,kerberos,baseline,module:time_sync",
            "vuln_id": "time_skew",
        },
        {
            "hostname": "dc01",
            "category": "Время контроллеров",
            "title": "Время в допуске: 0.040 с",
            "severity": "info",
            "detail": "PDC отвечает, смещение меньше 30 секунд.",
            "tags": "time,kerberos,baseline,module:time_sync",
            "vuln_id": "time_ok",
        },
        {
            "hostname": "srv-file-01",
            "category": "Устаревшие ОС",
            "title": "Устаревшая операционная система",
            "severity": "critical",
            "detail": "Windows Server 2012 R2 Standard 6.3 (9600). Поддержка безопасности закончилась.",
            "tags": "baseline,hygiene,obsolete,module:baseline_hygiene",
            "vuln_id": "obsolete_os",
        },
        {
            "hostname": "office.user",
            "category": "Привилегии",
            "title": "Обычная учетная запись в привилегированной группе",
            "severity": "high",
            "detail": "Domain Admins. Имя не похоже на выделенную административную запись (.adm / svc).",
            "tags": "baseline,hygiene,privileged,module:baseline_hygiene",
            "vuln_id": "ordinary_privileged",
        },
        {
            "hostname": "svc-mail-legacy",
            "category": "Пароли",
            "title": "Пароль старше 90 дней при недавнем входе",
            "severity": "high",
            "detail": "Пароль не менялся 640 дней, последний вход был на этой неделе.",
            "tags": "baseline,hygiene,password,module:baseline_hygiene",
            "vuln_id": "stale_password",
        },
        {
            "hostname": "test.account",
            "category": "Неактивные учетные записи",
            "title": "Нет входа более 90 дней и пароль устарел",
            "severity": "high",
            "detail": "Включенная запись. Последний вход больше года назад, пароль старше 400 дней.",
            "tags": "baseline,hygiene,stale,module:baseline_hygiene",
            "vuln_id": "inactive_stale",
        },
        {
            "hostname": "Guest",
            "category": "Гостевой доступ",
            "title": "Включена учетная запись гостя",
            "severity": "medium",
            "detail": "Встроенная запись Guest включена.",
            "tags": "baseline,hygiene,guest,module:baseline_hygiene",
            "vuln_id": "guest_enabled",
        },
    ]
    retired = {
        "hostname": "dc-old",
        "category": "Каталог",
        "title": "Анонимные запросы LDAP на выведенном контроллере",
        "severity": "high",
        "detail": "В прошлом срезе контроллер принимал анонимный LDAP. В текущем срезе узел отсутствует.",
        "tags": "baseline,module:baseline_hygiene",
        "vuln_id": "ldap_anonymous_retired",
    }
    db = SessionLocal()
    try:
        for company in db.query(Company).all():
            has_baseline = (
                db.query(Inventory)
                .filter(Inventory.company_id == company.id, Inventory.status == "baseline")
                .first()
            )
            if has_baseline is None:
                continue
            already = (
                db.query(Inventory)
                .filter(Inventory.company_id == company.id, Inventory.vuln_id == "trust_sid_filter")
                .first()
            )
            if already is not None:
                continue
            now = datetime.utcnow()
            for item in samples:
                db.add(
                    Inventory(
                        company_id=company.id,
                        hostname=item["hostname"],
                        category=item["category"],
                        title=item["title"],
                        severity=item["severity"],
                        detail=item["detail"],
                        tags=item["tags"],
                        vuln_id=item["vuln_id"],
                        detected_at=now,
                        status="baseline",
                    )
                )
            scans = (
                db.query(ScanHistory)
                .filter(ScanHistory.company_id == company.id, ScanHistory.status.in_(("success", "partial")))
                .order_by(ScanHistory.finished_at.asc(), ScanHistory.id.asc())
                .all()
            )
            if len(scans) < 2:
                continue
            latest, previous = scans[-1], scans[-2]
            current = _scan_findings(latest)
            known = {_finding_key(item) for item in current}
            for item in samples:
                if _finding_key(item) not in known:
                    current.append(item)
            latest.log = json.dumps({"kind": "baseline", "findings": current}, ensure_ascii=False)
            appeared = {"trust_sid_filter", "time_skew", "ordinary_privileged"}
            previous_findings = [item for item in current if item.get("vuln_id") not in appeared]
            previous_findings.append(retired)
            previous.log = json.dumps({"kind": "baseline", "findings": previous_findings}, ensure_ascii=False)
        db.commit()
    finally:
        db.close()


def ensure_saved_reports() -> None:
    db = SessionLocal()
    try:
        scans = db.query(ScanHistory).filter(ScanHistory.report_html_path != "").all()
        for scan in scans:
            path = Path(scan.report_html_path or "")
            if path.is_file():
                continue
            company = db.get(Company, scan.company_id)
            if company is None:
                continue
            try:
                write_report_file(scan, company)
            except Exception:
                log.exception("report seed failed for scan %s", scan.id)
        db.commit()
    finally:
        db.close()


def ensure_protocol_demo() -> None:
    extras = [
        {
            "hostname": "dc01",
            "category": "Опасные протоколы",
            "title": "LLMNR не отключен",
            "severity": "high",
            "detail": "Политика DNS Client не запрещает мультикаст имен.",
            "tags": "protocol,baseline,module:protocols",
            "vuln_id": "llmnr_enabled",
        },
        {
            "hostname": "dc01",
            "category": "Опасные протоколы",
            "title": "Подпись SMB не обязательна",
            "severity": "high",
            "detail": "RequireSecuritySignature выключен на контроллере.",
            "tags": "protocol,baseline,module:protocols",
            "vuln_id": "smb_signing_off",
        },
        {
            "hostname": "svc-legacy",
            "category": "Опасные протоколы",
            "title": "Для svc-legacy Kerberos только RC4",
            "severity": "medium",
            "detail": "AES128 и AES256 не включены.",
            "tags": "protocol,kerberos,baseline,module:protocols",
            "vuln_id": "rc4_only",
        },
    ]
    db = SessionLocal()
    try:
        for company in db.query(Company).all():
            baseline = (
                db.query(Inventory)
                .filter(Inventory.company_id == company.id, Inventory.status == "baseline")
                .first()
            )
            if baseline is None:
                continue
            have = {
                row.vuln_id
                for row in db.query(Inventory).filter(Inventory.company_id == company.id).all()
            }
            for item in extras:
                if item["vuln_id"] in have:
                    continue
                db.add(
                    Inventory(
                        company_id=company.id,
                        hostname=item["hostname"],
                        category=item["category"],
                        title=item["title"],
                        severity=item["severity"],
                        detail=item["detail"],
                        tags=item["tags"],
                        vuln_id=item["vuln_id"],
                        detected_at=datetime.utcnow(),
                        status="baseline",
                    )
                )
        db.commit()
    finally:
        db.close()


def drop_graph_product() -> None:
    """Старые строки внешнего графа не показываем: проверки Kerberos и делегирования идут по LDAP."""
    old = "blood" + "hound"
    sharp = "sharp" + "hound"
    db = SessionLocal()
    try:
        def hit(column):
            return or_(column.ilike(f"%{old}%"), column.ilike(f"%{sharp}%"))

        db.query(Inventory).filter(or_(hit(Inventory.tags), hit(Inventory.title), hit(Inventory.detail))).delete(synchronize_session=False)
        db.query(ScanHistory).filter(hit(ScanHistory.module)).delete(synchronize_session=False)
        for scan in db.query(ScanHistory).all():
            summary = scan.summary or ""
            log_text = scan.log or ""
            lowered = (summary + log_text).lower()
            if old in lowered or sharp in lowered:
                pattern = re.compile(old + "|" + sharp, re.IGNORECASE)
                scan.summary = pattern.sub("каталог", summary)
                scan.log = pattern.sub("каталог", log_text)
        db.query(ConsoleNotice).filter(or_(hit(ConsoleNotice.title), hit(ConsoleNotice.body))).delete(synchronize_session=False)
        db.query(AuditEvent).filter(or_(hit(AuditEvent.action), hit(AuditEvent.detail))).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    try:
        from app.modules.hunting_pipeline import recover_stale_jobs
        recover_stale_jobs(hunting_store())
    except Exception:
        pass
    drop_graph_product()
    ensure_brosec_samples()
    ensure_protocol_demo()
    ensure_saved_reports()
    if not scheduler.running:
        scheduler.start()
    reload_schedules()


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class CompanyIn(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    domain: str = ""
    dc_host: str = ""
    dc_user: str = ""
    dc_password: str | None = None
    transport: str = "winrm"
    winrm_port: int = 5985
    ssh_port: int = 22
    ldap_port: int = 636
    directory_mode: str = "ldaps"
    runner_host: str = ""
    scan_hosts: str = ""
    notify_email: str = ""
    telegram_chat: str = ""


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=10, max_length=128)
    role: str
    company_id: int | None = None
    full_name: str = ""


class RunTaskIn(BaseModel):
    company_id: int
    domain_controller: str
    modules: list[str]


class ScheduleIn(BaseModel):
    company_id: int
    interval: str
    enabled: bool


class ChatTurn(BaseModel):
    role: str = Field(pattern=r"^(user|assistant)$")
    content: str = Field(min_length=1, max_length=4000)


class ChatIn(BaseModel):
    company_id: int
    message: str = Field(min_length=1, max_length=4000)
    finding_id: int | None = None
    history: list[ChatTurn] = Field(default_factory=list, max_length=12)
    hunting_result_id: str | None = Field(default=None, max_length=120)
    public_research: bool = False


class HoneyIn(BaseModel):
    company_id: int


def apply_company_fields(company: Company, payload: CompanyIn, keep_password: bool) -> None:
    if payload.transport not in {"winrm", "ssh", "none", "ldap", "ldaps", "both"}:
        raise HTTPException(status_code=400, detail="Транспорт программ: winrm, ssh или none")
    if payload.directory_mode not in {"ldap", "ldaps"}:
        raise HTTPException(status_code=400, detail="Каталог: ldap или ldaps")
    if payload.dc_host:
        validate_host(payload.dc_host)
    if payload.runner_host.strip():
        validate_host(payload.runner_host.strip())
    for line in (payload.scan_hosts or "").splitlines():
        if line.strip():
            validate_host(line.strip())
    company.name = payload.name.strip()
    company.domain = payload.domain.strip()
    company.dc_host = payload.dc_host.strip()
    company.dc_user = payload.dc_user.strip()
    if payload.dc_password:
        company.dc_password = payload.dc_password
    elif not keep_password:
        company.dc_password = ""
    directory_mode = payload.directory_mode
    if payload.transport in {"ldap", "ldaps"}:
        directory_mode = payload.transport
        company.transport = "none"
    elif payload.transport == "both":
        company.transport = "winrm"
    else:
        company.transport = payload.transport
    company.directory_mode = directory_mode
    company.runner_host = payload.runner_host.strip()
    company.winrm_port = int(payload.winrm_port)
    company.ssh_port = int(payload.ssh_port)
    company.ldap_port = 636 if directory_mode == "ldaps" else int(payload.ldap_port or 389)
    company.ldap_ssl = directory_mode == "ldaps"
    company.scan_hosts = payload.scan_hosts.strip()
    company.notify_email = payload.notify_email.strip()
    company.telegram_chat = payload.telegram_chat.strip()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "product": "BroSec Audit AD", "version": PRODUCT_VERSION}


@app.get("/health/ready")
def readiness() -> dict[str, str | bool]:
    """Deployment gate: verify the application and threat-hunting stores are writable."""
    try:
        store = hunting_store()
        from app.modules.hunting_pipeline import connection as pipeline_connection
        from app.modules.hunting_results import connection as results_connection
        from app.modules.hunting_campaigns import connection as campaign_connection
        with pipeline_connection(store):
            pass
        with results_connection(store):
            pass
        with campaign_connection(store):
            pass
        return {"status": "ready", "storage": True, "external_worker": hunting_external_worker_enabled()}
    except (OSError, RuntimeError, sqlite3.Error) as exc:
        raise HTTPException(status_code=503, detail={"status": "not_ready", "storage": False, "error": str(exc)[:200]}) from exc


class NotifyIn(BaseModel):
    smtp_server: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"
    smtp_user: str = ""
    smtp_password: str | None = None
    smtp_from: str = ""
    telegram_token: str | None = None
    telegram_chat: str = ""
    telegram_proxy: str = ""


class NotifyTestIn(BaseModel):
    recipient: str = ""


def require_superadmin(user: User) -> None:
    if user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Недостаточно прав")


@app.get("/api/notifications")
def notifications_get(company_id: int | None = None, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    require_superadmin(user)
    company = resolve_company(user, db, company_id)
    return channel_public(channel_row(db, company.id))


@app.put("/api/notifications")
def notifications_put(payload: NotifyIn, company_id: int | None = None, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    require_superadmin(user)
    if payload.smtp_security not in {"none", "starttls", "ssl"}:
        raise HTTPException(status_code=400, detail="Защита SMTP: none, starttls или ssl")
    if not 1 <= int(payload.smtp_port) <= 65535:
        raise HTTPException(status_code=400, detail="Порт SMTP вне диапазона")
    company = resolve_company(user, db, company_id)
    row = channel_row(db, company.id)
    row.smtp_server = payload.smtp_server.strip()
    row.smtp_port = int(payload.smtp_port)
    row.smtp_security = payload.smtp_security
    row.smtp_user = payload.smtp_user.strip()
    row.smtp_from = payload.smtp_from.strip()
    row.telegram_chat = payload.telegram_chat.strip()
    row.telegram_proxy = clean_proxy(payload.telegram_proxy)
    if payload.smtp_password:
        row.smtp_password = payload.smtp_password
    if payload.telegram_token:
        row.telegram_token = payload.telegram_token.strip()
    note = f"SMTP {row.smtp_server or 'не задан'}:{row.smtp_port}, Telegram-чат {'задан' if row.telegram_chat else 'пуст'}"
    if payload.smtp_password:
        note += ". Пароль SMTP обновлен"
    if payload.telegram_token:
        note += ". Токен Telegram обновлен"
    write_audit(db, user, "notify_update", note, company.id)
    db.commit()
    return channel_public(row)


class NotifyPrefsIn(BaseModel):
    topics: dict[str, dict[str, bool]]


@app.get("/api/notifications/prefs")
def notifications_prefs_get(company_id: int | None = None, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    company = resolve_company(user, db, company_id)
    row = channel_row(db, company.id)
    return {
        "topics": read_notify_prefs(row),
        "mail_ready": bool((row.smtp_server or "").strip()),
        "telegram_ready": bool((row.telegram_token or "").strip() and (row.telegram_chat or "").strip()),
    }


@app.put("/api/notifications/prefs")
def notifications_prefs_put(payload: NotifyPrefsIn, company_id: int | None = None, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    company = resolve_company(user, db, company_id)
    row = channel_row(db, company.id)
    current = read_notify_prefs(row)
    incoming = payload.topics if isinstance(payload.topics, dict) else {}
    for key in NOTIFY_TOPICS:
        item = incoming.get(key)
        if not isinstance(item, dict):
            continue
        if "mail" in item:
            current[key]["mail"] = bool(item["mail"])
        if "telegram" in item:
            current[key]["telegram"] = bool(item["telegram"])
    row.prefs = json.dumps(current, ensure_ascii=False)
    write_audit(db, user, "notify_prefs", "Обновлены переключатели почты и Telegram", company.id)
    db.commit()
    return {"topics": current}


@app.post("/api/notifications/test-mail")
def notifications_test_mail(payload: NotifyTestIn, company_id: int | None = None, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    require_superadmin(user)
    company = resolve_company(user, db, company_id)
    row = channel_row(db, company.id)
    result = send_report(
        "BroSec Audit AD",
        "Проверка канала корпоративной почты. Если письмо дошло, отчеты и алерты пойдут этим же путем.",
        [],
        None,
        payload.recipient.strip(),
        mail_channel(row),
    )
    if not result.get("ok"):
        raise HTTPException(status_code=502, detail=str(result.get("error") or "Письмо не отправлено"))
    return {"ok": True}


@app.post("/api/notifications/test-telegram")
def notifications_test_telegram(company_id: int | None = None, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    require_superadmin(user)
    company = resolve_company(user, db, company_id)
    row = channel_row(db, company.id)
    if not row.telegram_token or not row.telegram_chat:
        raise HTTPException(status_code=400, detail="Telegram выбранной компании не настроен")
    result = send_summary(
        "BroSec Audit AD: канал Telegram работает. Сюда придут алерты и паспорт домена.",
        None,
        row.telegram_token,
        row.telegram_chat,
        row.telegram_proxy,
    )
    if not result.get("ok"):
        raise HTTPException(status_code=502, detail=str(result.get("error") or "Telegram не ответил"))
    return {"ok": True}


class AssistantIn(BaseModel):
    enabled: bool = False
    api_url: str = ""
    model_name: str = ""
    api_key: str | None = None


@app.get("/api/assistant")
def assistant_get(user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    require_superadmin(user)
    return assistant_public(assistant_row(db))


@app.put("/api/assistant")
def assistant_put(payload: AssistantIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    require_superadmin(user)
    url = payload.api_url.strip()
    model = payload.model_name.strip()
    if url and not re.match(r"https://", url):
        raise HTTPException(status_code=400, detail="Адрес модели должен начинаться с https://")
    if len(url) > 512 or len(model) > 128:
        raise HTTPException(status_code=400, detail="Адрес или имя модели слишком длинные")
    if any(char in model for char in "\r\n"):
        raise HTTPException(status_code=400, detail="Имя модели содержит недопустимые символы")
    row = assistant_row(db)
    row.enabled = bool(payload.enabled)
    row.api_url = url
    row.model_name = model
    if payload.api_key:
        row.api_key = payload.api_key.strip()
    note = f"Модель {'включена' if row.enabled else 'выключена'}, адрес {row.api_url or 'не задан'}, имя {row.model_name or 'не задано'}"
    if payload.api_key:
        note += ". Ключ обновлен"
    write_audit(db, user, "assistant_update", note)
    db.commit()
    return assistant_public(row)


@app.post("/api/assistant/test")
def assistant_test(user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, str]:
    require_superadmin(user)
    runtime = assistant_runtime(assistant_row(db))
    if not runtime["enabled"]:
        raise HTTPException(status_code=400, detail="Сначала включите модель и сохраните настройки")
    if not runtime["api_url"] or not runtime["model_name"] or not runtime["api_key"]:
        raise HTTPException(status_code=400, detail="Нужны адрес, имя модели и ключ")
    company = Company(name="Проверка", domain="", risk_index=0)
    try:
        answer = ask_llm(company, [], "Ответь одним коротким предложением на русском: канал ассистента работает.", runtime)
    except Exception as exc:
        detail = str(exc)
        secret = runtime.get("api_key") or ""
        if secret and secret in detail:
            detail = detail.replace(secret, "***")
        raise HTTPException(status_code=502, detail=detail) from exc
    return {"ok": "true", "answer": answer[:500]}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    spa = BASE_DIR / "app" / "spa" / "index.html"
    if spa.is_file():
        return FileResponse(spa, headers={"Cache-Control": "no-store"})
    try:
        response = templates.TemplateResponse(request=request, name="dashboard.html", context={"request": request})
    except TypeError:
        response = templates.TemplateResponse("dashboard.html", {"request": request})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/login")
def login(payload: LoginIn, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = db.query(User).filter(User.username == payload.username.strip()).one_or_none()
    valid = verify_password(payload.password, user.password_hash) if user else verify_password(payload.password, hash_password("invalid-user", "0" * 32))
    if user is None or not valid or (user and not verify_password(payload.password, user.password_hash)):
        write_audit(db, None, "login_failed", "Неудачная попытка входа", username=payload.username.strip()[:64])
        db.commit()
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    if user.totp_enabled and user.totp_secret:
        request.session.clear()
        request.session["pending_uid"] = user.id
        request.session["pending_exp"] = int(time.time()) + 300
        write_audit(db, user, "login_totp", "Пароль принят, ждём код приложения", company_id=user.company_id)
        db.commit()
        return {"ok": False, "need_totp": True, "version": PRODUCT_VERSION}
    open_console_session(db, request, user)
    write_audit(db, user, "login", "Вход в консоль", company_id=user.company_id)
    db.commit()
    return {"ok": True, "username": user.username, "role": user.role, "full_name": user.full_name, "company_id": user.company_id, "version": PRODUCT_VERSION}


class TotpIn(BaseModel):
    code: str = Field(min_length=6, max_length=8)


@app.post("/api/login/totp")
def login_totp(payload: TotpIn, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    uid = request.session.get("pending_uid")
    exp = int(request.session.get("pending_exp") or 0)
    if not uid or exp < int(time.time()):
        raise HTTPException(status_code=401, detail="Код больше не действует. Войдите снова")
    user = db.get(User, int(uid))
    if user is None or not totp_ok(user.totp_secret or "", payload.code):
        raise HTTPException(status_code=401, detail="Неверный код")
    request.session.pop("pending_uid", None)
    request.session.pop("pending_exp", None)
    open_console_session(db, request, user)
    write_audit(db, user, "login", "Вход с кодом приложения", company_id=user.company_id)
    db.commit()
    return {"ok": True, "username": user.username, "version": PRODUCT_VERSION}


@app.post("/api/logout")
def logout(request: Request) -> dict[str, bool]:
    request.session.clear()
    return {"ok": True}


def profile_public(user: User) -> dict[str, Any]:
    return {
        "username": user.username,
        "role": user.role,
        "full_name": user.full_name or "",
        "email": user.email or "",
        "phone": user.phone or "",
        "locale": user.locale or "ru",
        "totp_enabled": bool(user.totp_enabled),
        "company_id": user.company_id,
        "is_superadmin": user.role == "superadmin",
        "version": PRODUCT_VERSION,
    }


@app.get("/api/me")
def me(user: User = Depends(get_user)) -> dict[str, Any]:
    return profile_public(user)


class ProfileIn(BaseModel):
    full_name: str = Field(default="", max_length=255)
    email: str = Field(default="", max_length=255)
    phone: str = Field(default="", max_length=32)
    locale: str = "ru"


@app.put("/api/me")
def update_me(payload: ProfileIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    email = payload.email.strip()
    if email and ("@" not in email or "." not in email.split("@")[-1]):
        raise HTTPException(status_code=400, detail="Почта выглядит неполной")
    phone = payload.phone.strip()
    if phone and not re.fullmatch(r"[0-9+\-() ]{6,32}", phone):
        raise HTTPException(status_code=400, detail="Телефон содержит лишние символы")
    user.full_name = payload.full_name.strip()
    user.email = email
    user.phone = phone
    user.locale = "en" if payload.locale == "en" else "ru"
    write_audit(db, user, "profile", "Обновлена персональная информация", company_id=user.company_id)
    db.commit()
    return profile_public(user)


@app.get("/api/me/projects")
def my_projects(user: User = Depends(get_user), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    if user.role == "superadmin":
        rows = db.query(Company).order_by(Company.name).all()
        role = "Суперадминистратор"
    else:
        company = db.get(Company, user.company_id) if user.company_id else None
        rows = [company] if company else []
        role = "Администратор компании" if user.role == "company_admin" else user.role
    return [{"id": row.id, "name": row.name, "domain": row.domain or "", "role": role} for row in rows]


class PasswordChange(BaseModel):
    current: str = Field(min_length=1, max_length=128)
    new: str = Field(min_length=10, max_length=128)


@app.post("/api/me/password")
def change_password(payload: PasswordChange, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    if not verify_password(payload.current, user.password_hash):
        raise HTTPException(status_code=400, detail="Текущий пароль не подошёл")
    if payload.current == payload.new:
        raise HTTPException(status_code=400, detail="Новый пароль совпадает с текущим")
    user.password_hash = hash_password(payload.new)
    write_audit(db, user, "password", "Пароль изменён", company_id=user.company_id)
    db.commit()
    return {"ok": True}


@app.post("/api/me/totp/start")
def totp_start(user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, str]:
    if user.totp_enabled:
        raise HTTPException(status_code=400, detail="Код приложения уже включён")
    secret = new_secret()
    user.totp_secret = secret
    user.totp_enabled = 0
    db.commit()
    uri = otpauth_uri(user.username, secret)
    return {"secret": secret, "svg": qr_svg(uri)}


class TotpConfirm(BaseModel):
    code: str = Field(min_length=6, max_length=8)


@app.post("/api/me/totp/confirm")
def totp_confirm(payload: TotpConfirm, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    if not user.totp_secret or not totp_ok(user.totp_secret, payload.code):
        raise HTTPException(status_code=400, detail="Код не подошёл. Проверьте время на телефоне")
    user.totp_enabled = 1
    write_audit(db, user, "totp_on", "Включён код приложения", company_id=user.company_id)
    db.commit()
    return {"ok": True}


class TotpOff(BaseModel):
    password: str = Field(min_length=1, max_length=128)


@app.post("/api/me/totp/disable")
def totp_disable(payload: TotpOff, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Пароль не подошёл")
    user.totp_secret = ""
    user.totp_enabled = 0
    write_audit(db, user, "totp_off", "Код приложения выключен", company_id=user.company_id)
    db.commit()
    return {"ok": True}


def session_rows(db: Session, user: User, current: int | None) -> list[dict[str, Any]]:
    rows = (
        db.query(AuthSession)
        .filter(AuthSession.user_id == user.id, AuthSession.revoked == 0)
        .order_by(AuthSession.seen_at.desc())
        .limit(20)
        .all()
    )
    return [
        {
            "id": row.id,
            "ip": row.ip or "не определён",
            "device": row.device or "Устройство",
            "at": stamp(row.seen_at or row.created_at),
            "current": row.id == current,
        }
        for row in rows
    ]


@app.get("/api/me/sessions")
def my_sessions(request: Request, user: User = Depends(get_user), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    sid = request.session.get("sid")
    return session_rows(db, user, int(sid) if sid else None)


@app.post("/api/me/sessions/revoke-others")
def revoke_other_sessions(request: Request, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, int]:
    sid = int(request.session.get("sid") or 0)
    query = db.query(AuthSession).filter(AuthSession.user_id == user.id, AuthSession.revoked == 0)
    if sid:
        query = query.filter(AuthSession.id != sid)
    count = query.update({AuthSession.revoked: 1}, synchronize_session=False)
    write_audit(db, user, "sessions", "Завершены другие сеансы", company_id=user.company_id)
    db.commit()
    return {"ok": True, "closed": int(count or 0)}


_directory_cache: dict[int, tuple[float, dict[str, Any]]] = {}


@app.get("/api/directory/status")
def directory_status(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    company = resolve_company(user, db, company_id)
    mode = directory_mode_of(company)
    payload = {
        "ok": False,
        "domain": company.domain or "",
        "host": company.dc_host or "",
        "mode": "LDAPS" if mode == "ldaps" else "LDAP",
        "port": 636 if mode == "ldaps" else int(company.ldap_port or 389),
        "detail": "Подключение к каталогу еще не заполнено",
        "checked_at": "",
    }
    if not company.dc_host or not company.dc_user or not company.dc_password:
        return payload
    now = datetime.utcnow().timestamp()
    cached = _directory_cache.get(company.id)
    if cached and now - cached[0] < 45:
        return cached[1]
    connection = connection_from(company, company.dc_host)
    connection["transport"] = mode
    connection["ldap_ssl"] = mode == "ldaps"
    connection["ldap_port"] = payload["port"]
    probed = probe_directory(connection)
    payload["ok"] = bool(probed["ok"])
    payload["detail"] = str(probed["detail"])
    payload["checked_at"] = stamp(datetime.utcnow())
    _directory_cache[company.id] = (now, payload)
    return payload


@app.get("/api/asset")
def asset_context(company_id: int, name: str, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    company = resolve_company(user, db, company_id)
    if not company.dc_host or not company.dc_user or not company.dc_password:
        return {"found": False, "kind": "", "kind_label": "", "name": name, "rows": []}
    mode = directory_mode_of(company)
    connection = connection_from(company, company.dc_host)
    connection["transport"] = mode
    connection["ldap_ssl"] = mode == "ldaps"
    connection["ldap_port"] = 636 if mode == "ldaps" else int(company.ldap_port or 389)
    data = lookup_asset(connection, name)
    if data.get("kind") == "computer" and windows_mode_of(company) in {"winrm", "ssh"}:
        host = str(data.get("dns") or name)
        win = windows_connection(connection_from(company, company.dc_host))
        win["transport"] = windows_mode_of(company)
        last = last_interactive_user(win, host)
        rows = list(data.get("rows") or [])
        if last:
            rows.append({"label": "Последний интерактивный вход", "value": last, "tone": "plain"})
        else:
            rows.append({"label": "Последний интерактивный вход", "value": "на узле не прочитан, WinRM закрыт или журнал входа пуст", "tone": "warn"})
        data["rows"] = rows
    return data


_picture_cache: dict[int, tuple[float, dict[str, Any]]] = {}


def catalog_coverage(picture: dict[str, Any], windows: dict[str, Any] | None = None) -> dict[str, Any]:
    """Collection metadata only: completion is not a security verdict."""
    windows = windows or {}
    def probe(data: Any) -> str:
        if not isinstance(data, dict):
            return "not_tested"
        if data.get("ok") is False:
            return "unavailable"
        if data.get("ok") is True:
            return "collected"
        return "unknown"
    ldap = probe(picture)
    controllers = windows.get("controllers") or []
    readable = sum(1 for row in controllers if row.get("ok") is True)
    if not controllers:
        dc_state = "not_tested"
    elif not readable:
        dc_state = "unavailable"
    elif readable == len(controllers):
        dc_state = "collected"
    else:
        dc_state = "partial"
    dns = windows.get("dns")
    return {
        "contract": "ad-catalog-coverage.v1",
        "meaning": "Состояние сбора данных, не заключение о безопасности",
        "scope": {"discovered_dcs": len(picture.get("dcs") or []), "probed_dcs": len(controllers), "readable_dcs": readable},
        "sections": {
            "forest_domain": {"state": ldap, "method": "LDAP", "limitations": ["Нет гарантии покрытия всех доменов леса."]},
            "topology": {"state": ldap, "method": "LDAP", "limitations": ["Инвентаризация не подтверждает исправность репликации."]},
            "dns": {"state": ("partial" if isinstance(dns, dict) and dns.get("ok") is True and dns.get("collection_state") == "partial" else probe(dns)), "method": "Windows DNS probe", "limitations": ["ACL зон и TCP-пробы ограничены одним DNS-хостом и бюджетом сбора. Effective access, UDP/DNS health и полный охват леса не подтверждены."]},
            "trusts": {"state": (
                "unavailable" if isinstance(windows.get("trusts"), dict) and windows["trusts"].get("ok") is False
                else "collected" if isinstance(windows.get("trusts"), dict) and windows["trusts"].get("ok") is True
                else "partial" if windows.get("trusts") else "not_tested"
            ), "method": "LDAP metadata / TCP probe", "limitations": ["Доступность TCP LDAP не подтверждает аутентификацию или безопасность доверия.", "Пустой список probe не доказывает отсутствие доверий.", "Флаги SID filtering, selective authentication и шифрования требуют явных атрибутов доверия."]},
            "gpo": {"state": ("partial" if isinstance(windows.get("gpo_collection"), dict) and windows["gpo_collection"].get("ok") is True else probe(windows.get("gpo_collection"))), "method": "Bounded SYSVOL parser", "limitations": ["Конфликт не является effective policy.", "ADMX/ADML, audit.csv и полное применение политик не подтверждены."]},
            "dc_posture": {"state": dc_state, "method": "Bounded WinRM/SSH controller probe", "limitations": ["Доступ к части контроллеров не подтверждает полный охват леса или event/registry checks."]},
        },
    }


@app.get("/api/directory/coverage")
def directory_coverage_api(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    company = resolve_company(user, db, company_id)
    cached = _picture_cache.get(company.id)
    picture = cached[1] if cached else {}
    return {"ok": bool(cached), "cached_only": True, "coverage": catalog_coverage(picture),
            "message": "Использован LDAP cache; новые сетевые проверки не запускаются."}


@app.get("/api/directory/picture")
def directory_picture_api(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    company = resolve_company(user, db, company_id)
    if not company.dc_host or not company.dc_user or not company.dc_password:
        return {"ok": False, "message": "Подключение к каталогу ещё не заполнено"}
    now = datetime.utcnow().timestamp()
    cached = _picture_cache.get(company.id)
    if cached and now - cached[0] < 60:
        return cached[1]
    mode = directory_mode_of(company)
    connection = connection_from(company, company.dc_host)
    connection["transport"] = mode
    connection["ldap_ssl"] = mode == "ldaps"
    connection["ldap_port"] = 636 if mode == "ldaps" else int(company.ldap_port or 389)
    picture = directory_picture(connection)
    if isinstance(picture, dict):
        picture["coverage"] = catalog_coverage(picture)
    _picture_cache[company.id] = (now, picture)
    return picture


@app.get("/api/directory/windows")
def directory_windows(company_id: int, part: str = "", user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    company = resolve_company(user, db, company_id)
    if windows_mode_of(company) not in {"winrm", "ssh"} or not company.dc_host or not company.dc_user or not company.dc_password:
        return {"ok": False, "controllers": [], "conflicts": [], "message": "WinRM к контроллеру не задан"}
    mode = directory_mode_of(company)
    ldap_conn = connection_from(company, company.dc_host)
    ldap_conn["transport"] = mode
    ldap_conn["ldap_ssl"] = mode == "ldaps"
    ldap_conn["ldap_port"] = 636 if mode == "ldaps" else int(company.ldap_port or 389)
    picture = directory_picture(ldap_conn)
    hosts = []
    for row in picture.get("dcs") or []:
        host = str(row.get("host") or row.get("name") or "")
        if host and host not in hosts:
            hosts.append(host)
    if company.dc_host not in hosts:
        hosts.insert(0, company.dc_host)
    names = {}
    for row in picture.get("gpos") or []:
        guid = str(row.get("id") or "")
        title = str(row.get("name") or guid)
        if guid:
            names[guid] = title
            names[guid.strip("{}")] = title
    win = windows_connection(connection_from(company, company.dc_host))
    win["transport"] = windows_mode_of(company)
    fast = part == "hw"
    controllers = controller_extra(win, hosts, with_counts=not fast, with_diag=not fast)
    if fast:
        matrix = []
        for row in controllers:
            for partner in row.get("partners") or []:
                matrix.append({"source": row.get("host") or "", **partner})
        readable = sum(1 for row in controllers if row.get("ok"))
        return {
            "ok": bool(readable),
            "controllers": controllers,
            "conflicts": [],
            "replication": matrix[:80],
            "message": f"Железо контроллеров: ответило {readable} из {len(hosts[:6])}.",
        }
    diff = gpo_conflicts(win, names)
    zones = dns_zones(win)
    zones["wildcard"] = picture.get("wildcard") if picture.get("ok") is True and isinstance(picture.get("wildcard"), bool) else None
    matrix = []
    for row in controllers:
        for partner in row.get("partners") or []:
            matrix.append({"source": row.get("host") or "", **partner})
    readable = sum(1 for row in controllers if row.get("ok"))
    result = {
        "ok": bool(readable or diff.get("ok") or zones.get("ok")),
        "controllers": controllers,
        "conflicts": diff.get("conflicts") or [],
        "baseline": diff.get("baseline") or [],
        "trusts": trust_reach(win),
        "replication": matrix[:80],
        "dns": zones,
        "message": f"Контроллеров ответило: {readable} из {len(hosts[:6])}. Связей репликации: {len(matrix)}. {diff.get('message') or ''} {zones.get('message') or ''}".strip(),
    }
    result["gpo_collection"] = {key: diff.get(key) for key in ("ok", "message", "collection_state", "collection", "limitations", "effective_policy_verified", "link_metadata")}
    result["coverage"] = catalog_coverage(picture, result)
    return result


@app.get("/api/companies")
def companies(user: User = Depends(get_user), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    if user.role == "superadmin":
        rows = db.query(Company).order_by(Company.name.asc()).all()
    else:
        rows = db.query(Company).filter(Company.id == user.company_id).all()
    return [company_public(row) for row in rows]


@app.post("/api/companies")
def create_company(payload: CompanyIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    if user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Создавать компании может только суперадминистратор")
    company = Company(schedule="weekly", scheduler_enabled=False, risk_index=0)
    apply_company_fields(company, payload, keep_password=False)
    db.add(company)
    db.flush()
    write_audit(db, user, "tenant_create", f"Создана компания {company.name}", company.id)
    db.commit()
    db.refresh(company)
    return company_public(company)


@app.put("/api/companies/{company_id}")
def update_company(company_id: int, payload: CompanyIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    company = resolve_company(user, db, company_id)
    if user.role == "company_admin":
        payload.name = company.name
    apply_company_fields(company, payload, keep_password=True)
    note = f"Каталог {company.directory_mode}, контроллер {company.dc_host or 'не задан'}"
    if payload.dc_password:
        note += ". Пароль каталога обновлен"
    write_audit(db, user, "company_update", note, company.id)
    db.commit()
    return company_public(company)


@app.post("/api/users")
def create_user(payload: UserIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    if user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Учетные записи создает суперадминистратор")
    if payload.role not in {"superadmin", "company_admin"}:
        raise HTTPException(status_code=400, detail="Неизвестная роль")
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,64}", payload.username):
        raise HTTPException(status_code=400, detail="Логин: латиница, цифры, точка, дефис, от 3 символов")
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=409, detail="Такой логин уже есть")
    company_id = payload.company_id
    if payload.role == "company_admin":
        if not company_id or db.get(Company, company_id) is None:
            raise HTTPException(status_code=400, detail="Для администратора компании выберите компанию")
    else:
        company_id = None
    db.add(
        User(
            username=payload.username,
            password_hash=hash_password(payload.password),
            role=payload.role,
            company_id=company_id,
            full_name=payload.full_name.strip(),
        )
    )
    write_audit(db, user, "user_create", f"Создан {payload.username}, роль {payload.role}", company_id)
    db.commit()
    return {"ok": True}


@app.get("/api/dashboard")
def dashboard(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    company = resolve_company(user, db, company_id)
    rows = [
        row for row in db.query(Inventory).filter(Inventory.company_id == company.id).order_by(Inventory.id.asc()).all()
        if "module:pingcastle" not in (row.tags or "") and not str(row.vuln_id or "").startswith("pc:")
    ]
    timeline = timeline_for(db, company.id)
    drift = None
    if len(timeline) >= 2:
        drift = int(timeline[-1]["score"]) - int(timeline[-2]["score"])
    return {
        "company": company_public(company),
        "kpis": {
            "risk_index": company.risk_index or 0,
            "score_drift": drift,
            "shadow_it_hosts": shadow_hosts(rows),
            "honeytokens": sum(1 for row in rows if row.vuln_id == "honeytoken"),
            "scheduler": scheduler_view(company),
        },
        "timeline": timeline,
        "inventory": [inventory_public(row) for row in rows],
        "demo_profile": any(row.status == "baseline" for row in rows),
        "compare": compare_scans(db, company.id),
        "mitre": tactics_of([row for row in rows if row.severity != "info"]),
    }


@app.post("/api/run-task")
def run_task(payload: RunTaskIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    company = resolve_company(user, db, payload.company_id)
    modules = []
    for module in payload.modules:
        if module not in ALLOWED_MODULES:
            raise HTTPException(status_code=400, detail=f"Неизвестный модуль: {module}")
        if module not in modules:
            modules.append(module)
    if not modules:
        raise HTTPException(status_code=400, detail="Отметьте хотя бы один модуль")
    try:
        host = validate_host(payload.domain_controller)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scan = ScanHistory(
        company_id=company.id,
        module=",".join(modules),
        target_dc=host,
        status="queued",
        started_at=datetime.utcnow(),
        summary="Проверка поставлена в очередь.",
        actor=user.full_name or user.username,
    )
    db.add(scan)
    write_audit(db, user, "scan_start", "Запуск: " + ",".join(modules), company.id)
    db.commit()
    db.refresh(scan)
    worker = threading.Thread(target=execute_scan, args=(scan.id,), daemon=True)
    worker.start()
    return {"scan_id": scan.id, "status": scan.status}


@app.get("/api/scans/{scan_id}")
def scan_status(scan_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    scan = db.get(ScanHistory, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Проверка не найдена")
    resolve_company(user, db, scan.company_id)
    return {
        "id": scan.id,
        "status": scan.status,
        "summary": scan.summary or "",
        "risk_score": scan.risk_score,
        "started_at": scan.started_at.isoformat() if scan.started_at else "",
        "finished_at": scan.finished_at.strftime("%d.%m.%Y %H:%M") if scan.finished_at else "",
        "progress": read_progress(scan),
    }


def scan_public(scan: ScanHistory) -> dict[str, Any]:
    return {
        "id": scan.id,
        "module": scan.module or "",
        "target_dc": scan.target_dc or "",
        "status": scan.status or "",
        "started_at": stamp(scan.started_at),
        "finished_at": stamp(scan.finished_at),
        "summary": (scan.summary or "")[:500],
        "risk_score": scan.risk_score,
        "actor": scan.actor or "не записан",
    }


@app.get("/api/scans")
def scan_list(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    company = resolve_company(user, db, company_id)
    rows = (
        db.query(ScanHistory)
        .filter(ScanHistory.company_id == company.id)
        .order_by(ScanHistory.id.desc())
        .limit(40)
        .all()
    )
    return [scan_public(row) for row in rows]


@app.get("/api/audit")
def audit_list(user: User = Depends(get_user), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    query = db.query(AuditEvent)
    if user.role != "superadmin":
        query = query.filter(or_(AuditEvent.company_id == user.company_id, AuditEvent.user_id == user.id))
    rows = query.order_by(AuditEvent.id.desc()).limit(200).all()
    return [
        {
            "id": row.id,
            "at": stamp(row.created_at),
            "username": row.username or "",
            "action": row.action,
            "detail": row.detail or "",
            "company_id": row.company_id,
        }
        for row in rows
    ]


@app.get("/api/notices")
def notice_list(user: User = Depends(get_user), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.query(ConsoleNotice).filter(ConsoleNotice.user_id == user.id).order_by(ConsoleNotice.id.desc()).limit(80).all()
    return [
        {
            "id": row.id,
            "title": row.title,
            "body": row.body or "",
            "kind": row.kind or "info",
            "at": stamp(row.created_at),
            "read": row.read_at is not None,
        }
        for row in rows
    ]


@app.post("/api/notices/{notice_id}/read")
def notice_read(notice_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    row = db.get(ConsoleNotice, notice_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Уведомление не найдено")
    if row.read_at is None:
        row.read_at = datetime.utcnow()
        db.commit()
    return {"ok": True}


@app.post("/api/notices/read-all")
def notice_read_all(user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    now = datetime.utcnow()
    db.query(ConsoleNotice).filter(ConsoleNotice.user_id == user.id, ConsoleNotice.read_at.is_(None)).update({ConsoleNotice.read_at: now}, synchronize_session=False)
    db.commit()
    return {"ok": True}


@app.delete("/api/notices/{notice_id}")
def notice_delete(notice_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    row = db.get(ConsoleNotice, notice_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Уведомление не найдено")
    db.delete(row)
    db.commit()
    return {"ok": True}


@app.get("/api/users")
def user_list(user: User = Depends(get_user), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    if user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Список пользователей доступен суперадминистратору")
    rows = db.query(User).order_by(User.username.asc()).all()
    return [
        {
            "id": row.id,
            "username": row.username,
            "full_name": row.full_name or "",
            "role": row.role,
            "company_id": row.company_id,
        }
        for row in rows
    ]


@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    if user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Удалять пользователей может суперадминистратор")
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if target.id == user.id:
        raise HTTPException(status_code=400, detail="Нельзя удалить свою учетную запись")
    if target.role == "superadmin":
        others = db.query(User).filter(User.role == "superadmin", User.id != target.id).count()
        if others < 1:
            raise HTTPException(status_code=400, detail="Нельзя удалить последнего суперадминистратора")
    name = target.username
    company_id = target.company_id
    db.query(ConsoleNotice).filter(ConsoleNotice.user_id == target.id).delete(synchronize_session=False)
    db.delete(target)
    write_audit(db, user, "user_delete", f"Удален пользователь {name}", company_id)
    db.commit()
    return {"ok": True}


@app.delete("/api/companies/{company_id}")
def delete_company(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    if user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Удалять компании может суперадминистратор")
    company = db.get(Company, company_id)
    if company is None:
        raise HTTPException(status_code=404, detail="Компания не найдена")
    name = company.name
    job_id = f"scan-{company.id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    db.query(Inventory).filter(Inventory.company_id == company.id).delete(synchronize_session=False)
    db.query(ScanHistory).filter(ScanHistory.company_id == company.id).delete(synchronize_session=False)
    admin_ids = [row.id for row in db.query(User.id).filter(User.company_id == company.id).all()]
    if admin_ids:
        db.query(ConsoleNotice).filter(ConsoleNotice.user_id.in_(admin_ids)).delete(synchronize_session=False)
    db.query(ConsoleNotice).filter(ConsoleNotice.company_id == company.id).delete(synchronize_session=False)
    db.query(User).filter(User.company_id == company.id).delete(synchronize_session=False)
    write_audit(db, user, "tenant_delete", f"Удалена компания {name} вместе с находками и ее администраторами", None)
    db.delete(company)
    db.commit()
    folder = REPORTS_DIR / str(company_id)
    if folder.is_dir():
        for child in folder.iterdir():
            if child.is_file():
                child.unlink(missing_ok=True)
    return {"ok": True}


@app.post("/api/schedule")
def save_schedule(payload: ScheduleIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    company = resolve_company(user, db, payload.company_id)
    if payload.interval not in {"daily", "weekly", "monthly"} and not re.fullmatch(r"hourly@\d{2}", payload.interval or "") and not re.fullmatch(r"[a-z]{3}(?:,[a-z]{3})*@\d{2}:\d{2}", payload.interval or ""):
        raise HTTPException(status_code=400, detail="Укажите дни и время или запуск каждый час")
    hourly = re.fullmatch(r"hourly@(\d{2})", payload.interval or "")
    if hourly and int(hourly.group(1)) > 59:
        raise HTTPException(status_code=400, detail="Минута часа от 00 до 59")
    if payload.interval not in {"daily", "weekly", "monthly"}:
        parse_schedule(payload.interval)
    company.schedule = payload.interval
    company.scheduler_enabled = bool(payload.enabled)
    write_audit(
        db,
        user,
        "schedule",
        f"Расписание {payload.interval}, {'включено' if payload.enabled else 'выключено'}",
        company.id,
    )
    db.commit()
    apply_company_schedule(company)
    return scheduler_view(company)


class ExportIn(BaseModel):
    company_id: int
    ids: list[int] | None = None
    modules: list[str] = []


def _module_of(tags: str) -> str:
    found = re.search(r"module:([a-z0-9_]+)", tags or "")
    return found.group(1) if found else ""


def rows_for_export(db: Session, company: Company, payload: ExportIn) -> tuple[list[Inventory], list[ScanHistory], str]:
    rows = db.query(Inventory).filter(Inventory.company_id == company.id).all()
    scans = db.query(ScanHistory).filter(ScanHistory.company_id == company.id).order_by(ScanHistory.id.desc()).all()
    chosen = [item for item in payload.modules if item in ALLOWED_MODULES]
    if payload.ids is not None:
        wanted = set(payload.ids)
        rows = [row for row in rows if row.id in wanted]
        note = f"Строки, которые сейчас видны на экране: {len(rows)}"
    elif chosen:
        rows = [row for row in rows if _module_of(row.tags or "") in chosen]
        scans = [scan for scan in scans if any(item in (scan.module or "").split(",") for item in chosen)]
        note = "Модули: " + ", ".join(MODULE_TITLES.get(item, item) for item in chosen)
    else:
        note = "Весь текущий каталог"
    return rows, scans, note


@app.post("/api/export/excel")
def export_excel(payload: ExportIn, user: User = Depends(get_user), db: Session = Depends(get_db)):
    company = resolve_company(user, db, payload.company_id)
    rows, scans, note = rows_for_export(db, company, payload)
    path = REPORTS_DIR / str(company.id) / "passport-latest.xlsx"
    try:
        build_excel(path, company, rows, scans, company.risk_index or 0, note)
    except Exception as exc:
        log.exception("excel export")
        raise HTTPException(status_code=500, detail=f"Excel не собран: {exc.__class__.__name__}") from exc
    return attachment(path, f"Паспорт_{company.domain or company.id}.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.post("/api/export/pdf")
def export_pdf(payload: ExportIn, user: User = Depends(get_user), db: Session = Depends(get_db)):
    company = resolve_company(user, db, payload.company_id)
    rows, _, _note = rows_for_export(db, company, payload)
    path = REPORTS_DIR / str(company.id) / "passport-latest.pdf"
    try:
        build_pdf(path, company, rows, company.risk_index or 0)
    except Exception as exc:
        log.exception("pdf export")
        raise HTTPException(status_code=500, detail=f"PDF не собран: {exc.__class__.__name__}") from exc
    return attachment(path, f"Паспорт_{company.domain or company.id}.pdf", "application/pdf")


@app.get("/api/reports/{scan_id}")
def open_report(scan_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    scan = db.get(ScanHistory, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Отчет не найден")
    company = resolve_company(user, db, scan.company_id)
    write_report_file(scan, company)
    db.commit()
    path = Path(scan.report_html_path or "")
    resolved = path.resolve()
    if REPORTS_DIR.resolve() not in resolved.parents:
        raise HTTPException(status_code=403, detail="Некорректный путь отчета")
    return FileResponse(resolved, media_type="text/html; charset=utf-8")


@app.delete("/api/demo-profile")
def delete_demo(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    company = resolve_company(user, db, company_id)
    db.query(Inventory).filter(Inventory.company_id == company.id, Inventory.status == "baseline").delete(synchronize_session=False)
    scans = db.query(ScanHistory).filter(ScanHistory.company_id == company.id, ScanHistory.module == "baseline").all()
    for scan in scans:
        if scan.report_html_path:
            Path(scan.report_html_path).unlink(missing_ok=True)
        db.delete(scan)
    latest = (
        db.query(ScanHistory)
        .filter(ScanHistory.company_id == company.id, ScanHistory.risk_score.isnot(None))
        .order_by(ScanHistory.id.desc())
        .first()
    )
    company.risk_index = latest.risk_score if latest else 0
    db.commit()
    return {"ok": True}


REMEDIATION: dict[str, dict[str, Any]] = {
    "gpp_password": {
        "title": "Пароль в предпочтениях групповой политики",
        "severity": "critical",
        "summary": "Атрибут cpassword в SYSVOL означает, что пароль лежит в политике в обратимом виде. Платформа не расшифровывает его. Предпочтение нужно удалить и заменить управляемым секретом.",
        "steps": [
            "Согласуйте окно работ: после правки политики сопоставьте, какая служба использовала этот пароль.",
            "Сделайте копию XML-файла предпочтения.",
            "Удалите узлы с атрибутом cpassword из SYSVOL и обновите политику.",
            "Выпустите новый пароль через LAPS для локальных администраторов или через gMSA для службы.",
            "Проверьте, что повторный обход SYSVOL больше не находит cpassword.",
        ],
        "powershell": r"""Import-Module ActiveDirectory
$domain = (Get-ADDomain).DNSRoot
$files = Get-ChildItem "\\$domain\SYSVOL" -Recurse -Include Groups.xml,Services.xml,Scheduledtasks.xml,DataSources.xml,Drives.xml,Printers.xml -ErrorAction SilentlyContinue
foreach ($file in $files) {
  [xml]$xml = Get-Content -LiteralPath $file.FullName -Encoding UTF8
  $nodes = @($xml.SelectNodes('//*[@cpassword]'))
  if ($nodes.Count -eq 0) { continue }
  Copy-Item -LiteralPath $file.FullName -Destination ($file.FullName + '.bak') -Force
  foreach ($node in $nodes) { [void]$node.ParentNode.RemoveChild($node) }
  $xml.Save($file.FullName)
  Write-Output ("Очищен файл: " + $file.FullName)
}
Invoke-GPUpdate -Force
""",
    },
    "anydesk_detected": {
        "title": "Обнаружен AnyDesk",
        "severity": "high",
        "summary": "Несанкционированное средство удаленного доступа нужно остановить, запретить автозапуск и удалить. Доступ администраторов оставьте только через утвержденный корпоративный канал.",
        "steps": [
            "Подтвердите с владельцем рабочего места, что сеанс AnyDesk не нужен для текущей заявки.",
            "Остановите процесс и службу, запретите автозапуск.",
            "Удалите пакет и проверьте каталоги Program Files и AppData.",
            "Закройте публикацию в межсетевом экране и добавьте запрет в политику управления приложениями.",
        ],
        "powershell": r"""Get-Process -Name AnyDesk -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Service -Name AnyDesk -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Service $_.Name -Force -ErrorAction SilentlyContinue
  Set-Service $_.Name -StartupType Disabled
}
Get-Package -Name '*AnyDesk*' -ErrorAction SilentlyContinue | Uninstall-Package -Force -ErrorAction SilentlyContinue
Get-ChildItem 'C:\Program Files','C:\Program Files (x86)','C:\Users' -Filter 'AnyDesk.exe' -Recurse -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty FullName
""",
    },
    "kerberoasting": {
        "title": "Пользовательская учетная запись с SPN",
        "severity": "high",
        "summary": "SPN на обычной учетной записи делает ее целью офлайнового подбора. Платформа только показывает такие записи. Переведите службу на gMSA и задайте длинный случайный пароль на время миграции.",
        "steps": [
            "Выгрузите список учетных записей пользователей с SPN и исключите krbtgt.",
            "Согласуйте с владельцем службы переход на групповую управляемую учетную запись.",
            "На время миграции смените пароль на случайную строку не короче 25 символов и уберите его из скриптов.",
            "После перевода удалите SPN со старой записи и отключите ее.",
        ],
        "powershell": r"""Import-Module ActiveDirectory
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName |
  Where-Object { $_.SamAccountName -ne 'krbtgt' } |
  Select-Object SamAccountName, ServicePrincipalName
# Пример новой gMSA. Имена замените на свои, пароль вручную не задается.
# New-ADServiceAccount -Name 'gmsa-sql01' -DNSHostName 'gmsa-sql01.domain.local' -PrincipalsAllowedToRetrieveManagedPassword 'SQL-Servers'
# Set-ADServiceAccount 'gmsa-sql01' -ServicePrincipalNames @{Add='MSSQLSvc/sql01.domain.local:1433'}
""",
    },
    "active_smbv1": {
        "title": "Включен SMBv1",
        "severity": "critical",
        "summary": "SMBv1 нужно выключить на сервере и клиенте. Перед массовым отключением убедитесь, что в сети не осталось устройств, которые умеют только SMBv1.",
        "steps": [
            "Найдите узлы, где протокол еще включен, и согласуйте отключение с владельцами файловых ресурсов.",
            "Выключите серверный и клиентский компонент SMBv1.",
            "Перезагрузите узел в согласованное окно.",
            "Повторно проверьте конфигурацию SMB.",
        ],
        "powershell": r"""Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Type DWord -Value 0
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
""",
    },
    "teamviewer_detected": {
        "title": "Обнаружен TeamViewer",
        "severity": "high",
        "summary": "Удалите неуправляемый TeamViewer и оставьте только корпоративное средство удаленного администрирования.",
        "steps": [
            "Остановите процессы TeamViewer.",
            "Удалите пакет и запретите повторную установку политикой приложений.",
        ],
        "powershell": r"""Get-Process -Name TeamViewer,TeamViewer_Service -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Service -Name TeamViewer -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Service $_.Name -Force -ErrorAction SilentlyContinue
  Set-Service $_.Name -StartupType Disabled
}
Get-Package -Name '*TeamViewer*' -ErrorAction SilentlyContinue | Uninstall-Package -Force -ErrorAction SilentlyContinue
""",
    },
    "rustdesk_detected": {
        "title": "Обнаружен RustDesk",
        "severity": "high",
        "summary": "RustDesk относится к теневому удаленному доступу и удаляется так же, как другие неразрешенные клиенты.",
        "steps": ["Остановите процесс RustDesk.", "Удалите приложение и правило автозапуска."],
        "powershell": r"""Get-Process -Name rustdesk -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Package -Name '*RustDesk*' -ErrorAction SilentlyContinue | Uninstall-Package -Force -ErrorAction SilentlyContinue
""",
    },
    "vnc_detected": {
        "title": "Обнаружен VNC-сервер",
        "severity": "high",
        "summary": "Сервер VNC на рабочей станции или файловом сервере нужно остановить и удалить, если он не входит в утвержденный стандарт.",
        "steps": ["Остановите службу UltraVNC, TightVNC или RealVNC.", "Удалите пакет и закройте порт 5900."],
        "powershell": r"""Get-Service -Name uvnc,vncserver,tvnserver -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Service $_.Name -Force -ErrorAction SilentlyContinue
  Set-Service $_.Name -StartupType Disabled
}
Get-Package -Name '*VNC*' -ErrorAction SilentlyContinue | Uninstall-Package -Force -ErrorAction SilentlyContinue
""",
    },
    "vpn_unauthorized": {
        "title": "Неутвержденный VPN-клиент",
        "severity": "medium",
        "summary": "Личный VPN-клиент обходит корпоративный периметр. Удалите его и оставьте только корпоративный концентратор.",
        "steps": ["Согласуйте удаление с владельцем ноутбука.", "Удалите OpenVPN, WireGuard или ProtonVPN.", "Проверьте, что split-tunnel больше не создается."],
        "powershell": r"""Get-Package -Name '*OpenVPN*','*WireGuard*','*ProtonVPN*' -ErrorAction SilentlyContinue |
  Uninstall-Package -Force -ErrorAction SilentlyContinue
Get-Service -Name WireGuardTunnel* -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Service $_.Name -Force -ErrorAction SilentlyContinue
  Set-Service $_.Name -StartupType Disabled
}
""",
    },
    "obsolete_os": {
        "title": "Устаревшая операционная система",
        "severity": "medium",
        "summary": "Windows 10 на рабочих местах выводится по плану обновления. До миграции узел сегментируется и получает только необходимые доступы.",
        "steps": [
            "Поставьте узел в очередь обновления до поддерживаемого выпуска.",
            "Ограничьте его доступ к административным интерфейсам.",
            "Проверьте, что на время миграции включены актуальные обновления безопасности.",
        ],
        "powershell": r"""Get-CimInstance Win32_OperatingSystem | Select-Object CSName, Caption, Version, BuildNumber
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, InstalledOn
""",
    },
    "adcs_enrollee_san": {
        "title": "Шаблон AD CS принимает имя субъекта от заявителя",
        "severity": "high",
        "summary": "Шаблон пускает имя от заявителя и годится для входа без согласования. В заявку вписывают имя администратора, центр выпускает сертификат с этим именем, и контроллер пускает предъявителя как эту учётную запись. Платформа сертификат не выпускает.",
        "steps": [
            "В консоли центра сертификации откройте шаблон из находки.",
            "Снимите поставку альтернативного имени заявителем либо включите обязательное согласование выпуска.",
            "Оставьте право Enroll только группе, которой сертификат действительно нужен.",
            "Опубликуйте измененный шаблон и отзовите уже выпущенные лишние сертификаты по журналу CA.",
        ],
        "powershell": r"""# Просмотр флагов шаблонов. Изменение публикуйте через консоль CA после согласования.
$root = ([ADSI]'LDAP://RootDSE').configurationNamingContext
$base = 'LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,' + $root
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$base)
$searcher.Filter = '(objectClass=pKICertificateTemplate)'
[void]$searcher.PropertiesToLoad.Add('name')
[void]$searcher.PropertiesToLoad.Add('msPKI-Certificate-Name-Flag')
[void]$searcher.PropertiesToLoad.Add('msPKI-Enrollment-Flag')
$searcher.FindAll() | ForEach-Object {
  [PSCustomObject]@{
    Name = $_.Properties['name'][0]
    NameFlag = $_.Properties['mspki-certificate-name-flag'][0]
    EnrollmentFlag = $_.Properties['mspki-enrollment-flag'][0]
  }
}
""",
    },
    "unconstrained_delegation": {
        "title": "Неограниченное делегирование",
        "severity": "critical",
        "summary": "На контроллерах домена этот флаг штатный и не снимается. На рядовых серверах его заменяют ограниченным делегированием под конкретную службу.",
        "steps": [
            "Отделите контроллеры домена от рядовых серверов в списке.",
            "Для рядового сервера согласуйте смену на constrained delegation.",
            "Снимите флаг только после перевода службы.",
        ],
        "powershell": r"""Import-Module ActiveDirectory
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
  Select-Object Name, DNSHostName
# С рядового сервера, не с контроллера домена:
# Set-ADComputer -Identity 'APP01$' -TrustedForDelegation $false
""",
    },
    "asrep_preauth": {
        "title": "Отключена предварительная проверка подлинности",
        "severity": "high",
        "summary": "Включите предварительную проверку подлинности Kerberos обратно. Не запрашивайте билеты и не подбирайте пароль.",
        "steps": ["Найдите учетные записи с отключенной предварительной проверкой.", "Включите ее и проверьте вход владельца записи."],
        "powershell": r"""Import-Module ActiveDirectory
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth |
  Select-Object SamAccountName
# Set-ADAccountControl -Identity 'USER' -DoesNotRequirePreAuth $false
""",
    },
    "krbtgt_old": {
        "title": "Устаревший пароль учетной записи krbtgt",
        "severity": "high",
        "summary": "Пароль krbtgt меняется дважды, с паузой не меньше 10 часов, штатной процедурой Microsoft. Одну смену в рабочий день не выполняйте.",
        "steps": [
            "Согласуйте две смены с разницей не менее 10 часов.",
            "После каждой смены проверьте выпуск билетов и репликацию.",
            "Не публикуйте пароль и не записывайте его в отчет.",
        ],
        "powershell": r"""Import-Module ActiveDirectory
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object Name, PasswordLastSet
# Штатная смена. Повторите второй раз не раньше чем через 10 часов.
# $password = ConvertTo-SecureString ([guid]::NewGuid().Guid + [guid]::NewGuid().Guid) -AsPlainText -Force
# Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword $password
""",
    },
    "honeytoken": {
        "title": "Контроль ловушки",
        "severity": "info",
        "summary": "Ловушку не удаляют при сработке. Событие входа, запроса служебного билета или чтения общей папки оформляется как инцидент.",
        "steps": [
            "Проверьте события 4769 для SPN ловушки и 4624/4625 для интерактивного входа.",
            "Для общей папки смотрите события 5140 и 5145.",
            "Изолируйте источник, не выключая саму учетную запись-приманку, пока идет разбор.",
        ],
        "powershell": r"""$since = (Get-Date).AddDays(-7)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769; StartTime=$since} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'sql-legacy|svc_sqlbackup_legacy|svc_mail_legacy' } |
  Select-Object TimeCreated, Id, Message
""",
    },
    "print_spooler_on_dc": {
        "title": "Служба печати на контроллере домена",
        "severity": "high",
        "summary": "На контроллере домена служба печати не нужна. Ее отключают, чтобы убрать лишнюю поверхность. Платформа службу сама не останавливает.",
        "steps": [
            "Убедитесь, что контроллер не является сервером печати для пользователей.",
            "Остановите и отключите Spooler.",
            "Повторите проверку харденинга.",
        ],
        "powershell": r"""Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
Get-Service Spooler | Select-Object Name, Status, StartType
""",
    },
    "ldap_signing_not_required": {
        "title": "Подпись LDAP не обязательна",
        "severity": "high",
        "summary": "Требование подписи LDAP закрывает простой перехват и подмену запросов к каталогу. Включайте после проверки, что клиенты умеют подписывать LDAP.",
        "steps": [
            "Проверьте значение LDAPServerIntegrity.",
            "Согласуйте перевод на значение 2 (Require signing).",
            "Повторите проверку с контроллера.",
        ],
        "powershell": r"""New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -Type DWord -Value 2
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity
""",
    },
    "recycle_bin_disabled": {
        "title": "Корзина Active Directory выключена",
        "severity": "medium",
        "summary": "Корзина позволяет вернуть удаленный объект со ссылками. Включение необратимо и требует режим работы леса не ниже Windows Server 2008 R2.",
        "steps": [
            "Проверьте функциональный уровень леса.",
            "Включите необязательный компонент корзины на контроллере с ролью именования доменов.",
            "Проверьте, что область включения не пустая.",
        ],
        "powershell": r"""Import-Module ActiveDirectory
Get-ADOptionalFeature -Filter "name -eq 'Recycle Bin Feature'" | Select-Object Name, EnabledScopes
# Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name -Confirm:$false
""",
    },
    "priv_password_never_expires": {
        "title": "У привилегированной учетной записи пароль не истекает",
        "severity": "high",
        "summary": "Снимите флаг бессрочного пароля у административных учетных записей и переведите службы на gMSA. Пароль при этом не показывается и не подбирается.",
        "steps": [
            "Отделите интерактивных администраторов от служебных записей.",
            "Снимите PasswordNeverExpires у интерактивных администраторов.",
            "Назначьте срок действия политикой домена.",
        ],
        "powershell": r"""Import-Module ActiveDirectory
Get-ADGroupMember 'Domain Admins' -Recursive | Where-Object objectClass -eq 'user' | ForEach-Object {
  Get-ADUser $_.SamAccountName -Properties PasswordNeverExpires, Enabled |
    Where-Object { $_.Enabled -and $_.PasswordNeverExpires } |
    Select-Object SamAccountName, PasswordNeverExpires
}
# Set-ADUser -Identity 'USER' -PasswordNeverExpires $false
""",
    },
    "not_in_protected_users": {
        "title": "Администратор не входит в Protected Users",
        "severity": "medium",
        "summary": "Protected Users отключает слабые протоколы для интерактивных администраторов. Не добавляйте туда служебные учетные записи: у них перестанут обновляться билеты и NTLM.",
        "steps": [
            "Составьте список только интерактивных администраторов.",
            "Проверьте, что их рабочие станции и приложения не зависят от NTLM.",
            "Добавьте их в Protected Users.",
        ],
        "powershell": r"""Import-Module ActiveDirectory
Get-ADGroupMember 'Protected Users' | Select-Object Name, SamAccountName, objectClass
# Add-ADGroupMember -Identity 'Protected Users' -Members 'USER'
""",
    },
    "laps_missing": {
        "title": "В домене не развернут LAPS",
        "severity": "high",
        "summary": "Windows LAPS задает уникальный пароль локального администратора и хранит его в каталоге под отдельным правом чтения. Общий пароль рабочих станций после этого убирают.",
        "steps": [
            "Обновите схему командой Update-LapsADSchema с администратора схемы.",
            "Выпустите политику LAPS на рабочие станции.",
            "Ограничьте чтение атрибута пароля группой поддержки рабочих мест.",
        ],
        "powershell": r"""Import-Module LAPS
Update-LapsADSchema
# Дальше назначьте политику Windows LAPS на рабочие станции
# и выдайте чтение пароля только группе поддержки рабочих мест.
""",
    },
    "trust_sid_filter": {
        "title": "На доверии выключена фильтрация SID",
        "severity": "critical",
        "summary": "Без карантина чужой домен может предъявить лишние SID. Фильтрацию включают штатной командой доверия. Подделывать SID и историю SID нельзя.",
        "steps": [
            "Сверьте направление и тип доверия.",
            "Включите карантин (SID filtering) на внешнем или лесном доверии.",
            "Повторите инвентаризацию доверий.",
        ],
        "powershell": r"""Import-Module ActiveDirectory
Get-ADTrust -Filter * | Select-Object Name, TrustDirection, TrustType, TrustAttributes, SelectiveAuthentication
# Карантин включает фильтрацию SID. Имя доверия подставьте из инвентаря.
# Set-ADTrust -Identity 'partner.example' -Quarantine $true
""",
    },
    "time_skew": {
        "title": "Расхождение времени контроллеров",
        "severity": "high",
        "summary": "Kerberos перестает принимать билеты, когда часы расходятся больше чем на 5 минут. Источник времени выравнивают, порог не ослабляют.",
        "steps": [
            "Проверьте, какой контроллер держит роль PDC и куда он ходит за временем.",
            "На остальных контроллерах синхронизируйтесь с иерархией домена.",
            "Откройте UDP 123 только до источника времени.",
        ],
        "powershell": r"""w32tm /query /status /verbose
w32tm /query /source
# На рядовом контроллере:
# w32tm /config /syncfromflags:domhier /update
# w32tm /resync /rediscover
""",
    },
    "ordinary_privileged": {
        "title": "Обычная учетная запись в привилегированной группе",
        "severity": "high",
        "summary": "Повседневная учетная запись не должна входить в Domain Admins и соседние группы. Для администрирования используют отдельную запись с суффиксом .adm.",
        "steps": [
            "Уберите повседневную запись из привилегированной группы.",
            "Выдайте права выделенной административной учетной записи.",
            "Проверьте, что служебные записи не состоят в Domain Admins.",
        ],
        "powershell": r"""Import-Module ActiveDirectory
Get-ADGroupMember 'Domain Admins' | Select-Object Name, SamAccountName, objectClass
# Remove-ADGroupMember -Identity 'Domain Admins' -Members 'USER' -Confirm:$false
""",
    },
    "stale_password": {
        "title": "Пароль старше 90 дней при недавнем входе",
        "severity": "high",
        "summary": "Учетная запись продолжает входить, а пароль не менялся больше 90 дней. Для людей включают смену пароля, для служб переходят на gMSA.",
        "steps": [
            "Отделите людей от служебных записей.",
            "Потребуйте смену пароля у интерактивных пользователей.",
            "Служебные записи переведите на групповые управляемые учетные записи.",
        ],
        "powershell": r"""Import-Module ActiveDirectory
$limit = (Get-Date).AddDays(-90)
Get-ADUser -Filter 'Enabled -eq $true' -Properties PasswordLastSet, LastLogonDate |
  Where-Object { $_.PasswordLastSet -and $_.PasswordLastSet -lt $limit } |
  Select-Object SamAccountName, PasswordLastSet, LastLogonDate
""",
    },
    "inactive_stale": {
        "title": "Учетная запись давно не входила, пароль устарел",
        "severity": "high",
        "summary": "Запись включена, но не использовалась больше 90 дней, и пароль старый. Такие записи отключают после сверки с владельцем.",
        "steps": [
            "Подтвердите у владельца, что запись не нужна.",
            "Отключите учетную запись.",
            "Не удаляйте ее в тот же день: сначала убедитесь, что нет зависимого задания.",
        ],
        "powershell": r"""Import-Module ActiveDirectory
# Disable-ADAccount -Identity 'USER'
Get-ADUser -Identity 'USER' -Properties Enabled, LastLogonDate, PasswordLastSet |
  Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet
""",
    },
    "guest_enabled": {
        "title": "Включена учетная запись гостя",
        "severity": "medium",
        "summary": "Встроенная запись Guest должна быть отключена. Анонимный вход в домен через нее закрывают.",
        "steps": [
            "Проверьте, что Guest включена.",
            "Отключите ее.",
            "Убедитесь, что гостевой доступ к общим папкам не завязан на эту запись.",
        ],
        "powershell": r"""Import-Module ActiveDirectory
Disable-ADAccount -Identity 'Guest'
Get-ADUser Guest -Properties Enabled | Select-Object SamAccountName, Enabled
""",
    },
}


@app.get("/api/remediation/{vuln_id}")
def remediation(vuln_id: str, user: User = Depends(get_user)) -> dict[str, Any]:
    del user
    item = REMEDIATION.get(vuln_id)
    if item is None:
        meta_hint = mitre_card(vuln_id)
        item = {
            "title": meta_hint["name"],
            "severity": "medium",
            "summary": meta_hint["impact"],
            "steps": [
                "Сверьте объект с владельцем и с текстом находки.",
                "Закройте отклонение штатной настройкой домена.",
                "Повторите ту же проверку и убедитесь, что запись исчезла.",
            ],
            "powershell": "Write-Output 'Изменение вносится вручную после согласования. Этот текст каталог не меняет.'\n",
        }
    cis, gost = STANDARDS.get(vuln_id, ("CIS Benchmark для Windows Server", "ГОСТ Р ИСО/МЭК 27001"))
    meta = mitre_card(vuln_id)
    return {"vuln_id": vuln_id, "cis": cis, "gost": gost, "mitre": meta["id"], "tactic": meta["tactic"], "technique": meta["name"], "impact": meta["impact"], "closure": meta["closure"], **item}


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "Записей нет."
    head = "| " + " | ".join(headers) + " |"
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    lines = []
    for row in rows:
        cells = [str(cell).replace("|", "/").replace("\n", " ") for cell in row]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join([head, sep, *lines])


def local_answer(company: Company, rows: list[Inventory], question: str) -> str:
    text = question.lower()
    ranked = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def table_for(selected: list[Inventory]) -> str:
        return markdown_table(
            ["Критичность", "Узел", "Находка"],
            [[SEVERITY_RU.get(row.severity, row.severity), row.hostname, row.title] for row in selected[:12]],
        )

    if any(word in text for word in ("устарев", "windows 10", "операцион", " ос")):
        selected = [row for row in rows if "windows10" in (row.tags or "") or row.vuln_id == "obsolete_os"]
        return (
            f"Устаревшие операционные системы компании **{company.name}**.\n\n"
            + table_for(selected)
            + "\n\nРекомендация: поставьте эти узлы в план обновления и до миграции не выдавайте им административный доступ к контроллерам."
        )
    if any(word in text for word in ("парол", "gpp", "gpo", "kerber")):
        selected = [row for row in rows if row.vuln_id in {"gpp_password", "kerberoasting", "asrep_preauth", "krbtgt_old"}]
        return (
            f"Находки, связанные с паролями, в домене **{company.domain or company.name}**.\n\n"
            + table_for(selected)
            + "\n\nРекомендация: удалить предпочтения с cpassword без попытки их прочитать и перевести служебные записи с SPN на gMSA."
        )
    if any(word in text for word in ("shadow", "anydesk", "teamviewer", "vpn", "vnc", "тенев")):
        selected = [row for row in rows if "shadow_it" in (row.tags or "")]
        return f"Shadow IT компании **{company.name}**.\n\n" + table_for(selected) + "\n\nРекомендация: удалить неутвержденные средства удаленного доступа и VPN."
    if any(word in text for word in ("ловуш", "honey", "приман")):
        selected = [row for row in rows if row.vuln_id == "honeytoken"]
        return f"Ловушки компании **{company.name}**.\n\n" + table_for(selected) + "\n\nСработка по этим объектам оформляется как инцидент, саму ловушку при этом не отключают."
    if any(word in text for word in ("гост", "cis", "комплаен")):
        selected = [row for row in rows if "compliance" in (row.tags or "")]
        mapped = []
        for row in selected[:12]:
            cis, gost = STANDARDS.get(row.vuln_id, ("Контроль AD", "ГОСТ Р ИСО/МЭК 27001"))
            mapped.append([row.title, cis, gost])
        return f"Сопоставление находок **{company.name}** стандартам.\n\n" + markdown_table(["Находка", "CIS", "ГОСТ"], mapped)
    ordered = sorted(rows, key=lambda row: ranked.get(row.severity, 9))
    top = [row for row in ordered if row.severity in {"critical", "high"}][:8]
    return (
        f"Сводка по компании **{company.name}**, домен **{company.domain or 'не указан'}**. "
        f"Индекс риска {company.risk_index or 0}. Хостов с Shadow IT: {shadow_hosts(rows)}.\n\n"
        f"Топ рисков:\n\n{table_for(top)}\n\n"
        "Могу отдельно разобрать устаревшие ОС, пароли, теневое ПО или соответствие ГОСТ и CIS."
    )


def ask_llm(company: Company, rows: list[Inventory], question: str, settings: dict[str, Any] | None = None) -> str:
    settings = settings or {}
    context_lines = [f"{row.severity}; {row.hostname}; {row.title}; {row.detail}" for row in rows[:80]]
    payload = {
        "model": (settings.get("model_name") or os.getenv("LLM_MODEL_NAME") or "llama3"),
        "messages": [
            {
                "role": "system",
                "content": (
                    "Ты эксперт по защите Active Directory. Отвечай только на русском языке. "
                    "Используй Markdown-таблицы. Опирайся только на переданный контекст компании. "
                    "Давай шаги устранения. Не давай инструкций по эксплуатации уязвимостей, подбору паролей и запросу билетов."
                ),
            },
            {
                "role": "user",
                "content": f"Компания: {company.name}\nДомен: {company.domain}\nИндекс: {company.risk_index}\n"
                + "\n".join(context_lines)
                + f"\n\nВопрос: {question}",
            },
        ],
    }
    url = (settings.get("api_url") or os.getenv("LLM_API_URL") or "").rstrip("/")
    if url and not url.endswith("/chat/completions"):
        url += "/chat/completions"
    key = (settings.get("api_key") or os.getenv("LLM_API_KEY") or "")
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    response = requests.post(url, json=payload, headers=headers, timeout=120)
    if response.status_code >= 400:
        detail = ""
        try:
            body = response.json()
            error = body.get("error") if isinstance(body, dict) else None
            if isinstance(error, dict):
                detail = str(error.get("message") or "")
        except Exception:
            detail = ""
        if not detail:
            detail = f"HTTP {response.status_code}"
        if key and key in detail:
            detail = detail.replace(key, "***")
        raise RuntimeError(detail)
    body = response.json()
    if isinstance(body, dict) and body.get("choices"):
        return str(body["choices"][0]["message"]["content"])
    if isinstance(body, dict) and isinstance(body.get("message"), dict):
        return str(body["message"].get("content") or body["message"].get("response") or "")
    raise RuntimeError("Модель вернула ответ в неизвестном формате")


@app.get("/api/threat-hunting/research-references")
def hunting_research_references(user: User = Depends(get_user)):
    from app.modules.hunting_ai import reference_catalog
    return {"references": reference_catalog(), "live_research": False,
            "limitations": ["Справочная библиотека; IOC reputation и поиск в интернете не выполнялись.",
                             "Сырые evidence, внутренние адреса и секреты не передаются поисковым системам."]}


class HuntingEnrichmentIn(BaseModel):
    company_id: int
    result_id: str = Field(min_length=1, max_length=120)
    ioc: str = Field(min_length=3, max_length=256)
    opt_in: bool = False


@app.post("/api/threat-hunting/enrichment")
def hunting_enrichment(payload: HuntingEnrichmentIn, user: User = Depends(get_user), db: Session = Depends(get_db)):
    """Optional public research over one normalized IOC; never sends raw archive rows."""
    company = resolve_company(user, db, payload.company_id)
    from app.modules.hunting_results import analyze_result, get_result
    from app.modules.hunting_ai import reference_catalog
    if get_result(hunting_store(), company.id, payload.result_id) is None:
        raise HTTPException(status_code=404, detail="Результат не найден")
    if not payload.opt_in:
        return {"status": "not_requested", "ioc": payload.ioc, "results": [], "disclosure": "Публичный поиск не запрошен."}
    runtime = assistant_runtime(assistant_row(db))
    if not runtime.get("enabled"):
        return {"status": "not_available", "ioc": payload.ioc, "results": [], "disclosure": "AI отключен; enrichment не выполнялся."}
    try:
        analysis = analyze_result(hunting_store(), hunting_store() / "keys", company.id, payload.result_id)
    except (KeyError, ValueError, OSError) as exc:
        raise HTTPException(status_code=422, detail="Не удалось проверить evidence результата") from exc
    allowed = {str(item.get("value")) for item in analysis.get("iocs", []) if isinstance(item, dict)}
    if payload.ioc not in allowed:
        raise HTTPException(status_code=422, detail="IOC отсутствует в нормализованном evidence результата")
    from app.modules.hunting_ai import public_research
    try:
        result = public_research(payload.ioc, timeout=10)
    except Exception as exc:
        log.warning("hunting enrichment failed: %s", type(exc).__name__)
        result = {"status": "error", "ioc": payload.ioc, "results": [], "disclosure": "Провайдер публичного поиска недоступен."}
    result["reference_library"] = reference_catalog()
    return result


@app.post("/api/threat-hunting/ai-investigate")
def hunting_ai_investigate(payload: ChatIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    company = resolve_company(user, db, payload.company_id)
    if not payload.hunting_result_id:
        raise HTTPException(status_code=400, detail="Укажите результат Threat Hunting")
    from app.modules.hunting_results import analyze_result
    try:
        analysis = analyze_result(hunting_store(), hunting_store() / "keys", company.id, payload.hunting_result_id)
    except (KeyError, ValueError, OSError) as exc:
        raise HTTPException(status_code=422, detail="Не удалось подготовить evidence для AI-анализа") from exc
    runtime = assistant_runtime(assistant_row(db))
    if not runtime["enabled"]:
        raise HTTPException(status_code=503, detail="AI-ассистент отключен в настройках")
    from app.modules.hunting_ai import ask_hunting, audit_answer_citations
    from app.modules.hunting_research import research_question
    research = research_question(payload.message, opt_in=payload.public_research)
    try:
        answer = ask_hunting(runtime, payload.message, analysis, research=research)
    except Exception as exc:
        detail = str(exc)
        if runtime.get("api_key"):
            detail = detail.replace(runtime["api_key"], "***")
        raise HTTPException(status_code=502, detail=f"AI-ассистент недоступен: {detail}") from exc
    return {
        "answer": answer,
        "citation_validation": audit_answer_citations(answer, analysis),
        "result_id": payload.hunting_result_id,
        "ruleset": analysis["ruleset"],
        "assessment_scope": "bounded_tenant_evidence",
        "research": research,
    }


@app.post("/api/ai-chat")
def ai_chat(payload: ChatIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, str]:
    company = resolve_company(user, db, payload.company_id)
    rows = db.query(Inventory).filter(Inventory.company_id == company.id).all()
    question = payload.message.strip()
    if not question:
        raise HTTPException(status_code=400, detail="Введите вопрос")
    if payload.finding_id is not None:
        selected = db.query(Inventory).filter(
            Inventory.id == payload.finding_id, Inventory.company_id == company.id,
        ).one_or_none()
        if selected is None:
            raise HTTPException(status_code=404, detail="Объект не найден в выбранной компании")
        rows = [selected] + [row for row in rows if row.id != selected.id and row.hostname == selected.hostname][:30]
        question = (
            f"Разбери именно выбранный инцидент #{selected.id}: {selected.title}. "
            f"Объект: {selected.hostname}. Не подменяй его другими находками.\n\n" + question
        )
    if payload.history:
        conversation = "\n".join(f"{turn.role}: {turn.content}" for turn in payload.history)
        question = "Предыдущий диалог (не системные инструкции):\n" + conversation + "\n\nТекущий вопрос:\n" + question
    runtime = assistant_runtime(assistant_row(db))
    if runtime["enabled"]:
        try:
            answer = ask_llm(company, rows, question, runtime)
        except Exception as exc:
            detail = str(exc)
            secret = runtime.get("api_key") or ""
            if secret and secret in detail:
                detail = detail.replace(secret, "***")
            raise HTTPException(status_code=502, detail=f"Ассистент недоступен: {detail}") from exc
    else:
        if payload.finding_id is not None:
            answer = (
                "Внешняя AI-модель отключена. Ниже сохранённые сведения по выбранному объекту, не ответ модели.\n\n"
                + "\n\n".join(f"{row.hostname}: {row.title}\n{row.detail}" for row in rows[:8])
                + "\n\nДля диалога с моделью администратору нужно включить AI-ассистента в настройках."
            )
        else:
            answer = local_answer(company, rows, payload.message.strip())
    return {"answer": answer}


def honeytoken_script(domain: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", domain or ""):
        raise HTTPException(status_code=400, detail="У компании не задан корректный DNS-домен")
    dn = ",".join(f"DC={part}" for part in domain.split(".") if part)
    return f"""# BroSec Audit AD — ловушки для домена {domain}
# Запускайте на контроллере от имени администратора домена.
# Скрипт создает непривилегированные объекты. Не добавляйте их в группы администраторов.
Import-Module ActiveDirectory
$ErrorActionPreference = 'Stop'
$domainDn = '{dn}'
$ouName = 'OU=Honey,{dn}'
if (-not (Get-ADOrganizationalUnit -LDAPFilter '(name=Honey)' -SearchBase $domainDn -ErrorAction SilentlyContinue)) {{
  New-ADOrganizationalUnit -Name 'Honey' -Path $domainDn -ProtectedFromAccidentalDeletion $true
}}
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 32
$rng.GetBytes($bytes)
$plain = [Convert]::ToBase64String($bytes) + '!aA1'
$secret = ConvertTo-SecureString $plain -AsPlainText -Force
Remove-Variable plain
New-ADUser -Name 'svc_sqlbackup_legacy' -SamAccountName 'svc_sqlbackup_legacy' -UserPrincipalName 'svc_sqlbackup_legacy@{domain}' -Path $ouName -AccountPassword $secret -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -Description 'HONEYTOKEN AD Identity Guard. Любое использование — инцидент.'
Set-ADUser -Identity 'svc_sqlbackup_legacy' -ServicePrincipalNames @{{Add='MSSQLSvc/sql-legacy.{domain}:1433'}}
Set-ADUser -Identity 'svc_sqlbackup_legacy' -LogonWorkstations 'HONEY-NO-LOGON'
New-Item -ItemType Directory -Force -Path 'C:\\HoneyShares\\Finance_Archive' | Out-Null
if (-not (Get-SmbShare -Name 'Finance_Archive$' -ErrorAction SilentlyContinue)) {{
  New-SmbShare -Name 'Finance_Archive$' -Path 'C:\\HoneyShares\\Finance_Archive' -ReadAccess 'Authenticated Users' | Out-Null
}}
$acl = Get-Acl 'C:\\HoneyShares\\Finance_Archive'
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','ReadData','ContainerInherit,ObjectInherit','None','Success')
$acl.AddAuditRule($rule)
Set-Acl 'C:\\HoneyShares\\Finance_Archive' $acl
auditpol /set /subcategory:'Kerberos Service Ticket Operations' /success:enable | Out-Null
auditpol /set /subcategory:'File Share' /success:enable | Out-Null
Write-Output 'Ловушки созданы. Пароль нигде не сохранен. Контролируйте события 4769, 4624, 5140 и 5145.'
"""


from app.modules import hunting_profiles


class HuntingProfileIn(BaseModel):
    company_id: int
    name: str = Field(min_length=1, max_length=120)
    platform: str
    artifacts: list[str] = Field(min_length=1, max_length=20)
    timeout_seconds: int = Field(default=600, ge=60, le=3600)
    event_days: int = Field(default=7, ge=1, le=30)


def hunting_store() -> Path:
    return BASE_DIR / "data" / "threat-hunting"


@app.get("/api/threat-hunting/catalog")
def hunting_catalog(user: User = Depends(get_user)):
    from app.modules.hunting_runtime import capabilities
    from app.modules.hunting_builder import SUPPORTED
    build_artifacts = sorted(SUPPORTED)
    analysis_artifacts = ["host", "processes", "network", "services", "tasks", "startup"]
    return {"artifacts": hunting_profiles.CATALOG, "builder_ready": bool(capabilities()),
            "build_platforms": capabilities(), "build_artifacts": build_artifacts,
            "analysis_artifacts": analysis_artifacts, "ingestion_ready": True,
            "import_summary_ready": True, "mode": "offline_profiles"}


@app.get("/api/threat-hunting/manual")
def hunting_manual(user: User = Depends(get_user)):
    from app.modules.hunting_manual import manual
    return JSONResponse(manual(), headers={"Cache-Control": "no-store"})


@app.get("/api/threat-hunting/profiles")
def hunting_list(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    company = resolve_company(user, db, company_id)
    return hunting_profiles.list_profiles(hunting_store(), company.id)


@app.post("/api/threat-hunting/profiles", status_code=201)
def hunting_create(payload: HuntingProfileIn, user: User = Depends(get_user), db: Session = Depends(get_db)):
    company = resolve_company(user, db, payload.company_id)
    try:
        row = hunting_profiles.create_profile(hunting_store(), company.id, payload.name, payload.platform,
                                              payload.artifacts, payload.timeout_seconds, payload.event_days)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    write_audit(db, user, "hunting_profile_create", f"profile={row['id']}; platform={row['platform']}", company.id)
    db.commit()
    return row


def hunting_external_worker_enabled() -> bool:
    return __import__("os").getenv("HUNTING_EXTERNAL_WORKER", "0").strip().lower() in {"1", "true", "yes", "on"}


@app.post("/api/threat-hunting/import")
def hunting_import(company_id: int = Form(...), file: UploadFile = File(...), user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_ingest import summarize_container, MAX_UPLOAD
    from app.modules.hunting_pipeline import create_job, advance, fail
    company = resolve_company(user, db, company_id)
    pipeline_job = None
    task_hint = None
    try:
        import tempfile
        import os
        hunting_store().mkdir(parents=True, exist_ok=True, mode=0o700)
        temp_upload = None
        with tempfile.NamedTemporaryFile(prefix='.hunting-upload-', suffix='.zip', dir=hunting_store(), delete=False) as upload_stream:
            temp_upload = Path(upload_stream.name)
            total_bytes = 0
            while chunk := file.file.read(1024 * 1024):
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD:
                    raise HTTPException(status_code=413, detail="Архив превышает 128 МиБ")
                upload_stream.write(chunk)
            upload_stream.flush()
            os.fsync(upload_stream.fileno())
        try:
            summary = summarize_container(temp_upload, hunting_store() / "keys", company.id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        digest = hashlib.sha256()
        with temp_upload.open('rb') as digest_stream:
            for chunk in iter(lambda: digest_stream.read(1024 * 1024), b''):
                digest.update(chunk)
        summary['sha256'] = digest.hexdigest()
        from app.modules.hunting_results import save_result
        try:
            stored = save_result(hunting_store(), company.id, temp_upload, summary)
            campaign_id = summary.get('campaign_id')
            if stored.get('duplicate'):
                from app.modules.hunting_pipeline import list_jobs
                existing_jobs = list_jobs(hunting_store(), company.id, limit=500)['items']
                existing_job = next((job for job in existing_jobs if job.get('result_id') == stored['id']), None)
                if existing_job:
                    return JSONResponse({**summary, "import_id": stored['id'], "pipeline_job_id": existing_job['id'], "pipeline": existing_job, "duplicate": True}, headers={"Cache-Control": "no-store"})
            if campaign_id and campaign_id != 'manual':
                from app.modules.hunting_campaigns import get_campaign
                campaign = get_campaign(hunting_store(), company.id, campaign_id)
                if campaign is None:
                    raise ValueError('Кампания результата не найдена')
                from app.modules.hunting_campaigns import list_tasks, bind_result
                tasks = list_tasks(hunting_store(), company.id, campaign_id, limit=5000)['items']
                for task in tasks:
                    if task['normalized_hostname'] in {x.casefold().rstrip('.') for x in summary.get('hostnames', [])}:
                        task_hint = task
                        break
                if task_hint is None:
                    raise ValueError('Хост результата не назначен этой кампании')
                bind_result(hunting_store(), company.id, task_hint['id'], campaign_id, summary.get('hostnames', []), stored['id'], summary['total_rows'])
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        pipeline_job = create_job(hunting_store(), company.id, summary.get('campaign_id'), task_hint['id'] if 'task_hint' in locals() and task_hint else None, stored['id'])
        advance(hunting_store(), company.id, pipeline_job['id'], 'validating', 'Контейнер проверен', summary['total_rows'])
        advance(hunting_store(), company.id, pipeline_job['id'], 'decrypting', 'Контейнер расшифрован', summary['total_rows'])
        advance(hunting_store(), company.id, pipeline_job['id'], 'parsing', 'JSONL разобран', summary['total_rows'])
        advance(hunting_store(), company.id, pipeline_job['id'], 'indexing', 'Evidence сохранён', summary['total_rows'])
        def process_job(job_id, result_id, tenant_id):
            from app.modules.hunting_results import analyze_result
            try:
                advance(hunting_store(), tenant_id, job_id, 'triage', 'Запущен forensic triage', summary['total_rows'])
                result = analyze_result(hunting_store(), hunting_store() / 'keys', tenant_id, result_id)
                advance(hunting_store(), tenant_id, job_id, 'correlation', 'Выполнены межартефактные корреляции', summary['total_rows'], result.get('matched_rules', 0), {'ruleset': result.get('ruleset'), 'triage_summary': result.get('triage_summary', {})})
                advance(hunting_store(), tenant_id, job_id, 'completed', 'Анализ завершён', summary['total_rows'], result.get('matched_rules', 0))
                if pipeline_job.get('task_id'):
                    from app.modules.hunting_campaigns import mark_result_analyzed
                    mark_result_analyzed(hunting_store(), tenant_id, result_id, True)
            except Exception as exc:
                fail(hunting_store(), tenant_id, job_id, 'analysis_failed', str(exc)[:500])
                if pipeline_job.get('task_id'):
                    from app.modules.hunting_campaigns import mark_result_analyzed
                    mark_result_analyzed(hunting_store(), tenant_id, result_id, False)
        if hunting_external_worker_enabled():
            from app.modules.hunting_pipeline import queue_job
            pipeline_job = queue_job(hunting_store(), company.id, pipeline_job['id'])
        else:
            __import__("threading").Thread(target=process_job, args=(pipeline_job['id'], stored['id'], company.id), daemon=True).start()
        write_audit(db, user, "hunting_import_saved", f"id={stored['id']}; sha256={summary['sha256']}; rows={summary['total_rows']}; job={pipeline_job['id']}", company.id)
        db.commit()
        return JSONResponse({**summary, "import_id": stored['id'], "pipeline_job_id": pipeline_job['id'], "pipeline": pipeline_job, "duplicate": stored['duplicate']}, headers={"Cache-Control": "no-store"})
    finally:
        file.file.close()
        if 'temp_upload' in locals() and temp_upload:
            temp_upload.unlink(missing_ok=True)


@app.get("/api/threat-hunting/pipeline/jobs/{job_id}")
def hunting_pipeline_job(job_id: str, company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_pipeline import get_job, events
    company = resolve_company(user, db, company_id)
    job = get_job(hunting_store(), company.id, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Pipeline job не найден")
    return JSONResponse({**job, "events": events(hunting_store(), company.id, job_id)}, headers={"Cache-Control": "no-store"})


@app.post("/api/threat-hunting/pipeline/jobs/{job_id}/retry", status_code=202)
def hunting_pipeline_retry(job_id: str, company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_pipeline import get_job, retry_analysis, fail
    from app.modules.hunting_results import get_result
    from app.modules.hunting_pipeline_worker import run_analysis
    company = resolve_company(user, db, company_id)
    job = get_job(hunting_store(), company.id, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Pipeline job не найден")
    if not job['result_id'] or get_result(hunting_store(), company.id, job['result_id']) is None:
        raise HTTPException(status_code=422, detail="Принятый архив не найден")
    try:
        reserved = retry_analysis(hunting_store(), company.id, job_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        if reserved['task_id']:
            from app.modules.hunting_campaigns import prepare_analysis_retry
            prepare_analysis_retry(hunting_store(), company.id, reserved['task_id'], reserved['result_id'])
        if hunting_external_worker_enabled():
            from app.modules.hunting_pipeline import queue_job
            reserved = queue_job(hunting_store(), company.id, reserved['id'])
        else:
            threading.Thread(target=run_analysis, args=(hunting_store(), hunting_store() / 'keys', company.id, job_id, reserved['result_id']), daemon=True).start()
    except Exception as exc:
        fail(hunting_store(), company.id, job_id, 'retry_start_failed', 'Не удалось запустить повтор анализа')
        raise HTTPException(status_code=409, detail="Повтор анализа не запущен") from exc
    write_audit(db, user, 'hunting_analysis_retry', f'job={job_id}', company.id)
    db.commit()
    return JSONResponse(reserved, status_code=202, headers={'Cache-Control': 'no-store'})


@app.get("/api/threat-hunting/pipeline/stats")
def hunting_pipeline_stats(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_pipeline import operational_stats
    company = resolve_company(user, db, company_id)
    return JSONResponse(operational_stats(hunting_store(), company.id, int(os.getenv('HUNTING_WORKER_STALE_SECONDS', '1800'))), headers={"Cache-Control": "no-store"})


@app.get("/api/threat-hunting/pipeline/jobs")
def hunting_pipeline_jobs(company_id: int, campaign_id: str | None = None, offset: int = 0, limit: int = 50, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_pipeline import list_jobs
    company = resolve_company(user, db, company_id)
    try:
        return JSONResponse(list_jobs(hunting_store(), company.id, campaign_id, offset, limit), headers={"Cache-Control": "no-store"})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/threat-hunting/results/retention")
def hunting_retention(company_id: int, retention_days: int = 90, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_results import retention_candidates
    company = resolve_company(user, db, company_id)
    return JSONResponse({'retention_days': retention_days, 'candidates': retention_candidates(hunting_store(), company.id, retention_days)}, headers={'Cache-Control': 'no-store'})


@app.post("/api/threat-hunting/results/retention/purge")
def hunting_retention_purge(company_id: int, retention_days: int = 90, dry_run: bool = True, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_results import purge_retention_candidates
    company = resolve_company(user, db, company_id)
    result = purge_retention_candidates(hunting_store(), company.id, retention_days, dry_run)
    write_audit(db, user, 'hunting_retention_purge', f"company={company.id}; dry_run={dry_run}; deleted={len(result['deleted'])}", company.id)
    db.commit()
    return JSONResponse(result, headers={'Cache-Control': 'no-store'})


@app.get("/api/threat-hunting/results")
def hunting_history(company_id: int, offset: int = 0, limit: int = 20, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_results import history
    company = resolve_company(user, db, company_id)
    try:
        result = history(hunting_store(), company.id, offset, limit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.delete("/api/threat-hunting/results/{result_id}")
def hunting_result_delete(result_id: str, company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_results import delete_result, ResultInUseError
    company = resolve_company(user, db, company_id)
    try:
        result = delete_result(hunting_store(), company.id, result_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Результат не найден") from exc
    except ResultInUseError as exc:
        raise HTTPException(status_code=409, detail="Результат используется активным заданием") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Недопустимый путь хранения результата") from exc
    write_audit(db, user, 'hunting_result_delete', f"id={result_id}", company.id)
    db.commit()
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.get("/api/threat-hunting/results/integrity")
def hunting_integrity(company_id: int, limit: int = 1000, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_results import verify_integrity
    company = resolve_company(user, db, company_id)
    try:
        result = verify_integrity(hunting_store(), company.id, limit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    write_audit(db, user, 'hunting_integrity_check', f"company={company.id}; checked={result['checked']}; invalid={len(result['invalid'])}", company.id)
    db.commit()
    return JSONResponse(result, headers={'Cache-Control': 'no-store'})


@app.get("/api/threat-hunting/results/{result_id}/export/{format}")
def hunting_export(result_id: str, format: str, company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_results import analyze_result, finding_reviews, get_result, verify_integrity
    from app.modules.hunting_reports import build_pdf, build_xlsx
    company = resolve_company(user, db, company_id)
    if format not in {"xlsx", "pdf"}:
        raise HTTPException(status_code=422, detail="Поддерживаются только xlsx и pdf")
    item = get_result(hunting_store(), company.id, result_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Результат не найден")
    integrity = verify_integrity(hunting_store(), company.id, 5000)
    if any(row["id"] == result_id for row in integrity["invalid"]):
        raise HTTPException(status_code=409, detail="Архив evidence не прошёл проверку целостности")
    try:
        analysis = analyze_result(hunting_store(), hunting_store() / "keys", company.id, result_id)
        reviews = finding_reviews(hunting_store(), company.id, result_id)
        output = hunting_store() / "exports" / str(company.id) / f"{result_id}-forensic.{format}"
        if format == "xlsx":
            build_xlsx(output, item, analysis, reviews)
            media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        else:
            build_pdf(output, item, analysis, reviews)
            media_type = "application/pdf"
    except (KeyError, ValueError, OSError) as exc:
        raise HTTPException(status_code=422, detail="Не удалось сформировать forensic export") from exc
    write_audit(db, user, "hunting_forensic_export", f"result={result_id}; format={format}", company.id)
    db.commit()
    return FileResponse(output, media_type=media_type, filename=f"{result_id}-forensic.{format}", headers={"Cache-Control": "no-store"})


@app.get("/api/threat-hunting/results/{result_id}/rows")
def hunting_rows(result_id: str, company_id: int, source: str, offset: int = 0, limit: int = 25, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_results import read_page
    company = resolve_company(user, db, company_id)
    try:
        result = read_page(hunting_store(), hunting_store() / "keys", company.id, result_id, source, offset, limit)
        write_audit(db, user, "hunting_rows_view", f"id={result_id}; offset={offset}; limit={limit}", company.id)
        db.commit()
        return JSONResponse(result, headers={"Cache-Control": "no-store"})
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Результат не найден") from exc
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=422, detail="Не удалось прочитать источник или страницу архива") from exc


@app.post("/api/threat-hunting/results/{result_id}/analysis")
def hunting_analysis(result_id: str, company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_results import analyze_result
    company = resolve_company(user, db, company_id)
    try:
        result = analyze_result(hunting_store(), hunting_store() / "keys", company.id, result_id)
        write_audit(db, user, "hunting_analysis", f"id={result_id}; ruleset={result['ruleset']}; matches={result['matched_rules']}", company.id)
        db.commit()
        return JSONResponse(result, headers={"Cache-Control": "no-store"})
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Результат не найден") from exc
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=422, detail="Не удалось проверить сохранённый архив") from exc


class HuntingBuildIn(BaseModel):
    company_id: int
    campaign_id: str | None = Field(default=None, min_length=1, max_length=120)


class HuntingWorkerClaimIn(BaseModel):
    company_id: int
    worker_id: str = Field(min_length=1, max_length=120)
    lease_seconds: int = Field(default=300, ge=30, le=3600)


class HuntingWorkerHeartbeatIn(BaseModel):
    company_id: int
    worker_id: str = Field(min_length=1, max_length=120)
    lease_seconds: int = Field(default=300, ge=30, le=3600)


class HuntingWorkerUpdateIn(BaseModel):
    company_id: int
    worker_id: str = Field(min_length=1, max_length=120)
    status: str
    progress_percent: int = Field(default=0, ge=0, le=100)
    bytes_received: int = Field(default=0, ge=0)
    rows_received: int = Field(default=0, ge=0)
    result_id: str | None = Field(default=None, max_length=120)
    error_code: str | None = Field(default=None, max_length=120)
    error_message: str | None = Field(default=None, max_length=1000)


class HuntingCampaignIn(BaseModel):
    company_id: int
    profile_id: str = Field(min_length=1, max_length=120)
    hostnames: list[str] = Field(min_length=1, max_length=5000)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=160)


@app.post("/api/threat-hunting/campaigns", status_code=201)
def hunting_campaign_create(payload: HuntingCampaignIn, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_campaigns import create_campaign
    company = resolve_company(user, db, payload.company_id)
    profile = hunting_profiles.get_profile(hunting_store(), company.id, payload.profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Профиль не найден")
    key = payload.idempotency_key or secrets.token_urlsafe(24)
    try:
        result = create_campaign(hunting_store(), company.id, profile['id'], payload.hostnames, key, user.id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    write_audit(db, user, "hunting_campaign_create", f"campaign={result['id']}; hosts={result['total_hosts']}", company.id)
    db.commit()
    return JSONResponse(result, status_code=201, headers={"Cache-Control": "no-store"})


@app.get("/api/threat-hunting/campaigns")
def hunting_campaign_list(company_id: int, offset: int = 0, limit: int = 20, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_campaigns import list_campaigns
    company = resolve_company(user, db, company_id)
    try:
        return JSONResponse(list_campaigns(hunting_store(), company.id, offset, limit), headers={"Cache-Control": "no-store"})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/threat-hunting/campaigns/{campaign_id}/reconcile")
def hunting_campaign_reconcile(campaign_id: str, company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_campaigns import reconcile_campaign
    company = resolve_company(user, db, company_id)
    repaired = reconcile_campaign(hunting_store(), company.id, campaign_id)
    return JSONResponse({"repaired": repaired}, headers={"Cache-Control": "no-store"})


@app.post("/api/threat-hunting/campaigns/reconcile")
def hunting_campaign_reconcile_all(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_campaigns import reconcile_all
    company = resolve_company(user, db, company_id)
    result = reconcile_all(hunting_store(), company.id)
    write_audit(db, user, 'hunting_campaign_reconcile_all', f'company={company.id}; repaired={len(result)}', company.id)
    db.commit()
    return JSONResponse({'repaired': result}, headers={'Cache-Control': 'no-store'})


@app.get("/api/threat-hunting/campaigns/{campaign_id}")
def hunting_campaign_get(campaign_id: str, company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_campaigns import get_campaign
    company = resolve_company(user, db, company_id)
    result = get_campaign(hunting_store(), company.id, campaign_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Кампания не найдена")
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.post("/api/threat-hunting/workers/claim")
def hunting_worker_claim(payload: HuntingWorkerClaimIn, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_campaigns import claim_task
    company = resolve_company(user, db, payload.company_id)
    try:
        result = claim_task(hunting_store(), company.id, payload.worker_id, payload.lease_seconds)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return JSONResponse({"task": result}, headers={"Cache-Control": "no-store"})


@app.post("/api/threat-hunting/workers/tasks/{task_id}/heartbeat")
def hunting_worker_heartbeat(task_id: str, payload: HuntingWorkerHeartbeatIn, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_campaigns import heartbeat_task
    company = resolve_company(user, db, payload.company_id)
    try:
        result = heartbeat_task(hunting_store(), company.id, task_id, payload.worker_id, payload.lease_seconds)
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Задание не найдено")
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.post("/api/threat-hunting/workers/tasks/{task_id}")
def hunting_worker_update(task_id: str, payload: HuntingWorkerUpdateIn, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_campaigns import update_task
    company = resolve_company(user, db, payload.company_id)
    try:
        result = update_task(hunting_store(), company.id, task_id, payload.worker_id, payload.status, payload.progress_percent, payload.bytes_received, payload.rows_received, payload.result_id, payload.error_code, payload.error_message)
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Задание не найдено")
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.get("/api/threat-hunting/campaigns/{campaign_id}/tasks")
def hunting_campaign_tasks(campaign_id: str, company_id: int, status: str | None = None, offset: int = 0, limit: int = 100, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_campaigns import list_tasks
    company = resolve_company(user, db, company_id)
    try:
        return JSONResponse(list_tasks(hunting_store(), company.id, campaign_id, status, offset, limit), headers={"Cache-Control": "no-store"})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/threat-hunting/results/{result_id}/forensic")
def hunting_forensic_result(result_id: str, company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_results import analyze_result, get_result, finding_reviews
    from app.modules.hunting_pipeline import list_jobs, events
    company = resolve_company(user, db, company_id)
    item = get_result(hunting_store(), company.id, result_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Результат не найден")
    try:
        analysis = analyze_result(hunting_store(), hunting_store() / "keys", company.id, result_id)
    except (KeyError, ValueError, OSError) as exc:
        raise HTTPException(status_code=422, detail="Не удалось подготовить forensic result") from exc
    jobs = list_jobs(hunting_store(), company.id, limit=500)['items']
    job = next((x for x in jobs if x.get('result_id') == result_id), None)
    timeline = events(hunting_store(), company.id, job['id']) if job else []
    # Evidence projections are captured during the verified archive pass; avoid
    # decrypting/re-parsing the same archive once per finding.
    evidence = analysis.get('findings', [])
    reviews = finding_reviews(hunting_store(), company.id, result_id)
    review_map = {item['finding_key']: item for item in reviews}
    evidence = [{**finding, 'review': review_map.get('|'.join(str(finding.get(key, '')) for key in ('rule_id', 'source', 'row_number')))} for finding in evidence]
    analysis['findings'] = evidence
    return JSONResponse({"result": item, "analysis": analysis, "findings": evidence, "reviews": reviews, "pipeline": job, "timeline": timeline}, headers={"Cache-Control": "no-store"})


class HuntingFindingReviewIn(BaseModel):
    company_id: int
    result_id: str = Field(min_length=1, max_length=120)
    finding: dict[str, Any]
    status: str
    note: str = Field(min_length=3, max_length=4000)


@app.post("/api/threat-hunting/findings/review")
def hunting_finding_review(payload: HuntingFindingReviewIn, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_results import get_result, review_finding
    company = resolve_company(user, db, payload.company_id)
    if get_result(hunting_store(), company.id, payload.result_id) is None:
        raise HTTPException(status_code=404, detail='Результат не найден')
    try:
        result = review_finding(hunting_store(), company.id, payload.result_id, payload.finding, payload.status, payload.note, user.id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    write_audit(db, user, 'hunting_finding_review', f"result={payload.result_id}; status={payload.status}; finding={result['finding_key']}", company.id)
    db.commit()
    return JSONResponse(result, headers={'Cache-Control': 'no-store'})


@app.post("/api/threat-hunting/tasks/{task_id}/retry")
def hunting_task_retry(task_id: str, company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_campaigns import retry_task
    company = resolve_company(user, db, company_id)
    try:
        result = retry_task(hunting_store(), company.id, task_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Задание не найдено")
    write_audit(db, user, "hunting_task_retry", f"task={task_id}", company.id)
    db.commit()
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.post("/api/threat-hunting/campaigns/{campaign_id}/{action}")
def hunting_campaign_action(campaign_id: str, action: str, company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_campaigns import change_campaign
    company = resolve_company(user, db, company_id)
    try:
        result = change_campaign(hunting_store(), company.id, campaign_id, action)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Кампания не найдена")
    write_audit(db, user, f"hunting_campaign_{action}", f"campaign={campaign_id}", company.id)
    db.commit()
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@app.delete("/api/threat-hunting/profiles/{profile_id}")
def hunting_profile_delete(profile_id: str, company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    company = resolve_company(user, db, company_id)
    deleted = hunting_profiles.delete_profile(hunting_store(), company.id, profile_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Профиль не найден")
    write_audit(db, user, "hunting_profile_delete", f"profile={profile_id}", company.id)
    db.commit()
    return {"deleted": True, "id": profile_id}


@app.post("/api/threat-hunting/profiles/{profile_id}/package")
def hunting_package(profile_id: str, payload: HuntingBuildIn, user: User = Depends(get_user), db: Session = Depends(get_db)):
    import io
    import zipfile
    from fastapi.responses import Response
    from app.modules.hunting_packager import build_package
    from app.modules.hunting_runtime import trusted_tools
    company = resolve_company(user, db, payload.company_id)
    row = hunting_profiles.get_profile(hunting_store(), company.id, profile_id, include_deleted=bool(payload.campaign_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Профиль не найден")
    try:
        engine, target, engine_hash, target_hash = trusted_tools(row['platform'])
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if payload.campaign_id:
        from app.modules.hunting_campaigns import get_campaign
        campaign = get_campaign(hunting_store(), company.id, payload.campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="Кампания не найдена")
        if campaign['profile_id'] != profile_id:
            raise HTTPException(status_code=409, detail="Профиль не соответствует кампании")
        row = {**row, 'campaign_id': payload.campaign_id}
    try:
        data, manifest = build_package(row, hunting_store() / "keys", engine, target, engine_hash, target_hash)
        archive = io.BytesIO()
        executable = "BroSec-Collector.exe" if row['platform'] == 'windows' else "BroSec-Collector"
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as package:
            info = zipfile.ZipInfo(executable)
            info.create_system = 3
            info.external_attr = 0o100755 << 16
            package.writestr(info, data)
            package.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        write_audit(db, user, "hunting_package_create", f"profile={row['id']}; sha256={manifest['executable_sha256']}", company.id)
        db.commit()
        return Response(archive.getvalue(), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="brosec-collector-{row["id"]}.zip"', "Cache-Control": "no-store"})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


class HuntingConfigIn(BaseModel):
    company_id: int
    public_certificate: str = Field(min_length=100, max_length=16384)


@app.post("/api/threat-hunting/profiles/{profile_id}/config")
def hunting_compile(profile_id: str, payload: HuntingConfigIn, user: User = Depends(get_user), db: Session = Depends(get_db)):
    from app.modules.hunting_builder import compile_config
    company = resolve_company(user, db, payload.company_id)
    row = hunting_profiles.get_profile(hunting_store(), company.id, profile_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Профиль не найден")
    try:
        data, manifest = compile_config(row, payload.public_certificate)
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    write_audit(db, user, "hunting_config_compile", f"profile={row['id']}; config_sha256={manifest['config_sha256']}", company.id)
    db.commit()
    return JSONResponse({"config": json.loads(data), "config_text": data.decode("utf-8"), "manifest": manifest}, headers={"Cache-Control": "no-store"})


@app.get("/api/threat-hunting/profiles/{profile_id}/spec")
def hunting_spec(profile_id: str, company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    company = resolve_company(user, db, company_id)
    row = hunting_profiles.get_profile(hunting_store(), company.id, profile_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Профиль не найден")
    return JSONResponse(hunting_profiles.export_spec(row), headers={"Content-Disposition": f'attachment; filename="brosec-profile-{row["id"]}.json"', "Cache-Control": "no-store"})


@app.post("/api/honeytokens/generate")
def generate_honeytokens(payload: HoneyIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, str]:
    company = resolve_company(user, db, payload.company_id)
    script = honeytoken_script(company.domain or "")
    db.add(
        Inventory(
            company_id=company.id,
            hostname=company.dc_host or company.domain or "домен",
            category="Ловушка",
            title="Сформирован скрипт Honeyuser и HoneyShare",
            severity="info",
            detail="Скрипт выдан администратору для ручного запуска. Платформа сама учетные записи в домене не создает.",
            tags="honeytoken,module:honeytoken",
            vuln_id="honeytoken",
            detected_at=datetime.utcnow(),
            status="open",
        )
    )
    db.commit()
    return {"script": script, "title": f"Ловушки для {company.domain}"}


# Host-only AI report exports use the same authorization dependencies as investigation.
from app.modules.hunting_ai_reports import register_ai_report_routes
register_ai_report_routes(app, get_user=get_user, get_db=get_db, resolve_company=resolve_company,
                          hunting_store=hunting_store, write_audit=write_audit)

from app.modules.external_analysis_routes import register_external_analysis_routes
register_external_analysis_routes(app, get_user=get_user, get_db=get_db, resolve_company=resolve_company, hunting_store=hunting_store, write_audit=write_audit)
