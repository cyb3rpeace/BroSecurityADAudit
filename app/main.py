"""AD Identity Guard v2.0 — ядро, изоляция тенантов, отчеты и копилот."""

from __future__ import annotations

import hashlib
import html
import json
import logging
import os
import re
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
    NotifyChannel,
    ScanHistory,
    AuthSession,
    SessionLocal,
    User,
    hash_password,
    init_db,
    verify_password,
)
from app.modules.account_auth import device_label, new_secret, otpauth_uri, qr_svg, totp_ok
from app.modules.bloodhound import ingest_sharphound_zip, run_bloodhound
from app.modules.dc_hardening import scan_hardening
from app.modules.ldap_audit import directory_picture, list_computer_names, lookup_asset, probe_directory, scan_adcs_ldap, scan_hardening_ldap, scan_hygiene_ldap, scan_trusts_ldap
from app.modules.mitre import card as mitre_card
from app.modules.mitre import tactics_of
from app.modules.protocols import scan_protocols_ldap, scan_protocols_windows
from app.modules.notifier_mail import send_report
from app.modules.notifier_tg import send_summary
from app.modules.posture import scan_hygiene, scan_time, scan_trusts
from app.modules.software_scan import controller_extra, dns_zones, gpo_conflicts, last_interactive_user, repair_caption, scan_gpp, scan_software, validate_host

load_dotenv(BASE_DIR / ".env")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("adguard")

try:
    TZ = ZoneInfo("Europe/Moscow")
except Exception:
    TZ = ZoneInfo("UTC")

PRODUCT_VERSION = "2.6.8"

ALLOWED_MODULES = (
    "bloodhound",
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
    "bloodhound": "BloodHound CE",
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


def channel_row(db: Session) -> NotifyChannel:
    row = db.get(NotifyChannel, 1)
    if row is None:
        row = NotifyChannel(id=1)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def mail_channel(row: NotifyChannel) -> dict[str, Any]:
    return {
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
    if (raw or "") == "monthly":
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


def build_excel(path: Path, company: Company, rows: list[Inventory], scans: list[ScanHistory], score: int) -> None:
    findings = pd.DataFrame([
        {
            "Критичность": SEVERITY_RU.get(row.severity, row.severity),
            "Узел": row.hostname,
            "Категория": row.category,
            "Находка": row.title,
            "Описание": row.detail,
            "Теги": row.tags,
            "На что влияет": mitre_card(row.vuln_id or "")["impact"],
            "Как закрыть": mitre_card(row.vuln_id or "")["closure"],
            "MITRE": mitre_card(row.vuln_id or "")["id"],
            "Тактика MITRE": mitre_card(row.vuln_id or "")["tactic"],
            "Техника MITRE": mitre_card(row.vuln_id or "")["name"],
            "Стандарт CIS": STANDARDS.get(row.vuln_id, ("", ""))[0],
            "ГОСТ": STANDARDS.get(row.vuln_id, ("", ""))[1],
            "Обнаружено": row.detected_at.strftime("%d.%m.%Y %H:%M") if row.detected_at else "",
            "Статус": row.status,
        }
        for row in rows
    ])
    history = pd.DataFrame([
        {
            "Дата": (scan.finished_at or scan.started_at).strftime("%d.%m.%Y %H:%M") if (scan.finished_at or scan.started_at) else "",
            "Модули": scan.module,
            "Контроллер": scan.target_dc,
            "Статус": scan.status,
            "Индекс": scan.risk_score if scan.risk_score is not None else "",
            "Сводка": scan.summary,
        }
        for scan in scans
    ])
    summary = pd.DataFrame([
        {"Показатель": "Компания", "Значение": company.name},
        {"Показатель": "Домен", "Значение": company.domain or ""},
        {"Показатель": "Индекс риска AD", "Значение": score},
        {"Показатель": "Хостов с Shadow IT", "Значение": shadow_hosts(rows)},
        {"Показатель": "Ловушек", "Значение": sum(1 for row in rows if row.vuln_id == "honeytoken")},
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
    "bloodhound": "SharpHound",
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
        modules = [item for item in (scan.module or "").split(",") if item]
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
                elif module == "bloodhound":
                    if win_connection:
                        result = run_bloodhound(windows_connection(win_connection))
                    else:
                        result = run_bloodhound(None)
                        note = "SharpHound удаленно не запускался. Запустите его вручную на компьютере, где уже выполнен вход в домен, и загрузите zip на странице SharpHound. Граф читается, если сбор уже загружали."
                        result["message"] = (note + " " + (result.get("message") or "")).strip()
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
                elif module not in {"software_audit", "dc_hardening"} and not dc_windows and module not in {"trusts", "baseline_hygiene", "bloodhound", "protocols"}:
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
        channel = channel_row(db)
        chat = (company.telegram_chat or channel.telegram_chat or "").strip()
        prefs = read_notify_prefs(channel)
        status_key = "scan_failed" if scan.status == "failed" else "scan_done"
        mail_text = alert_body(prefs, "mail", status_key, text, collected)
        tg_text = alert_body(prefs, "telegram", status_key, text, collected)
        telegram = (
            send_summary(tg_text, str(pdf_path) if pdf_path else None, channel.telegram_token, chat)
            if tg_text else {"ok": True}
        )
        mail = (
            send_report(
                company.name,
                mail_text,
                collected if prefs.get("critical", {}).get("mail") or prefs.get("software_danger", {}).get("mail") else [],
                str(pdf_path) if pdf_path else None,
                company.notify_email,
                mail_channel(channel),
            )
            if mail_text else {"ok": True}
        )
        extra = []
        if not telegram.get("ok"):
            extra.append(str(telegram.get("error")))
        if not mail.get("ok"):
            extra.append(str(mail.get("error")))
        for secret in (channel.smtp_password or "", channel.telegram_token or ""):
            if secret:
                extra = [line.replace(secret, "***") for line in extra]
        if extra:
            scan.summary = (scan.summary + "\n" + "\n".join(extra))[:8000]
        try:
            publish_scan_notice(db, scan, company)
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
                publish_scan_notice(db, scan, failed_company)
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


def apply_company_schedule(company: Company) -> None:
    job_id = f"scan-{company.id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    if not company.scheduler_enabled:
        return
    if (company.schedule or "") == "monthly":
        trigger = CronTrigger(day=1, hour=2, minute=0, timezone=TZ)
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


@app.on_event("startup")
def on_startup() -> None:
    init_db()
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


class ChatIn(BaseModel):
    company_id: int
    message: str = Field(min_length=1, max_length=4000)


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


class NotifyIn(BaseModel):
    smtp_server: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"
    smtp_user: str = ""
    smtp_password: str | None = None
    smtp_from: str = ""
    telegram_token: str | None = None
    telegram_chat: str = ""


class NotifyTestIn(BaseModel):
    recipient: str = ""


def require_superadmin(user: User) -> None:
    if user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Недостаточно прав")


@app.get("/api/notifications")
def notifications_get(user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    require_superadmin(user)
    return channel_public(channel_row(db))


@app.put("/api/notifications")
def notifications_put(payload: NotifyIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    require_superadmin(user)
    if payload.smtp_security not in {"none", "starttls", "ssl"}:
        raise HTTPException(status_code=400, detail="Защита SMTP: none, starttls или ssl")
    if not 1 <= int(payload.smtp_port) <= 65535:
        raise HTTPException(status_code=400, detail="Порт SMTP вне диапазона")
    row = channel_row(db)
    row.smtp_server = payload.smtp_server.strip()
    row.smtp_port = int(payload.smtp_port)
    row.smtp_security = payload.smtp_security
    row.smtp_user = payload.smtp_user.strip()
    row.smtp_from = payload.smtp_from.strip()
    row.telegram_chat = payload.telegram_chat.strip()
    if payload.smtp_password:
        row.smtp_password = payload.smtp_password
    if payload.telegram_token:
        row.telegram_token = payload.telegram_token.strip()
    note = f"SMTP {row.smtp_server or 'не задан'}:{row.smtp_port}, Telegram-чат {'задан' if row.telegram_chat else 'пуст'}"
    if payload.smtp_password:
        note += ". Пароль SMTP обновлен"
    if payload.telegram_token:
        note += ". Токен Telegram обновлен"
    write_audit(db, user, "notify_update", note)
    db.commit()
    return channel_public(row)


class NotifyPrefsIn(BaseModel):
    topics: dict[str, dict[str, bool]]


@app.get("/api/notifications/prefs")
def notifications_prefs_get(user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    row = channel_row(db)
    return {
        "topics": read_notify_prefs(row),
        "mail_ready": bool((row.smtp_server or "").strip()),
        "telegram_ready": bool((row.telegram_token or "").strip() and (row.telegram_chat or "").strip()),
    }


@app.put("/api/notifications/prefs")
def notifications_prefs_put(payload: NotifyPrefsIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    row = channel_row(db)
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
    write_audit(db, user, "notify_prefs", "Обновлены переключатели почты и Telegram")
    db.commit()
    return {"topics": current}


@app.post("/api/notifications/test-mail")
def notifications_test_mail(payload: NotifyTestIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    require_superadmin(user)
    row = channel_row(db)
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
def notifications_test_telegram(user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, bool]:
    require_superadmin(user)
    row = channel_row(db)
    result = send_summary(
        "BroSec Audit AD: канал Telegram работает. Сюда придут алерты и паспорт домена.",
        None,
        row.telegram_token,
        row.telegram_chat,
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
    _picture_cache[company.id] = (now, picture)
    return picture


@app.get("/api/directory/windows")
def directory_windows(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, Any]:
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
    controllers = controller_extra(win, hosts)
    diff = gpo_conflicts(win, names)
    zones = dns_zones(win)
    zones["wildcard"] = bool(picture.get("wildcard"))
    matrix = []
    for row in controllers:
        for partner in row.get("partners") or []:
            matrix.append({"source": row.get("host") or "", **partner})
    readable = sum(1 for row in controllers if row.get("ok"))
    return {
        "ok": bool(readable or diff.get("ok") or zones.get("ok")),
        "controllers": controllers,
        "conflicts": diff.get("conflicts") or [],
        "replication": matrix[:80],
        "dns": zones,
        "message": f"Контроллеров ответило: {readable} из {len(hosts[:6])}. Связей репликации: {len(matrix)}. {diff.get('message') or ''} {zones.get('message') or ''}".strip(),
    }


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
    if payload.interval not in {"daily", "weekly", "monthly"} and not re.fullmatch(r"[a-z]{3}(?:,[a-z]{3})*@\d{2}:\d{2}", payload.interval or ""):
        raise HTTPException(status_code=400, detail="Укажите дни недели и время")
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


@app.get("/api/export/excel")
def export_excel(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    company = resolve_company(user, db, company_id)
    rows = db.query(Inventory).filter(Inventory.company_id == company.id).all()
    scans = db.query(ScanHistory).filter(ScanHistory.company_id == company.id).order_by(ScanHistory.id.desc()).all()
    path = REPORTS_DIR / str(company.id) / "passport-latest.xlsx"
    build_excel(path, company, rows, scans, company.risk_index or 0)
    return attachment(path, f"Паспорт_{company.domain or company.id}.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.get("/api/export/pdf")
def export_pdf(company_id: int, user: User = Depends(get_user), db: Session = Depends(get_db)):
    company = resolve_company(user, db, company_id)
    rows = db.query(Inventory).filter(Inventory.company_id == company.id).all()
    path = REPORTS_DIR / str(company.id) / "passport-latest.pdf"
    build_pdf(path, company, rows, company.risk_index or 0)
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


@app.post("/api/import/sharphound")
async def import_sharphound(
    company_id: int = Form(...),
    upload: UploadFile = File(...),
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    company = resolve_company(user, db, company_id)
    blob = await upload.read()
    if len(blob) > 80 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Архив больше 80 МБ")
    if not blob.startswith(b"PK"):
        raise HTTPException(status_code=400, detail="Файл не похож на zip-архив SharpHound")
    try:
        message = ingest_sharphound_zip(blob)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"BloodHound CE не принял архив: {exc}") from exc
    if not str(message).startswith("Архив SharpHound принят"):
        raise HTTPException(status_code=502, detail=str(message))
    result = run_bloodhound(None)
    findings = result.get("findings") or []
    if findings:
        replace_findings(db, company.id, "bloodhound", findings)
    note = (str(message) + " " + str(result.get("message") or "")).strip()
    scan = ScanHistory(
        company_id=company.id,
        module="bloodhound",
        target_dc=company.dc_host or "",
        status="success" if result.get("ok") else "partial",
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        summary=note[:800],
        risk_score=None,
        log="",
        actor=user.full_name or user.username,
    )
    db.add(scan)
    write_audit(db, user, "sharphound_import", "Загружен архив SharpHound", company.id)
    publish_notice(db, company.id, "Загружен архив SharpHound", f"{company.name}. Загрузил: {user.full_name or user.username}. {note[:240]}", "import")
    db.commit()
    return {"ok": bool(result.get("ok")), "message": note[:800], "findings": len(findings)}


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
        "summary": "Шаблон с EKU проверки подлинности клиента, автовыпуском и правом заявителя указать SAN нужно сузить. Платформа не выпускает сертификаты и не показывает способ злоупотребления шаблоном.",
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


@app.post("/api/ai-chat")
def ai_chat(payload: ChatIn, user: User = Depends(get_user), db: Session = Depends(get_db)) -> dict[str, str]:
    company = resolve_company(user, db, payload.company_id)
    rows = db.query(Inventory).filter(Inventory.company_id == company.id).all()
    runtime = assistant_runtime(assistant_row(db))
    if runtime["enabled"]:
        try:
            answer = ask_llm(company, rows, payload.message.strip(), runtime)
        except Exception as exc:
            detail = str(exc)
            secret = runtime.get("api_key") or ""
            if secret and secret in detail:
                detail = detail.replace(secret, "***")
            raise HTTPException(status_code=502, detail=f"Ассистент недоступен: {detail}") from exc
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
