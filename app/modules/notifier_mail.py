"""HTML-отчеты по корпоративному SMTP."""

from __future__ import annotations

import html
import ipaddress
import os
import smtplib
import ssl
import socket
import re
from email.message import EmailMessage
from pathlib import Path

from .email_template import render_html


_SEV = {
    "critical": ("#ef4444", "Критический"),
    "high": ("#f59e0b", "Высокий"),
    "medium": ("#e879f9", "Средний"),
    "low": ("#22d3ee", "Низкий"),
    "info": ("#a1a1aa", "Справка"),
}


def _badge(severity: str) -> str:
    color, label = _SEV.get(severity.lower(), ("#a1a1aa", severity or "Отметка"))
    return (
        f'<span style="display:inline-block;padding:3px 10px;border-radius:999px;'
        f'background:{color};color:#09090b;font-size:12px;font-weight:600;">{html.escape(label)}</span>'
    )


def _rows(findings: list[dict]) -> str:
    cards = []
    for item in findings[:25]:
        host = html.escape(str(item.get("hostname", "") or "объект не указан"))
        title = html.escape(str(item.get("title", "") or "Находка"))
        cards.append(
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="margin:0 0 10px;background:#18181b;border:1px solid #27272a;border-radius:8px;">'
            '<tr><td style="padding:14px 16px;">'
            f'{_badge(str(item.get("severity", "")))}'
            f'<div style="padding-top:8px;font-size:15px;font-weight:650;line-height:1.35;color:#fafafa;">{title}</div>'
            f'<div style="padding-top:4px;font-size:13px;color:#a1a1aa;">{host}</div>'
            "</td></tr></table>"
        )
    if not cards:
        return '<div style="color:#a1a1aa;font-size:14px;">Новых находок в этом письме нет.</div>'
    return "".join(cards)


def _counts(findings: list[dict]) -> str:
    order = ("critical", "high", "medium", "low")
    chips = []
    for key in order:
        amount = sum(1 for item in findings if str(item.get("severity", "")).lower() == key)
        if not amount:
            continue
        color, label = _SEV[key]
        chips.append(
            f'<td style="padding:0 8px 0 0;">'
            f'<div style="background:#18181b;border:1px solid #27272a;border-radius:8px;padding:12px 16px;min-width:96px;">'
            f'<div style="color:#a1a1aa;font-size:12px;">{label}</div>'
            f'<div style="color:{color};font-size:26px;font-weight:750;line-height:1.15;padding-top:4px;">{amount}</div>'
            f"</div></td>"
        )
    if not chips:
        return ""
    return f'<table role="presentation" style="border-collapse:separate;margin:0 0 18px;"><tr>{"".join(chips)}</tr></table>'


def platform_url() -> str:
    return (os.getenv("APP_PUBLIC_URL") or "").strip().rstrip("/")


def usable_address(value: str) -> str:
    text = (value or "").strip()
    # Settings accept one bare mailbox, not lists or mail headers.
    if not re.fullmatch(r"[^\s@<>,;:\x00-\x1f\x7f]+@[^\s@<>,;:\x00-\x1f\x7f]+", text):
        return ""
    domain = text.split("@", 1)[1].lower()
    if domain in {"local", "company.local", "example.com", "example.local"}:
        return ""
    return text


def _configuration_error(reason: str) -> dict[str, str | bool]:
    return {"ok": False, "error": "Почта не настроена: " + reason + "."}


def _smtp_settings(channel: dict, recipient: str | None) -> dict:
    """Resolve DB/channel overrides before environment; never include secret values in errors."""
    def env(name):
        return "" if channel.get("tenant_scoped") else os.getenv(name)
    server = (channel.get("server") or env("SMTP_SERVER") or "").strip()
    if not server:
        return _configuration_error("укажите сервер SMTP (smtp_server / SMTP_SERVER)")
    if server.lower().rstrip(".") in {"company.local", "smtp.company.local"}:
        return _configuration_error("замените шаблон SMTP_SERVER / smtp_server реальным DNS-именем SMTP")
    try:
        ipaddress.ip_address(server)
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip and re.search(r"[\s/@:#?\x00-\x1f\x7f]", server):
        return _configuration_error("SMTP_SERVER / smtp_server должен содержать только имя сервера или IP, без URL и порта")
    raw_port = channel.get("port")
    if raw_port is None or raw_port == "":
        raw_port = env("SMTP_PORT") or "587"
    try:
        if isinstance(raw_port, bool) or not re.fullmatch(r"[0-9]+", str(raw_port)):
            raise ValueError
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        return _configuration_error("порт SMTP должен быть числом от 1 до 65535 (smtp_port / SMTP_PORT)")
    security = (channel.get("security") or env("SMTP_SECURITY") or "").strip().lower()
    if security not in {"", "none", "starttls", "ssl"}:
        return _configuration_error("защита SMTP — none, starttls или ssl (smtp_security / SMTP_SECURITY)")
    username = (channel.get("username") or env("SMTP_USER") or "").strip()
    password = channel.get("password") if channel.get("password") is not None else (env("SMTP_PASSWORD") or "")
    sender_value = channel.get("sender") or env("SMTP_FROM") or username
    target_value = recipient if recipient and recipient.strip() else (env("SMTP_TO") or username)
    sender = usable_address(sender_value)
    target = usable_address(target_value)
    if not sender:
        return _configuration_error("неверный или отсутствующий адрес отправителя (smtp_from / SMTP_FROM)")
    if not target:
        return _configuration_error("неверный или отсутствующий адрес получателя (notify_email / SMTP_TO)")
    if password == "password":
        return _configuration_error("замените шаблон пароля SMTP реальными учетными данными или очистите учетные данные для доверенного relay")
    if bool(username) != bool(password):
        return _configuration_error("для SMTP AUTH задайте и пользователя, и пароль; для relay очистите оба поля")
    return dict(server=server, port=port, security=security, username=username,
                password=password, sender=sender, target=target)


def _send_report(
    company_name: str,
    summary: str,
    findings: list[dict],
    pdf_path: str | None = None,
    recipient: str | None = None,
    channel: dict | None = None,
    subject: str | None = None,
    headline: str | None = None,
    include_findings: bool = True,
) -> dict[str, str | bool]:
    channel = channel or {}
    settings = _smtp_settings(channel, recipient)
    if settings.get("ok") is False:
        return settings
    server, port, security = settings["server"], settings["port"], settings["security"]
    username, password = settings["username"], settings["password"]
    sender, target = settings["sender"], settings["target"]
    message = EmailMessage()
    message["Subject"] = subject or f"Паспорт безопасности домена — {company_name}"
    message["From"] = sender
    message["To"] = target
    link = platform_url()
    plain = summary or "Сводка проверки BroSec Audit AD."
    if link:
        plain = plain + "\n\nПерейти в платформу: " + link
    message.set_content(plain)
    shown = findings[:25]
    more = len(findings) - len(shown)
    more_line = f'<p style="margin:12px 0 0;color:#a1a1aa;font-size:12px;">В письме первые {len(shown)} из {len(findings)}. Остальные {more} остаются в консоли.</p>' if more > 0 else ""
    title = headline or "Паспорт безопасности домена"
    findings_block = ""
    if include_findings:
        findings_block = f"""
        <tr><td style="padding:8px 28px 0;color:#fafafa;font-size:14px;font-weight:650;">Находки</td></tr>
        <tr><td style="padding:10px 28px 0;">
          {_rows(shown)}
          {more_line}
        </td></tr>"""
    button = ""
    if link:
        button = (
            '<tr><td style="padding:18px 28px 0;">'
            f'<a href="{html.escape(link, quote=True)}" '
            'style="display:inline-block;background:#fafafa;color:#09090b;text-decoration:none;'
            'font-weight:650;font-size:14px;padding:12px 18px;border-radius:8px;">Перейти в платформу</a>'
            "</td></tr>"
        )
    logo = Path(__file__).resolve().parents[1] / "static" / "logo.png"
    html_body = render_html(
        company_name, summary, findings, title,
        include_findings=include_findings, app_url=link, logo_available=logo.is_file(),
    )
    message.add_alternative(html_body, subtype="html")
    if logo.is_file():
        part = message.get_payload()[-1]
        part.add_related(logo.read_bytes(), maintype="image", subtype="png", cid="<brosec-logo>")
    attachment = Path(pdf_path) if pdf_path else None
    if attachment and attachment.is_file():
        message.add_attachment(
            attachment.read_bytes(),
            maintype="application",
            subtype="pdf",
            filename=attachment.name,
        )
    try:
        if security == "ssl" or (not security and port == 465):
            smtp_cm = smtplib.SMTP_SSL(server, port, timeout=20, context=ssl.create_default_context())
        else:
            smtp_cm = smtplib.SMTP(server, port, timeout=20)
        with smtp_cm as smtp:
            smtp.ehlo()
            if security == "starttls" or (not security and port == 587):
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
            if username and password:
                smtp.login(username, password)
            refused = smtp.send_message(message)
            if refused:
                return {"ok": False, "error": "Письмо не отправлено: SMTP отклонил получателя; проверьте адрес и разрешение relay для получателя."}
    except (OSError, smtplib.SMTPException) as exc:
        return _delivery_error(exc)
    return {"ok": True, "error": ""}


def _delivery_error(exc: Exception) -> dict[str, str | bool]:
    """Never expose SMTP replies: they may echo credentials or message data."""
    if isinstance(exc, ssl.SSLCertVerificationError):
        reason = "не удалось проверить сертификат TLS; проверьте имя сервера и доверенный центр сертификации"
    elif isinstance(exc, ssl.SSLError):
        reason = "ошибка TLS; проверьте режим защиты и порт SMTP"
    elif isinstance(exc, smtplib.SMTPAuthenticationError):
        reason = "SMTP отклонил авторизацию; проверьте учетные данные и разрешение SMTP AUTH"
    elif isinstance(exc, smtplib.SMTPRecipientsRefused):
        reason = "SMTP отклонил получателя; проверьте адрес и разрешение relay для получателя"
    elif isinstance(exc, smtplib.SMTPSenderRefused):
        reason = "SMTP отклонил отправителя; проверьте адрес и права отправки"
    elif isinstance(exc, smtplib.SMTPDataError):
        reason = "SMTP отклонил сообщение после команды DATA; проверьте размер вложения, квоту и почтовую политику"
    elif isinstance(exc, smtplib.SMTPNotSupportedError):
        reason = "SMTP не поддерживает требуемую команду STARTTLS или AUTH; проверьте настройки сервера"
    elif isinstance(exc, socket.gaierror):
        reason = "имя SMTP-сервера не разрешается DNS; проверьте SMTP_SERVER / smtp_server и DNS из контейнера приложения"
    elif isinstance(exc, (TimeoutError, socket.timeout)):
        reason = "истекло время ожидания SMTP; проверьте сеть, порт и межсетевой экран"
    elif isinstance(exc, ConnectionRefusedError):
        reason = "соединение SMTP отклонено; проверьте сервер и порт"
    elif isinstance(exc, smtplib.SMTPServerDisconnected):
        reason = "SMTP разорвал соединение; проверьте порт и режим TLS"
    elif isinstance(exc, smtplib.SMTPException):
        reason = "SMTP отклонил сообщение или команду; проверьте политику почтового сервера"
    elif isinstance(exc, OSError):
        reason = "ошибка сети или чтения вложения; проверьте доступность SMTP и файла отчета"
    else:
        reason = "некорректные параметры письма или SMTP"
    return {"ok": False, "error": "Письмо не отправлено: " + reason + "."}


def send_report(
    company_name: str,
    summary: str,
    findings: list[dict],
    pdf_path: str | None = None,
    recipient: str | None = None,
    channel: dict | None = None,
    subject: str | None = None,
    headline: str | None = None,
    include_findings: bool = True,
) -> dict[str, str | bool]:
    # Message headers and attachment reads can fail before opening SMTP too.
    try:
        return _send_report(company_name, summary, findings, pdf_path, recipient,
                            channel, subject, headline, include_findings)
    except (OSError, smtplib.SMTPException, ValueError, TypeError) as exc:
        return _delivery_error(exc)
