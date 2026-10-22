"""HTML-отчеты по корпоративному SMTP."""

from __future__ import annotations

import html
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path


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
    body = []
    for item in findings[:25]:
        body.append(
            "<tr>"
            f'<td style="padding:12px;border-bottom:1px solid #27272a;vertical-align:top;">{_badge(str(item.get("severity", "")))}</td>'
            f'<td style="padding:12px;border-bottom:1px solid #27272a;color:#e4e4e7;vertical-align:top;">{html.escape(str(item.get("hostname", "") or "—"))}</td>'
            f'<td style="padding:12px;border-bottom:1px solid #27272a;color:#fafafa;vertical-align:top;">{html.escape(str(item.get("title", "")))}</td>'
            "</tr>"
        )
    if not body:
        body.append(
            '<tr><td colspan="3" style="padding:16px;color:#a1a1aa;">Новых находок в этом письме нет.</td></tr>'
        )
    return "".join(body)


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
            f'<div style="background:#18181b;border:1px solid #27272a;border-radius:12px;padding:10px 14px;min-width:92px;">'
            f'<div style="color:#a1a1aa;font-size:11px;">{label}</div>'
            f'<div style="color:{color};font-size:22px;font-weight:650;line-height:1.2;">{amount}</div>'
            f"</div></td>"
        )
    if not chips:
        return ""
    return f'<table role="presentation" style="border-collapse:separate;margin:0 0 18px;"><tr>{"".join(chips)}</tr></table>'


def send_report(
    company_name: str,
    summary: str,
    findings: list[dict],
    pdf_path: str | None = None,
    recipient: str | None = None,
    channel: dict | None = None,
) -> dict[str, str | bool]:
    channel = channel or {}
    server = (channel.get("server") or os.getenv("SMTP_SERVER") or "").strip()
    sender = (channel.get("sender") or os.getenv("SMTP_FROM") or os.getenv("SMTP_USER") or "").strip()
    target = (recipient or os.getenv("SMTP_TO") or os.getenv("SMTP_USER") or "").strip()
    if not server or server.endswith("company.local") or not sender or not target:
        return {"ok": False, "error": "Почта не настроена: укажите сервер, адрес отправителя и получателя."}
    port = int(channel.get("port") or os.getenv("SMTP_PORT") or "587")
    security = (channel.get("security") or "").strip().lower()
    username = (channel.get("username") or os.getenv("SMTP_USER") or "").strip()
    password = channel.get("password") if channel.get("password") is not None else (os.getenv("SMTP_PASSWORD") or "")
    message = EmailMessage()
    message["Subject"] = f"Паспорт безопасности домена — {company_name}"
    message["From"] = sender
    message["To"] = target
    message.set_content(summary or "Сводка проверки BroSec Audit AD.")
    shown = findings[:25]
    more = len(findings) - len(shown)
    more_line = f'<p style="margin:12px 0 0;color:#a1a1aa;font-size:12px;">В письме первые {len(shown)} из {len(findings)}. Остальные {more} остаются в консоли.</p>' if more > 0 else ""
    logo = Path(__file__).resolve().parents[1] / "static" / "logo.png"
    mark = '<img src="cid:brosec-logo" width="64" height="64" alt="" style="display:block;border-radius:16px;border:0;">' if logo.is_file() else ""
    html_body = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"></head><body style="margin:0;padding:0;background:#09090b;color:#fafafa;font-family:Segoe UI,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#09090b;">
    <tr><td align="center" style="padding:28px 16px;">
      <table role="presentation" width="640" cellpadding="0" cellspacing="0" style="width:640px;max-width:640px;background:#18181b;border:1px solid #3f3f46;border-radius:16px;">
        <tr><td style="height:4px;background:#e879f9;background:linear-gradient(90deg,#e879f9,#22d3ee);font-size:0;line-height:0;">&nbsp;</td></tr>
        <tr><td style="padding:28px 28px 8px;">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr>
            <td style="padding-right:16px;vertical-align:middle;">{mark}</td>
            <td style="vertical-align:middle;">
              <div style="color:#e879f9;font-size:11px;letter-spacing:.16em;font-weight:650;">BROSEC AUDIT AD</div>
              <div style="font-size:22px;font-weight:650;line-height:1.3;padding-top:4px;">Паспорт безопасности домена</div>
            </td>
          </tr></table>
        </td></tr>
        <tr><td style="padding:8px 28px 0;color:#a1a1aa;font-size:14px;">{html.escape(company_name)}</td></tr>
        <tr><td style="padding:16px 28px 0;">{_counts(findings)}</td></tr>
        <tr><td style="padding:0 28px;">
          <div style="background:#09090b;border:1px solid #27272a;border-radius:12px;padding:14px 16px;color:#e4e4e7;font-size:14px;line-height:1.5;white-space:pre-wrap;">{html.escape(summary or "Сводка проверки BroSec Audit AD.")}</div>
        </td></tr>
        <tr><td style="padding:18px 28px 8px;color:#fafafa;font-size:14px;font-weight:650;">Находки</td></tr>
        <tr><td style="padding:0 28px 8px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:14px;">
            <tr>
              <th align="left" style="padding:8px 12px;border-bottom:1px solid #3f3f46;color:#a1a1aa;font-size:12px;font-weight:600;">Критичность</th>
              <th align="left" style="padding:8px 12px;border-bottom:1px solid #3f3f46;color:#a1a1aa;font-size:12px;font-weight:600;">Узел</th>
              <th align="left" style="padding:8px 12px;border-bottom:1px solid #3f3f46;color:#a1a1aa;font-size:12px;font-weight:600;">Находка</th>
            </tr>
            {_rows(findings)}
          </table>
          {more_line}
        </td></tr>
        <tr><td style="padding:8px 28px 24px;color:#71717a;font-size:12px;line-height:1.5;">Пароли, билеты и значения cpassword в письмо не попадают. Закрытие находки выполняется в консоли BroSec Audit AD.</td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""
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
            smtp_cm = smtplib.SMTP_SSL(server, port, timeout=20)
        else:
            smtp_cm = smtplib.SMTP(server, port, timeout=20)
        with smtp_cm as smtp:
            smtp.ehlo()
            if security == "starttls" or (not security and port == 587):
                smtp.starttls()
                smtp.ehlo()
            if username and password and password != "password":
                smtp.login(username, password)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        return {"ok": False, "error": f"Письмо не отправлено: {exc}"}
    return {"ok": True, "error": ""}
