"""HTML-отчеты по корпоративному SMTP."""

from __future__ import annotations

import html
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path


def _rows(findings: list[dict]) -> str:
    body = []
    for item in findings[:25]:
        body.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('severity', '')))}</td>"
            f"<td>{html.escape(str(item.get('hostname', '')))}</td>"
            f"<td>{html.escape(str(item.get('title', '')))}</td>"
            "</tr>"
        )
    if not body:
        body.append("<tr><td colspan='3'>Новых находок нет.</td></tr>")
    return "".join(body)


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
    table = _rows(findings)
    html_body = f"""<!DOCTYPE html>
<html lang="ru"><body style="margin:0;background:#090d16;color:#e6edf3;font-family:Segoe UI,Arial,sans-serif;">
  <div style="padding:24px;">
    <div style="background:#111827;border:1px solid #58a6ff;border-radius:12px;padding:20px;">
      <div style="color:#58a6ff;font-size:12px;letter-spacing:.14em;">BROSEC AUDIT AD</div>
      <h1 style="margin:8px 0 12px;font-size:22px;">Паспорт безопасности домена</h1>
      <p style="margin:0 0 12px;">{html.escape(company_name)}</p>
      <p style="white-space:pre-wrap;">{html.escape(summary or "")}</p>
      <table style="width:100%;border-collapse:collapse;font-size:14px;">
        <thead><tr>
          <th align="left" style="border-bottom:1px solid #58a6ff;padding:8px;">Критичность</th>
          <th align="left" style="border-bottom:1px solid #58a6ff;padding:8px;">Узел</th>
          <th align="left" style="border-bottom:1px solid #58a6ff;padding:8px;">Находка</th>
        </tr></thead>
        <tbody>{table}</tbody>
      </table>
    </div>
  </div>
</body></html>"""
    message.add_alternative(html_body, subtype="html")
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
