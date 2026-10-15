"""Отправка сводки и PDF в Telegram Bot API."""

from __future__ import annotations

import os
from pathlib import Path

import requests


def _escape(text: str) -> str:
    return (
        (text or "")
        .replace("\\", "\\\\")
        .replace("_", "\\_")
        .replace("*", "\\*")
        .replace("[", "\\[")
        .replace("`", "\\`")
    )


def send_summary(
    text: str,
    pdf_path: str | None = None,
    token: str | None = None,
    chat_id: str | None = None,
) -> dict[str, str | bool]:
    token = (token or os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (chat_id or os.getenv("TELEGRAM_CHAT_ID") or "").strip()
    if not token or token.startswith("your_") or not chat_id or chat_id.startswith("your_"):
        return {"ok": False, "error": "Telegram не настроен: укажите токен бота и chat id."}
    api = f"https://api.telegram.org/bot{token}"
    message = _escape(text)[:3900]
    try:
        response = requests.post(
            f"{api}/sendMessage",
            json={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"},
            timeout=30,
        )
        if response.status_code >= 300:
            plain = requests.post(
                f"{api}/sendMessage",
                json={"chat_id": chat_id, "text": text[:3900]},
                timeout=30,
            )
            plain.raise_for_status()
        else:
            response.raise_for_status()
        attachment = Path(pdf_path) if pdf_path else None
        if attachment and attachment.is_file():
            with attachment.open("rb") as handle:
                document = requests.post(
                    f"{api}/sendDocument",
                    data={"chat_id": chat_id, "caption": "Паспорт безопасности домена"},
                    files={"document": (attachment.name, handle, "application/pdf")},
                    timeout=60,
                )
            document.raise_for_status()
    except requests.RequestException as exc:
        detail = str(exc).replace(token, "***")
        return {"ok": False, "error": f"Telegram не принял сообщение: {detail}"}
    return {"ok": True, "error": ""}
