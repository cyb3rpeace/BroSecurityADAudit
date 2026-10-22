"""Код приложения и подпись устройства. Секрет не пишется в журнал."""

import base64
import hmac
import io
import secrets
import struct
import time

import qrcode
import qrcode.image.svg


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    padded = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
    return base64.b32decode(padded, casefold=True)


def totp_code(secret: str, moment: int | None = None) -> str:
    counter = int((moment if moment is not None else time.time()) // 30)
    digest = hmac.new(_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 1_000_000).zfill(6)


def totp_ok(secret: str, code: str) -> bool:
    digits = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(digits) != 6 or not secret:
        return False
    now = int(time.time())
    for shift in (-30, 0, 30):
        if hmac.compare_digest(totp_code(secret, now + shift), digits):
            return True
    return False


def otpauth_uri(username: str, secret: str) -> str:
    label = "BroSec%20Audit%20AD:" + username.replace(" ", "%20")
    return f"otpauth://totp/{label}?secret={secret}&issuer=BroSec%20Audit%20AD&digits=6&period=30"


def qr_svg(payload: str) -> str:
    image = qrcode.make(payload, image_factory=qrcode.image.svg.SvgPathImage, border=2, box_size=6)
    buffer = io.BytesIO()
    image.save(buffer)
    raw = buffer.getvalue().decode("utf-8")
    start = raw.find("<svg")
    return raw[start:] if start >= 0 else raw


def device_label(agent: str) -> str:
    text = agent or ""
    if "Edg/" in text:
        browser = "Edge"
    elif "Chrome/" in text:
        browser = "Chrome"
    elif "Firefox/" in text:
        browser = "Firefox"
    elif "Safari/" in text:
        browser = "Safari"
    else:
        browser = "Браузер"
    if "Windows" in text:
        system = "Windows"
    elif "Android" in text:
        system = "Android"
    elif "iPhone" in text or "iPad" in text:
        system = "iOS"
    elif "Mac OS" in text:
        system = "macOS"
    elif "Linux" in text:
        system = "Linux"
    else:
        system = "устройство"
    return f"{browser}, {system}"
