"""Интеграция с BloodHound CE и запуск уже установленного SharpHound."""

from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path
from typing import Any

import requests

from app.modules.software_scan import run_remote

_QUERIES = (
    (
        "kerberoasting",
        "high",
        "Kerberos",
        "Учетная запись пользователя с SPN",
        "У записи есть SPN. Переведите службу на gMSA и задайте длинный пароль. Хеши и билеты не запрашиваются.",
        "kerberos,пароли,compliance,module:bloodhound",
        "MATCH (u:User {enabled:true, hasspn:true}) RETURN u LIMIT 100",
    ),
    (
        "asrep_preauth",
        "high",
        "Kerberos",
        "Отключена предварительная проверка подлинности Kerberos",
        "Включите предварительную проверку подлинности. Запрос билетов из платформы не выполняется.",
        "kerberos,пароли,compliance,module:bloodhound",
        "MATCH (u:User {enabled:true, dontreqpreauth:true}) RETURN u LIMIT 100",
    ),
    (
        "unconstrained_delegation",
        "critical",
        "Делегирование",
        "Неограниченное делегирование на компьютере",
        "Для контроллеров домена флаг штатный. На рядовых серверах его нужно снять.",
        "compliance,module:bloodhound",
        "MATCH (c:Computer {unconstraineddelegation:true}) RETURN c LIMIT 100",
    ),
    (
        "obsolete_os",
        "medium",
        "Операционные системы",
        "Windows 10 в графе BloodHound",
        "Узел отмечен операционной системой Windows 10.",
        "windows10,compliance,module:bloodhound",
        "MATCH (c:Computer) WHERE c.operatingsystem CONTAINS 'Windows 10' RETURN c LIMIT 100",
    ),
)


def _session() -> requests.Session:
    http = requests.Session()
    http.headers["Accept"] = "application/json"
    return http


def _login(base: str, username: str, password: str) -> str:
    response = _session().post(
        f"{base}/api/v2/login",
        json={"login_principal": username, "password": password},
        timeout=30,
    )
    response.raise_for_status()
    body = response.json()
    data = body.get("data") if isinstance(body, dict) else {}
    token = ""
    if isinstance(data, dict):
        token = str(data.get("session_token") or "")
    if not token and isinstance(body, dict):
        token = str(body.get("session_token") or "")
    if not token:
        raise RuntimeError("BloodHound CE не вернул токен сессии.")
    return token


def _names_from_payload(payload: Any) -> list[str]:
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key in ("samaccountname", "name", "objectid"):
                value = node.get(key)
                if isinstance(value, str) and value.strip():
                    found.append(value.strip())
                    break
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            if node and all(isinstance(item, str) for item in node):
                found.extend(item.strip() for item in node if item.strip())
            else:
                for item in node:
                    walk(item)

    walk(payload)
    unique: list[str] = []
    for item in found:
        lowered = item.lower()
        if lowered in {"krbtgt"} or item in unique:
            continue
        if lowered.endswith("$") and "delegation" not in lowered:
            pass
        unique.append(item)
    return unique[:100]


def _cypher(base: str, token: str, query: str) -> list[str]:
    response = _session().post(
        f"{base}/api/v2/graphs/cypher",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": query, "include_properties": True},
        timeout=60,
    )
    response.raise_for_status()
    return _names_from_payload(response.json())


def _collect_sharphound(connection: dict[str, Any]) -> str:
    candidates = os.getenv(
        "SHARPHOUND_REMOTE_PATH",
        r"C:\Tools\SharpHound\SharpHound.exe;C:\Program Files\SharpHound\SharpHound.exe",
    )
    quoted = ",".join("'" + item.replace("'", "''") + "'" for item in candidates.split(";") if item.strip())
    script = f"""
$ErrorActionPreference = 'Continue'
$candidates = @({quoted})
$exe = $candidates | Where-Object {{ Test-Path -LiteralPath $_ }} | Select-Object -First 1
if (-not $exe) {{
  $found = Get-ChildItem -LiteralPath 'C:\\Tools','C:\\Program Files' -Filter 'SharpHound.exe' -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($found) {{ $exe = $found.FullName }}
}}
if (-not $exe) {{
  Write-Output 'SHARPHOUND_NOT_FOUND'
  Get-ChildItem -LiteralPath 'C:\\Tools' -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 40 | ForEach-Object {{ Write-Output ('ITEM|' + $_.Name) }}
  exit 2
}}
$work = 'C:\\Windows\\Temp\\ad-identity-guard-bh'
New-Item -ItemType Directory -Force -Path $work | Out-Null
Get-ChildItem -LiteralPath $work -Filter *.zip -ErrorAction SilentlyContinue | Remove-Item -Force
& $exe -c DCOnly,Session,LocalAdmin,CA --outputdirectory $work --zipfilename adguard --nosavecache --memcache
$zip = Get-ChildItem -LiteralPath $work -Filter *.zip | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $zip) {{ Write-Output 'SHARPHOUND_NO_ZIP'; exit 3 }}
if ($zip.Length -gt 8MB) {{ Write-Output ('SHARPHOUND_ZIP_TOO_LARGE|' + $zip.FullName + '|' + $zip.Length); exit 4 }}
Write-Output 'SHARPHOUND_B64_BEGIN'
[Convert]::ToBase64String([IO.File]::ReadAllBytes($zip.FullName))
Write-Output 'SHARPHOUND_B64_END'
"""
    remote = run_remote(
        connection["host"],
        connection["username"],
        connection["password"],
        connection["transport"],
        connection["winrm_port"],
        connection["ssh_port"],
        script,
        timeout=900,
    )
    stdout = remote["stdout"]
    if "SHARPHOUND_NOT_FOUND" in stdout:
        names = [line.split("|", 1)[1] for line in stdout.splitlines() if line.startswith("ITEM|")]
        listed = ", ".join(names[:20]) if names else "каталог C:\\Tools пуст или недоступен"
        return f"SharpHound.exe не найден. В C:\\Tools видно: {listed}."
    if "SHARPHOUND_ZIP_TOO_LARGE" in stdout:
        return "Архив SharpHound больше 8 МБ. Загрузите его вручную в BloodHound CE, автоматическая передача остановлена."
    begin = stdout.find("SHARPHOUND_B64_BEGIN")
    end = stdout.find("SHARPHOUND_B64_END")
    if begin < 0 or end < 0:
        detail = "\n".join(part for part in (stdout, remote["stderr"], remote["error"]) if part).strip()
        return f"SharpHound не собрал архив: {(detail or 'коллекция не вернула архив')[:800]}"
    raw_b64 = "".join(stdout[begin + len("SHARPHOUND_B64_BEGIN") : end].split())
    try:
        blob = base64.b64decode(raw_b64, validate=True)
    except (ValueError, base64.binascii.Error):
        return "Архив SharpHound получен, но содержимое повреждено и не загружено."
    base = os.getenv("BLOODHOUND_URL", "http://bloodhound-ce:8080").rstrip("/")
    token = _login(base, os.getenv("BLOODHOUND_USER", "admin"), os.getenv("BLOODHOUND_PASSWORD", ""))
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as handle:
        handle.write(blob)
        temp_path = handle.name
    try:
        with open(temp_path, "rb") as handle:
            response = _session().post(
                f"{base}/api/v2/file-upload",
                headers={"Authorization": f"Bearer {token}"},
                files={"file": ("adguard.zip", handle, "application/zip")},
                timeout=180,
            )
        if response.status_code >= 300:
            return f"Архив собран, BloodHound CE отклонил загрузку: HTTP {response.status_code}."
    finally:
        Path(temp_path).unlink(missing_ok=True)
    return "Коллекция SharpHound передана в BloodHound CE. Разбор графа может занять несколько минут."


def run_bloodhound(connection: dict[str, Any] | None) -> dict[str, Any]:
    notes: list[str] = []
    if connection and connection.get("username") and connection.get("password"):
        try:
            notes.append(_collect_sharphound(connection))
        except Exception as exc:
            notes.append(f"Коллекция SharpHound не выполнена: {exc}")
    else:
        notes.append("Учетные данные Windows не заданы, запуск SharpHound пропущен. Читается текущий граф BloodHound CE.")
    base = os.getenv("BLOODHOUND_URL", "http://bloodhound-ce:8080").rstrip("/")
    try:
        token = _login(base, os.getenv("BLOODHOUND_USER", "admin"), os.getenv("BLOODHOUND_PASSWORD", ""))
    except Exception as exc:
        return {
            "ok": False,
            "findings": [],
            "score": None,
            "message": "\n".join(notes + [f"API BloodHound CE недоступен: {exc}"]),
        }
    findings: list[dict[str, Any]] = []
    for vuln_id, severity, category, title, detail, tags, query in _QUERIES:
        try:
            names = _cypher(base, token, query)
        except Exception as exc:
            notes.append(f"Запрос {vuln_id} не выполнен: {exc}")
            continue
        notes.append(f"{title}: {len(names)}")
        for name in names:
            if vuln_id == "kerberoasting" and name.lower() == "krbtgt":
                continue
            findings.append(
                {
                    "hostname": name,
                    "category": category,
                    "title": f"{title}: {name}",
                    "severity": severity,
                    "detail": detail,
                    "tags": tags,
                    "vuln_id": vuln_id,
                }
            )
    return {
        "ok": True,
        "findings": findings,
        "score": None,
        "message": "\n".join(notes),
    }


def ingest_sharphound_zip(blob: bytes) -> str:
    """Принимает архив официального SharpHound и кладет его в BloodHound CE. Хеши не извлекаются."""
    if len(blob) > 80 * 1024 * 1024:
        return "Архив больше 80 МБ и не загружен."
    if not blob.startswith(b"PK"):
        return "Файл не похож на zip-архив SharpHound."
    base = os.getenv("BLOODHOUND_URL", "http://bloodhound-ce:8080").rstrip("/")
    token = _login(base, os.getenv("BLOODHOUND_USER", "admin"), os.getenv("BLOODHOUND_PASSWORD", ""))
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as handle:
        handle.write(blob)
        temp_path = handle.name
    try:
        with open(temp_path, "rb") as handle:
            response = _session().post(
                f"{base}/api/v2/file-upload",
                headers={"Authorization": f"Bearer {token}"},
                files={"file": ("collector.zip", handle, "application/zip")},
                timeout=180,
            )
        if response.status_code >= 300:
            return f"BloodHound CE отклонил архив: HTTP {response.status_code}."
    finally:
        Path(temp_path).unlink(missing_ok=True)
    return "Архив SharpHound принят BloodHound CE. Разбор графа может занять несколько минут."
