"""Удаленный опрос Windows по WinRM или SSH: ПО, GPP и шаблоны AD CS."""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
from typing import Any

log = logging.getLogger("adguard.remote")

HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
MAX_OUTPUT = 1_500_000

BLACKLIST = (
    ("anydesk", "AnyDesk", "anydesk_detected", "high"),
    ("teamviewer", "TeamViewer", "teamviewer_detected", "high"),
    ("rustdesk", "RustDesk", "rustdesk_detected", "high"),
    ("ultravnc", "UltraVNC", "vnc_detected", "high"),
    ("tightvnc", "TightVNC", "vnc_detected", "high"),
    ("realvnc", "RealVNC", "vnc_detected", "high"),
    ("openvpn", "OpenVPN", "vpn_unauthorized", "medium"),
    ("wireguard", "WireGuard", "vpn_unauthorized", "medium"),
    ("protonvpn", "ProtonVPN", "vpn_unauthorized", "medium"),
    ("proton vpn", "ProtonVPN", "vpn_unauthorized", "medium"),
)


def validate_host(host: str) -> str:
    value = (host or "").strip().rstrip(".")
    if not HOST_RE.match(value):
        raise ValueError("Некорректное имя узла. Допустимы буквы, цифры, точка, дефис и подчеркивание.")
    return value


def _redact(text: str, secrets: list[str] | None = None) -> str:
    cleaned = re.sub(r'(?i)cpassword\s*=\s*"[^"]*"', 'cpassword="[скрыто]"', text or "")
    for secret in secrets or []:
        if secret and len(secret) >= 4:
            cleaned = cleaned.replace(secret, "[скрыто]")
    return cleaned[:MAX_OUTPUT]


def run_remote(
    host: str,
    username: str,
    password: str,
    transport: str,
    winrm_port: int,
    ssh_port: int,
    script: str,
    timeout: int = 180,
) -> dict[str, Any]:
    """Выполняет фиксированный PowerShell-скрипт на узле Windows."""
    host = validate_host(host)
    if not username or not password:
        return {
            "ok": False,
            "stdout": "",
            "stderr": "",
            "fingerprint": "",
            "error": "Не заданы учетные данные подключения к Windows.",
        }
    mode = (transport or "winrm").lower()
    try:
        if mode == "ssh":
            return _run_ssh(host, int(ssh_port or 22), username, password, script, timeout)
        return _run_winrm(host, int(winrm_port or 5985), username, password, script, timeout)
    except Exception as exc:
        log.warning("remote %s via %s failed: %s", host, mode, type(exc).__name__)
        return {
            "ok": False,
            "stdout": "",
            "stderr": "",
            "fingerprint": "",
            "error": _redact(str(exc), [password]),
        }


def _decode_output(raw: bytes) -> str:
    if not raw:
        return ""
    best = raw.decode("utf-8", errors="replace")
    best_bad = best.count("\ufffd") + len(re.findall(r"\?{3,}", best))
    for encoding in ("cp866", "cp1251"):
        text = raw.decode(encoding, errors="replace")
        bad = text.count("\ufffd") + len(re.findall(r"\?{3,}", text))
        if bad < best_bad:
            best, best_bad = text, bad
    return best


def repair_caption(text: str) -> str:
    """Русская Windows пишет «Майкрософт» в названии выпуска. Старый ответ WinRM терял эти буквы."""
    return re.sub(r"\?{3,}(?=\s*Windows)", "Майкрософт", text or "")


def _run_winrm(host: str, port: int, username: str, password: str, script: str, timeout: int) -> dict[str, Any]:
    import winrm

    scheme = "https" if port == 5986 else "http"
    endpoint = f"{scheme}://{host}:{port}/wsman"
    verify = os.getenv("WINRM_TLS_VERIFY", "true").lower() not in {"0", "false", "no"}
    session = winrm.Session(
        endpoint,
        auth=(username, password),
        transport="ntlm",
        server_cert_validation="validate" if verify else "ignore",
        operation_timeout_sec=max(20, timeout - 5),
        read_timeout_sec=timeout + 10,
    )
    script = "$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false\n" + script
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    if len(encoded) > 6000:
        remote_b64 = r"C:\Windows\Temp\adguard-run.b64"
        session.run_cmd("cmd", ["/c", "del", "/q", remote_b64])
        for offset in range(0, len(encoded), 1400):
            part = encoded[offset : offset + 1400]
            session.run_cmd("cmd", ["/c", f"echo {part}>>{remote_b64}"])
        script = (
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n"
            "$OutputEncoding = [Text.Encoding]::UTF8\n"
            "$enc = (Get-Content -Raw 'C:\\Windows\\Temp\\adguard-run.b64') -replace '\\s',''\n"
            "$body = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($enc))\n"
            "Invoke-Expression $body\n"
        )
    result = session.run_ps(script)
    stdout = _decode_output(result.std_out or b"")
    stderr = _decode_output(result.std_err or b"")
    ok = result.status_code == 0
    return {
        "ok": ok,
        "stdout": _redact(stdout, [password]),
        "stderr": _redact(stderr, [password]),
        "fingerprint": "",
        "error": "" if ok else f"WinRM вернул код {result.status_code}",
    }


class _FingerprintPolicy:
    def __init__(self) -> None:
        self.fingerprint = ""

    def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
        digest = hashlib.sha256(key.asbytes()).hexdigest()
        self.fingerprint = "SHA256:" + digest[:32]
        client.get_host_keys().add(hostname, key.get_name(), key)


def _run_ssh(host: str, port: int, username: str, password: str, script: str, timeout: int) -> dict[str, Any]:
    import paramiko

    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    command = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}"
    policy = _FingerprintPolicy()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(policy)
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=20,
            banner_timeout=20,
            auth_timeout=20,
            look_for_keys=False,
            allow_agent=False,
        )
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read(MAX_OUTPUT + 1).decode("utf-8", errors="replace")
        err = stderr.read(200_000).decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
    finally:
        client.close()
    ok = code == 0
    return {
        "ok": ok,
        "stdout": _redact(out, [password]),
        "stderr": _redact(err, [password]),
        "fingerprint": policy.fingerprint,
        "error": "" if ok else f"SSH вернул код {code}",
    }


def _hosts(primary: str, extra: str) -> list[str]:
    values = [primary]
    for line in (extra or "").replace(",", "\n").splitlines():
        item = line.strip()
        if item:
            values.append(item)
    unique: list[str] = []
    for item in values:
        host = validate_host(item)
        if host not in unique:
            unique.append(host)
    return unique


_INVENTORY_PS = r"""
$ErrorActionPreference = 'Continue'
$os = Get-CimInstance Win32_OperatingSystem
$paths = @(
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = foreach ($item in (Get-ItemProperty $paths -ErrorAction SilentlyContinue)) {
  if ($item.DisplayName) {
    [PSCustomObject]@{
      DisplayName = [string]$item.DisplayName
      DisplayVersion = [string]$item.DisplayVersion
      Publisher = [string]$item.Publisher
    }
  }
}
[PSCustomObject]@{
  Hostname = $env:COMPUTERNAME
  Caption = [string]$os.Caption
  Version = [string]$os.Version
  Apps = @($apps)
} | ConvertTo-Json -Compress -Depth 4
"""


def _port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    import socket

    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect((host, int(port)))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _read_software_host(connection: dict[str, Any], host: str) -> tuple[str, list[dict[str, Any]], str]:
    import json

    port = int(connection["ssh_port"] if connection.get("transport") == "ssh" else connection["winrm_port"] or 5985)
    if not _port_open(host, port):
        return "closed", [], ""
    remote = run_remote(
        host,
        connection["username"],
        connection["password"],
        connection["transport"],
        connection["winrm_port"],
        connection["ssh_port"],
        _INVENTORY_PS,
        timeout=90,
    )
    if not remote["ok"]:
        return "error", [], remote["error"] or remote["stderr"] or "нет ответа"
    text = remote["stdout"] or ""
    start = text.rfind('{"Hostname"')
    if start < 0:
        start = text.rfind("{")
    try:
        payload = json.loads(text[start:]) if start >= 0 else None
    except (json.JSONDecodeError, ValueError):
        payload = None
    if not isinstance(payload, dict):
        return "error", [], "ответ реестра не разобран"
    findings: list[dict[str, Any]] = []
    hostname = payload.get("Hostname") or host
    caption = str(payload.get("Caption") or "")
    version = str(payload.get("Version") or "")
    if "windows 10" in caption.lower():
        findings.append(
            {
                "hostname": hostname,
                "category": "Операционные системы",
                "title": repair_caption(caption.strip()) or "Windows 10",
                "severity": "medium",
                "detail": f"Сборка {version}. Windows 10 не соответствует актуальному базису для рабочих мест.",
                "tags": "windows10,compliance,module:software_audit",
                "vuln_id": "obsolete_os",
            }
        )
    apps = payload.get("Apps") or []
    if isinstance(apps, dict):
        apps = [apps]
    for app in apps:
        if not isinstance(app, dict):
            continue
        name = str(app.get("DisplayName") or "")
        lowered = name.lower()
        for needle, label, vuln_id, severity in BLACKLIST:
            if needle in lowered:
                app_version = str(app.get("DisplayVersion") or "").strip()
                title = label if not app_version else f"{label} {app_version}"
                findings.append(
                    {
                        "hostname": hostname,
                        "category": "Shadow IT",
                        "title": title,
                        "severity": severity,
                        "detail": f"Издатель: {app.get('Publisher') or 'не указан'}. Продукт найден в ветке Uninstall и входит в черный список удаленного доступа и VPN.",
                        "tags": f"shadow_it,{needle},module:software_audit",
                        "vuln_id": vuln_id,
                    }
                )
                break
    return "ok", findings, ""


def scan_software(connection: dict[str, Any], extra_hosts: str) -> dict[str, Any]:
    from concurrent.futures import ThreadPoolExecutor

    findings: list[dict[str, Any]] = []
    hosts = _hosts(connection["host"], extra_hosts)
    scanned = 0
    closed = 0
    errors: list[str] = []
    workers = 8 if len(hosts) > 1 else 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, (status, host_findings, detail) in zip(hosts, pool.map(lambda item: _read_software_host(connection, item), hosts)):
            if status == "closed":
                closed += 1
                continue
            if status != "ok":
                errors.append(f"{host}: {detail}")
                continue
            scanned += 1
            findings.extend(host_findings)
    message = f"Опрошено узлов: {scanned}. WinRM не открыт: {closed}. Ошибок чтения: {len(errors)}. Замечаний по ПО: {len(findings)}."
    if errors:
        message += " " + "; ".join(errors[:6])
    return {
        "ok": scanned > 0,
        "findings": findings,
        "score": None,
        "message": message,
    }


_GPP_PS = r"""
$ErrorActionPreference = 'Continue'
$domain = (Get-CimInstance Win32_ComputerSystem).Domain
if (-not $domain) { Write-Output 'GPP_NO_DOMAIN'; exit 2 }
$root = "\\$domain\SYSVOL"
if (-not (Test-Path -LiteralPath $root)) { Write-Output 'GPP_NO_SYSVOL'; exit 3 }
$files = Get-ChildItem -LiteralPath $root -Recurse -Include Groups.xml,Services.xml,Scheduledtasks.xml,DataSources.xml,Drives.xml,Printers.xml -ErrorAction SilentlyContinue
$hits = 0
foreach ($file in $files) {
  $match = Select-String -LiteralPath $file.FullName -Pattern 'cpassword' -SimpleMatch -Quiet
  if ($match) {
    Write-Output ("GPP_HIT|" + $file.FullName)
    $hits++
  }
}
Write-Output ("GPP_DONE|" + $hits)
"""


def scan_gpp(connection: dict[str, Any]) -> dict[str, Any]:
    remote = run_remote(
        connection["host"],
        connection["username"],
        connection["password"],
        connection["transport"],
        connection["winrm_port"],
        connection["ssh_port"],
        _GPP_PS,
        timeout=300,
    )
    if not remote["ok"] and "GPP_DONE|" not in remote["stdout"]:
        return {
            "ok": False,
            "findings": [],
            "score": None,
            "message": remote["error"] or remote["stderr"] or remote["stdout"] or "Проверка SYSVOL не выполнена",
        }
    findings = []
    for line in remote["stdout"].splitlines():
        if not line.startswith("GPP_HIT|"):
            continue
        path = line.split("|", 1)[1].strip()
        findings.append(
            {
                "hostname": path,
                "category": "Пароли",
                "title": "Пароль в предпочтениях групповой политики",
                "severity": "critical",
                "detail": "В XML предпочтений найден атрибут cpassword. Значение пароля намеренно не извлекается и не сохраняется. Удалите предпочтение и замените его на LAPS или gMSA.",
                "tags": "gpo_password,пароли,compliance,module:gpp_passwords",
                "vuln_id": "gpp_password",
            }
        )
    if not findings:
        message = "Предпочтения с атрибутом cpassword в SYSVOL не найдены."
    else:
        message = f"Найдено файлов с cpassword: {len(findings)}. Содержимое паролей не считывалось."
    return {"ok": True, "findings": findings, "score": None, "message": message}


_ADCS_PS = r"""
$ErrorActionPreference = 'Continue'
try {
  $root = ([ADSI]'LDAP://RootDSE').configurationNamingContext
  if (-not $root) { Write-Output 'ADCS_NO_ROOT'; exit 2 }
  $base = 'LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,' + $root
  $searcher = New-Object System.DirectoryServices.DirectorySearcher
  $searcher.SearchRoot = [ADSI]$base
  $searcher.Filter = '(objectClass=pKICertificateTemplate)'
  $searcher.PageSize = 200
  [void]$searcher.PropertiesToLoad.Add('displayName')
  [void]$searcher.PropertiesToLoad.Add('name')
  [void]$searcher.PropertiesToLoad.Add('msPKI-Certificate-Name-Flag')
  [void]$searcher.PropertiesToLoad.Add('msPKI-Enrollment-Flag')
  [void]$searcher.PropertiesToLoad.Add('pkiExtendedKeyUsage')
  $clientAuth = '1.3.6.1.5.5.7.3.2'
  $smartCard = '1.3.6.1.4.1.311.20.2.2'
  foreach ($item in $searcher.FindAll()) {
    $props = $item.Properties
    $name = if ($props['displayname']) { [string]$props['displayname'][0] } else { [string]$props['name'][0] }
    $cn = [string]$props['name'][0]
    $nameFlag = 0
    $enrollFlag = 0
    if ($props['mspki-certificate-name-flag']) { $nameFlag = [int]$props['mspki-certificate-name-flag'][0] }
    if ($props['mspki-enrollment-flag']) { $enrollFlag = [int]$props['mspki-enrollment-flag'][0] }
    $eku = @()
    if ($props['pkiextendedkeyusage']) { $eku = @($props['pkiextendedkeyusage'] | ForEach-Object { [string]$_ }) }
    $enrolleeSan = (($nameFlag -band 1) -eq 1)
    $pending = (($enrollFlag -band 2) -eq 2)
    $auth = ($eku -contains $clientAuth) -or ($eku -contains $smartCard)
    if ($enrolleeSan -and $auth -and -not $pending) {
      Write-Output ("ADCS_HIT|{0}|{1}" -f $cn, ($name -replace '\|', '/'))
    }
  }
  Write-Output 'ADCS_DONE'
} catch {
  Write-Output ('ADCS_ERR|' + $_.Exception.Message)
  exit 4
}
"""


def scan_adcs(connection: dict[str, Any]) -> dict[str, Any]:
    remote = run_remote(
        connection["host"],
        connection["username"],
        connection["password"],
        connection["transport"],
        connection["winrm_port"],
        connection["ssh_port"],
        _ADCS_PS,
        timeout=180,
    )
    stdout = remote["stdout"]
    if "ADCS_DONE" not in stdout and not remote["ok"]:
        return {
            "ok": False,
            "findings": [],
            "score": None,
            "message": (stdout or remote["stderr"] or remote["error"] or "Проверка шаблонов AD CS не выполнена")[:800],
        }
    findings = []
    for line in stdout.splitlines():
        if not line.startswith("ADCS_HIT|"):
            continue
        parts = line.split("|", 2)
        cn = parts[1] if len(parts) > 1 else "template"
        title = parts[2] if len(parts) > 2 else cn
        findings.append(
            {
                "hostname": connection["host"],
                "category": "AD CS",
                "title": f"Шаблон {title}: заявитель задает альтернативное имя",
                "severity": "high",
                "detail": (
                    f"Шаблон {cn} одновременно разрешает имя субъекта от заявителя, "
                    "содержит EKU проверки подлинности клиента и не требует согласования выпуска. "
                    "Сузьте право Enroll и отключите поставку SAN заявителем."
                ),
                "tags": "compliance,adcs,module:ad_cs",
                "vuln_id": "adcs_enrollee_san",
            }
        )
    if not findings:
        message = "Шаблонов с комбинацией «SAN от заявителя + проверка подлинности клиента + автовыпуск» не найдено."
    else:
        message = f"Рискованных шаблонов AD CS: {len(findings)}."
    return {"ok": True, "findings": findings, "score": None, "message": message}
