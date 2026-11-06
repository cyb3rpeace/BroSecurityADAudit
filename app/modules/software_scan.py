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
    ("tigervnc", "TigerVNC", "vnc_detected", "high"),
    ("ultraviewer", "UltraViewer", "remote_access_detected", "high"),
    ("ammyy", "Ammyy Admin", "remote_access_detected", "high"),
    ("supremo", "Supremo", "remote_access_detected", "high"),
    ("radmin", "Radmin", "remote_access_detected", "high"),
    ("dameware", "Dameware", "remote_access_detected", "high"),
    ("splashtop", "Splashtop", "remote_access_detected", "high"),
    ("screenconnect", "ScreenConnect", "remote_access_detected", "high"),
    ("connectwise", "ConnectWise", "remote_access_detected", "high"),
    ("atera", "Atera", "remote_access_detected", "high"),
    ("ninjarmm", "NinjaOne", "remote_access_detected", "medium"),
    ("logmein", "LogMeIn", "remote_access_detected", "high"),
    ("gotomypc", "GoToMyPC", "remote_access_detected", "high"),
    ("chrome remote", "Chrome Remote Desktop", "remote_access_detected", "high"),
    ("anyviewer", "AnyViewer", "remote_access_detected", "high"),
    ("todesk", "ToDesk", "remote_access_detected", "high"),
    ("sunlogin", "Sunlogin", "remote_access_detected", "high"),
    ("oray", "Oray", "remote_access_detected", "high"),
    ("dwservice", "DWService", "remote_access_detected", "high"),
    ("meshcentral", "MeshCentral", "remote_access_detected", "medium"),
    ("parsec", "Parsec", "remote_access_detected", "medium"),
    ("remotepc", "RemotePC", "remote_access_detected", "high"),
    ("zoho assist", "Zoho Assist", "remote_access_detected", "medium"),
    ("netsupport", "NetSupport", "remote_access_detected", "high"),
    ("litemanager", "LiteManager", "remote_access_detected", "high"),
    ("remotemanipulator", "Remote Manipulator", "remote_access_detected", "high"),
    ("rms agent", "RMS", "remote_access_detected", "high"),
    ("ngrok", "ngrok", "remote_access_detected", "high"),
    ("cloudflared", "cloudflared", "remote_access_detected", "medium"),
    ("frpc", "frp", "remote_access_detected", "high"),
    ("remcos", "Remcos", "rat_detected", "critical"),
    ("quasar", "QuasarRAT", "rat_detected", "critical"),
    ("asyncrat", "AsyncRAT", "rat_detected", "critical"),
    ("njrat", "NjRAT", "rat_detected", "critical"),
    ("nanocore", "NanoCore", "rat_detected", "critical"),
    ("darkcomet", "DarkComet", "rat_detected", "critical"),
    ("warzone", "Warzone RAT", "rat_detected", "critical"),
    ("orcus", "Orcus", "rat_detected", "critical"),
    ("dcrat", "DcRAT", "rat_detected", "critical"),
    ("xworm", "XWorm", "rat_detected", "critical"),
    ("venom rat", "Venom RAT", "rat_detected", "critical"),
    ("openvpn", "OpenVPN", "vpn_unauthorized", "medium"),
    ("wireguard", "WireGuard", "vpn_unauthorized", "medium"),
    ("protonvpn", "ProtonVPN", "vpn_unauthorized", "medium"),
    ("proton vpn", "ProtonVPN", "vpn_unauthorized", "medium"),
    ("nordvpn", "NordVPN", "vpn_unauthorized", "medium"),
    ("expressvpn", "ExpressVPN", "vpn_unauthorized", "medium"),
    ("surfshark", "Surfshark", "vpn_unauthorized", "medium"),
    ("windscribe", "Windscribe", "vpn_unauthorized", "medium"),
    ("tunnelbear", "TunnelBear", "vpn_unauthorized", "medium"),
    ("hotspot shield", "Hotspot Shield", "vpn_unauthorized", "medium"),
    ("cyberghost", "CyberGhost", "vpn_unauthorized", "medium"),
    ("private internet access", "Private Internet Access", "vpn_unauthorized", "medium"),
    ("mullvad", "Mullvad", "vpn_unauthorized", "medium"),
    ("atlas vpn", "Atlas VPN", "vpn_unauthorized", "medium"),
    ("urban vpn", "Urban VPN", "vpn_unauthorized", "medium"),
    ("psiphon", "Psiphon", "vpn_unauthorized", "high"),
    ("softether", "SoftEther", "vpn_unauthorized", "medium"),
    ("tailscale", "Tailscale", "vpn_unauthorized", "medium"),
    ("zerotier", "ZeroTier", "vpn_unauthorized", "medium"),
    ("hamachi", "Hamachi", "vpn_unauthorized", "medium"),
    ("outline client", "Outline", "vpn_unauthorized", "medium"),
    ("getscreen", "Getscreen", "remote_access_detected", "high"),
    ("rudesktop", "RuDesktop", "remote_access_detected", "high"),
    ("aspia", "Aspia", "remote_access_detected", "high"),
    ("isl light", "ISL Light", "remote_access_detected", "medium"),
    ("isl online", "ISL Online", "remote_access_detected", "medium"),
    ("bomgar", "Bomgar", "remote_access_detected", "medium"),
    ("beyondtrust", "BeyondTrust", "remote_access_detected", "medium"),
    ("simplehelp", "SimpleHelp", "remote_access_detected", "high"),
    ("syncro", "Syncro", "remote_access_detected", "medium"),
    ("action1", "Action1", "remote_access_detected", "medium"),
    ("tactical rmm", "Tactical RMM", "remote_access_detected", "high"),
    ("kaseya", "Kaseya", "remote_access_detected", "medium"),
    ("datto rmm", "Datto RMM", "remote_access_detected", "medium"),
    ("n-able", "N-able", "remote_access_detected", "medium"),
    ("pulseway", "Pulseway", "remote_access_detected", "medium"),
    ("remote utilities", "Remote Utilities", "remote_access_detected", "high"),
    ("gh0st", "Gh0st", "rat_detected", "critical"),
    ("ghost rat", "Gh0st RAT", "rat_detected", "critical"),
    ("poison ivy", "Poison Ivy", "rat_detected", "critical"),
    ("darkgate", "DarkGate", "rat_detected", "critical"),
    ("brute ratel", "Brute Ratel", "rat_detected", "critical"),
    ("systembc", "SystemBC", "rat_detected", "critical"),
    ("netwire", "NetWire", "rat_detected", "critical"),
    ("imminent monitor", "Imminent Monitor", "rat_detected", "critical"),
    ("luminosity", "LuminosityLink", "rat_detected", "critical"),
    ("agent tesla", "Agent Tesla", "rat_detected", "critical"),
    ("formbook", "FormBook", "rat_detected", "critical"),
    ("snake keylogger", "Snake Keylogger", "rat_detected", "critical"),
    ("redline", "RedLine", "rat_detected", "critical"),
    ("lumma", "Lumma", "rat_detected", "critical"),
    ("amadey", "Amadey", "rat_detected", "critical"),
    ("smoke loader", "SmokeLoader", "rat_detected", "critical"),
    ("purevpn", "PureVPN", "vpn_unauthorized", "medium"),
    ("vyprvpn", "VyprVPN", "vpn_unauthorized", "medium"),
    ("ivpn", "IVPN", "vpn_unauthorized", "medium"),
    ("hideme", "hide.me", "vpn_unauthorized", "medium"),
    ("hide.me", "hide.me", "vpn_unauthorized", "medium"),
    ("zenmate", "ZenMate", "vpn_unauthorized", "medium"),
    ("betternet", "Betternet", "vpn_unauthorized", "medium"),
    ("hola vpn", "Hola VPN", "vpn_unauthorized", "high"),
    ("ultrasurf", "Ultrasurf", "vpn_unauthorized", "high"),
    ("lantern", "Lantern", "vpn_unauthorized", "high"),
    ("tor browser", "Tor Browser", "vpn_unauthorized", "medium"),
    ("shadowsocks", "Shadowsocks", "vpn_unauthorized", "high"),
    ("v2ray", "V2Ray", "vpn_unauthorized", "high"),
    ("nekoray", "Nekoray", "vpn_unauthorized", "high"),
    ("nekobox", "Nekobox", "vpn_unauthorized", "high"),
    ("clash verge", "Clash Verge", "vpn_unauthorized", "high"),
    ("clash for windows", "Clash for Windows", "vpn_unauthorized", "high"),
    ("hiddify", "Hiddify", "vpn_unauthorized", "high"),
    ("amnezia", "AmneziaVPN", "vpn_unauthorized", "high"),
    ("radmin vpn", "Radmin VPN", "vpn_unauthorized", "medium"),
    ("twingate", "Twingate", "vpn_unauthorized", "medium"),
    ("netbird", "NetBird", "vpn_unauthorized", "medium"),
    ("pritunl", "Pritunl", "vpn_unauthorized", "medium"),
    ("cloudflare warp", "Cloudflare WARP", "vpn_unauthorized", "medium"),
    ("proxifier", "Proxifier", "vpn_unauthorized", "medium"),
    ("proxycap", "ProxyCap", "vpn_unauthorized", "medium"),
    ("ccproxy", "CCProxy", "vpn_unauthorized", "high"),
    ("3proxy", "3proxy", "vpn_unauthorized", "high"),
    ("localtonet", "Localtonet", "remote_access_detected", "high"),
    ("playit", "playit.gg", "remote_access_detected", "high"),
)


def _listed(needle: str, lowered: str) -> bool:
    """Совпадение по целому имени. «todesk» не срабатывает внутри AutoDesk."""
    if " " in needle:
        return needle in lowered
    return re.search(r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])", lowered) is not None


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
        remote_b64 = "C:/Windows/Temp/adguard-".replace("/", chr(92)) + os.urandom(16).hex() + ".b64"
        session.run_cmd("cmd", ["/c", "del", "/q", remote_b64])
        for offset in range(0, len(encoded), 1400):
            part = encoded[offset : offset + 1400]
            session.run_cmd("cmd", ["/c", f"echo {part}>>{remote_b64}"])
        script = (
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n"
            "$OutputEncoding = [Text.Encoding]::UTF8\n"
            "try {\n"
            f"$enc = (Get-Content -Raw '{remote_b64}') -replace '\\s',''\n"
            "$body = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($enc))\n"
            "Invoke-Expression $body\n"
            f"}} finally {{ Remove-Item -LiteralPath '{remote_b64}' -Force -ErrorAction SilentlyContinue }}\n"
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
            if _listed(needle, lowered):
                app_version = str(app.get("DisplayVersion") or "").strip()
                title = label if not app_version else f"{label} {app_version}"
                findings.append(
                    {
                        "hostname": hostname,
                        "category": "Shadow IT",
                        "title": title,
                        "severity": severity,
                        "detail": f"Продукт: {name}. Издатель: {app.get('Publisher') or 'не указан'}. Найден в ветке Uninstall.",
                        "tags": f"shadow_it,{needle},module:software_audit",
                        "vuln_id": vuln_id,
                    }
                )
                break
    return "ok", findings, ""


def scan_software(connection: dict[str, Any], extra_hosts: str, on_progress=None) -> dict[str, Any]:
    from concurrent.futures import ThreadPoolExecutor

    findings: list[dict[str, Any]] = []
    hosts = _hosts(connection["host"], extra_hosts)
    scanned = 0
    closed = 0
    errors: list[str] = []
    seen = 0
    total = len(hosts)

    def emit() -> None:
        if on_progress is None:
            return
        on_progress({"total": total, "seen": seen, "read": scanned, "closed": closed, "error": len(errors)})

    emit()
    workers = 8 if len(hosts) > 1 else 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, (status, host_findings, detail) in zip(hosts, pool.map(lambda item: _read_software_host(connection, item), hosts)):
            seen += 1
            if status == "closed":
                closed += 1
            elif status != "ok":
                errors.append(f"{host}: {detail}")
            else:
                scanned += 1
                findings.extend(host_findings)
            if seen == total or seen % 8 == 0:
                emit()
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


_SECRET_KEY = re.compile(r"(?i)password|cpassword|pwd|passwd|secret")

_DC_EXTRA_PS = r"""
$ErrorActionPreference = 'Continue'
try {
  $cs = Get-CimInstance Win32_ComputerSystem
  $os = Get-CimInstance Win32_OperatingSystem
  $cpu = @(Get-CimInstance Win32_Processor)[0]
  $disk = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')[0]
  $ram = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 1)
  $freeRam = 0
  if ($os.TotalVisibleMemorySize -gt 0) { $freeRam = [math]::Round(100 * $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) }
  $freeDisk = 0
  if ($disk -and $disk.Size -gt 0) { $freeDisk = [math]::Round(100 * $disk.FreeSpace / $disk.Size) }
  $maker = (([string]$cs.Manufacturer) -replace '\|','/')
  $model = (([string]$cs.Model) -replace '\|','/')
  $cpuName = (([string]$cpu.Name) -replace '\|','/')
  Write-Output ('HW|' + $maker + '|' + $model + '|' + $ram + '|' + $freeRam + '|' + $cpuName + '|' + $freeDisk)
  $volSent = 0
  foreach ($v in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)) {
    if ($volSent -ge 24) { break }
    $size = 0
    $free = 0
    if ($v.Size -gt 0) {
      $size = [math]::Round($v.Size / 1GB, 1)
      $free = [math]::Round(100 * $v.FreeSpace / $v.Size)
    }
    $drive = (([string]$v.DeviceID) -replace '\|','/')
    if ($drive) { Write-Output ('VOL|' + $drive + '|' + $size + '|' + $free); $volSent++ }
  }
  $nicSent = 0
  foreach ($n in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue)) {
    if ($nicSent -ge 4) { break }
    $desc = (([string]$n.Description) -replace '\|','/')
    if ($desc.Length -gt 60) { $desc = $desc.Substring(0, 60) }
    $ip = ''
    if ($n.IPAddress) { $ip = [string](@($n.IPAddress) | Where-Object { $_ -notmatch ':' } | Select-Object -First 1) }
    $ip = ($ip -replace '\|','/')
    Write-Output ('NIC|' + $desc + '|' + $ip)
    $nicSent++
  }
  try {
    $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
    $biosVer = (([string]$bios.SMBIOSBIOSVersion) -replace '\|','/')
    if ($biosVer.Length -gt 40) { $biosVer = $biosVer.Substring(0, 40) }
    if ($biosVer) { Write-Output ('BIOS|' + $biosVer) }
  } catch {}
} catch { Write-Output 'HW_FAIL' }
try {
  $dit = ''
  try {
    $reg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction Stop
    $dit = [string]$reg.'DSA Database file'
  } catch {}
  if (-not $dit) { $dit = Join-Path $env:SystemRoot 'NTDS\ntds.dit' }
  $mb = ''
  if ($dit -and (Test-Path -LiteralPath $dit)) {
    $len = (Get-Item -LiteralPath $dit -ErrorAction Stop).Length
    $mb = [string]([math]::Round($len / 1MB, 1))
  }
  Write-Output ('NTDS|' + $mb)
} catch { Write-Output 'NTDS|' }
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $now = Get-Date
  $meta = @(Get-ADReplicationPartnerMetadata -Target $env:COMPUTERNAME -Scope Server -ErrorAction Stop)
  $sent = 0
  foreach ($p in $meta) {
    if ($sent -ge 20) { break }
    $partner = [string]$p.Partner
    if ($partner -match 'CN=NTDS Settings,CN=([^,]+)') { $partner = $Matches[1] }
    elseif ($partner -match 'CN=([^,]+)') { $partner = $Matches[1] }
    $partner = ($partner -replace '\|','/')
    $part = [string]$p.Partition
    if ($part -match '^DC=([^,]+)') { $part = $Matches[1] }
    elseif ($part -match 'CN=([^,]+)') { $part = $Matches[1] }
    $part = ($part -replace '\|','/')
    $hours = -1
    if ($p.LastReplicationSuccess -and $p.LastReplicationSuccess.Year -gt 1900) {
      $hours = [math]::Round(($now - $p.LastReplicationSuccess).TotalHours, 1)
    }
    $code = 0
    try { $code = [int]$p.LastReplicationResult } catch { $code = 0 }
    $fails = 0
    try { $fails = [int]$p.ConsecutiveFailureCount } catch { $fails = 0 }
    Write-Output ('REPL|' + $partner + '|' + $part + '|' + $hours + '|' + $code + '|' + $fails)
    $sent++
  }
} catch { Write-Output 'REPL_FAIL' }
try {
  $osBoot = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  $bootDays = [math]::Floor(((Get-Date) - $osBoot.LastBootUpTime).TotalDays)
  Write-Output ('BOOT|' + $bootDays)
} catch { Write-Output 'BOOT|' }
try {
  $osver = [Environment]::OSVersion.Version
  if ($osver.Major -ge 10) { Write-Output 'HF|na' }
  else {
    $hf = Get-HotFix -Id KB3011780 -ErrorAction SilentlyContinue
    Write-Output ('HF|' + $(if ($hf) { 'yes' } else { 'no' }))
  }
} catch { Write-Output 'HF|na' }
Write-Output 'DC_DONE'
"""

_DIAG_PS = r"""
$ErrorActionPreference = 'Continue'
$exe = Join-Path $env:windir 'System32\dcdiag.exe'
if (-not (Test-Path -LiteralPath $exe)) { Write-Output 'DIAG_FAIL'; Write-Output 'DIAG_DONE'; exit }
foreach ($test in @('Advertising','Replications','NetLogons','Services','FSMOCheck')) {
  $out = & $exe /test:$test /q 2>&1 | Out-String
  $bad = ($LASTEXITCODE -ne 0) -or ($out -match '(?i)failed')
  Write-Output ('DIAG|' + $test + '|' + $(if ($bad) { '0' } else { '1' }))
}
Write-Output 'DIAG_DONE'
"""

_COUNT_PS = r"""
$ErrorActionPreference = 'Continue'
$since = (Get-Date).AddHours(-24)
function Count-Id([int]$id) {
  try { return @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$id; StartTime=$since} -MaxEvents 400 -ErrorAction Stop).Count }
  catch {
    if ($_.Exception.Message -match 'No events were found') { return 0 }
    return -1
  }
}
Write-Output ('COUNT|' + (Count-Id 4625) + '|' + (Count-Id 4740))
Write-Output 'COUNT_DONE'
"""

_DNS_ZONE_PS = r"""
$ErrorActionPreference = 'Continue'
try { Import-Module DnsServer -ErrorAction Stop } catch { Write-Output 'DNS_FAIL'; Write-Output 'DNS_DONE'; exit }
try {
  $zones = @(Get-DnsServerZone -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated } | Select-Object -First 41)
  if ($zones.Count -gt 40) { Write-Output 'DNS_TRUNCATED' }
  $zones = @($zones | Select-Object -First 40)
  Write-Output 'DNS_ZONES_OK'
} catch { Write-Output 'DNS_FAIL'; Write-Output 'DNS_DONE'; exit }
foreach ($z in $zones) {
  $name = (([string]$z.ZoneName) -replace '\|','/')
  if (-not $name -or $name.Length -gt 80) { continue }
  $aging = '?'
  try {
    $ag = Get-DnsServerZoneAging -Name $z.ZoneName -ErrorAction Stop
    if ($null -ne $ag -and $null -ne $ag.AgingEnabled) { if ($ag.AgingEnabled) { $aging = '1' } else { $aging = '0' } }
  } catch {}
  $dyn = (([string]$z.DynamicUpdate) -replace '\|','/')
  $xfer = (([string]$z.SecureSecondaries) -replace '\|','/')
  $type = (([string]$z.ZoneType) -replace '\|','/')
  $scope = (([string]$z.ReplicationScope) -replace '\|','/')
  $rev = '0'
  if ($z.IsReverseLookupZone) { $rev = '1' }
  $signed = '?'
  try { if ($null -ne $z.IsSigned) { if ($z.IsSigned) { $signed = '1' } else { $signed = '0' } } } catch {}
  Write-Output ('ZONE|' + $name + '|' + $type + '|' + $scope + '|' + $dyn + '|' + $xfer + '|' + $aging + '|' + $rev + '|' + $signed)
  if ($z.ZoneType -eq 'Forwarder') {
    $masters = @()
    try { $masters = @($z.MasterServers | Select-Object -First 4 | ForEach-Object { ([string]$_) -replace '\|','/' }) } catch {}
    Write-Output ('CFWD|' + $name + '|' + ($masters -join ','))
  }
}
try {
  $fw = Get-DnsServerForwarder -ErrorAction Stop
  $ips = @($fw.IPAddress | Select-Object -First 8 | ForEach-Object { ([string]$_) -replace '\|','/' })
  if ($null -ne $fw) { Write-Output ('FWD|' + ($ips -join ',')) } else { Write-Output 'FWD_FAIL' }
} catch { Write-Output 'FWD_FAIL' }
try {
  $sc = Get-DnsServerScavenging -ErrorAction Stop
  $on = '?'
  if ($null -ne $sc) { $on = '0' }
  if ($sc -and $sc.ScavengingState) { $on = '1' }
  $interval = ''
  $norefresh = ''
  $refresh = ''
  if ($sc) {
    $interval = (([string]$sc.ScavengingInterval) -replace '\|','/')
    $norefresh = (([string]$sc.NoRefreshInterval) -replace '\|','/')
    $refresh = (([string]$sc.RefreshInterval) -replace '\|','/')
  }
  Write-Output ('SCAV|' + $on + '|' + $interval + '|' + $norefresh + '|' + $refresh)
} catch { Write-Output 'SCAV|?|||' }
$counted = 0
foreach ($z in $zones) {
  if ($counted -ge 4) { break }
  $name = [string]$z.ZoneName
  if (-not $name) { continue }
  $bag = @{}
  $seen = 0
  foreach ($r in @(Get-DnsServerResourceRecord -ZoneName $name -ErrorAction SilentlyContinue)) {
    $seen++
    if ($seen -gt 400) { break }
    $t = [string]$r.RecordType
    if (-not $t) { continue }
    if ($bag.ContainsKey($t)) { $bag[$t]++ } else { $bag[$t] = 1 }
  }
  $parts = ($bag.GetEnumerator() | ForEach-Object { $_.Key + '=' + $_.Value }) -join ','
  Write-Output ('STAT|' + (($name -replace '\|','/')) + '|' + $parts)
  $counted++
}
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $domainObj = Get-ADDomain -Server $env:COMPUTERNAME -ErrorAction Stop
  $domain = [string]$domainObj.DNSRoot
  $domainDn = [string]$domainObj.DistinguishedName
  foreach ($label in @('_ldap._tcp','_kerberos._tcp','_gc._tcp')) {
    $q = $label + '.' + $domain
    $ok = '0'
    try {
      $ans = @(Resolve-DnsName -Name $q -Type SRV -Server $env:COMPUTERNAME -ErrorAction Stop)
      if ($ans.Count -gt 0) { $ok = '1' }
    } catch {}
    Write-Output ('LOC|' + $label + '|' + $ok)
  }
  $live = New-Object 'System.Collections.Generic.HashSet[string]'
  foreach ($dc in @(Get-ADDomainController -Filter * -Server $env:COMPUTERNAME -ErrorAction SilentlyContinue)) {
    foreach ($value in @([string]$dc.HostName, [string]$dc.Name)) {
      if ($value) { [void]$live.Add($value.ToLower()) }
    }
  }
  $stale = 0
  function Test-Gone([string]$target) {
    $name = $target.Trim().Trim('.').ToLower()
    if (-not $name) { return $false }
    if ($live.Contains($name)) { return $false }
    $short = $name.Split('.')[0]
    foreach ($item in $live) { if ($item.Split('.')[0] -eq $short) { return $false } }
    return $true
  }
  foreach ($label in @('_ldap._tcp','_kerberos._tcp','_gc._tcp')) {
    if ($stale -ge 12) { break }
    foreach ($rec in @(Get-DnsServerResourceRecord -ZoneName $domain -RRType SRV -Name $label -ErrorAction SilentlyContinue)) {
      if ($stale -ge 12) { break }
      $target = ''
      try { $target = [string]$rec.RecordData.DomainName } catch {}
      if (Test-Gone $target) {
        Write-Output ('STALE|' + $label + '|' + (($target -replace '\|','/')))
        $stale++
      }
    }
  }
  $msdcs = '_msdcs.' + $domain
  $seenCname = 0
  foreach ($rec in @(Get-DnsServerResourceRecord -ZoneName $msdcs -RRType CNAME -ErrorAction SilentlyContinue)) {
    if ($stale -ge 12 -or $seenCname -ge 40) { break }
    $seenCname++
    $target = ''
    try { $target = [string]$rec.RecordData.HostNameAlias } catch {}
    if (Test-Gone $target) {
      Write-Output ('STALE|cname|' + (($target -replace '\|','/')))
      $stale++
    }
  }
} catch { Write-Output 'LOC_FAIL' }
# TCP/53 only: does not test UDP, recursion, DNS answers or conditional routing.
function Test-DnsTcp([string]$address) {
  $parsed = $null
  if (-not [System.Net.IPAddress]::TryParse($address, [ref]$parsed)) { return '?' }
  $client = New-Object System.Net.Sockets.TcpClient($parsed.AddressFamily)
  $wait = $null
  try {
    $wait = $client.BeginConnect($parsed, 53, $null, $null)
    if (-not $wait.AsyncWaitHandle.WaitOne(500, $false)) { return '0' }
    $client.EndConnect($wait)
    return '1'
  } catch { return '0' } finally {
    if ($wait) { $wait.AsyncWaitHandle.Close() }
    $client.Close()
  }
}
try {
  $localIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object IPAddress)
  $adapters = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.ServerAddresses } | Select-Object -First 4)
  foreach ($a in $adapters) {
    $pos = 0
    foreach ($server in @($a.ServerAddresses | Select-Object -First 4)) {
      $ip = ([string]$server).Trim()
      $self = if ($localIps -contains $ip -or $ip -eq '127.0.0.1') { '1' } else { '0' }
      Write-Output ('RES|' + $ip + '|' + $pos + '|' + $self + '|' + (Test-DnsTcp $ip) + '|' + $a.InterfaceIndex)
      $pos++
    }
  }
  Write-Output 'RES_OK'
} catch { Write-Output 'RES_FAIL' }
try {
  $forwarderConfig = Get-DnsServerForwarder -ErrorAction Stop
  $targets = @($forwarderConfig.IPAddress | Select-Object -First 8)
  foreach ($server in $targets) {
    $ip = ([string]$server).Trim()
    if ($ip) { Write-Output ('FWDPROBE|forwarder|' + $ip + '|' + (Test-DnsTcp $ip)) }
  }
  # Use zone objects already read by Get-DnsServerZone, not a nonexistent cmdlet.
  $conditionalTargets = @($zones | Where-Object { $_.ZoneType -eq 'Forwarder' } | ForEach-Object { $_.MasterServers } | ForEach-Object { [string]$_ } | Select-Object -Unique)
  if ($conditionalTargets.Count -gt 16) { Write-Output 'FWDPROBE_LIMIT' }
  foreach ($ip in $conditionalTargets | Select-Object -First 16) {
    if ($ip) { Write-Output ('FWDPROBE|conditional|' + $ip + '|' + (Test-DnsTcp $ip)) }
  }
  Write-Output 'FWDPROBE_OK'
} catch { Write-Output 'FWDPROBE_FAIL' }
# Enumerate actual zone objects in standard DNS partitions, never construct zone DNs.
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $rootDse = Get-ADRootDSE -Server $env:COMPUTERNAME -ErrorAction Stop
  $domainDn = [string]$rootDse.defaultNamingContext
  $forestDn = [string]$rootDse.rootDomainNamingContext
  $bases = @(('CN=MicrosoftDNS,CN=System,' + $domainDn), ('CN=MicrosoftDNS,DC=DomainDnsZones,' + $domainDn), ('CN=MicrosoftDNS,DC=ForestDnsZones,' + $forestDn))
  $checked = 0; $broad = 0; $checkedZones = 0; $errors = 0; $discovered = 0; $budget = 40
  foreach ($base in $bases) {
    try {
      $zoneObjects = @(Get-ADObject -Server $env:COMPUTERNAME -SearchBase $base -SearchScope OneLevel -LDAPFilter '(objectClass=dnsZone)' -ResultSetSize 41 -ErrorAction Stop)
      $discovered += $zoneObjects.Count
      foreach ($zoneObject in $zoneObjects) {
        if (($checkedZones + $errors) -ge $budget) { Write-Output 'ACL_LIMIT'; break }
        try {
          # DACL only, no SACL/record values/principal names.
          $entry = New-Object System.DirectoryServices.DirectoryEntry(('LDAP://' + $env:COMPUTERNAME + '/' + $zoneObject.DistinguishedName))
          try {
            $entry.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
            $entry.psbase.RefreshCache(@('ntSecurityDescriptor'))
            $rules = $entry.psbase.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            foreach ($ace in $rules) {
              $checked++
              $sid = $ace.IdentityReference.Value
              # Everyone, Authenticated Users, Builtin Users only; not a full access check.
              if ($sid -in @('S-1-1-0','S-1-5-11','S-1-5-32-545') -and $ace.AccessControlType -eq 'Allow' -and -not ($ace.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)) {
                $rights = [int]$ace.ActiveDirectoryRights
                # WriteDacl/WriteOwner or unscoped WriteProperty; CreateChild alone is often default.
                $danger = ($rights -band 0xC0000) -ne 0 -or (($rights -band 0x20) -ne 0 -and $ace.ObjectType -eq [guid]::Empty)
                if ($danger) { $broad++ }
              }
            }
            $checkedZones++
          } finally { $entry.Dispose() }
        } catch { $errors++ }
      }
    } catch { $errors++ }
  }
  $aclState = if ($checkedZones -eq 0) { 'unavailable' } elseif ($errors -gt 0 -or $discovered -gt $checkedZones -or $checkedZones -ge $budget) { 'partial' } else { 'collected' }
  Write-Output ('ACL|' + $aclState + '|' + $checked + '|' + $broad + '|0|' + $checkedZones + '|' + $errors)
} catch { Write-Output 'ACL_FAIL' }
Write-Output 'DNS_DONE'
"""

_TRUST_REACH_PS = r"""
$ErrorActionPreference = 'Continue'
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Output 'TRUST_DONE'; exit }
$sent = 0
foreach ($trust in @(Get-ADTrust -Filter * -ErrorAction SilentlyContinue)) {
  if ($sent -ge 12) { break }
  $name = (([string]$trust.Name) -replace '\|','/')
  if (-not $name) { continue }
  $open = '0'
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $wait = $client.BeginConnect($name, 389, $null, $null)
    if ($wait.AsyncWaitHandle.WaitOne(2000, $false) -and $client.Connected) { $open = '1' }
    $client.Close()
  } catch {}
  Write-Output ('TRUST|' + $name + '|' + $open)
  $sent++
}
Write-Output 'TRUST_DONE'
"""

_LAST_USER_PS = r"""
$ErrorActionPreference = 'Continue'
$ui = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -ErrorAction SilentlyContinue
$name = [string]$ui.LastLoggedOnSAMUser
if (-not $name) { $name = [string]$ui.LastLoggedOnUser }
if ($name) { Write-Output ('LAST|' + ($name -replace '[^\w\\.@$-]', '')) }
Write-Output 'LAST_DONE'
"""

_GPO_DIFF_PS = r"""
$ErrorActionPreference = 'Continue'
$root = 'C:\Windows\SYSVOL\domain\Policies'
if (-not (Test-Path -LiteralPath $root)) {
  $found = Get-ChildItem 'C:\Windows\SYSVOL\sysvol' -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'Policies' } | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($found) { $root = $found }
}
try {
  $allPolicies = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop)
  Write-Output 'GPO_ROOT_OK'
} catch { Write-Output 'GPO_FAIL'; Write-Output 'GPO_DONE'; exit }
if ($allPolicies.Count -gt 20) { Write-Output 'GPO_LIMIT' }
$safeNumeric = @('MinimumPasswordLength','PasswordHistorySize','MaximumPasswordAge','ClearTextPassword')
$secret = '(?i)password|cpassword|pwd|passwd|secret'
$emitted = 0
$allPolicies | Select-Object -First 80 | ForEach-Object {
  $guid = $_.Name
  $inf = Join-Path $_.FullName 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
  if (-not (Test-Path -LiteralPath $inf)) { return }
  try { $infLines = @(Get-Content -LiteralPath $inf -ErrorAction Stop); Write-Output ('GPO_INF_OK|' + $guid) } catch { Write-Output ('GPO_ERROR|INF|' + $guid); return }
  foreach ($line in $infLines) {
    if ($emitted -ge 2500) { Write-Output 'GPO_LIMIT'; break }
    if ($line -match '^[;#\[]' -or $line -notmatch '=') { continue }
    $pair = $line.Split('=', 2)
    $key = $pair[0].Trim()
    $val = $pair[1].Trim()
    if (($key -match $secret -and -not ($safeNumeric -contains $key -and $val -match '^\d+$')) -or $val -match $secret) { $val = '[скрыто]' }
    if ($key.Length -gt 80 -or $key.Length -eq 0) { continue }
    if ($val.Length -gt 60) { $val = $val.Substring(0, 60) }
    Write-Output ('INF|' + $guid + '|' + ($key -replace '\|','/') + '|' + ($val -replace '\|','/'))
    $emitted++
  }
}
$polSeen = 0
$allPolicies | Select-Object -First 20 | ForEach-Object {
  if ($polSeen -ge 400) { return }
  $guid = $_.Name
  foreach ($hive in @('Machine','User')) {
    $pol = Join-Path $_.FullName ($hive + '\Registry.pol')
    if (-not (Test-Path -LiteralPath $pol)) { continue }
    try { $bytes = [System.IO.File]::ReadAllBytes($pol); Write-Output ('GPO_POL_READ|' + $guid + '|' + $hive) } catch { Write-Output ('GPO_ERROR|POL|' + $guid + '|' + $hive); continue }
    if ($bytes.Length -lt 8 -or [BitConverter]::ToUInt32($bytes,0) -ne 0x67655250 -or [BitConverter]::ToUInt32($bytes,4) -ne 1) { Write-Output ('GPO_ERROR|HEADER|' + $guid + '|' + $hive); continue }
    $offset = 8
    $taken = 0
    while ($offset -lt ($bytes.Length - 1) -and $taken -lt 20 -and $polSeen -lt 400) {
      if (-not ($bytes[$offset] -eq 0x5B -and $bytes[$offset+1] -eq 0x00)) { break }
      $offset += 2
      $key = ''
      while ($offset + 1 -lt $bytes.Length) {
        $ch = [BitConverter]::ToChar($bytes, $offset); $offset += 2
        if ($ch -eq [char]0) { break }
        $key += $ch
      }
      $offset += 2
      $name = ''
      while ($offset + 1 -lt $bytes.Length) {
        $ch = [BitConverter]::ToChar($bytes, $offset); $offset += 2
        if ($ch -eq [char]0) { break }
        $name += $ch
      }
      $offset += 2
      if ($offset + 4 -gt $bytes.Length) { break }
      $type = [BitConverter]::ToInt32($bytes, $offset); $offset += 4
      $offset += 2
      if ($offset + 4 -gt $bytes.Length) { break }
      $size = [BitConverter]::ToInt32($bytes, $offset); $offset += 4
      $offset += 2
      $data = ''
      if ($size -gt 0) {
        if (($offset + $size) -gt $bytes.Length) { break }
        if ($type -eq 4 -and $size -ge 4) { $data = [string][BitConverter]::ToInt32($bytes, $offset) }
        elseif ($type -eq 1 -or $type -eq 2) { $data = [System.Text.Encoding]::Unicode.GetString($bytes, $offset, $size).Trim([char]0) }
        else { $data = '[двоичное]' }
        $offset += $size
      }
      if ($offset + 1 -lt $bytes.Length -and $bytes[$offset] -eq 0x5D) { $offset += 2 }
      $label = (($hive + '\' + $key + '\' + $name) -replace '\|','/')
      if ($label.Length -gt 90) { $label = $hive + '\...\' + $label.Substring($label.Length - 75) }
      if ($label -match $secret -or $data -match $secret) { $data = '[скрыто]' }
      if ($data.Length -gt 40) { $data = $data.Substring(0, 40) }
      Write-Output ('REG|' + $guid + '|' + $label + '|' + ($data -replace '\|','/'))
      $taken++
      $polSeen++
    }
    if ($offset -lt ($bytes.Length - 1)) { Write-Output 'GPO_LIMIT' }
  }
}
# Read local DC explicitly: serverless ADSI can fail in a WinRM network logon.
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $rd = Get-ADRootDSE -Server $env:COMPUTERNAME -ErrorAction Stop
  $domainDn = [string]$rd.defaultNamingContext
  $results = @(Get-ADObject -Server $env:COMPUTERNAME -SearchBase $domainDn -SearchScope Subtree -LDAPFilter '(|(objectClass=domainDNS)(objectClass=organizationalUnit))' -Properties gPLink,gPOptions -ResultSetSize 501 -ErrorAction Stop)
  $count = 0
  foreach ($item in $results) {
    if ($count -ge 500) { Write-Output 'GPO_LINK_LIMIT'; break }
    $dn = [string]$item.DistinguishedName
    $link = [string]$item.gPLink
    $options = if ($null -ne $item.gPOptions) { [string]$item.gPOptions } else { '0' }
    $json = @{dn=$dn;links=$link;options=$options} | ConvertTo-Json -Compress
    Write-Output ('GPO_SCOPE|' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
    $count++
  }
  if ($count -gt 0) { Write-Output 'GPO_LINK_OK' } else { Write-Output 'GPO_LINK_FAIL' }
} catch { Write-Output 'GPO_LINK_FAIL' }
Write-Output 'GPO_DONE'
"""


def last_interactive_user(connection: dict[str, Any], host: str) -> str:
    """Имя последнего интерактивного входа с узла. Текст сессии не читается."""
    try:
        checked = validate_host(host)
    except ValueError:
        return ""
    port = int(connection["ssh_port"] if connection.get("transport") == "ssh" else connection.get("winrm_port") or 5985)
    if not _port_open(checked, port, timeout=2.0):
        return ""
    remote = run_remote(
        checked,
        connection["username"],
        connection["password"],
        connection["transport"],
        connection["winrm_port"],
        connection["ssh_port"],
        _LAST_USER_PS,
        timeout=25,
    )
    for line in (remote.get("stdout") or "").splitlines():
        if line.startswith("LAST|") and len(line) > 5:
            return line.split("|", 1)[1][:80]
    return ""


def controller_extra(connection: dict[str, Any], hosts: list[str], with_counts: bool = True, with_diag: bool = True) -> list[dict[str, Any]]:
    """Железо и счётчики входов по контроллерам. Сообщения журнала не сохраняются."""
    rows = []
    port = int(connection["ssh_port"] if connection.get("transport") == "ssh" else connection.get("winrm_port") or 5985)
    for index, host in enumerate(hosts[:6]):
        try:
            checked = validate_host(host)
        except ValueError:
            continue
        if not _port_open(checked, port, timeout=2.0):
            rows.append({"host": checked, "ok": False, "detail": "WinRM не открыт"})
            continue
        remote = run_remote(
            checked,
            connection["username"],
            connection["password"],
            connection["transport"],
            connection["winrm_port"],
            connection["ssh_port"],
            _DC_EXTRA_PS,
            timeout=45,
        )
        item: dict[str, Any] = {"host": checked, "ok": "DC_DONE" in (remote.get("stdout") or "")}
        if not item["ok"]:
            item["detail"] = (remote.get("error") or remote.get("stderr") or "контроллер не ответил")[:180]
            rows.append(item)
            continue
        for line in remote["stdout"].splitlines():
            if line.startswith("COUNT|"):
                parts = line.split("|")
                if len(parts) >= 3:
                    item["failed_24h"] = parts[1]
                    item["locked_24h"] = parts[2]
            elif line.startswith("HW|"):
                parts = line.split("|")
                if len(parts) >= 7:
                    item.update({
                        "maker": parts[1],
                        "model": parts[2],
                        "ram_gb": parts[3],
                        "ram_free_pct": parts[4],
                        "cpu": parts[5],
                        "disk_free_pct": parts[6],
                    })
            elif line.startswith("VOL|"):
                parts = line.split("|")
                if len(parts) >= 4 and len(item.setdefault("volumes", [])) < 24:
                    item["volumes"].append({"drive": parts[1][:8], "size_gb": parts[2][:8], "free_pct": parts[3][:4]})
            elif line.startswith("NIC|"):
                parts = line.split("|")
                if len(parts) >= 3 and len(item.setdefault("nics", [])) < 4:
                    item["nics"].append({"name": parts[1][:60], "address": parts[2][:48]})
            elif line.startswith("BIOS|"):
                item["bios"] = line.split("|", 1)[1][:40]
            elif line.startswith("NTDS|"):
                item["ntds_mb"] = line.split("|", 1)[1][:16]
            elif line.startswith("BOOT|"):
                item["boot_days"] = line.split("|", 1)[1][:8]
            elif line.startswith("HF|"):
                item["hotfix_ms14"] = line.split("|", 1)[1][:8]
            elif line.startswith("REPL|"):
                parts = line.split("|")
                if len(parts) >= 6:
                    item.setdefault("partners", []).append({
                        "partner": parts[1][:80],
                        "partition": parts[2][:40],
                        "hours": parts[3],
                        "code": parts[4],
                        "fails": parts[5],
                        "state": _repl_state(parts[3], parts[4], parts[5]),
                    })
            elif line == "REPL_FAIL":
                item["repl_ok"] = False
        if "repl_ok" not in item:
            item["repl_ok"] = "partners" in item or "REPL_FAIL" not in (remote.get("stdout") or "")
        if with_counts:
            counted = run_remote(
                checked,
                connection["username"],
                connection["password"],
                connection["transport"],
                connection["winrm_port"],
                connection["ssh_port"],
                _COUNT_PS,
                timeout=12,
            )
            for line in (counted.get("stdout") or "").splitlines():
                if not line.startswith("COUNT|"):
                    continue
                parts = line.split("|")
                if len(parts) >= 3:
                    item["failed_24h"] = parts[1]
                    item["locked_24h"] = parts[2]
        if with_diag:
            diag = run_remote(
                checked,
                connection["username"],
                connection["password"],
                connection["transport"],
                connection["winrm_port"],
                connection["ssh_port"],
                _DIAG_PS,
                timeout=40,
            )
            for line in (diag.get("stdout") or "").splitlines():
                if not line.startswith("DIAG|"):
                    continue
                parts = line.split("|")
                if len(parts) >= 3 and len(item.setdefault("diag", [])) < 8:
                    item["diag"].append({"test": parts[1][:32], "ok": parts[2] == "1"})
        rows.append(item)
    return rows


def _repl_state(hours: str, code: str, fails: str) -> str:
    try:
        result = int(float(code))
        failed = int(float(fails))
        age = float(hours)
    except ValueError:
        return "не прочитано"
    if result != 0 or failed > 0:
        return "сбой"
    if age < 0:
        return "нет отметки"
    if age > 24:
        return "задержка"
    return "норма"


def _dns_advanced_assessment(acl: dict[str, Any] | None, resolvers: list[dict[str, Any]], forwarders: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Evidence of candidate ACEs / TCP failure, not effective permissions or DNS failure."""
    findings: list[dict[str, Any]] = []
    if isinstance(acl, dict) and acl.get("state") in {"collected", "partial"} and (acl.get("broad_write_principals") or 0) > 0:
        findings.append({"code": "adidns_broad_write", "severity": "medium", "title": "ACL DNS требует проверки широких прав",
            "detail": "Обнаружены Allow ACE для Everyone, Authenticated Users или Builtin Users с WriteDacl/WriteOwner либо неограниченным WriteProperty. Deny, группы и effective access не вычислялись; CreateChild сам по себе не считается риском.", "evidence": acl})
    for row in resolvers:
        if row.get("reachable") is False:
            findings.append({"code": "dns_resolver_unreachable", "severity": "medium", "title": "TCP/53 резолвера не ответил за 500 мс",
                "detail": "UDP/53 и фактический DNS-ответ не проверены. Таймаут TCP не доказывает отказ DNS. Порядок self/peer не оценивается как DNS island.", "evidence": row})
    for row in forwarders:
        if row.get("reachable") is False:
            findings.append({"code": "dns_conditional_forwarder_unreachable" if row.get("kind") == "conditional" else "dns_forwarder_unreachable", "severity": "medium", "title": "TCP/53 сервера пересылки не ответил за 500 мс",
                "detail": "Только TCP-доступность, не DNS health. UDP, рекурсия, ответы и conditional routing не проверены.", "evidence": row})
    return findings


def _dns_zone_assessment(zones: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Configuration findings, not an exploit test or a complete DNS security verdict."""
    findings = []
    for row in zones[:40]:
        name = str(row.get("name") or "")[:80]
        dynamic = str(row.get("dynamic") or "").strip().lower()
        transfer = str(row.get("transfer") or "").strip().lower()
        if dynamic == "nonsecureandsecure":
            findings.append({"zone": name, "code": "dns_nonsecure_updates", "severity": "high",
                "title": "Разрешены незащищённые динамические обновления",
                "evidence": {"DynamicUpdate": row.get("dynamic")},
                "detail": "Конфигурация допускает обновления без защищённой аутентификации. Проверьте необходимость и перейдите на Secure, если тип зоны позволяет; запись тестовых данных не выполнялась."})
        if transfer in {"transferanyserver", "nosecurity", "any"}:
            findings.append({"zone": name, "code": "dns_open_transfer", "severity": "high",
                "title": "Передача зоны разрешена любому серверу",
                "evidence": {"SecureSecondaries": row.get("transfer")},
                "detail": "Настройка допускает широкий круг получателей AXFR. Ограничьте вторичными серверами; реальная передача и сетевые ACL не проверялись."})
    return findings


def dns_zones(connection: dict[str, Any]) -> dict[str, Any]:
    """Свойства зон, состав по типам записей и служебные SRV. Имена записей не сохраняются."""
    remote = run_remote(
        connection["host"],
        connection["username"],
        connection["password"],
        connection["transport"],
        connection["winrm_port"],
        connection["ssh_port"],
        _DNS_ZONE_PS,
        timeout=110,
    )
    stdout = remote.get("stdout") or ""
    markers = set(stdout.splitlines())
    if "DNS_DONE" not in markers or "DNS_FAIL" in markers or "DNS_ZONES_OK" not in markers:
        return {"ok": False, "zones": [], "locator": [], "wildcard": None, "assessment": [], "collection_state": "unavailable", "message": (remote.get("error") or remote.get("stderr") or "DNS-сервер не ответил")[:180]}
    zones = []
    composition: dict[str, dict[str, int]] = {}
    locator = []
    forwarders: list[str] = []
    conditional: list[dict[str, str]] = []
    stale: list[dict[str, str]] = []
    resolvers: list[dict[str, Any]] = []
    forwarder_probes: list[dict[str, Any]] = []
    acl: dict[str, Any] | None = None
    scavenging = {"enabled": None, "interval": "", "no_refresh": "", "refresh": ""}
    wildcard = None
    for line in stdout.splitlines():
        if line.startswith("ZONE|"):
            parts = line.split("|")
            if len(parts) < 8:
                continue
            zones.append({
                "name": parts[1],
                "type": parts[2],
                "scope": parts[3],
                "dynamic": parts[4],
                "transfer": parts[5],
                "aging": {"1": True, "0": False}.get(parts[6]),
                "reverse": parts[7] == "1",
                "signed": {"1": True, "0": False}.get(parts[8]) if len(parts) > 8 else None,
            })
        elif line.startswith("STAT|"):
            parts = line.split("|", 2)
            if len(parts) < 3:
                continue
            bag: dict[str, int] = {}
            for piece in parts[2].split(","):
                if "=" not in piece:
                    continue
                kind, amount = piece.split("=", 1)
                try:
                    bag[kind[:12]] = int(amount)
                except ValueError:
                    continue
            if bag:
                composition[parts[1][:80]] = bag
        elif line.startswith("LOC|"):
            parts = line.split("|")
            if len(parts) >= 3:
                locator.append({"name": parts[1], "ok": parts[2] == "1"})
        elif line.startswith("RES|"):
            parts = line.split("|")
            if len(parts) >= 5 and len(resolvers) < 48:
                resolvers.append({"server": parts[1][:48], "position": int(parts[2]) if parts[2].isdigit() else None, "is_self": {"1": True, "0": False}.get(parts[3]), "reachable": {"1": True, "0": False}.get(parts[4]), "interface_index": parts[5][:16] if len(parts) > 5 else None})
        elif line.startswith("FWDPROBE|"):
            parts = line.split("|")
            if len(parts) >= 4 and len(forwarder_probes) < 24:
                forwarder_probes.append({"kind": parts[1][:16], "server": parts[2][:48], "reachable": {"1": True, "0": False}.get(parts[3])})
            elif len(parts) >= 3 and len(forwarder_probes) < 24:
                forwarder_probes.append({"kind": "forwarder", "server": parts[1][:48], "reachable": {"1": True, "0": False}.get(parts[2])})
        elif line.startswith("ACL|"):
            parts = line.split("|")
            if len(parts) >= 7:
                acl = {"state": parts[1] or "unknown", "aces_checked": int(parts[2]) if parts[2].isdigit() else None, "broad_write_principals": int(parts[3]) if parts[3].isdigit() else None, "unresolved_aces": int(parts[4]) if parts[4].isdigit() else None, "zones_checked": int(parts[5]) if parts[5].isdigit() else None, "acl_errors": int(parts[6]) if parts[6].isdigit() else None}
            elif len(parts) >= 5:
                acl = {"state": "unknown", "aces_checked": int(parts[1]) if parts[1].isdigit() else None, "broad_write_principals": int(parts[2]) if parts[2].isdigit() else None, "unresolved_aces": int(parts[3]) if parts[3].isdigit() else None, "zones_checked": int(parts[4]) if parts[4].isdigit() else None}
        elif line.startswith("FWD|"):
            forwarders = [piece.strip()[:48] for piece in line.split("|", 1)[1].split(",") if piece.strip()][:8]
        elif line.startswith("CFWD|") and len(conditional) < 12:
            parts = line.split("|", 2)
            if len(parts) >= 2 and parts[1]:
                conditional.append({"name": parts[1][:80], "masters": (parts[2] if len(parts) > 2 else "")[:120]})
        elif line.startswith("SCAV|"):
            parts = line.split("|")
            scavenging = {
                "enabled": {"1": True, "0": False}.get(parts[1]) if len(parts) > 1 else None,
                "interval": parts[2][:40] if len(parts) > 2 else "",
                "no_refresh": parts[3][:40] if len(parts) > 3 else "",
                "refresh": parts[4][:40] if len(parts) > 4 else "",
            }
        elif line.startswith("STALE|") and len(stale) < 12:
            parts = line.split("|", 2)
            if len(parts) >= 3 and parts[2]:
                stale.append({"name": parts[1][:40], "target": parts[2][:80]})
    if acl and "ACL_LIMIT" in markers and acl.get("state") == "collected":
        acl["state"] = "partial"
    return {
        "ok": True,
        "collection_state": "partial" if ("DNS_TRUNCATED" in markers or "ACL_FAIL" in markers or "RES_FAIL" in markers or "FWDPROBE_FAIL" in markers or not acl or acl.get("state") != "collected" or "RES_OK" not in markers or "FWDPROBE_OK" not in markers or "ACL_LIMIT" in markers or "FWDPROBE_LIMIT" in markers) else "collected",
        "forwarders_collected": any(line.startswith("FWD|") for line in markers),
        "acl": acl or {"state": "unavailable", "message": "ADIDNS ACL не получен"},
        "resolver_state": "unavailable" if "RES_OK" not in markers else "collected",
        "forwarder_probe_state": "unavailable" if "FWDPROBE_OK" not in markers else "partial" if "FWDPROBE_LIMIT" in markers else "collected",
        "probe_method": "TCP/53, 500ms, local DNS host; IPv4 resolvers only",
        "resolvers": resolvers,
        "forwarder_probes": forwarder_probes,
        "advanced_assessment": _dns_advanced_assessment(acl, resolvers, forwarder_probes),
        "zone_limit": 40,
        "assessment": _dns_zone_assessment(zones),
        "limitations": ["Проверены свойства не более 40 зон одного DNS-сервера, не всех серверов леса.", "ACL анализирует до 40 zone objects стандартных DNS-разделов AD; корни контейнеров и record ACL не проверены, имена principals не сохраняются. Нулевой результат при ошибках чтения не считается чистым ACL.", "DNSSEC не обязателен для каждой внутренней зоны; отсутствие подписи само по себе не доказывает уязвимость."],
        "zones": zones,
        "composition": composition,
        "locator": locator,
        "forwarders": forwarders,
        "conditional": conditional,
        "stale": stale,
        "scavenging": scavenging,
        "wildcard": wildcard,
        "message": f"Зон прочитано: {len(zones)}. Состав по типам: {len(composition)}. Имена записей не копировались.",
    }


_FRIENDLY = {
    "LmCompatibilityLevel": "Уровень проверки подлинности LAN Manager",
    "NoLMHash": "Не хранить хеш LM",
    "LDAPServerIntegrity": "Подпись LDAP на контроллере",
    "LDAPClientIntegrity": "Подпись LDAP на клиенте",
    "RequireSecuritySignature": "Обязательная подпись SMB",
    "EnableSecuritySignature": "Подпись SMB включена",
    "RestrictAnonymous": "Дополнительные ограничения анонимного доступа",
    "RestrictAnonymousSAM": "Анонимное перечисление SAM",
    "EveryoneIncludesAnonymous": "Everyone включает анонимный доступ",
    "SupportedEncryptionTypes": "Типы шифрования Kerberos",
    "MaxClockSkew": "Максимальная погрешность часов Kerberos",
    "MinimumPasswordLength": "Минимальная длина пароля",
    "PasswordHistorySize": "История паролей",
    "LockoutBadCount": "Порог блокировки",
    "MaximumPasswordAge": "Максимальный срок пароля",
    "ClearTextPassword": "Обратимое шифрование пароля",
    "LsaCfgFlags": "Защита учётных данных LSA",
    "RunAsPPL": "LSA как защищённый процесс",
    "EnableLUA": "Контроль учётных записей",
    "ConsentPromptBehaviorAdmin": "Поведение запроса UAC для администратора",
    "EnableMulticast": "Мультикаст имён LLMNR",
    "AllowInsecureGuestAuth": "Гостевой вход SMB",
    "RequireMutualAuthentication": "Взаимная проверка UNC",
    "RequireIntegrity": "Целостность UNC",
    "SeDenyNetworkLogonRight": "Запрет входа по сети",
    "SeDenyInteractiveLogonRight": "Запрет локального входа",
    "SeDenyRemoteInteractiveLogonRight": "Запрет входа через удалённый рабочий стол",
    "EnableGuestAccount": "Учётная запись гостя",
    "NewAdministratorName": "Имя встроенного администратора",
    "NewGuestName": "Имя встроенного гостя",
    "ForceLogoffWhenHourExpire": "Принудительный выход по окончании часов",
    "TicketValidateClient": "Проверка пакетов Kerberos",
    "AuditSystemEvents": "Аудит системных событий",
    "AuditLogonEvents": "Аудит входов",
    "AuditPrivilegeUse": "Аудит использования привилегий",
    "AuditPolicyChange": "Аудит изменения политики",
    "AuditAccountManage": "Аудит управления учётными записями",
    "AuditDSAccess": "Аудит доступа к службе каталогов",
    "AuditAccountLogon": "Аудит проверки учётных записей",
}


_BASELINE = {
    "MinimumPasswordLength": (12, "gte", "не короче 12"),
    "PasswordHistorySize": (24, "gte", "не меньше 24"),
    "ClearTextPassword": (0, "eq", "выключено"),
    "NoLMHash": (1, "eq", "включено"),
    "LmCompatibilityLevel": (5, "eq", "5: отклонять LM и NTLM"),
    "LDAPServerIntegrity": (2, "eq", "требовать подпись"),
    "LDAPClientIntegrity": (1, "gte", "не ниже 1"),
    "RequireSecuritySignature": (1, "eq", "включено"),
    "EnableLUA": (1, "eq", "включено"),
    "LsaCfgFlags": (1, "one_or_two", "1 или 2: Credential Guard включён"),
    "RunAsPPL": (1, "one_or_two", "1 или 2: защита LSA включена"),
    "AllowInsecureGuestAuth": (0, "eq", "выключено"),
    "EnableMulticast": (0, "eq", "выключено"),
    "RestrictAnonymous": (1, "gte", "не ниже 1"),
    "RestrictAnonymousSAM": (1, "eq", "включено"),
    "SupportedEncryptionTypes": (24, "aes_mask", "AES128/AES256 (бит 0x08 или 0x10)"),
    "KdcEnableFast": (1, "gte", "не ниже 1"),
}


def _friendly(key: str) -> str:
    tail = key.replace("/", "\\").split("\\")[-1]
    return _FRIENDLY.get(tail) or _FRIENDLY.get(key) or ""


_GPO_SAFE_NUMERIC = {"MinimumPasswordLength", "PasswordHistorySize", "MaximumPasswordAge", "ClearTextPassword"}


def _gpo_numeric_baseline(number: int, expected: int, mode: str) -> bool:
    if number < 0:
        return False
    if mode == "aes_mask":
        return bool(number & 0x18)
    if mode == "one_or_two":
        return number in (1, 2)
    return number >= expected if mode == "gte" else number == expected


def _gpo_inherited_links(scopes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Structural link eligibility only; no resultant setting or filtering claims."""
    def components(dn: str) -> list[str]:
        # An escaped comma (odd backslash run) is part of an RDN.
        result, start, slashes = [], 0, 0
        for index, ch in enumerate(dn):
            if ch == "," and slashes % 2 == 0:
                result.append(dn[start:index].strip())
                start = index + 1
            slashes = slashes + 1 if ch == "\\" else 0
        result.append(dn[start:].strip())
        return result
    lookup = {tuple(x.casefold() for x in components(row["dn"])): row for row in scopes}
    for scope in scopes:
        parts = components(scope["dn"])
        chain, missing = [], []
        for index in range(len(parts)):
            suffix = parts[index:]
            if not suffix[0].lower().startswith(("ou=", "dc=")):
                continue
            # A domain starts at the first DC component, not at each DC suffix.
            if index > 0 and suffix[0].lower().startswith("dc=") and parts[index-1].lower().startswith("dc="):
                continue
            parent = lookup.get(tuple(x.casefold() for x in suffix))
            if parent is None:
                missing.append(",".join(suffix))
            else:
                chain.append(parent)
        candidates: list[dict[str, Any]] = []
        blocked: list[dict[str, Any]] = []
        for ancestor in reversed(chain):
            if ancestor.get("block_inheritance"):
                blocked.extend({**link, "blocked_at": ancestor["dn"]} for link in candidates if not link.get("enforced"))
                candidates = [link for link in candidates if link.get("enforced")]
            for link in ancestor.get("links", []):
                if link.get("enabled"):
                    candidates.append({**link, "source_dn": ancestor["dn"], "inherited": ancestor["dn"].casefold() != scope["dn"].casefold()})
        scope["structural_inheritance"] = {
            "state": "partial" if missing else "collected", "missing_ancestors": missing,
            "candidate_links": candidates, "blocked_links": blocked,
            "effective_policy_verified": False,
        }
    return scopes


def _gpo_link_metadata(stdout: str, names: dict[str, str]) -> dict[str, Any]:
    """Decode bounded domain/OU metadata, never claim resultant policy."""
    import json
    scopes: list[dict[str, Any]] = []
    errors = 0
    markers = set(stdout.splitlines())
    pattern = re.compile(r"\[LDAP://([^;\]]+);([0-9]+)\]", re.I)
    for line in stdout.splitlines():
        if not line.startswith("GPO_SCOPE|"):
            continue
        if len(scopes) >= 500:
            break
        try:
            payload = line.split("|", 1)[1]
            if len(payload) > 100000:
                raise ValueError("oversize scope")
            row = json.loads(base64.b64decode(payload, validate=True).decode("utf-8"))
            dn, raw, options = row["dn"], row["links"], int(row["options"])
            if not isinstance(dn, str) or not dn or len(dn) > 4096 or not isinstance(raw, str) or not 0 <= options <= 0xffffffff:
                raise ValueError("invalid scope")
            matches = list(pattern.finditer(raw))
            if pattern.sub("", raw).strip() or len(matches) > 100:
                raise ValueError("malformed or excessive links")
            links = []
            for order, match in enumerate(matches, 1):
                target, flags = match.group(1), int(match.group(2))
                if flags > 3:
                    raise ValueError("unknown link flags")
                guid_match = re.match(r"CN=(\{[0-9a-f-]{36}\}),CN=Policies,CN=System,", target, re.I)
                guid = guid_match.group(1) if guid_match else None
                label = next((v for k, v in names.items() if guid and k.strip("{}").lower() == guid.strip("{}").lower()), guid or target)
                links.append({"target_dn": target, "guid": guid, "name": label,
                              "order": len(matches) - order + 1, "enabled": not bool(flags & 1), "enforced": bool(flags & 2)})
            scopes.append({"dn": dn, "block_inheritance": bool(options & 1), "options": options, "links": links})
        except (ValueError, TypeError, KeyError, UnicodeError, AttributeError):
            errors += 1
    complete = "GPO_LINK_OK" in markers and "GPO_LINK_FAIL" not in markers and bool(scopes)
    state = "partial" if (scopes and (not complete or errors or "GPO_LINK_LIMIT" in markers)) else "collected" if complete else "unavailable"
    return {"state": state, "scopes": _gpo_inherited_links(scopes), "scopes_read": len(scopes), "parse_errors": errors,
            "limit_reached": "GPO_LINK_LIMIT" in markers,
            "effective_policy_verified": False,
            "limitations": ["Только domain/OU одного домена, до 500 объектов и 100 links на scope; sites и другие домены не охвачены.",
                            "Порядок 1 — наивысший приоритет ссылки внутри scope; список кандидатов не является итоговым порядком применения GPO.",
                            "Модель наследования исключает disabled links, сохраняет enforced через block inheritance; отсутствие родительского scope означает частичный расчёт.",
                            "Enabled/enforced и block inheritance — метаданные AD. Security/WMI filters, GPO status, loopback, CSE и RSoP не проверены."]}


def gpo_conflicts(connection: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    """Сравнение GptTmpl.inf и части Registry.pol. Значения, похожие на секрет, скрываются."""
    remote = run_remote(
        connection["host"],
        connection["username"],
        connection["password"],
        connection["transport"],
        connection["winrm_port"],
        connection["ssh_port"],
        _GPO_DIFF_PS,
        timeout=180,
    )
    stdout = remote.get("stdout") or ""
    markers = set(stdout.splitlines())
    if "GPO_DONE" not in markers or "GPO_ROOT_OK" not in markers or "GPO_FAIL" in markers:
        return {"ok": False, "conflicts": [], "message": (remote.get("error") or remote.get("stderr") or "SYSVOL не прочитан")[:240]}
    bucket: dict[str, dict[str, str]] = {}
    for line in stdout.splitlines():
        if not (line.startswith("INF|") or line.startswith("REG|")):
            continue
        parts = line.split("|", 3)
        if len(parts) < 4:
            continue
        guid, key, value = parts[1], parts[2], parts[3]
        if (_SECRET_KEY.search(key) and key not in _GPO_SAFE_NUMERIC) or _SECRET_KEY.search(value) or (key in _GPO_SAFE_NUMERIC and not value.isdecimal()):
            value = "[скрыто]"
        label = (names.get(guid) or names.get(guid.strip("{}")) or guid) + " [" + guid + "]"
        if value != "[скрыто]":
            bucket.setdefault(key, {})[label] = value
    conflicts = []
    for key, by_gpo in bucket.items():
        if len(by_gpo) < 2 or len(set(by_gpo.values())) < 2:
            continue
        row = {
            "key": key,
            "values": [{"gpo": name, "value": val} for name, val in list(by_gpo.items())[:6]],
        }
        title = _friendly(key)
        if title:
            row["title"] = title
        conflicts.append(row)
        if len(conflicts) >= 30:
            break
    baseline = []
    for key, by_gpo in bucket.items():
        tail = key.replace("/", "\\").split("\\")[-1]
        rule = _BASELINE.get(tail) or _BASELINE.get(key)
        if not rule or len(baseline) >= 40:
            continue
        expect, mode, label = rule
        for gpo, value in list(by_gpo.items())[:4]:
            if value == "[скрыто]":
                continue
            try:
                number = int(str(value).strip())
            except ValueError:
                continue
            ok = _gpo_numeric_baseline(number, expect, mode)
            baseline.append({
                "key": key[:80],
                "title": _friendly(key) or tail,
                "gpo": gpo,
                "value": str(number),
                "expected": label,
                "ok": ok,
            })
            if len(baseline) >= 40:
                break
    return {
        "ok": True,
        "collection_state": "partial",
        "effective_policy_verified": False,
        "link_metadata": _gpo_link_metadata(stdout, names),
        "collection": {
            "root_readable": True,
            "inf_files_read": sum(line.startswith("GPO_INF_OK|") for line in markers),
            "registry_files_read": sum(line.startswith("GPO_POL_READ|") for line in markers),
            "read_or_parse_errors": sum(line.startswith("GPO_ERROR|") for line in markers),
            "limits_reached": "GPO_LIMIT" in markers,
            "settings_compared": len(bucket),
            "conflicts_truncated": len(conflicts) >= 30,
            "baseline_truncated": len(baseline) >= 40,
        },
        "limitations": ["Сравнение сохранённых параметров, не RSoP/gpresult и не effective policy.", "INF: до 80 GPO и 2500 параметров; Registry.pol: до 20 GPO, 20 записей на файл, 400 суммарно. Парсер ограниченный.", "Не учитываются security filtering, порядок links, enforced/block inheritance, WMI и доступность расширений на целевом узле.", "ADMX/ADML, audit.csv и целостность репликации SYSVOL не проверены. Отсутствующий параметр baseline не считается безопасным.", "Имена registry-параметров могут быть сокращены коллектором; совпадение имён не доказывает одинаковый контекст."],
        "conflicts": conflicts,
        "baseline": baseline,
        "message": f"Сравнены шаблон безопасности и реестр политик. Расхождений: {len(conflicts)}. Сверка с линией: {len(baseline)}. Секреты в значения не попадают.",
    }


def trust_reach(connection: dict[str, Any]) -> list[dict[str, Any]]:
    """Доступен ли LDAP партнёра с контроллера. Вход на партнёра не выполняется."""
    remote = run_remote(
        connection["host"],
        connection["username"],
        connection["password"],
        connection["transport"],
        connection["winrm_port"],
        connection["ssh_port"],
        _TRUST_REACH_PS,
        timeout=40,
    )
    rows = []
    for line in (remote.get("stdout") or "").splitlines():
        if not line.startswith("TRUST|") or len(rows) >= 12:
            continue
        parts = line.split("|")
        if len(parts) >= 3 and parts[1]:
            rows.append({"name": parts[1][:80], "reachable": parts[2] == "1"})
    return rows
