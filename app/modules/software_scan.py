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
    if ($volSent -ge 6) { break }
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
$zones = @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated } | Select-Object -First 40)
foreach ($z in $zones) {
  $name = (([string]$z.ZoneName) -replace '\|','/')
  if (-not $name -or $name.Length -gt 80) { continue }
  $aging = '0'
  try {
    $ag = Get-DnsServerZoneAging -Name $z.ZoneName -ErrorAction SilentlyContinue
    if ($ag -and $ag.AgingEnabled) { $aging = '1' }
  } catch {}
  $dyn = (([string]$z.DynamicUpdate) -replace '\|','/')
  $xfer = (([string]$z.SecureSecondaries) -replace '\|','/')
  $type = (([string]$z.ZoneType) -replace '\|','/')
  $scope = (([string]$z.ReplicationScope) -replace '\|','/')
  $rev = '0'
  if ($z.IsReverseLookupZone) { $rev = '1' }
  $signed = '0'
  try { if ($z.IsSigned) { $signed = '1' } } catch {}
  Write-Output ('ZONE|' + $name + '|' + $type + '|' + $scope + '|' + $dyn + '|' + $xfer + '|' + $aging + '|' + $rev + '|' + $signed)
  if ($z.ZoneType -eq 'Forwarder') {
    $masters = @()
    try { $masters = @($z.MasterServers | Select-Object -First 4 | ForEach-Object { ([string]$_) -replace '\|','/' }) } catch {}
    Write-Output ('CFWD|' + $name + '|' + ($masters -join ','))
  }
}
try {
  $fw = Get-DnsServerForwarder -ErrorAction SilentlyContinue
  $ips = @($fw.IPAddress | Select-Object -First 8 | ForEach-Object { ([string]$_) -replace '\|','/' })
  Write-Output ('FWD|' + ($ips -join ','))
} catch { Write-Output 'FWD|' }
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
  $domain = [string](Get-ADDomain -Server $env:COMPUTERNAME).DNSRoot
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
Write-Output 'DNS_DONE'
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
$secret = '(?i)password|cpassword|pwd|passwd|secret'
$emitted = 0
Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Select-Object -First 80 | ForEach-Object {
  $guid = $_.Name
  $inf = Join-Path $_.FullName 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
  if (-not (Test-Path -LiteralPath $inf)) { return }
  foreach ($line in (Get-Content -LiteralPath $inf -ErrorAction SilentlyContinue)) {
    if ($emitted -ge 2500) { break }
    if ($line -match '^[;#\[]' -or $line -notmatch '=') { continue }
    $pair = $line.Split('=', 2)
    $key = $pair[0].Trim()
    $val = $pair[1].Trim()
    if ($key -match $secret -or $val -match $secret) { $val = '[скрыто]' }
    if ($key.Length -gt 80 -or $key.Length -eq 0) { continue }
    if ($val.Length -gt 60) { $val = $val.Substring(0, 60) }
    Write-Output ('INF|' + $guid + '|' + ($key -replace '\|','/') + '|' + ($val -replace '\|','/'))
    $emitted++
  }
}
$polSeen = 0
Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object {
  if ($polSeen -ge 400) { return }
  $guid = $_.Name
  foreach ($hive in @('Machine','User')) {
    $pol = Join-Path $_.FullName ($hive + '\Registry.pol')
    if (-not (Test-Path -LiteralPath $pol)) { continue }
    try { $bytes = [System.IO.File]::ReadAllBytes($pol) } catch { continue }
    if ($bytes.Length -lt 8 -or $bytes[0] -ne 0x50 -or $bytes[1] -ne 0x52) { continue }
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
      $label = (($key + '\' + $name) -replace '\|','/')
      if ($label.Length -gt 90) { $label = $label.Substring($label.Length - 90) }
      if ($label -match $secret -or $data -match $secret) { $data = '[скрыто]' }
      if ($data.Length -gt 40) { $data = $data.Substring(0, 40) }
      Write-Output ('REG|' + $guid + '|' + $label + '|' + ($data -replace '\|','/'))
      $taken++
      $polSeen++
    }
  }
}
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
                if len(parts) >= 4 and len(item.setdefault("volumes", [])) < 6:
                    item["volumes"].append({"drive": parts[1][:8], "size_gb": parts[2][:8], "free_pct": parts[3][:4]})
            elif line.startswith("NIC|"):
                parts = line.split("|")
                if len(parts) >= 3 and len(item.setdefault("nics", [])) < 4:
                    item["nics"].append({"name": parts[1][:60], "address": parts[2][:48]})
            elif line.startswith("BIOS|"):
                item["bios"] = line.split("|", 1)[1][:40]
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
        if with_diag and index == 0:
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
    if "DNS_DONE" not in stdout:
        return {"ok": False, "zones": [], "locator": [], "wildcard": False, "message": (remote.get("error") or remote.get("stderr") or "DNS-сервер не ответил")[:180]}
    zones = []
    composition: dict[str, dict[str, int]] = {}
    locator = []
    forwarders: list[str] = []
    conditional: list[dict[str, str]] = []
    stale: list[dict[str, str]] = []
    wildcard = False
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
                "aging": parts[6] == "1",
                "reverse": parts[7] == "1",
                "signed": len(parts) > 8 and parts[8] == "1",
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
        elif line.startswith("FWD|"):
            forwarders = [piece.strip()[:48] for piece in line.split("|", 1)[1].split(",") if piece.strip()][:8]
        elif line.startswith("CFWD|") and len(conditional) < 12:
            parts = line.split("|", 2)
            if len(parts) >= 2 and parts[1]:
                conditional.append({"name": parts[1][:80], "masters": (parts[2] if len(parts) > 2 else "")[:120]})
        elif line.startswith("STALE|") and len(stale) < 12:
            parts = line.split("|", 2)
            if len(parts) >= 3 and parts[2]:
                stale.append({"name": parts[1][:40], "target": parts[2][:80]})
    return {
        "ok": True,
        "zones": zones,
        "composition": composition,
        "locator": locator,
        "forwarders": forwarders,
        "conditional": conditional,
        "stale": stale,
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
}


def _friendly(key: str) -> str:
    tail = key.replace("/", "\\").split("\\")[-1]
    return _FRIENDLY.get(tail) or _FRIENDLY.get(key) or ""


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
    if "GPO_DONE" not in stdout:
        return {"ok": False, "conflicts": [], "message": (remote.get("error") or remote.get("stderr") or "SYSVOL не прочитан")[:240]}
    bucket: dict[str, dict[str, str]] = {}
    for line in stdout.splitlines():
        if not (line.startswith("INF|") or line.startswith("REG|")):
            continue
        parts = line.split("|", 3)
        if len(parts) < 4:
            continue
        guid, key, value = parts[1], parts[2], parts[3]
        if _SECRET_KEY.search(key) or _SECRET_KEY.search(value):
            value = "[скрыто]"
        label = names.get(guid) or names.get(guid.strip("{}")) or guid
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
    return {
        "ok": True,
        "conflicts": conflicts,
        "message": f"Сравнены шаблон безопасности и реестр политик. Расхождений: {len(conflicts)}. Секреты в значения не попадают.",
    }
