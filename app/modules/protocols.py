"""Устаревшие и опасные протоколы. Чтение конфигурации, без изменения домена и без эксплуатации."""

from __future__ import annotations

from typing import Any

from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException

from app.modules.ldap_audit import connect
from app.modules.software_scan import run_remote

_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
function Emit([string]$id, [string]$sev, [string]$title, [string]$detail) {
  $safeTitle = ($title -replace '\|','/')
  $safeDetail = ($detail -replace '\|','/' -replace '[\r\n]+',' ')
  Write-Output ("PROTO|{0}|{1}|{2}|{3}" -f $id, $sev, $safeTitle, $safeDetail)
}
try {
  $smb = Get-SmbServerConfiguration -ErrorAction Stop
  if ($smb.EnableSMB1Protocol) { Emit 'active_smbv1' 'critical' 'Включен SMBv1' 'Серверный компонент SMBv1 еще принимает подключения.' }
  if (-not $smb.RequireSecuritySignature) { Emit 'smb_signing_off' 'high' 'Подпись SMB не обязательна' 'RequireSecuritySignature выключен.' }
  if (-not $smb.EncryptData) { Emit 'smb_encryption_off' 'medium' 'Шифрование SMB выключено' 'EncryptData не включен. Включайте его там, где клиенты уже умеют шифровать SMB.' }
} catch {
  Emit 'smb_unreadable' 'medium' 'Конфигурация SMB не прочитана' $_.Exception.Message
}
try {
  $client = Get-SmbClientConfiguration -ErrorAction Stop
  if (-not $client.RequireSecuritySignature) { Emit 'smb_client_signing_off' 'medium' 'Клиент SMB не требует подписи' 'RequireSecuritySignature клиента выключен.' }
} catch {
  Emit 'smb_client_unreadable' 'low' 'Клиент SMB не прочитан' $_.Exception.Message
}
$llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
if ($null -eq $llmnr -or [int]$llmnr -ne 0) { Emit 'llmnr_enabled' 'high' 'LLMNR не отключен' 'Политика DNS Client не запрещает мультикаст имен.' }
$adapters = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
foreach ($adapter in $adapters) {
  $opt = (Get-ItemProperty $adapter.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions
  if ($null -eq $opt -or [int]$opt -ne 2) { Emit 'netbios_enabled' 'medium' 'NetBIOS поверх TCP/IP включен' 'Хотя бы на одном адаптере NetbiosOptions не равен 2.'; break }
}
$wd = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
if ($wd -and [int]$wd -eq 1) { Emit 'wdigest_clear' 'critical' 'WDigest хранит пароль в памяти' 'UseLogonCredential равен 1.' }
$lm = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
if ($null -eq $lm -or [int]$lm -lt 5) { Emit 'ntlmv1_allowed' 'high' 'Разрешен устаревший NTLM' 'LmCompatibilityLevel ниже 5, NTLMv2 не обязателен.' }
$ldap = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -ErrorAction SilentlyContinue).LDAPServerIntegrity
if ($null -eq $ldap -or [int]$ldap -lt 2) { Emit 'ldap_signing_not_required' 'high' 'Подпись LDAP не обязательна' 'LDAPServerIntegrity должен быть равен 2.' }
$bind = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LdapEnforceChannelBinding -ErrorAction SilentlyContinue).LdapEnforceChannelBinding
if ($null -eq $bind -or [int]$bind -lt 2) { Emit 'ldap_channel_binding' 'medium' 'Привязка канала LDAP не обязательна' 'LdapEnforceChannelBinding ниже 2.' }
$anon = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -ErrorAction SilentlyContinue).RestrictAnonymous
if ($null -eq $anon -or [int]$anon -lt 1) { Emit 'null_session' 'high' 'Анонимный сеанс не ограничен' 'RestrictAnonymous не запрещает анонимный перебор.' }
$v2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
if ($v2 -and $v2.State -eq 'Enabled') { Emit 'powershell_v2' 'medium' 'Включен PowerShell 2.0' 'Старый движок не пишет современные журналы сценариев.' }
$tls = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name Enabled -ErrorAction SilentlyContinue).Enabled
if ($tls -and [int]$tls -eq 1) { Emit 'tls10_enabled' 'medium' 'На сервере включен TLS 1.0' 'Протокол устарел и должен быть выключен в Schannel.' }
$wpad = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Name EnableAutoproxyResultCache -ErrorAction SilentlyContinue).EnableAutoproxyResultCache
$wpadOff = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name DisableWpad -ErrorAction SilentlyContinue).DisableWpad
if (-not ($wpadOff -and [int]$wpadOff -eq 1)) { Emit 'wpad_enabled' 'medium' 'Автопоиск прокси WPAD не отключен' 'DisableWpad не равен 1.' }
$web = Get-Service -Name WebClient -ErrorAction SilentlyContinue
if ($web -and $web.Status -eq 'Running') { Emit 'webclient_running' 'medium' 'На контроллере запущена служба WebClient' 'Служба открывает контроллеру доступ к WebDAV. На контроллере её обычно не держат.' }
$fast = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name KdcEnableFast -ErrorAction SilentlyContinue).KdcEnableFast
if ($null -eq $fast -or [int]$fast -lt 1) { Emit 'kerberos_armoring' 'low' 'Броня Kerberos не включена' 'Параметр KdcEnableFast не задан. Билеты консоль не запрашивает.' }
$sam = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -ErrorAction SilentlyContinue).RestrictAnonymousSAM
if ($null -ne $sam -and [int]$sam -eq 0) { Emit 'anonymous_sam' 'medium' 'Анонимное чтение локальных имён разрешено' 'RestrictAnonymousSAM равен 0. Список имён по этому каналу консоль не запрашивает.' }
try {
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  $days = [math]::Floor(((Get-Date) - $os.LastBootUpTime).TotalDays)
  if ($days -gt 120) { Emit 'dc_uptime' 'low' 'Контроллер давно не перезагружался' ('С последней загрузки прошло ' + $days + ' дн. Журнал событий не копируется.') }
} catch {}
try {
  $ver = [Environment]::OSVersion.Version
  if ($ver.Major -lt 10) {
    $hf = Get-HotFix -Id KB3011780 -ErrorAction SilentlyContinue
    if (-not $hf) { Emit 'ms14_068' 'high' 'На старой версии Windows нет обновления Kerberos' 'В списке установленных обновлений нет KB3011780. Пакет не запускается, читается только факт установки.' }
  }
} catch {}
$strong = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name StrongCertificateBindingEnforcement -ErrorAction SilentlyContinue).StrongCertificateBindingEnforcement
if ($null -eq $strong -or [int]$strong -lt 2) { Emit 'adcs_weak_mapping' 'medium' 'Сопоставление сертификата с учётной записью не жёсткое' 'StrongCertificateBindingEnforcement ниже 2. Сертификаты не читаются.' }
$caRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
if (Test-Path -LiteralPath $caRoot) {
  $active = (Get-ItemProperty $caRoot -Name Active -ErrorAction SilentlyContinue).Active
  foreach ($caName in @($active)) {
    if (-not $caName) { continue }
    $caBase = Join-Path $caRoot $caName
    $policy = Join-Path $caBase 'PolicyModules\CertificateAuthority_MicrosoftDefault.Policy'
    $edit = (Get-ItemProperty $policy -Name EditFlags -ErrorAction SilentlyContinue).EditFlags
    if ($edit -and ([int]$edit -band 0x40000)) { Emit 'adcs_san_attrib' 'high' 'Центр сертификации принимает имя в атрибутах запроса' 'Включён признак имени субъекта в атрибутах запроса. Сам запрос не отправляется.' }
    $iface = (Get-ItemProperty $caBase -Name InterfaceFlags -ErrorAction SilentlyContinue).InterfaceFlags
    if ($null -ne $iface -and -not ([int]$iface -band 0x800)) { Emit 'adcs_rpc_encrypt' 'medium' 'Запрос сертификата по RPC не требует шифрования' 'На центре не включено требование шифрования запроса. Запрос не отправляется.' }
    $disabled = (Get-ItemProperty $policy -Name DisableExtensionList -ErrorAction SilentlyContinue).DisableExtensionList
    $joined = (@($disabled) -join ' ')
    if ($joined -match '1\.3\.6\.1\.4\.1\.311\.25\.2') { Emit 'adcs_ext_disabled' 'high' 'Центр сертификации отключил расширение безопасности' 'Расширение привязки сертификата к каталогу отключено в политике центра. Список целиком не копируется.' }
  }
}
Write-Output 'PROTO_DONE'
"""


def _rows(stdout: str, host: str) -> list[dict[str, Any]]:
    findings = []
    for line in stdout.splitlines():
        if not line.startswith("PROTO|"):
            continue
        parts = line.split("|", 4)
        if len(parts) < 5:
            continue
        findings.append(
            {
                "hostname": host,
                "category": "Опасные протоколы",
                "title": parts[3],
                "severity": parts[2] if parts[2] in {"critical", "high", "medium", "low"} else "medium",
                "detail": parts[4],
                "tags": "protocol,compliance,module:protocols",
                "vuln_id": parts[1][:64],
            }
        )
    return findings


def scan_protocols_windows(connection: dict[str, Any]) -> dict[str, Any]:
    remote = run_remote(
        connection["host"],
        connection["username"],
        connection["password"],
        connection["transport"],
        connection["winrm_port"],
        connection["ssh_port"],
        _SCRIPT,
        timeout=180,
    )
    stdout = remote["stdout"]
    if "PROTO_DONE" not in stdout and not remote["ok"]:
        return {"ok": False, "findings": [], "score": None, "message": (stdout or remote["stderr"] or remote["error"] or "Реестр протоколов на контроллере не прочитан")[:800]}
    findings = _rows(stdout, connection["host"])
    return {"ok": True, "findings": findings, "score": None, "message": f"Протоколы по реестру контроллера: отклонений {len(findings)}."}


def scan_protocols_ldap(connection: dict[str, Any]) -> dict[str, Any]:
    try:
        conn, base = connect(connection)
    except (LDAPException, OSError, RuntimeError) as exc:
        return {"ok": False, "findings": [], "score": None, "message": f"LDAP для типов шифрования не открылся: {exc}"}
    findings: list[dict[str, Any]] = []
    try:
        conn.search(
            base,
            "(&(objectCategory=person)(objectClass=user)(msDS-SupportedEncryptionTypes>=1))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "msDS-SupportedEncryptionTypes"],
            size_limit=400,
        )
        for entry in conn.entries:
            raw = entry["msDS-SupportedEncryptionTypes"].value
            try:
                flags = int(raw or 0)
            except (TypeError, ValueError):
                continue
            sam = str(entry["sAMAccountName"].value or "")
            if not sam or sam.lower() == "krbtgt":
                continue
            if flags & 0x3:
                findings.append(
                    {
                        "hostname": sam,
                        "category": "Опасные протоколы",
                        "title": f"Для {sam} разрешен DES",
                        "severity": "high",
                        "detail": "В msDS-SupportedEncryptionTypes включен устаревший DES.",
                        "tags": "protocol,kerberos,module:protocols",
                        "vuln_id": "des_enabled",
                    }
                )
            elif flags & 0x4 and not flags & 0x18:
                findings.append(
                    {
                        "hostname": sam,
                        "category": "Опасные протоколы",
                        "title": f"Для {sam} Kerberos только RC4",
                        "severity": "medium",
                        "detail": "AES128 и AES256 не включены, остается RC4.",
                        "tags": "protocol,kerberos,module:protocols",
                        "vuln_id": "rc4_only",
                    }
                )
            if len(findings) >= 40:
                break
    finally:
        conn.unbind()
    return {"ok": True, "findings": findings, "score": None, "message": f"По LDAP проверены типы шифрования Kerberos. Отклонений: {len(findings)}."}
