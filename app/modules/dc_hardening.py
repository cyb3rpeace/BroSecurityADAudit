"""Проверки харденинга контроллера: только чтение конфигурации, без изменений в домене."""

from __future__ import annotations

from typing import Any

from app.modules.software_scan import run_remote

_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
function Emit([string]$id, [string]$sev, [string]$title, [string]$detail) {
  $safeTitle = ($title -replace '\|','/')
  $safeDetail = ($detail -replace '\|','/' -replace '[\r\n]+',' ')
  Write-Output ("HARDEN|{0}|{1}|{2}|{3}" -f $id, $sev, $safeTitle, $safeDetail)
}
try {
  Import-Module ActiveDirectory -ErrorAction Stop
} catch {
  Emit 'ad_module_missing' 'high' 'На контроллере нет модуля ActiveDirectory' 'Установите RSAT: Active Directory и повторите проверку.'
  Write-Output 'HARDEN_DONE'
  exit 0
}
$spooler = Get-Service Spooler -ErrorAction SilentlyContinue
if ($spooler -and $spooler.Status -eq 'Running') {
  Emit 'print_spooler_on_dc' 'high' 'На контроллере запущена служба печати' 'Spooler на контроллере домена нужно остановить и отключить.'
}
$ldap = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -ErrorAction SilentlyContinue).LDAPServerIntegrity
if ($null -eq $ldap -or [int]$ldap -lt 2) {
  Emit 'ldap_signing_not_required' 'high' 'Подпись LDAP не обязательна' 'Параметр LDAPServerIntegrity должен быть равен 2.'
}
$krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
if ($krbtgt.PasswordLastSet) {
  $age = [int](New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).TotalDays
  if ($age -gt 180) {
    Emit 'krbtgt_old' 'high' "Пароль krbtgt не менялся $age дн." 'Нужна штатная двойная смена с паузой не меньше 10 часов. Пароль в отчет не попадает.'
  }
}
$recycle = Get-ADOptionalFeature -Filter "name -eq 'Recycle Bin Feature'"
if (-not $recycle.EnabledScopes) {
  Emit 'recycle_bin_disabled' 'medium' 'Корзина Active Directory выключена' 'Без корзины удаленный объект восстанавливается только авторитетным восстановлением.'
}
$protected = @(
  Get-ADGroupMember 'Protected Users' -ErrorAction SilentlyContinue |
    Where-Object { $_.objectClass -eq 'user' } |
    ForEach-Object { $_.SamAccountName }
)
$seen = @{}
foreach ($group in @('Domain Admins','Enterprise Admins','Schema Admins')) {
  $members = Get-ADGroupMember $group -Recursive -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq 'user' }
  foreach ($member in $members) {
    if ($seen.ContainsKey($member.SamAccountName)) { continue }
    $seen[$member.SamAccountName] = $true
    $user = Get-ADUser $member.SamAccountName -Properties PasswordNeverExpires, Enabled
    if (-not $user.Enabled) { continue }
    if ($user.PasswordNeverExpires) {
      Emit 'priv_password_never_expires' 'high' "У $($user.SamAccountName) пароль не истекает" "Учетная запись входит в $group."
    }
    if ($protected -notcontains $user.SamAccountName) {
      Emit 'not_in_protected_users' 'medium' "$($user.SamAccountName) не входит в Protected Users" "Группа $group. Добавляйте только интерактивных администраторов, не сервисные учетные записи."
    }
  }
}
$schema = (Get-ADRootDSE).schemaNamingContext
$laps = @(Get-ADObject -SearchBase $schema -LDAPFilter '(|(cn=ms-Mcs-AdmPwd)(cn=ms-LAPS-Password))' -ErrorAction SilentlyContinue)
if ($laps.Count -eq 0) {
  Emit 'laps_missing' 'high' 'В схеме домена нет LAPS' 'Разверните Windows LAPS и уберите общий пароль локального администратора.'
}
Write-Output 'HARDEN_DONE'
"""


def scan_hardening(connection: dict[str, Any]) -> dict[str, Any]:
    remote = run_remote(
        connection["host"],
        connection["username"],
        connection["password"],
        connection["transport"],
        connection["winrm_port"],
        connection["ssh_port"],
        _SCRIPT,
        timeout=240,
    )
    stdout = remote["stdout"]
    if "HARDEN_DONE" not in stdout and not remote["ok"]:
        return {
            "ok": False,
            "findings": [],
            "score": None,
            "message": (stdout or remote["stderr"] or remote["error"] or "Проверка харденинга не выполнена")[:800],
        }
    findings = []
    for line in stdout.splitlines():
        if not line.startswith("HARDEN|"):
            continue
        parts = line.split("|", 4)
        if len(parts) < 5:
            continue
        findings.append(
            {
                "hostname": connection["host"],
                "category": "Харденинг",
                "title": parts[3],
                "severity": parts[2] if parts[2] in {"critical", "high", "medium", "low"} else "medium",
                "detail": parts[4],
                "tags": "compliance,hardening,module:dc_hardening",
                "vuln_id": parts[1][:64],
            }
        )
    if findings:
        message = f"Проверок харденинга с отклонениями: {len(findings)}."
    else:
        message = "Базовые проверки харденинга контроллера отклонений не показали."
    return {"ok": True, "findings": findings, "score": None, "message": message}
