"""Read-only AD posture checks: trusts and SID filtering, DC time skew, basic hygiene.

Nothing here requests Kerberos tickets, decrypts passwords, or changes the directory.
Findings are names, ages, and configuration flags an administrator can remediate.
"""

from __future__ import annotations

import re
from typing import Any

from app.modules.software_scan import run_remote

_LINE = re.compile(r"^(TRUST|TIME|HYGIENE)\|")


def _rows(log: str, kind: str) -> list[list[str]]:
    parsed: list[list[str]] = []
    for line in (log or "").splitlines():
        line = line.strip()
        if not line.startswith(kind + "|"):
            continue
        parsed.append(line.split("|"))
    return parsed


def _call(connection: dict[str, Any], script: str) -> dict[str, Any]:
    return run_remote(
        connection["host"],
        connection["username"],
        connection["password"],
        connection["transport"],
        connection["winrm_port"],
        connection["ssh_port"],
        script,
        timeout=240,
    )


TRUST_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory -ErrorAction Stop
Get-ADTrust -Filter * -Properties TrustAttributes, SelectiveAuthentication, TrustDirection, TrustType, Name, Target |
  ForEach-Object {
    $attr = [int]$_.TrustAttributes
    $sidOn = (($attr -band 4) -eq 4)
    $forest = (($attr -band 8) -eq 8)
    $kind = if ($forest) { 'Forest' } elseif ($_.TrustType -eq 'External') { 'External' } else { [string]$_.TrustType }
    $dir = [string]$_.TrustDirection
    $sel = [bool]$_.SelectiveAuthentication
    $sid = if ($sidOn) { 'on' } else { 'off' }
    $selTxt = if ($sel) { 'yes' } else { 'no' }
    'TRUST|{0}|{1}|{2}|{3}|{4}|attributes={5}' -f $_.Name, $dir, $kind, $sid, $selTxt, $attr
  }
Write-Output 'POSTURE_DONE'
"""

TIME_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory -ErrorAction Stop
$dcs = @(Get-ADDomainController -Filter *)
foreach ($dc in $dcs) {
  $name = [string]$dc.HostName
  $raw = ''
  try { $raw = (& w32tm.exe /stripchart /computer:$name /samples:1 /dataonly /period:1 2>&1 | Out-String) } catch { $raw = $_.Exception.Message }
  $flat = ($raw -replace '\s+', ' ').Trim()
  $match = [regex]::Match($flat, '([+-]\d+(?:[.,]\d+)?)s')
  if ($match.Success) {
    $sec = $match.Groups[1].Value.Replace(',', '.')
    'TIME|{0}|{1}|ok|{2}' -f $name, $sec, $flat.Substring(0, [Math]::Min(180, $flat.Length))
  } else {
    'TIME|{0}||unreachable|{1}' -f $name, $flat.Substring(0, [Math]::Min(180, $flat.Length))
  }
}
Write-Output 'POSTURE_DONE'
"""

HYGIENE_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory -ErrorAction Stop
$now = Get-Date
$obsolete = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties OperatingSystem, OperatingSystemVersion |
  Where-Object {
    $os = [string]$_.OperatingSystem
    $os -match 'Windows 7|Windows 8|Windows XP|2003|2008|2012|Windows 10'
  } | Select-Object -First 40)
foreach ($c in $obsolete) {
  $sev = 'high'
  if ([string]$c.OperatingSystem -match '2003|2008|Windows 7|Windows XP') { $sev = 'critical' }
  'HYGIENE|obsolete_os|{0}|{1}|Устаревшая ОС без обновлений безопасности|{2}' -f $sev, $c.Name, ($c.OperatingSystem + ' ' + $c.OperatingSystemVersion)
}
$priv = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','DnsAdmins','DHCP Administrators'
$seen = @{}
foreach ($g in $priv) {
  try { $members = @(Get-ADGroupMember -Identity $g -ErrorAction Stop) } catch { continue }
  foreach ($m in $members) {
    if ($m.objectClass -ne 'user') { continue }
    $sam = [string]$m.SamAccountName
    if ($seen.ContainsKey($g + '|' + $sam)) { continue }
    $seen[$g + '|' + $sam] = $true
    $dedicated = ($sam -match '(?i)(\.adm$|^adm_|_adm$|\.svc$|^svc_|_svc$)')
    if (-not $dedicated) {
      'HYGIENE|ordinary_privileged|high|{0}|Обычная учетная запись в привилегированной группе|{1}' -f $sam, $g
    }
  }
}
$oldPw = @(Get-ADUser -Filter 'Enabled -eq $true -and PasswordNeverExpires -eq $false' -Properties PasswordLastSet, LastLogonDate |
  Where-Object { $_.PasswordLastSet -and $_.PasswordLastSet -lt $now.AddDays(-90) } |
  Sort-Object PasswordLastSet | Select-Object -First 25)
foreach ($u in $oldPw) {
  $days = [int]($now - $u.PasswordLastSet).TotalDays
  $last = if ($u.LastLogonDate) { $u.LastLogonDate.ToString('yyyy-MM-dd') } else { 'нет входа' }
  $stale = (-not $u.LastLogonDate) -or ($u.LastLogonDate -lt $now.AddDays(-90))
  if ($stale) {
    'HYGIENE|inactive_stale|high|{0}|Учетная запись не входила более 90 дней и пароль устарел|{1} дн. пароль, вход {2}' -f $u.SamAccountName, $days, $last
  } else {
    'HYGIENE|stale_password|high|{0}|Недавний вход при пароле старше 90 дней|{1} дн. пароль, вход {2}' -f $u.SamAccountName, $days, $last
  }
}
try {
  $guest = Get-ADUser -Identity 'Guest' -Properties Enabled -ErrorAction Stop
  if ($guest.Enabled) { 'HYGIENE|guest_enabled|medium|Guest|Включена встроенная учетная запись гостя|отключите Guest' }
} catch {}
Write-Output 'POSTURE_DONE'
"""


def _stdout(remote: dict[str, Any]) -> str:
    return remote.get("stdout") or ""


def scan_trusts(connection: dict[str, Any]) -> dict[str, Any]:
    remote = _call(connection, TRUST_SCRIPT)
    text = _stdout(remote)
    findings: list[dict[str, Any]] = []
    if "POSTURE_DONE" not in text and not remote.get("ok"):
        return {"ok": False, "findings": [], "score": None, "message": remote.get("error") or remote.get("stderr") or "Доверия не прочитаны"}
    for parts in _rows(text, "TRUST"):
        if len(parts) < 6:
            continue
        _, name, direction, kind, sid, selective = parts[:6]
        extra = parts[6] if len(parts) > 6 else ""
        missing = sid == "off" and kind in {"External", "Forest"}
        findings.append(
            {
                "hostname": name,
                "category": "Доверительные отношения",
                "title": (
                    f"Фильтрация SID выключена: {name}"
                    if missing
                    else f"Доверие {name}: фильтрация SID включена"
                ),
                "severity": "critical" if missing else "info",
                "detail": f"{kind}, направление {direction}, выборочная проверка {selective}. {extra}".strip(),
                "tags": "trust,sid-filter,module:trusts",
                "vuln_id": "trust_sid_filter" if missing else "trust_ok",
            }
        )
    bad = sum(1 for f in findings if f["severity"] == "critical")
    return {
        "ok": True,
        "findings": findings,
        "score": None,
        "message": f"Доверий {len(findings)}, без фильтрации SID: {bad}.",
    }


def scan_time(connection: dict[str, Any]) -> dict[str, Any]:
    remote = _call(connection, TIME_SCRIPT)
    text = _stdout(remote)
    findings: list[dict[str, Any]] = []
    if "POSTURE_DONE" not in text and not remote.get("ok"):
        return {"ok": False, "findings": [], "score": None, "message": remote.get("error") or remote.get("stderr") or "Время контроллеров не прочитано"}
    for parts in _rows(text, "TIME"):
        if len(parts) < 4:
            continue
        _, host, offset, status = parts[:4]
        detail = parts[4] if len(parts) > 4 else ""
        if status != "ok" or offset == "":
            findings.append(
                {
                    "hostname": host,
                    "category": "Время контроллеров",
                    "title": f"Контроллер не отвечает на запрос времени: {host}",
                    "severity": "high",
                    "detail": detail or "w32tm не вернул смещение",
                    "tags": "time,kerberos,module:time_sync",
                    "vuln_id": "time_skew",
                }
            )
            continue
        try:
            seconds = abs(float(offset))
        except ValueError:
            seconds = 0.0
        if seconds >= 300:
            sev, title = "critical", f"Расхождение времени {seconds:.0f} с — Kerberos уже ненадежен"
        elif seconds >= 30:
            sev, title = "high", f"Расхождение времени {seconds:.1f} с"
        else:
            sev, title = "info", f"Время в допуске: {seconds:.3f} с"
        findings.append(
            {
                "hostname": host,
                "category": "Время контроллеров",
                "title": title,
                "severity": sev,
                "detail": f"Смещение относительно опрашивающего узла: {offset} с. Порог Kerberos 300 с.",
                "tags": "time,kerberos,module:time_sync",
                "vuln_id": "time_skew" if sev != "info" else "time_ok",
            }
        )
    bad = sum(1 for f in findings if f["severity"] in {"critical", "high"})
    return {
        "ok": True,
        "findings": findings,
        "score": None,
        "message": f"Контроллеров {len(findings)}, с опасным расхождением: {bad}.",
    }


def scan_hygiene(connection: dict[str, Any]) -> dict[str, Any]:
    remote = _call(connection, HYGIENE_SCRIPT)
    text = _stdout(remote)
    findings: list[dict[str, Any]] = []
    if "POSTURE_DONE" not in text and not remote.get("ok"):
        return {"ok": False, "findings": [], "score": None, "message": remote.get("error") or remote.get("stderr") or "Базовые проверки не выполнены"}
    titles = {
        "obsolete_os": "Устаревшая операционная система",
        "ordinary_privileged": "Обычная учетная запись в привилегированной группе",
        "stale_password": "Пароль старше 90 дней при недавнем входе",
        "inactive_stale": "Нет входа более 90 дней и пароль устарел",
        "guest_enabled": "Включена учетная запись гостя",
    }
    categories = {
        "obsolete_os": "Устаревшие ОС",
        "ordinary_privileged": "Привилегии",
        "stale_password": "Пароли",
        "inactive_stale": "Неактивные учетные записи",
        "guest_enabled": "Гостевой доступ",
    }
    for parts in _rows(text, "HYGIENE"):
        if len(parts) < 6:
            continue
        _, vuln, sev, host, _title, detail = parts[:6]
        findings.append(
            {
                "hostname": host,
                "category": categories.get(vuln, "Базовая гигиена"),
                "title": titles.get(vuln, _title),
                "severity": sev if sev in {"critical", "high", "medium", "low"} else "medium",
                "detail": detail,
                "tags": "baseline,hygiene,module:baseline_hygiene",
                "vuln_id": vuln,
            }
        )
    crit = sum(1 for f in findings if f["severity"] == "critical")
    return {
        "ok": True,
        "findings": findings,
        "score": None,
        "message": f"Базовых отклонений {len(findings)}, критических {crit}.",
    }
