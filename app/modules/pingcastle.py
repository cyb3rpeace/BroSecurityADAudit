"""Запуск PingCastle на контроллере домена и разбор XML-отчета."""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from typing import Any

from app.modules.software_scan import run_remote, validate_host

_RISK_MAP = {
    "S-OldNtlm": "obsolete_os",
    "S-SMB-v1": "active_smbv1",
    "A-SMB1": "active_smbv1",
    "S-OS-SMB1": "active_smbv1",
    "A-Krbtgt": "krbtgt_old",
    "S-PwdGPO": "gpp_password",
    "A-PwdGPO": "gpp_password",
    "P-Deleg-Unconstrained": "unconstrained_delegation",
    "A-PreWin2000": "pre_windows_2000",
}


def parse_pingcastle_xml(xml_text: str) -> dict[str, Any]:
    start = xml_text.find("<HealthcheckData")
    end = xml_text.rfind("</HealthcheckData>")
    if start < 0 or end < 0:
        raise ValueError("В данных нет отчета HealthcheckData.")
    root = ET.fromstring(xml_text[start : end + len("</HealthcheckData>")])
    score_text = root.findtext("GlobalScore") or "0"
    try:
        score = max(0, min(100, int(float(score_text))))
    except ValueError:
        score = 0
    domain = (root.findtext("DomainFQDN") or "").strip()
    findings: list[dict[str, Any]] = []
    for rule in root.findall(".//HealthcheckRiskRule"):
        points_text = rule.findtext("Points") or "0"
        try:
            points = int(float(points_text))
        except ValueError:
            points = 0
        if points <= 0:
            continue
        risk_id = (rule.findtext("RiskId") or "unknown").strip()
        rationale = " ".join((rule.findtext("Rationale") or "").split())
        category = (rule.findtext("Category") or "PingCastle").strip()
        model = (rule.findtext("Model") or "").strip()
        if points >= 30:
            severity = "critical"
        elif points >= 15:
            severity = "high"
        elif points >= 5:
            severity = "medium"
        else:
            severity = "low"
        vuln_id = _RISK_MAP.get(risk_id, f"pc:{risk_id}")
        title = f"PingCastle {risk_id}"
        if model:
            title = f"{title} ({model})"
        findings.append(
            {
                "hostname": domain or "домен",
                "category": category or "PingCastle",
                "title": title,
                "severity": severity,
                "detail": rationale or f"Правило {risk_id}, баллы: {points}.",
                "tags": "compliance,pingcastle,module:pingcastle",
                "vuln_id": vuln_id,
            }
        )
    return {"domain": domain, "score": score, "findings": findings}


def _script(server: str) -> str:
    candidates = os.getenv(
        "PINGCASTLE_REMOTE_CANDIDATES",
        r"C:\Program Files\PingCastle\PingCastle.exe;C:\Tools\PingCastle\PingCastle.exe",
    )
    quoted = ",".join("'" + item.replace("'", "''") + "'" for item in candidates.split(";") if item.strip())
    safe_server = validate_host(server).replace("'", "")
    return f"""
$ErrorActionPreference = 'Continue'
$candidates = @({quoted})
$exe = $candidates | Where-Object {{ Test-Path -LiteralPath $_ }} | Select-Object -First 1
if (-not $exe) {{ Write-Output 'PINGCASTLE_NOT_FOUND'; exit 2 }}
$work = 'C:\\Windows\\Temp\\ad-identity-guard-pc'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$started = Get-Date
Push-Location $work
try {{
  $output = & $exe --healthcheck --server '{safe_server}' 2>&1 | Out-String
  if ($output) {{ Write-Output $output }}
}} finally {{
  Pop-Location
}}
$xml = Get-ChildItem -Path $work, (Split-Path -Parent $exe) -Filter *.xml -ErrorAction SilentlyContinue |
  Where-Object {{ $_.LastWriteTime -ge $started.AddMinutes(-2) }} |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
if (-not $xml) {{ Write-Output 'PINGCASTLE_NO_XML'; exit 3 }}
Get-Content -LiteralPath $xml.FullName -Raw -Encoding UTF8
"""


def run_pingcastle(connection: dict[str, Any]) -> dict[str, Any]:
    remote = run_remote(
        connection["host"],
        connection["username"],
        connection["password"],
        connection["transport"],
        connection["winrm_port"],
        connection["ssh_port"],
        _script(connection.get("directory_host") or connection["host"]),
        timeout=900,
    )
    if "PINGCASTLE_NOT_FOUND" in remote["stdout"]:
        return {
            "ok": False,
            "findings": [],
            "score": None,
            "message": "PingCastle.exe не найден на узле. Установите программу и укажите путь в PINGCASTLE_REMOTE_CANDIDATES.",
        }
    if "<HealthcheckData" not in remote["stdout"]:
        detail = "\n".join(part for part in (remote["stdout"], remote["stderr"], remote["error"]) if part).strip()
        return {"ok": False, "findings": [], "score": None, "message": (detail or "Пустой ответ PingCastle")[:2000]}
    try:
        parsed = parse_pingcastle_xml(remote["stdout"])
    except (ET.ParseError, ValueError) as exc:
        return {"ok": False, "findings": [], "score": None, "message": f"XML PingCastle не разобран: {exc}"}
    return {
        "ok": True,
        "findings": parsed["findings"],
        "score": parsed["score"],
        "message": f"PingCastle завершен. Домен {parsed['domain'] or connection['host']}, индекс {parsed['score']}, правил {len(parsed['findings'])}.",
    }


if __name__ == "__main__":
    sample = """
    <HealthcheckData>
      <DomainFQDN>lab.local</DomainFQDN>
      <GlobalScore>42</GlobalScore>
      <RiskRules>
        <HealthcheckRiskRule>
          <Points>20</Points>
          <Category>Anomalies</Category>
          <Model>Account</Model>
          <RiskId>A-Krbtgt</RiskId>
          <Rationale>Пароль krbtgt старый</Rationale>
        </HealthcheckRiskRule>
      </RiskRules>
    </HealthcheckData>
    """
    result = parse_pingcastle_xml(sample)
    assert result["score"] == 42
    assert result["findings"][0]["vuln_id"] == "krbtgt_old"
    print("pingcastle parser ok")
