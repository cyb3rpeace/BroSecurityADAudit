"""Structured forensic exports for one tenant-scoped hunting result."""
from __future__ import annotations

import json
import os
import re
import threading
from html import escape
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


_FONT_LOCK = threading.Lock()


def _pdf_font() -> str:
    """Use a Unicode font on both the deployment image and Windows development host."""
    name = 'HuntingUnicode'
    with _FONT_LOCK:
        if name not in pdfmetrics.getRegisteredFontNames():
            candidates = [
                Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'),
                Path(os.environ.get('WINDIR', 'C:/Windows')) / 'Fonts' / 'arial.ttf',
            ]
            font = next((path for path in candidates if path.is_file()), None)
            if font is None:
                raise ValueError('Unicode font is required for forensic PDF export')
            pdfmetrics.registerFont(TTFont(name, str(font)))
    return name


def _pdf_text(value: Any) -> str:
    # Evidence is plain text, never ReportLab markup or external resource links.
    return escape(str(value)).replace('\n', '<br/>')


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)[:120] or "result"


def _review_map(reviews: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("finding_key", "")): item for item in reviews}


def _finding_key(finding: dict[str, Any]) -> str:
    return "|".join(str(finding.get(key, "")) for key in ("rule_id", "source", "row_number"))


def _rows(analysis: dict[str, Any], reviews: list[dict[str, Any]]) -> list[list[Any]]:
    review_map = _review_map(reviews)
    result = []
    for finding in analysis.get("findings", []):
        review = review_map.get(_finding_key(finding), {})
        result.append([
            finding.get("rule_id", ""), finding.get("title", ""), finding.get("triage_level", ""),
            finding.get("classification", ""), finding.get("risk_score", ""), finding.get("confidence", ""),
            finding.get("source", ""), finding.get("row_number", ""), finding.get("reason", ""),
            review.get("status", finding.get("status", "needs_review")), review.get("note", ""),
            review.get("updated_at", ""),
        ])
    return result


def _timeline(analysis: dict[str, Any]) -> list[list[Any]]:
    return [[item.get("timestamp", ""), item.get("source", ""), item.get("row_number", "")] for item in analysis.get("triage_summary", {}).get("timeline", [])]


def _correlations(analysis: dict[str, Any]) -> list[list[Any]]:
    return [["process_network", analysis.get("triage_summary", {}).get("correlations", {}).get("process_network", 0)],
            ["process_persistence", analysis.get("triage_summary", {}).get("correlations", {}).get("process_persistence", 0)]]


def build_xlsx(path: Path, result: dict[str, Any], analysis: dict[str, Any], reviews: list[dict[str, Any]]) -> None:
    workbook = Workbook()
    overview = workbook.active
    overview.title = "Overview"
    overview_rows = [
        ["Field", "Value"], ["Result ID", result.get("id", "")], ["SHA-256", result.get("sha256", "")],
        ["Created at", result.get("created_at", "")], ["Ruleset", analysis.get("ruleset", "")],
        ["Verdict", analysis.get("verdict", "not_determined")], ["Matched rules", analysis.get("matched_rules", 0)],
        ["Rows reviewed", json.dumps(analysis.get("rows_reviewed", {}), ensure_ascii=False)],
        ["Generated at", datetime.now(timezone.utc).isoformat()],
    ]
    for row in overview_rows:
        overview.append(row)

    findings = workbook.create_sheet("Findings")
    headers = ["rule_id", "title", "triage_level", "classification", "risk_score", "confidence", "source", "row_number", "reason", "review_status", "review_note", "reviewed_at"]
    findings.append(headers)
    for row in _rows(analysis, reviews):
        findings.append(row)

    timeline = workbook.create_sheet("Timeline")
    timeline.append(["timestamp_utc", "source", "row_number"])
    for row in _timeline(analysis):
        timeline.append(row)

    correlations = workbook.create_sheet("Correlations")
    correlations.append(["type", "count"])
    for row in _correlations(analysis):
        correlations.append(row)

    for sheet in workbook.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str):
                    # Force literal OOXML strings, including values beginning with '='.
                    cell.data_type = 's'
        sheet.freeze_panes = "A2"
        sheet.auto_filter.ref = sheet.dimensions
        for cell in sheet[1]:
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill("solid", fgColor="1F4E78")
        for column in sheet.columns:
            width = min(max(max(len(str(cell.value or "")) for cell in column) + 2, 10), 60)
            sheet.column_dimensions[column[0].column_letter].width = width
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(path)


def build_pdf(path: Path, result: dict[str, Any], analysis: dict[str, Any], reviews: list[dict[str, Any]]) -> None:
    styles = getSampleStyleSheet()
    font = _pdf_font()
    title = ParagraphStyle("ThreatHuntingTitle", parent=styles["Title"], fontName=font, fontSize=16, leading=20)
    body = ParagraphStyle("ThreatHuntingBody", parent=styles["BodyText"], fontName=font, fontSize=8, leading=10)
    small = ParagraphStyle("ThreatHuntingSmall", parent=body, fontSize=6.5, leading=8)
    path.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(str(path), pagesize=landscape(A4), rightMargin=10 * mm, leftMargin=10 * mm, topMargin=10 * mm, bottomMargin=10 * mm)
    story: list[Any] = [Paragraph("Threat Hunting forensic report", title), Spacer(1, 4 * mm)]
    story.append(Paragraph(_pdf_text(f"Result: {result.get('id', '')} · SHA-256: {result.get('sha256', '')}"), body))
    story.append(Paragraph(_pdf_text(f"Ruleset: {analysis.get('ruleset', '')} · Verdict: {analysis.get('verdict', 'not_determined')} · Findings: {len(analysis.get('findings', []))}"), body))
    story.append(Spacer(1, 4 * mm))
    table_data = [[Paragraph("Rule", small), Paragraph("Citation", small), Paragraph("Risk", small), Paragraph("Status", small), Paragraph("Reason / analyst note", small)]]
    for row in _rows(analysis, reviews):
        table_data.append([Paragraph(_pdf_text(row[0]), small), Paragraph(_pdf_text(f"{row[6]} · row {row[7]}"), small), Paragraph(_pdf_text(row[4]), small), Paragraph(_pdf_text(row[9]), small), Paragraph(f"{_pdf_text(row[8])}<br/>{_pdf_text(row[10])}", small)])
    table = Table(table_data, colWidths=[35 * mm, 52 * mm, 15 * mm, 32 * mm, 130 * mm], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E78")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")])]))
    story.append(table)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Limitations: heuristic triage is not a confirmed incident verdict; citations refer to the immutable imported evidence and require analyst validation.", small))
    document.build(story)


AI_ANSWER_LIMIT = 100_000


def validate_ai_answer(answer: str) -> None:
    """Reject invalid input, never silently strip or truncate the supplied answer."""
    if not isinstance(answer, str) or not answer.strip() or len(answer) > AI_ANSWER_LIMIT:
        raise ValueError("Answer must contain 1 to 100000 characters and not be blank")
    try:
        answer.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Answer must be valid Unicode") from exc
    if any(ord(c) < 32 and c not in "\n\r\t" for c in answer):
        raise ValueError("Answer contains unsupported control characters")


def _ai_sections(company_id: int, result: dict, analysis: dict, answer: str):
    validate_ai_answer(answer)
    from app.modules.hunting_ai import audit_answer_citations
    citation_validation = audit_answer_citations(answer, analysis)
    summary = result.get("summary", {})
    literal = lambda value: json.dumps(value, ensure_ascii=False, indent=2, default=str)
    return [
        ("Status", "AI-generated / UNREVIEWED. Not a confirmed forensic verdict.\n"
         "The answer is supplied by the client; its model provenance and factual accuracy are not verified.\n"
         "No LLM or external research is invoked during export."),
        ("Identity", f"Company ID: {company_id}\nResult ID: {result.get('id', '')}\n"
         f"Archive SHA-256: {result.get('sha256', '')}\nImported at: {result.get('created_at', '')}\n"
         f"Exported at UTC: {datetime.now(timezone.utc).isoformat()}\nRuleset: {analysis.get('ruleset', 'unknown')}"),
        ("Evidence scope", "Single imported host result only; not a group or fleet assessment.\n" + literal({
            "hostnames": summary.get("hostnames", []), "sources": summary.get("sources", []),
            "rows_reviewed": analysis.get("rows_reviewed", {}), "total_rows": summary.get("total_rows") })),
        ("Limitations", "Heuristic, bounded collected evidence requires independent analyst validation.\n"
         "Absence of findings is not proof of absence of compromise. The answer may be stale or incorrect.\n"
         "Timeline timestamps are reproduced as recorded, not inferred or normalized.\n" + literal({
             "import": summary.get("limitations", []), "analysis": analysis.get("limitations", []),
             "findings_truncated": analysis.get("truncated", False),
             "timeline_truncated": analysis.get("triage_summary", {}).get("timeline_truncated", False),
             "source_coverage": analysis.get("source_coverage", []),
             "unsupported_sources": analysis.get("unsupported_sources", [])})),
        ("Timeline from actual analysis", literal(analysis.get("triage_summary", {}).get("timeline", []))),
        ("Source citations from actual analysis (not verification of AI claims)", literal([
            {key: finding.get(key) for key in ("rule_id", "source", "row_number", "title")}
            for finding in analysis.get("findings", [])])),
        ("AI citation audit (reference membership only; claims NOT verified)", literal(citation_validation)),
        ("Full AI answer (literal untrusted text)", answer),
    ]


_REPORT_TEXT = {
    "ru": {"title":"Подробный криминалистический отчёт по хосту", "status":"Статус и оценка", "identity":"Идентификация и целостность", "scope":"Объём и полнота доказательств", "verdict":"Вывод о компрометации", "timeline":"Хронология наблюдений (UTC)", "graph":"Граф связей", "iocs":"Индикаторы компрометации (IOC)", "ttps":"Сопоставление с MITRE ATT&CK", "access":"Гипотезы первоначального доступа", "findings":"Находки и наблюдаемые инструменты", "reviews":"Решения аналитика", "limitations":"Ограничения расследования", "ai":"Предоставленный AI-ответ (непроверенный)", "undetermined":"Не определено: данных недостаточно для подтверждения или исключения компрометации.", "review":"Есть сигналы, требующие проверки; компрометация не подтверждена.", "none":"Срабатываний не найдено. Это не доказывает отсутствие компрометации.", "initial":"Первоначальный доступ не установлен: доступные источники не дают достаточной телеметрии для определения вектора проникновения.", "ai_note":"AI-текст предоставлен клиентом; происхождение модели и достоверность утверждений не проверялись.", "unsupported":"Для правил анализа нет надёжного сопоставления ATT&CK."},
    "en": {"title":"Detailed Host Forensic Report", "status":"Status and assessment", "identity":"Identity and integrity", "scope":"Evidence scope and completeness", "verdict":"Compromise conclusion", "timeline":"Observation timeline (UTC)", "graph":"Relationship graph", "iocs":"Indicators of compromise (IOCs)", "ttps":"MITRE ATT&CK mapping", "access":"Initial access hypotheses", "findings":"Findings and observed tools", "reviews":"Analyst decisions", "limitations":"Investigation limitations", "ai":"Supplied AI answer (unverified)", "undetermined":"Undetermined: evidence is insufficient to confirm or rule out compromise.", "review":"Signals require review; compromise is not confirmed.", "none":"No detections. This does not prove absence of compromise.", "initial":"Initial access is undetermined: available sources do not provide sufficient telemetry to identify an entry vector.", "ai_note":"AI text was supplied by the client; model provenance and claim accuracy were not verified.", "unsupported":"No reliable ATT&CK mapping is available for these analysis rules."},
}
_ATTACK_RULES = {"process.encoded_powershell":("T1059.001","PowerShell","Execution"), "process.suspicious_invocation":("T1059","Command and Scripting Interpreter","Execution"), "persistence.service_suspicious_invocation":("T1543.003","Windows Service","Persistence, Privilege Escalation"), "persistence.task_suspicious_invocation":("T1053.005","Scheduled Task","Execution, Persistence"), "persistence.startup_suspicious_invocation":("T1547.001","Registry Run Keys / Startup Folder","Persistence"), "persistence.registry_run_suspicious_invocation":("T1547.001","Registry Run Keys / Startup Folder","Persistence"), "persistence.linux_systemd_suspicious_invocation":("T1543.002","Systemd Service","Persistence, Privilege Escalation"), "persistence.linux_cron_suspicious_invocation":("T1053.003","Cron","Execution, Persistence")}

def _host_investigation_sections(company_id, result, analysis, answer, language):
    t = _REPORT_TEXT["ru" if language == "ru" else "en"]
    findings = analysis.get("findings", [])
    from app.modules.hunting_ai import audit_answer_citations
    citation_audit = audit_answer_citations(answer, analysis)
    confirmed = [f for f in findings if (f.get("review") or {}).get("status") == "confirmed"]
    unresolved = [f for f in findings if (f.get("review") or {}).get("status") not in {"benign", "confirmed"}]
    verdict = t["review"] if unresolved else t["undetermined"]
    if confirmed:
        verdict = ("Есть находки, подтверждённые аналитиком; статус компрометации хоста отдельно не установлен."
                   if language == "ru" else "Some findings were analyst-confirmed; host compromise status is not independently established.")
    triage = analysis.get("triage_summary", {})
    summary = result.get("summary", {})
    attack = []
    for f in findings:
        m = _ATTACK_RULES.get(f.get("rule_id"))
        if m: attack.append({"technique_id":m[0],"technique":m[1],"tactics":m[2],"rule_id":f.get("rule_id"),"evidence":{"source":f.get("source"),"row_number":f.get("row_number")},"note":"Сопоставление правила, не атрибуция злоумышленника." if language == "ru" else "Rule mapping, not attacker attribution."})
    return [
        (t["status"], ("UNREVIEWED; " if language != "ru" else "НЕ ПРОВЕРЕНО; ") + verdict),
        (t["identity"],json.dumps({"company_id":company_id,"company_label":"Company ID: " + str(company_id),"result_id":result.get("id"),"archive_sha256":result.get("sha256"),"archive_created_at":result.get("created_at"),"exported_at_utc":datetime.now(timezone.utc).isoformat(),"ruleset":analysis.get("ruleset"),"verdict":analysis.get("verdict")},ensure_ascii=False,indent=2,default=str)),
        (t["scope"],json.dumps({"reported_hostnames":summary.get("hostnames",[]),"sources":analysis.get("source_coverage",summary.get("sources",[])),"rows_reviewed":analysis.get("rows_reviewed",{}),"missing_sources":analysis.get("missing_sources",[]),"empty_sources":analysis.get("empty_sources",[]),"unsupported_sources":analysis.get("unsupported_sources",[]),"collection_provenance":summary.get("collection_provenance",{}),"findings_truncated":analysis.get("truncated",False),"timeline_truncated":triage.get("timeline_truncated",False),"graph_truncated":analysis.get("graph",{}).get("truncated",False)},ensure_ascii=False,indent=2,default=str)),
        (t["verdict"],verdict), (t["timeline"],json.dumps(triage.get("timeline",[]),ensure_ascii=False,indent=2,default=str)),
        (t["graph"],json.dumps(analysis.get("graph",{}),ensure_ascii=False,indent=2,default=str)), (t["iocs"],json.dumps(analysis.get("iocs",[]),ensure_ascii=False,indent=2,default=str)),
        (t["ttps"],json.dumps(attack,ensure_ascii=False,indent=2,default=str) if attack else t["unsupported"]),
        (t["access"],t["initial"]), (t["findings"],json.dumps(findings,ensure_ascii=False,indent=2,default=str)),
        (t["reviews"],json.dumps([{k:f.get(k) for k in ("rule_id","title","source","row_number","review")} for f in findings],ensure_ascii=False,indent=2,default=str)),
        (t["limitations"],json.dumps({"analysis_limitations":analysis.get("limitations",[]),"missing_sources":analysis.get("missing_sources",[]),"note":t["undetermined"]},ensure_ascii=False,indent=2,default=str)),
        (("AI citation audit (reference membership only; claims NOT verified)" if language != "ru" else "Проверка ссылок AI (только наличие ссылок; утверждения не проверены)"),json.dumps(citation_audit,ensure_ascii=False,indent=2,default=str)),
        (t["ai"],t["ai_note"]+"\n"+answer)]

def build_ai_markdown(company_id: int, result: dict, analysis: dict, answer: str, language: str = "en") -> bytes:
    """Indent untrusted content as literal Markdown code, including HTML and links."""
    t = _REPORT_TEXT["ru" if language == "ru" else "en"]
    parts = ["# " + t["title"], ""]
    for heading, text in _host_investigation_sections(company_id, result, analysis, answer, language):
        parts.extend(["## " + heading, "", *["    " + line for line in text.split("\n")], ""])
    return ("\n".join(parts) + "\n").encode("utf-8")


def build_ai_pdf(company_id: int, result: dict, analysis: dict, answer: str, language: str = "en") -> bytes:
    """Build bytes only; ReportLab receives escaped text, never user markup."""
    from io import BytesIO
    output = BytesIO()
    font = _pdf_font()
    body = ParagraphStyle("AIReportBody", fontName=font, fontSize=9, leading=13,
                          splitLongWords=True, spaceAfter=3)
    heading_style = ParagraphStyle("AIReportHeading", parent=body, fontSize=13, leading=17, spaceBefore=10)
    t = _REPORT_TEXT["ru" if language == "ru" else "en"]
    story = [Paragraph(_pdf_text(t["title"]), heading_style)]
    for heading, text in _host_investigation_sections(company_id, result, analysis, answer, language):
        story.append(Paragraph(_pdf_text(heading), heading_style))
        # Small flowables prevent huge paragraphs/lines from overflowing a page.
        for line in text.split("\n"):
            if not line:
                story.append(Spacer(1, 3))
            for start in range(0, len(line), 1000):
                story.append(Paragraph(_pdf_text(line[start:start + 1000]), body))
    SimpleDocTemplate(output, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm,
                      topMargin=16*mm, bottomMargin=16*mm).build(story)
    return output.getvalue()


_GROUP_CITATION = re.compile(r"\[evidence:([0-9a-f]{32}):([^#\]\r\n]+)#([0-9]{1,12})\]")

def validate_group_ai_citations(answer: str, correlation: dict[str, Any]) -> dict[str, Any]:
    allowed = set()
    for node in correlation.get("graph", {}).get("nodes", []):
        for ref in node.get("evidence_refs", []):
            if isinstance(ref, dict):
                allowed.add((str(ref.get("result_id", "")), str(ref.get("source", "")), ref.get("row_number")))
    for edge in correlation.get("graph", {}).get("edges", []):
        for ref in edge.get("evidence_refs", []):
            if isinstance(ref, dict):
                allowed.add((str(ref.get("result_id", "")), str(ref.get("source", "")), ref.get("row_number")))
        for ref in edge.get("host_evidence_refs", []):
            if isinstance(ref, dict):
                allowed.add((str(ref.get("result_id", "")), str(ref.get("source", "")), ref.get("row_number")))
    tokens = list(dict.fromkeys(re.findall(r"\[evidence:([^\]\r\n]*)\]", answer)))
    valid, invalid = [], []
    for token in tokens:
        match = _GROUP_CITATION.fullmatch("[evidence:" + token + "]")
        key = (match.group(1), match.group(2), int(match.group(3))) if match else None
        if key in allowed:
            valid.append({"result_id": key[0], "source": key[1], "row_number": key[2]})
        else:
            invalid.append(token[:500])
    status = "invalid_references" if invalid else "references_present" if valid else "no_verifiable_references"
    return {"status": status, "valid_references": valid, "invalid_references": invalid,
            "claims_verified": False, "scope": "exact_reference_membership_in_verified_group_correlation",
            "limitation": "A citation's presence does not prove the claim it accompanies; correlation is not attribution or a compromise verdict."}


def _group_ai_sections(company_id: int, results: list[dict[str, Any]], correlation: dict[str, Any], answer: str):
    validate_ai_answer(answer)
    audit = validate_group_ai_citations(answer, correlation)
    graph = correlation.get("graph", {})
    return [
        ("Status", "AI-generated / UNREVIEWED. Not a confirmed forensic verdict. Model provenance and factual accuracy are not verified. No LLM or external research is invoked during export."),
        ("Identity and scope", json.dumps({"company_id": company_id, "exported_at_utc": datetime.now(timezone.utc).isoformat(), "correlation_version": correlation.get("version"), "result_ids": correlation.get("result_ids"), "archives": [{k: item.get(k) for k in ("id", "sha256", "created_at", "size")} for item in results]}, ensure_ascii=False, indent=2)),
        ("Deterministic correlation evidence", json.dumps({"graph": graph, "truncated": correlation.get("truncated"), "limits": correlation.get("limits")}, ensure_ascii=False, indent=2)),
        ("Limitations", "Shared indicators show co-occurrence only. They do not establish maliciousness, causation, communication, lateral movement, or attacker identity. Host nodes represent collection scopes, not verified assets. Matching IP alone, PID, path, or unqualified username does not prove participation. Missing evidence is not negative evidence.\n" + "\n".join("- " + str(item) for item in correlation.get("limitations", []))),
        ("Citation audit (membership only; claims not verified)", json.dumps(audit, ensure_ascii=False, indent=2)),
        ("Full AI answer (literal untrusted text)", answer),
    ]

def build_group_ai_markdown(company_id: int, results: list[dict[str, Any]], correlation: dict[str, Any], answer: str) -> bytes:
    parts = ["# AI-assisted multi-host investigation report", ""]
    for heading, text in _group_ai_sections(company_id, results, correlation, answer):
        parts.extend(["## " + heading, "", *["    " + line for line in text.split("\n")], ""])
    return ("\n".join(parts) + "\n").encode("utf-8")

def build_group_ai_pdf(company_id: int, results: list[dict[str, Any]], correlation: dict[str, Any], answer: str) -> bytes:
    from io import BytesIO
    output = BytesIO(); font = _pdf_font()
    body = ParagraphStyle("AIGroupBody", fontName=font, fontSize=8, leading=11, splitLongWords=True, spaceAfter=3)
    heading_style = ParagraphStyle("AIGroupHeading", parent=body, fontSize=13, leading=17, spaceBefore=10)
    story = [Paragraph("AI-assisted multi-host investigation report", heading_style)]
    for heading, text in _group_ai_sections(company_id, results, correlation, answer):
        story.append(Paragraph(_pdf_text(heading), heading_style))
        for line in text.split("\n"):
            if not line: story.append(Spacer(1, 3))
            for start in range(0, len(line), 1000): story.append(Paragraph(_pdf_text(line[start:start+1000]), body))
    SimpleDocTemplate(output, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm).build(story)
    return output.getvalue()
