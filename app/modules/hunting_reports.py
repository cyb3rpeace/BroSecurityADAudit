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
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.graphics.shapes import Drawing, Rect, Line, String
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


def _ru_verdict(analysis: dict[str, Any]) -> str:
    findings = analysis.get("findings", [])
    confirmed = [f for f in findings if (f.get("review") or {}).get("status") == "confirmed"]
    unresolved = [f for f in findings if (f.get("review") or {}).get("status") not in {"benign", "confirmed"}]
    if confirmed: return "Есть подтверждённые аналитиком находки; компрометация хоста требует отдельного решения"
    if unresolved: return "Требуется проверка сигналов; заражение/компрометация не подтверждены"
    return "Не определено: отсутствие находок не доказывает отсутствие компрометации"


def _recommendations(analysis: dict[str, Any]) -> list[str]:
    findings = analysis.get("findings", [])
    if not findings: return ["Проверьте полноту источников и сохраните исходный архив; пустой результат не является доказательством чистоты."]
    return [
        "Сохранить исходный архив и SHA-256; не удалять подозрительный объект до фиксации evidence.",
        "Проверить цифровую подпись, SHA-256, владельца, ACL, время создания и родительский процесс для каждого сигнала.",
        "Сопоставить процесс, persistence, пользователя, сетевые соединения и Security/PowerShell события по UTC-времени.",
        "При подтверждении подозрительной активности изолировать хост по утверждённой процедуре и собрать volatile evidence.",
    ]


def build_xlsx(path: Path, result: dict[str, Any], analysis: dict[str, Any], reviews: list[dict[str, Any]]) -> None:
    workbook = Workbook(); overview = workbook.active; overview.title = "Обзор расследования"
    verdict = _ru_verdict(analysis)
    overview_rows = [["Поле", "Значение"], ["Продукт", "BroSec Audit AD"], ["ID расследования", result.get("id", "")], ["SHA-256 архива", result.get("sha256", "")], ["Создано", result.get("created_at", "")], ["Набор правил", analysis.get("ruleset", "")], ["Вердикт хоста", verdict], ["Найдено сигналов", len(analysis.get("findings", []))], ["Проверено строк", json.dumps(analysis.get("rows_reviewed", {}), ensure_ascii=False)], ["Сформировано UTC", datetime.now(timezone.utc).isoformat()]]
    for row in overview_rows: overview.append(row)
    findings = workbook.create_sheet("Находки и доказательства"); findings.append(["Правило", "Название", "Уровень", "Класс", "Приоритет", "Уверенность", "Источник", "Строка", "Обоснование", "Статус проверки", "Комментарий аналитика", "Время проверки"])
    for row in _rows(analysis, reviews): findings.append(row)
    timeline = workbook.create_sheet("Хронология наблюдений"); timeline.append(["Время UTC", "Источник", "Строка"])
    for row in _timeline(analysis): timeline.append(row)
    graph = workbook.create_sheet("Граф связей доказательств"); graph.append(["Источник", "Цель", "Отношение", "Уверенность"])
    for edge in analysis.get("graph", {}).get("edges", []): graph.append([edge.get("source", ""), edge.get("target", ""), edge.get("relation", ""), edge.get("confidence", "")])
    rec = workbook.create_sheet("Рекомендации по реагированию"); rec.append(["№", "Рекомендация"])
    for i, item in enumerate(_recommendations(analysis), 1): rec.append([i, item])
    for sheet in workbook.worksheets:
        sheet.freeze_panes = "A2"; sheet.auto_filter.ref = sheet.dimensions
        for cell in sheet[1]: cell.font = Font(bold=True, color="FFFFFF"); cell.fill = PatternFill("solid", fgColor="123B5D")
        for row in sheet.iter_rows():
            for cell in row:
                if isinstance(cell.value, str): cell.data_type = "s"; cell.alignment = __import__("openpyxl").styles.Alignment(vertical="top", wrap_text=True)
        for column in sheet.columns:
            width = min(max(max(len(str(cell.value or "")) for cell in column) + 2, 12), 72); sheet.column_dimensions[column[0].column_letter].width = width
    path.parent.mkdir(parents=True, exist_ok=True); workbook.save(path)


def build_pdf(path: Path, result: dict[str, Any], analysis: dict[str, Any], reviews: list[dict[str, Any]]) -> None:
    """Render a structured Group-IB-inspired forensic report: navy cover, red verdict accents,
    executive summary, evidence-led findings, timeline, ATT&CK mapping and recommendations.
    The visual language is intentionally original while following the supplied reference's
    hierarchy and investigation-report conventions.
    """
    font = _pdf_font()
    navy, red, ink, slate, pale, line = [colors.HexColor(x) for x in ("#101B32", "#D52B3F", "#172033", "#596579", "#F3F5F8", "#D8DEE8")]
    styles = getSampleStyleSheet()
    cover = ParagraphStyle("Cover", parent=styles["Title"], fontName=font, fontSize=28, leading=32, textColor=colors.white, spaceAfter=10)
    subtitle = ParagraphStyle("Subtitle", parent=styles["BodyText"], fontName=font, fontSize=13, leading=18, textColor=colors.HexColor("#D8E2F0"))
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontName=font, fontSize=18, leading=22, textColor=navy, spaceBefore=10, spaceAfter=8)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontName=font, fontSize=11, leading=14, textColor=red, spaceBefore=8, spaceAfter=5)
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontName=font, fontSize=10, leading=14, textColor=ink, spaceAfter=5)
    small = ParagraphStyle("Small", parent=body, fontSize=8.5, leading=11, textColor=slate)
    callout = ParagraphStyle("Callout", parent=body, fontSize=11, leading=15, textColor=navy)
    verdict = _ru_verdict(analysis)
    finding_rows = _rows(analysis, reviews)
    timeline = _timeline(analysis)
    attack = []
    for f in analysis.get("findings", []):
        m = _ATTACK_RULES.get(f.get("rule_id"))
        if m: attack.append([m[0], m[1], m[2], f.get("rule_id", ""), f"{f.get('source','')} · {f.get('row_number','')}"])

    def p(value, style=body): return Paragraph(_pdf_text(value), style)
    def table(data, widths, header=True):
        converted = [[Paragraph(_pdf_text(x), small) for x in row] for row in data]
        t = Table(converted, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
        commands = [("VALIGN", (0,0), (-1,-1), "TOP"), ("GRID", (0,0), (-1,-1), .35, line), ("LEFTPADDING", (0,0), (-1,-1), 5), ("RIGHTPADDING", (0,0), (-1,-1), 5), ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5)]
        if header: commands += [("BACKGROUND", (0,0), (-1,0), navy), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("FONTNAME", (0,0), (-1,0), font)]
        if len(converted) > 1: commands += [("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, pale])]
        t.setStyle(TableStyle(commands)); return t

    def page(canvas, doc):
        canvas.saveState(); w, h = landscape(A4)
        canvas.setStrokeColor(line); canvas.line(14*mm, 11*mm, w-14*mm, 11*mm)
        canvas.setFillColor(slate); canvas.setFont(font, 7); canvas.drawString(14*mm, 6*mm, "BroSec Audit AD · Threat Hunting")
        canvas.drawRightString(w-14*mm, 6*mm, f"СТРАНИЦА {doc.page}")
        canvas.restoreState()

    kind_labels = {"host": "Хост", "process": "Процесс", "network": "Сетевой endpoint", "socket": "Сетевой endpoint", "endpoint": "Сетевой endpoint", "persistence": "Автозапуск / persistence", "service": "Служба", "task": "Задача", "startup": "Автозапуск"}
    relation_labels = {"parent_child": "родитель → потомок", "network_connection": "процесс → endpoint", "executes": "совпадение пути запуска", "observed_on": "наблюдается на хосте"}

    def graph_drawing(graph):
        nodes = graph.get("nodes", [])[:24]
        edges = graph.get("edges", [])[:60]
        width, height, card_w, card_h = 520, 190, 104, 38
        drawing = Drawing(width, height)
        labels = {str(n.get("id", "")): (str(n.get("label") or n.get("name") or n.get("id", ""))[:18], kind_labels.get(str(n.get("kind", "")).lower(), "Объект доказательств")) for n in nodes}
        ids = list(labels)
        positions = {node_id: (12 + (i % 4) * 126, height - 42 - (i // 4) * 58) for i, node_id in enumerate(ids)}
        for edge in edges:
            a, b = str(edge.get("source", "")), str(edge.get("target", ""))
            if a in positions and b in positions:
                x1,y1=positions[a]; x2,y2=positions[b]
                drawing.add(Line(x1+card_w,y1+card_h/2,x2,y2+card_h/2,strokeColor=colors.HexColor("#64748B"),strokeWidth=1.2))
                drawing.add(String((x1+x2+card_w)/2, (y1+y2+card_h)/2+5, relation_labels.get(str(edge.get("relation", "")), str(edge.get("relation", ""))[:18]), fontName=font, fontSize=5.2, fillColor=colors.HexColor("#2563EB")))
        for node_id, (x,y) in positions.items():
            drawing.add(Rect(x,y,card_w,card_h,rx=5,ry=5,fillColor=colors.HexColor("#EFF6FF"),strokeColor=colors.HexColor("#2563EB"),strokeWidth=1))
            drawing.add(String(x+6,y+card_h-13,labels[node_id][0],fontName=font,fontSize=6.5,fillColor=ink))
            drawing.add(String(x+6,y+7,labels[node_id][1],fontName=font,fontSize=5.2,fillColor=slate))
        return drawing

    path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(path), pagesize=landscape(A4), rightMargin=17*mm, leftMargin=17*mm, topMargin=18*mm, bottomMargin=17*mm)
    story = [Paragraph("Threat Hunting — отчёт расследования", h1), p("BroSec Audit AD · отчёт на русском языке по доказательствам", small), Spacer(1, 4*mm), p(f"ID расследования: {result.get('id','')}"), p(f"SHA-256 архива: {result.get('sha256','')}"), PageBreak()]
    story += [Paragraph("01  РЕЗЮМЕ РАССЛЕДОВАНИЯ", h1), p("Настоящий отчёт содержит только результаты точечного сбора, детерминированного анализа и указанные ссылки на evidence. Он не выполняет внешние исследования и не является самостоятельным подтверждением компрометации."), Spacer(1, 4*mm)]
    summary_data = [["СТАТУС", "ВЕРДИКТ", "СИГНАЛЫ", "ХРОНОЛОГИЯ"], ["Требует проверки", verdict, str(len(finding_rows)), str(len(timeline))]]
    story.append(table(summary_data, [40*mm, 113*mm, 30*mm, 35*mm]))
    story += [Spacer(1, 7*mm), Paragraph("Ключевой вывод", h2), p(verdict, callout), Paragraph("Ограничение интерпретации", h2), p("Эвристические сигналы, LISTEN-порты, пути persistence и неполные источники требуют проверки владельца, подписи, ACL, времени и контекста. Отсутствие события не доказывает отсутствие активности.", callout), PageBreak()]
    story += [Paragraph("02  НАХОДКИ И ДОКАЗАТЕЛЬСТВА", h1)]
    rows = [["Правило", "Источник · строка", "Уровень", "Статус", "Обоснование"]]
    rows += [[_rule_label(r[0]), f"{r[6]} · {r[7]}", _level_label(r[2] or r[4]), _status_label(r[9]), f"{r[8]} {r[10]}" ] for r in finding_rows]
    story.append(table(rows or [["—","—","—","—","Находки отсутствуют; это не доказательство чистоты."]], [43*mm, 54*mm, 23*mm, 30*mm, 112*mm]))
    story += [Spacer(1, 7*mm), Paragraph("03  ХРОНОЛОГИЯ НАБЛЮДЕНИЙ", h1)]
    timeline_rows = [["Время UTC", "Источник", "Строка"]] + [[str(x) for x in row] for row in timeline]
    story.append(table(timeline_rows or [["—","Источник не представлен","—"]], [58*mm, 125*mm, 25*mm]))
    story.append(PageBreak())
    story += [Paragraph("04  ТTP И MITRE ATT&CK", h1), p("Сопоставление правил анализа с MITRE ATT&CK; это не атрибуция злоумышленника и не подтверждение выполнения техники.", small)]
    story.append(table([["ID", "Техника", "Тактика", "Правило", "Evidence"]] + attack or [["—","Нет надёжного сопоставления","—","—","—"]], [22*mm, 62*mm, 42*mm, 58*mm, 58*mm]))
    story += [Spacer(1, 8*mm), Paragraph("05  ГРАФ СВЯЗЕЙ", h1)]
    graph = analysis.get("graph", {})
    story.append(graph_drawing(graph))
    edges = graph.get("edges", [])
    story.append(Spacer(1, 4*mm))
    story.append(table([["Источник", "Отношение", "Цель", "Уверенность"]] + [[str(e.get("source","")), relation_labels.get(str(e.get("relation", "")), str(e.get("relation", ""))), str(e.get("target","")), {"direct": "прямая", "context": "контекст"}.get(str(e.get("confidence", "")), str(e.get("confidence", "")))] for e in edges[:100]] or [["—","Связи не представлены","—","—"]], [62*mm, 48*mm, 62*mm, 35*mm]))
    story.append(PageBreak())
    story += [Paragraph("06  РЕКОМЕНДАЦИИ И ОГОВОРКИ", h1)]
    for i, item in enumerate(_recommendations(analysis), 1): story.append(Paragraph(_pdf_text(f"{i:02d}  {item}"), callout))
    story += [Spacer(1, 8*mm), Paragraph("Компрометация не подтверждена", h2), p("Формулировка отчёта не заменяет решение аналитика. Для подтверждения требуется независимая проверка исходного архива, владельца объекта, цифровой подписи, временной шкалы, сетевого контекста и связанных событий."), Spacer(1, 8*mm), p(f"Сформировано UTC: {datetime.now(timezone.utc).isoformat()} · Версия evidence-представления: BroSec Threat Hunting.", small)]
    doc.build(story, onFirstPage=page, onLaterPages=page)


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
        ("Полный ответ AI (непроверенный текст)", answer),
    ]


_REPORT_TEXT = {
    "ru": {"title":"Подробный криминалистический отчёт по хосту", "status":"Статус и оценка", "identity":"Идентификация и целостность", "scope":"Объём и полнота доказательств", "verdict":"Вывод о компрометации", "timeline":"Хронология наблюдений (UTC)", "graph":"Граф связей доказательств", "iocs":"Индикаторы компрометации (IOC)", "ttps":"Сопоставление с MITRE ATT&CK", "access":"Гипотезы первоначального доступа", "findings":"Находки и наблюдаемые инструменты", "reviews":"Решения аналитика", "limitations":"Ограничения расследования", "ai":"Предоставленный AI-ответ (непроверенный)", "undetermined":"Не определено: данных недостаточно для подтверждения или исключения компрометации.", "review":"Есть сигналы, требующие проверки; компрометация не подтверждена.", "none":"Срабатываний не найдено. Это не доказывает отсутствие компрометации.", "initial":"Первоначальный доступ не установлен: доступные источники не дают достаточной телеметрии для определения вектора проникновения.", "ai_note":"AI-текст предоставлен клиентом; происхождение модели и достоверность утверждений не проверялись.", "unsupported":"Для правил анализа нет надёжного сопоставления ATT&CK."},
    "en": {"title":"Detailed Host Forensic Report", "status":"Status and assessment", "identity":"Identity and integrity", "scope":"Evidence scope and completeness", "verdict":"Compromise conclusion", "timeline":"Observation timeline (UTC)", "graph":"Relationship graph", "iocs":"Indicators of compromise (IOCs)", "ttps":"MITRE ATT&CK mapping", "access":"Initial access hypotheses", "findings":"Findings and observed tools", "reviews":"Analyst decisions", "limitations":"Investigation limitations", "ai":"Supplied AI answer (unverified)", "undetermined":"Undetermined: evidence is insufficient to confirm or rule out compromise.", "review":"Signals require review; compromise is not confirmed.", "none":"No detections. This does not prove absence of compromise.", "initial":"Initial access is undetermined: available sources do not provide sufficient telemetry to identify an entry vector.", "ai_note":"AI text was supplied by the client; model provenance and claim accuracy were not verified.", "unsupported":"No reliable ATT&CK mapping is available for these analysis rules."},
}
_RULE_LABELS_RU = {
    "process.transient_path": "Процесс запущен из временного пути",
    "persistence.linux_systemd_suspicious_invocation": "Подозрительный запуск через systemd",
    "persistence.linux_cron_suspicious_invocation": "Подозрительная команда в cron",
    "process.encoded_powershell": "Закодированный PowerShell",
    "process.suspicious_invocation": "Подозрительный запуск интерпретатора",
}
_STATUS_RU = {"needs_review": "требует проверки", "confirmed": "подтверждено", "benign": "доброкачественно", "insufficient_evidence": "недостаточно evidence"}
_LEVEL_RU = {"critical": "критический", "high": "высокий", "medium": "средний", "low": "низкий", "observation": "наблюдение"}

def _rule_label(value: Any) -> str:
    text = str(value or "")
    return _RULE_LABELS_RU.get(text, text.replace("_", " "))

def _status_label(value: Any) -> str:
    return _STATUS_RU.get(str(value or ""), str(value or "—"))

def _level_label(value: Any) -> str:
    return _LEVEL_RU.get(str(value or ""), str(value or "—"))

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


def _group_ai_sections(company_id: int, results: list[dict[str, Any]], correlation: dict[str, Any], answer: str, language: str = "ru"):
    validate_ai_answer(answer)
    audit = validate_group_ai_citations(answer, correlation)
    graph = correlation.get("graph", {})
    return [
        ("Статус", "UNREVIEWED / Сформировано с помощью AI / НЕ ПРОВЕРЕНО. Это не подтверждённый криминалистический вывод. Происхождение модели и достоверность утверждений не проверялись. Внешние исследования при экспорте не выполнялись."),
        ("Идентификация и объём", json.dumps({"company_id": company_id, "exported_at_utc": datetime.now(timezone.utc).isoformat(), "correlation_version": correlation.get("version"), "result_ids": correlation.get("result_ids"), "archives": [{k: item.get(k) for k in ("id", "sha256", "created_at", "size")} for item in results]}, ensure_ascii=False, indent=2)),
        ("Детерминированные доказательства корреляции", json.dumps({"graph": graph, "truncated": correlation.get("truncated"), "limits": correlation.get("limits")}, ensure_ascii=False, indent=2)),
        ("Ограничения расследования", "Общие индикаторы показывают только совместное появление. Они не подтверждают вредоносность, причинность, обмен данными, латеральное перемещение или личность атакующего. Узлы хостов обозначают области сбора, а не проверенные активы. Совпадение IP, PID, пути или имени пользователя само по себе ничего не доказывает. Отсутствующие данные не являются отрицательным доказательством.\n" + "\n".join("- " + str(item) for item in correlation.get("limitations", []))),
        ("Проверка ссылок (только наличие; утверждения не проверены)", json.dumps(audit, ensure_ascii=False, indent=2)),
        ("Полный ответ AI (непроверенный текст)", answer),
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
    story = [Paragraph("Сводный криминалистический отчёт по нескольким хостам", heading_style)]
    for heading, text in _group_ai_sections(company_id, results, correlation, answer):
        story.append(Paragraph(_pdf_text(heading), heading_style))
        for line in text.split("\n"):
            if not line: story.append(Spacer(1, 3))
            for start in range(0, len(line), 1000): story.append(Paragraph(_pdf_text(line[start:start+1000]), body))
    SimpleDocTemplate(output, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm).build(story)
    return output.getvalue()


def build_group_xlsx(path: Path, results: list[dict[str, Any]], analyses: list[dict[str, Any]], correlation: dict[str, Any], sections: set[str], include_technical: bool = True) -> None:
    """Bounded multi-host workbook. Evidence remains tenant-scoped and cited by result/source/row."""
    workbook = Workbook(); overview = workbook.active; overview.title = "Сводка расследования"
    overview.append(["Поле", "Значение"])
    overview.append(["Выбранные архивы", len(results)])
    overview.append(["Общий объём строк", sum(int(r.get("summary", {}).get("total_rows", 0)) for r in results)])
    overview.append(["Лимит корреляции", json.dumps(correlation.get("limits", {}), ensure_ascii=False)])
    overview.append(["Ограничения полноты", "Да — эвристика и bounded evidence; отсутствие данных не доказывает отсутствие активности"])
    overview.append(["Компрометационный verdict", "Отдельное решение аналитика требуется; автоматическая корреляция не является доказательством компрометации"])
    if "summary" in sections:
        hosts = workbook.create_sheet("Хосты и объём")
        hosts.append(["Архив", "SHA-256", "Размер байт", "Строк", "Источники"])
        for result in results:
            hosts.append([result.get("id", ""), result.get("sha256", ""), result.get("size", ""), result.get("summary", {}).get("total_rows", 0), ", ".join(str(x.get("source", "")) for x in result.get("summary", {}).get("sources", []))])
    if "findings" in sections:
        sheet = workbook.create_sheet("Находки")
        sheet.append(["Архив", "Правило", "Название", "Уровень", "Источник", "Строка", "Обоснование", "Вердикт"])
        for analysis in analyses:
            for finding in analysis.get("findings", [])[:5000]:
                sheet.append([analysis.get("import_id", ""), finding.get("rule_id", ""), finding.get("title", ""), finding.get("triage_level", finding.get("classification", "")), finding.get("source", ""), finding.get("row_number", ""), finding.get("reason", "") if include_technical else "", "Не подтверждено автоматически"])
    if "timeline" in sections:
        sheet = workbook.create_sheet("Хронология")
        sheet.append(["Архив", "Время UTC", "Источник", "Строка"])
        for analysis in analyses:
            for item in analysis.get("triage_summary", {}).get("timeline", [])[:5000]:
                sheet.append([analysis.get("import_id", ""), item.get("timestamp", ""), item.get("source", ""), item.get("row_number", "")])
    if "mitre" in sections:
        sheet = workbook.create_sheet("MITRE ATT&CK")
        sheet.append(["Архив", "Правило", "Техника", "Источник", "Строка"])
        for analysis in analyses:
            for finding in analysis.get("findings", []):
                mapping = _ATTACK_RULES.get(finding.get("rule_id"))
                if mapping: sheet.append([analysis.get("import_id", ""), finding.get("rule_id", ""), f"{mapping[0]} {mapping[1]}", finding.get("source", ""), finding.get("row_number", "")])
    if "graph" in sections:
        sheet = workbook.create_sheet("Граф связей")
        sheet.append(["Источник", "Цель", "Связь", "Уверенность", "Индикатор"])
        for edge in correlation.get("graph", {}).get("edges", [])[:2000]: sheet.append([edge.get("source", ""), edge.get("target", ""), edge.get("relation", ""), edge.get("confidence", ""), json.dumps(edge.get("indicator", {}), ensure_ascii=False)])
    if "remediation" in sections:
        sheet = workbook.create_sheet("Рекомендации")
        for index, item in enumerate(_recommendations(analyses[0] if analyses else {}), 1): sheet.append([index, item])
    for sheet in workbook.worksheets:
        sheet.freeze_panes = "A2"; sheet.auto_filter.ref = sheet.dimensions
        for cell in sheet[1]: cell.font = Font(bold=True, color="FFFFFF"); cell.fill = PatternFill("solid", fgColor="123B5D")
        for column in sheet.columns:
            width = min(max(max(len(str(cell.value or "")) for cell in column) + 2, 12), 72); sheet.column_dimensions[column[0].column_letter].width = width
    path.parent.mkdir(parents=True, exist_ok=True); workbook.save(path)


def build_group_pdf(path: Path, results: list[dict[str, Any]], analyses: list[dict[str, Any]], correlation: dict[str, Any], sections: set[str], include_technical: bool = True) -> None:
    """Compact Russian multi-host report with explicit scope, limits and non-verdict disclaimer."""
    font = _pdf_font(); styles = getSampleStyleSheet(); body = ParagraphStyle("GroupBody", parent=styles["BodyText"], fontName=font, fontSize=8.5, leading=11, spaceAfter=5); heading = ParagraphStyle("GroupHeading", parent=styles["Heading1"], fontName=font, fontSize=16, leading=20, textColor=colors.HexColor("#101B32"), spaceBefore=10, spaceAfter=7)
    def p(value, style=body): return Paragraph(_pdf_text(value), style)
    output = SimpleDocTemplate(str(path), pagesize=landscape(A4), rightMargin=17*mm, leftMargin=17*mm, topMargin=17*mm, bottomMargin=15*mm)
    story = [p("BroSec Audit AD · Сводный криминалистический отчёт", heading), p("Выводы основаны на выбранных tenant-scoped архивах. Автоматическая корреляция не является доказательством компрометации.")]
    if "summary" in sections:
        story += [p("01 · Объём и ограничения", heading), p(f"Выбрано архивов: {len(results)} · общий объём строк: {sum(int(r.get('summary', {}).get('total_rows', 0)) for r in results)} · лимит: до 20 архивов и 200 000 строк."), p("Компрометационный verdict: НЕ ОПРЕДЕЛЁН автоматически. Требуется отдельное решение аналитика с проверкой исходных строк.")]
    if "findings" in sections:
        rows = [["Архив", "Правило", "Уровень", "Источник/строка", "Обоснование"]]
        for analysis in analyses:
            for f in analysis.get("findings", [])[:1000]: rows.append([analysis.get("import_id", ""), f.get("rule_id", ""), f.get("triage_level", f.get("classification", "")), f"{f.get('source','')}:{f.get('row_number','')}", f.get("reason", "") if include_technical else "См. исходный evidence"])
        story += [p("02 · Находки", heading), Table([[p(x) for x in row] for row in rows], colWidths=[35*mm, 45*mm, 25*mm, 55*mm, 105*mm], repeatRows=1)]
    if "timeline" in sections:
        story += [PageBreak(), p("03 · Хронология наблюдений", heading)]
        rows = [["Архив", "Время UTC", "Источник", "Строка"]]
        for analysis in analyses:
            rows.extend([[analysis.get("import_id", ""), i.get("timestamp", ""), i.get("source", ""), i.get("row_number", "")] for i in analysis.get("triage_summary", {}).get("timeline", [])[:2000]])
        story.append(Table([[p(x) for x in row] for row in rows], colWidths=[40*mm, 55*mm, 115*mm, 25*mm], repeatRows=1))
    if "graph" in sections:
        story += [p("04 · Граф связей", heading), p(f"Узлов: {len(correlation.get('graph', {}).get('nodes', []))}; связей: {len(correlation.get('graph', {}).get('edges', []))}. Общий индикатор означает совместное наблюдение, а не lateral movement.")]
    if "remediation" in sections:
        story += [p("05 · Рекомендации", heading)] + [p(f"{i}. {item}") for i, item in enumerate(_recommendations(analyses[0] if analyses else {}), 1)]
    output.build(story)
