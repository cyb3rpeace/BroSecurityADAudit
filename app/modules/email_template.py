"""Premium Outlook-compatible email rendering."""
from __future__ import annotations
import html
from collections import Counter
from datetime import datetime, timezone

SEVERITY = {"critical": (0, "#ef4444", "Критические"), "high": (1, "#f59e0b", "Высокие"), "medium": (2, "#f59e0b", "Средние"), "low": (3, "#64748b", "Низкие"), "info": (4, "#64748b", "Информационные")}

def _e(value, fallback="—"):
    return html.escape(str(value if value not in (None, "") else fallback), quote=True)

def _finding_rows(findings):
    ordered = sorted(enumerate(findings), key=lambda pair: (SEVERITY.get(str(pair[1].get("severity", "")).lower(), (99,))[0], pair[0]))
    rows=[]
    for _, item in ordered[:5]:
        sev=str(item.get("severity", "")).lower(); color,label=SEVERITY.get(sev,(99,"#64748b",sev or "Отметка"))[1:]
        rows.append(f'<tr><td style="padding:12px 10px;border-top:1px solid #e2e8f0;color:{color};font-weight:700;font-size:12px;white-space:nowrap;">{_e(label)}</td><td style="padding:12px 10px;border-top:1px solid #e2e8f0;color:#0f172a;font-size:14px;line-height:20px;">{_e(item.get("title"),"Находка")}<br><span style="color:#64748b;font-size:12px;">{_e(item.get("hostname"),"Объект не указан")}</span></td></tr>')
    return ''.join(rows) or '<tr><td colspan="2" style="padding:14px 10px;color:#64748b;">Новых находок в этом письме нет.</td></tr>'

def render_html(company_name, summary, findings, title, logo_cid="brosec-logo", include_findings=True, app_url="", logo_available=False):
    findings=list(findings or []); counts=Counter(str(x.get("severity","")).lower() for x in findings)
    critical=counts.get("critical",0); warnings=counts.get("high",0)+counts.get("medium",0)
    supplied=[x for x in findings if x.get("config_change") is True]
    config=str(len(supplied)) if any("config_change" in x for x in findings) else "н/д"
    stamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    logo=f'<img src="cid:{_e(logo_cid)}" width="48" height="48" alt="BroSec Audit AD" style="display:block;border:0;">' if logo_available else ''
    cta=''
    if app_url:
        safe=html.escape(app_url,quote=True)
        cta=f'<tr><td style="padding:22px 32px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td bgcolor="#2563eb" style="border-radius:6px;"><a href="{safe}" style="display:inline-block;padding:13px 20px;color:#ffffff;text-decoration:none;font-weight:700;font-size:14px;">Открыть консоль</a></td></tr></table></td></tr>'
    findings_block=f'<tr><td style="padding:24px 32px 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding:0 10px 8px;color:#0f172a;font-size:16px;font-weight:700;">Приоритетные находки</td></tr>{_finding_rows(findings)}</table></td></tr>' if include_findings else ''
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>table{{border-collapse:collapse}}a{{color:inherit}}</style></head><body style="margin:0;padding:0;background:#f1f5f9;color:#0f172a;font-family:Segoe UI,Arial,sans-serif;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f1f5f9;"><tr><td align="center" style="padding:24px 12px;"><!--[if mso]><table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]--><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:640px;background:#ffffff;border:1px solid #cbd5e1;"><tr><td style="padding:24px 32px;background:#1e293b;color:#ffffff;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding-right:14px;vertical-align:middle;">{logo}</td><td style="vertical-align:middle;"><span style="font-size:11px;letter-spacing:1.5px;font-weight:700;">BROSEC AUDIT AD</span><br><span style="font-size:22px;line-height:30px;font-weight:700;">{_e(title)}</span></td></tr></table></td></tr><tr><td style="padding:22px 32px 0;color:#475569;font-size:14px;">{_e(company_name)}<br><span style="font-size:12px;color:#64748b;">Сформировано: {stamp}</span></td></tr><tr><td style="padding:20px 32px 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td width="25%" style="padding:12px 8px;background:#fff1f2;border:1px solid #fecdd3;"><span style="color:#991b1b;font-size:12px;">Критические</span><br><strong style="color:#ef4444;font-size:26px;">{critical}</strong></td><td width="25%" style="padding:12px 8px;background:#fffbeb;border:1px solid #fde68a;"><span style="color:#92400e;font-size:12px;">Предупреждения</span><br><strong style="color:#f59e0b;font-size:26px;">{warnings}</strong></td><td width="25%" style="padding:12px 8px;background:#eff6ff;border:1px solid #bfdbfe;"><span style="color:#1d4ed8;font-size:12px;">Изменения конфигурации</span><br><strong style="color:#2563eb;font-size:26px;">{_e(config)}</strong></td><td width="25%" style="padding:12px 8px;background:#f8fafc;border:1px solid #e2e8f0;"><span style="color:#475569;font-size:12px;">Всего находок</span><br><strong style="color:#0f172a;font-size:26px;">{len(findings)}</strong></td></tr></table></td></tr><tr><td style="padding:22px 32px 0;color:#334155;font-size:15px;line-height:24px;">{_e(summary,"Сводка проверки отсутствует.")}</td></tr>{findings_block}{cta}<tr><td style="padding:28px 32px;color:#64748b;font-size:12px;line-height:18px;border-top:1px solid #e2e8f0;margin-top:24px;">Это уведомление предназначено для { _e(company_name) }. В письмо не включаются пароли, секреты или значения cpassword. По вопросам безопасности: SOC вашей организации.</td></tr></table><!--[if mso]></td></tr></table><![endif]--></td></tr></table></body></html>'''