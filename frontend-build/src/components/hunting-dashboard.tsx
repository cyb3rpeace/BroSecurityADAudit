import { HuntingCorrelation } from "@/components/hunting-correlation"
import { useEffect, useMemo, useState } from "react"
import { api } from "@/lib/api"
import { Button } from "@/components/ui/button"

type Result = { id: string; created_at: string; summary: { total_rows: number; sources: { source: string; rows: number }[] } }
type Finding = { triage_level?: string; classification?: string; risk_score?: number }
type Forensic = { analysis: { findings: Finding[]; truncated: boolean; source_coverage?: { source: string; rows: number }[]; triage_summary?: { max_risk_score?: number } } }
type Host = { item: Result; name?: string; ip?: string; level?: string; count?: number; score?: number; truncated?: boolean; error?: string; hostError?: string }
const levels = ["critical", "high", "medium", "low", "observation", "unknown"]
const labels: Record<string, string> = { critical: "Критический", high: "Высокий", medium: "Средний", low: "Низкий", observation: "Наблюдения", unknown: "Не определён", none: "Нет находок" }
function decodedSource(source: string) { try { return decodeURIComponent(source) } catch { return source } }
function field(row: Record<string, unknown>, keys: string[]) { for (const key of keys) { const value = row[key]; if (typeof value === "string" && value.trim()) return value; if (Array.isArray(value) && value.length) return value.filter(x => typeof x === "string").join(", ") } return undefined }

export function HuntingDashboard({ companyId, revision = 0, mode = "investigations", onOpenResult }: { companyId: number; revision?: number; mode?: "hq" | "investigations" | "analytics"; onOpenResult: (id: string) => void }) {
  const [hosts, setHosts] = useState<Host[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [retry, setRetry] = useState(0)
  const [q, setQ] = useState("")
  const [risk, setRisk] = useState("all")
  const [reportIds, setReportIds] = useState<string[]>([])
  const [reportFormat, setReportFormat] = useState<"pdf" | "xlsx">("pdf")
  const [reportBusy, setReportBusy] = useState(false)
  const [page, setPage] = useState(0)
  const pageSize = 10
  useEffect(() => {
    const controller = new AbortController()
    const options = { signal: controller.signal }
    setHosts([]); setTotal(0); setLoading(true); setError("")
    async function load() {
      try {
        // The forensic endpoint verifies and analyzes the archive. Keep at most
        // three requests active, including the optional host evidence read.
        const list = await api<{ items: Result[]; total: number }>(`/api/threat-hunting/results?company_id=${companyId}&offset=${page * pageSize}&limit=${pageSize}`, options)
        if (controller.signal.aborted) return
        setTotal(list.total); setHosts(list.items.map(item => ({ item })))
        let cursor = 0
        async function worker() {
          while (!controller.signal.aborted && cursor < list.items.length) {
            const item = list.items[cursor++]
            let host: Host = { item }
            try {
              const full = await api<Forensic>(`/api/threat-hunting/results/${encodeURIComponent(item.id)}/forensic?company_id=${companyId}`, options)
              const findings = full.analysis.findings
              const present = findings.map(f => (f.triage_level || f.classification || "unknown").toLowerCase())
              host = { item, count: findings.length, score: full.analysis.triage_summary?.max_risk_score, truncated: full.analysis.truncated, level: findings.length ? levels.find(level => present.includes(level)) || "unknown" : "none" }
              const source = (full.analysis.source_coverage || item.summary.sources).find(s => /(?:^|\/)Host\.json$/i.test(decodedSource(s.source)))?.source
              if (source) {
                try {
                  const page = await api<{ rows: Record<string, unknown>[] }>(`/api/threat-hunting/results/${encodeURIComponent(item.id)}/rows?company_id=${companyId}&source=${encodeURIComponent(source)}&offset=0&limit=1`, options)
                  const row = page.rows[0] || {}
                  host.name = field(row, ["Hostname", "Fqdn", "ComputerName", "hostname", "host"])
                  host.ip = field(row, ["IPAddress", "IP", "IPv4", "IPAddresses", "ip"])
                } catch (e) { host.hostError = e instanceof Error ? e.message : "Контекст хоста недоступен" }
              }
            } catch (e) { host.error = e instanceof Error ? e.message : "Анализ недоступен" }
            if (!controller.signal.aborted) setHosts(current => current.map(row => row.item.id === item.id ? host : row))
          }
        }
        await Promise.all(Array.from({ length: Math.min(3, list.items.length) }, worker))
      } catch (e) { if (!controller.signal.aborted) setError(e instanceof Error ? e.message : "Не удалось загрузить результаты") }
      finally { if (!controller.signal.aborted) setLoading(false) }
    }
    void load()
    return () => controller.abort()
  }, [companyId, revision, retry, page])
  const correlationArchives = useMemo(() => hosts.map(host => ({ id: host.item.id, name: host.name || host.item.id })), [hosts])
  const visible = useMemo(() => hosts.filter(h => `${h.name || ""} ${h.ip || ""} ${h.item.id}`.toLowerCase().includes(q.toLowerCase()) && (risk === "all" || h.level === risk)).sort((a, b) => (b.score ?? -1) - (a.score ?? -1)), [hosts, q, risk])
  const analyzed = hosts.filter(h => h.count !== undefined)
  const priority = analyzed.filter(h => h.level === "high" || h.level === "critical").length
  const distribution = [...levels, "none"].map(level => ({ level, count: analyzed.filter(h => h.level === level).length })).filter(x => x.count)
  const colors: Record<string, string> = { critical: "#dc2626", high: "#ef4444", medium: "#f59e0b", low: "#3b82f6", observation: "#64748b", unknown: "#a1a1aa", none: "#71717a" }
  let angle = 0
  const segments = distribution.map(x => { const start = angle; angle += x.count / analyzed.length * 100; return `${colors[x.level]} ${start}% ${angle}%` })
  async function exportCustomReport() {
    if (!reportIds.length || reportBusy) return
    setReportBusy(true); setError("")
    try {
      const response = await fetch("/api/threat-hunting/reports/custom-export", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ company_id: companyId, result_ids: reportIds, format: reportFormat, sections: ["summary", "findings", "timeline", "mitre", "graph", "remediation"], include_technical: true }) })
      if (!response.ok) { const detail = await response.json().catch(() => ({})); throw new Error(typeof detail.detail === "string" ? detail.detail : "Не удалось сформировать отчёт") }
      const url = URL.createObjectURL(await response.blob()); const link = document.createElement("a"); link.href = url; link.download = `BroSec-multi-host.${reportFormat}`; document.body.appendChild(link); link.click(); link.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 30000)
    } catch (e) { setError(e instanceof Error ? e.message : "Не удалось сформировать отчёт") } finally { setReportBusy(false) }
  }
  return <section className="space-y-4" aria-busy={loading}>
    <div className="flex flex-wrap items-end justify-between gap-3"><div><h2 className="text-xl font-semibold">{mode === "hq" ? "Операционная сводка" : mode === "analytics" ? "Приоритеты и объём данных" : "Хосты и сигналы"}</h2><p className="text-sm text-muted-foreground">Последние архивы выбранной компании. Приоритеты требуют проверки аналитиком.</p></div><Button variant="outline" disabled={loading} onClick={() => setRetry(value => value + 1)}>Обновить анализ</Button></div>
    <div className="grid gap-3 sm:grid-cols-3">{[["Архивов в компании", error ? "—" : total], ["Проанализировано в текущем срезе", `${analyzed.length}/${hosts.length}`], ["Архивов с высоким приоритетом", analyzed.length ? priority : "—"]].map(([label, value]) => <div key={label} className="rounded-lg border bg-card p-4"><p className="text-2xl font-semibold">{value}</p><p className="text-sm text-muted-foreground">{label}</p></div>)}</div>
    {mode === "investigations" && !loading && <HuntingCorrelation companyId={companyId} archives={correlationArchives} onOpenResult={onOpenResult} />}
    {mode !== "investigations" && analyzed.length > 0 && <div className="flex flex-wrap items-center gap-6 rounded-lg border bg-card p-4"><div role="img" aria-label={`Распределение приоритета: ${distribution.map(x => `${labels[x.level]} ${x.count}`).join(", ")}`} className="grid size-36 shrink-0 place-items-center rounded-full" style={{ background: `conic-gradient(${segments.join(",")})` }}><div className="grid size-24 content-center rounded-full bg-card text-center"><b className="text-2xl">{analyzed.length}</b><span className="text-xs text-muted-foreground">архивов</span></div></div><div><h3 className="mb-2 font-semibold">Распределение приоритета</h3><div className="flex flex-wrap gap-3">{distribution.map(x => <button key={x.level} onClick={() => { const first = hosts.find(h => h.level === x.level); if (first) onOpenResult(first.item.id) }} className="rounded-lg border px-3 py-2 text-sm hover:bg-muted"><span className="mr-2 inline-block size-2 rounded-full" style={{ backgroundColor: colors[x.level] }} />{labels[x.level]} · {x.count}</button>)}</div><p className="mt-2 text-xs text-muted-foreground">По успешно проанализированным архивам текущего среза; не оценка вероятности взлома.</p></div></div>}
    <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground"><span>Хосты и архивы: {total ? page * pageSize + 1 : 0}–{Math.min(page * pageSize + hosts.length, total)} из {total} · базовая страница: {pageSize}</span><span className="flex gap-1"><Button size="sm" variant="ghost" disabled={page === 0 || loading} onClick={() => setPage(value => value - 1)}>Назад</Button><Button size="sm" variant="ghost" disabled={loading || (page + 1) * pageSize >= total} onClick={() => setPage(value => value + 1)}>Далее</Button></span></div><p className="text-xs text-muted-foreground">Показаны {hosts.length} архивов текущей страницы, не уникальные хосты. Приоритет — уровень эвристик API, не вердикт о компрометации. Отсутствие находок не доказывает безопасность.{analyzed.some(h => h.truncated) ? " Часть списков находок ограничена API." : ""}</p>
    {loading && <p role="status" className="text-sm text-muted-foreground">Загрузка и проверка архивов… {analyzed.length} из {hosts.length}</p>}
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {mode === "investigations" && <div className="flex flex-wrap gap-2"><input aria-label="Поиск хоста или архива" className="h-10 rounded-lg border bg-background px-3 text-sm" placeholder="Hostname, IP или ID архива" value={q} onChange={e => { setQ(e.target.value); setPage(0) }} /><select aria-label="Фильтр приоритета" className="h-10 rounded-lg border bg-background px-3 text-sm" value={risk} onChange={e => { setRisk(e.target.value); setPage(0) }}><option value="all">Все приоритеты</option>{[...levels, "none"].map(level => <option key={level} value={level}>{labels[level]}</option>)}</select></div>}
    {mode !== "analytics" && <div className="max-h-[min(60vh,560px)] divide-y overflow-y-auto rounded-lg border bg-card">{(mode === "hq" ? visible.slice(0, 5) : visible).map(h => <button key={h.item.id} onClick={() => onOpenResult(h.item.id)} className="flex w-full min-w-0 items-center gap-3 px-3 py-2 text-left text-xs hover:bg-primary/5"><span className={`h-2 w-2 shrink-0 rounded-full ${h.level === "critical" || h.level === "high" ? "bg-red-500" : h.level === "medium" ? "bg-amber-500" : h.level === "low" ? "bg-blue-500" : "bg-slate-400"}`} aria-hidden="true"/><span className="min-w-0 flex-1"><b className="block truncate">{h.name || "Имя хоста не собрано"}</b><span className="block truncate font-mono text-[10px] text-muted-foreground">{h.item.id}</span></span><span className="hidden shrink-0 text-right text-[11px] text-muted-foreground sm:block">{h.ip || "IP не собран"}<br />{h.item.summary.total_rows.toLocaleString("ru-RU")} строк</span><span className="shrink-0 text-right text-[11px]">{h.error ? <span className="text-destructive">Ошибка</span> : h.count === undefined ? "Ожидает…" : <><span className="rounded border px-1.5 py-0.5">{labels[h.level || "unknown"]}</span><span className="mt-1 block text-muted-foreground">{h.count}{h.truncated ? "+" : ""} находок</span></>}</span></button>)}{!loading && !error && !visible.length && <p className="p-6 text-sm text-muted-foreground">{hosts.length ? "Нет архивов по выбранному фильтру." : "Загрузите первый архив в разделе «Сбор и импорт»."}</p>}</div>}
    {mode === "hq" && <p className="text-xs text-muted-foreground">Показаны до пяти архивов с наивысшим доступным риск-баллом. Полный список — в разделе «Анализ и расследования».</p>}
    {mode === "analytics" && <section className="space-y-3 rounded-lg border bg-card p-4" aria-label="Конструктор сводного отчёта"><div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="font-semibold">Конструктор сводного отчёта</h3><p className="mt-1 text-xs text-muted-foreground">Выберите от 1 до 20 архивов. Итоговый verdict требует проверки аналитиком и не равен вероятности компрометации.</p></div><div className="flex flex-wrap gap-2"><select aria-label="Формат отчёта" className="h-9 rounded-lg border bg-background px-2 text-sm" value={reportFormat} onChange={e => setReportFormat(e.target.value as "pdf" | "xlsx")}><option value="pdf">PDF</option><option value="xlsx">XLSX</option></select><Button size="sm" disabled={!reportIds.length || reportBusy} onClick={() => void exportCustomReport()}>Сформировать ({reportIds.length})</Button></div></div><div className="max-h-64 divide-y overflow-y-auto rounded-lg border">{hosts.map(h => <label key={h.item.id} className="flex min-w-0 items-center gap-2 px-3 py-2 text-xs hover:bg-muted/40"><input type="checkbox" checked={reportIds.includes(h.item.id)} onChange={e => setReportIds(current => e.target.checked ? [...current, h.item.id].slice(-20) : current.filter(id => id !== h.item.id))} /><span className="min-w-0 flex-1"><b className="block truncate">{h.name || "Хост не определён"}</b><span className="block truncate font-mono text-[10px] text-muted-foreground">{h.item.id}</span></span><span className="shrink-0 text-right text-[11px] text-muted-foreground">{h.item.summary.total_rows.toLocaleString("ru-RU")} строк<br />{h.count ?? "—"} находок · {labels[h.level || "unknown"]}</span></label>)}</div>{!hosts.length && !loading && <p className="rounded border border-dashed p-4 text-sm text-muted-foreground">Нет архивов для выбора.</p>}<div className="grid gap-2 sm:grid-cols-3"><div className="rounded border p-3"><p className="text-xs text-muted-foreground">Общий объём выбранного среза</p><p className="mt-1 text-lg font-semibold">{hosts.filter(h => reportIds.includes(h.item.id)).reduce((sum, h) => sum + h.item.summary.total_rows, 0).toLocaleString("ru-RU")} строк</p></div><div className="rounded border p-3"><p className="text-xs text-muted-foreground">Разделы</p><p className="mt-1 text-sm">Резюме · находки · timeline · MITRE · граф · рекомендации</p></div><div className="rounded border p-3"><p className="text-xs text-muted-foreground">Полнота и verdict</p><p className="mt-1 text-sm">Не подтверждены автоматически</p></div></div></section>}
  </section>
}
