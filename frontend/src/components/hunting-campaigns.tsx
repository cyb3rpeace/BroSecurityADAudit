import { useEffect, useMemo, useState } from "react"
import { api } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
type Profile = { id: string; name: string; platform: string }
type Campaign = {
  id: string; profile_id: string; status: string; total_hosts: number; completed_hosts: number
  progress_percent: number; counts: Record<string, number>; collection_completed?: number; analysis_completed?: number; analysis_pending?: number; created_at?: string
}
type Task = {
  id: string; hostname: string; status: string; attempt: number; max_attempts: number
  progress_percent: number; last_error_code?: string | null; last_error_message?: string | null
  result_id?: string | null; next_attempt_at?: string | null
}

const statusLabel: Record<string, string> = {
  pending: "Ожидает", running: "В работе", leased: "Назначено", uploading: "Загрузка",
  validating: "Проверка", analyzing: "Анализ", succeeded: "Сбор принят", analyzed: "Анализ завершён", failed: "Ошибка",
  expired: "Истёк lease", cancelled: "Отменено", paused: "Пауза", completed: "Завершено", partial: "Частично",
}

export function HuntingCampaigns({ companyId, profiles, onOpenResult }: { companyId: number; profiles: Profile[]; onOpenResult?: (resultId: string) => void }) {
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [selected, setSelected] = useState<Campaign | null>(null)
  const [tasks, setTasks] = useState<Task[]>([])
  const [profileId, setProfileId] = useState(profiles[0]?.id || "")
  const [hostText, setHostText] = useState("")
  const [filter, setFilter] = useState("")
  const [selectedTaskIds, setSelectedTaskIds] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  async function refresh() {
    const list = await api<{ items: Campaign[] }>(`/api/threat-hunting/campaigns?company_id=${companyId}&limit=50`)
    setCampaigns(list.items)
    if (selected) {
      const current = await api<Campaign>(`/api/threat-hunting/campaigns/${selected.id}?company_id=${companyId}`)
      const taskList = await api<{ items: Task[] }>(`/api/threat-hunting/campaigns/${selected.id}/tasks?company_id=${companyId}&limit=500`)
      setSelected(current); setTasks(taskList.items)
    }
  }
  useEffect(() => { void refresh().catch(e => setError(e instanceof Error ? e.message : "Не удалось загрузить кампании")) }, [companyId])
  useEffect(() => { if (profiles.length && !profiles.some(p => p.id === profileId)) setProfileId(profiles[0].id) }, [profiles, profileId])
  useEffect(() => {
    if (!selected || !["pending", "running", "paused"].includes(selected.status)) return
    const timer = window.setInterval(() => { void refresh().catch(() => undefined) }, 5000)
    return () => window.clearInterval(timer)
  }, [selected?.id, selected?.status])

  async function create() {
    const hostnames = hostText.split(/[\r\n,;]+/).map(x => x.trim()).filter(Boolean)
    if (!profileId || !hostnames.length) { setError("Выберите профиль и укажите хотя бы один хост"); return }
    setBusy(true); setError("")
    try {
      const campaign = await api<Campaign>("/api/threat-hunting/campaigns", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ company_id: companyId, profile_id: profileId, hostnames, idempotency_key: `ui-${Date.now()}-${Math.random().toString(36).slice(2)}` }) })
      setHostText(""); setSelected(campaign); await refresh()
    } catch (e) { setError(e instanceof Error ? e.message : "Не удалось создать кампанию") }
    finally { setBusy(false) }
  }
  async function action(actionName: "pause" | "resume" | "cancel") {
    if (!selected) return
    setBusy(true); setError("")
    try { await api(`/api/threat-hunting/campaigns/${selected.id}/${actionName}?company_id=${companyId}`, { method: "POST" }); await refresh() }
    catch (e) { setError(e instanceof Error ? e.message : "Действие отклонено") }
    finally { setBusy(false) }
  }
  async function retry(task: Task) {
    setBusy(true); setError("")
    try { await api(`/api/threat-hunting/tasks/${task.id}/retry?company_id=${companyId}`, { method: "POST" }); await refresh() }
    catch (e) { setError(e instanceof Error ? e.message : "Повтор не выполнен") }
    finally { setBusy(false) }
  }
  const visibleTasks = useMemo(() => tasks.filter(t => !filter || t.status === filter), [tasks, filter])
  function toggleTask(id: string) { setSelectedTaskIds(ids => ids.includes(id) ? ids.filter(x => x !== id) : [...ids, id]) }
  async function retrySelected() {
    const candidates = tasks.filter(t => selectedTaskIds.includes(t.id) && ["failed", "expired"].includes(t.status) && t.attempt < t.max_attempts)
    if (!candidates.length) return
    setBusy(true); setError("")
    try { await Promise.all(candidates.map(t => api(`/api/threat-hunting/tasks/${t.id}/retry?company_id=${companyId}`, { method: "POST" }))); setSelectedTaskIds([]); await refresh() }
    catch (e) { setError(e instanceof Error ? e.message : "Массовый повтор не выполнен") }
    finally { setBusy(false) }
  }

  return <div className="min-w-0 space-y-4">
    <Card className="rounded-md"><CardHeader><CardTitle>План массового сбора</CardTitle></CardHeader><CardContent className="space-y-3"><p className="text-sm text-muted-foreground">Кампания — это план: один профиль сборщика и список разрешённых хостов. Здесь отслеживаются задания и результаты. Создание плана само по себе не устанавливает сборщик на компьютеры: для развёртывания используйте инструкции Windows/GPO или Linux/Ansible.</p>
      <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
        <label className="text-sm">Профиль<select className="mt-1 block w-full rounded border bg-background p-2" value={profileId} onChange={e => setProfileId(e.target.value)}>{profiles.map(p => <option key={p.id} value={p.id}>{p.name} · {p.platform}</option>)}</select></label>
        <label className="text-sm">Хосты <span className="text-muted-foreground">(по одному в строке)</span><textarea className="mt-1 min-h-24 w-full rounded border bg-background p-2 font-mono text-sm" value={hostText} onChange={e => setHostText(e.target.value)} placeholder="DC01\nWS-001\nWS-002" /></label>
      </div>
      <Button disabled={busy || !profiles.length} onClick={() => void create()}>{busy ? "Обработка…" : "Создать план сбора"}</Button>
    </CardContent></Card>
    {error && <p role="alert" className="rounded-xl border border-destructive/40 p-3 text-sm text-destructive">{error}</p>}
    <div className="grid gap-4 xl:grid-cols-[minmax(240px,1fr)_minmax(0,2fr)]">
      <Card className="min-w-0 rounded-md"><CardHeader><CardTitle>Планы сбора <span className="text-sm text-muted-foreground">{campaigns.length}</span></CardTitle></CardHeader><CardContent className="space-y-2">{campaigns.length === 0 ? <p className="text-sm text-muted-foreground">Планов сбора пока нет.</p> : campaigns.map(c => <button key={c.id} className={`w-full rounded-lg border p-3 text-left ${selected?.id === c.id ? "border-primary bg-primary/5" : ""}`} onClick={() => { setSelected(c); setTasks([]); void api<{ items: Task[] }>(`/api/threat-hunting/campaigns/${c.id}/tasks?company_id=${companyId}&limit=500`).then(x => setTasks(x.items)).catch(e => setError(e.message)) }}><div className="flex justify-between gap-2"><strong className="truncate">{c.id.slice(0, 10)}</strong><span className="text-xs">{statusLabel[c.status] || c.status}</span></div><div className="mt-2 h-2 rounded bg-muted"><div className="h-2 rounded bg-primary" style={{ width: `${c.progress_percent || 0}%` }} /></div><p className="mt-1 text-xs text-muted-foreground">{c.completed_hosts}/{c.total_hosts} хостов · сбор: {c.collection_completed ?? c.completed_hosts} · анализ: {c.analysis_completed ?? 0} · {c.progress_percent || 0}%</p></button>)}</CardContent></Card>
      <Card className="min-w-0 rounded-md"><CardHeader><div className="flex flex-wrap items-center justify-between gap-2"><CardTitle>Задания {selected && <span className="text-sm text-muted-foreground">· {statusLabel[selected.status] || selected.status}</span>}</CardTitle>{selected && <div className="flex flex-wrap gap-2">{selected.status === "running" || selected.status === "pending" ? <Button size="sm" variant="outline" disabled={busy} onClick={() => void action("pause")}>Пауза</Button> : null}{selected.status === "paused" ? <Button size="sm" variant="outline" disabled={busy} onClick={() => void action("resume")}>Продолжить</Button> : null}{!["completed", "cancelled", "partial"].includes(selected.status) ? <Button size="sm" variant="destructive" disabled={busy} onClick={() => void action("cancel")}>Отменить</Button> : null}</div>}</div></CardHeader><CardContent>{!selected ? <p className="text-sm text-muted-foreground">Выберите кампанию.</p> : <div className="space-y-3"><div className="flex flex-wrap items-center gap-2"><select className="rounded border bg-background p-2 text-sm" value={filter} onChange={e => setFilter(e.target.value)}><option value="">Все статусы</option>{["pending", "leased", "uploading", "succeeded", "analyzed", "failed", "expired", "cancelled"].map(status => <option key={status} value={status}>{statusLabel[status] || status}</option>)}</select><span className="text-xs text-muted-foreground">{visibleTasks.length} из {tasks.length}</span>{selectedTaskIds.length > 0 && <Button size="sm" disabled={busy} onClick={() => void retrySelected()}>Повторить выбранные ({selectedTaskIds.length})</Button>}</div><div className="max-h-[30rem] overflow-auto"><div className="space-y-2">{visibleTasks.map(t => <div key={t.id} className="rounded-lg border p-3"><div className="flex flex-wrap items-center justify-between gap-2"><label className="flex items-center gap-2"><input type="checkbox" checked={selectedTaskIds.includes(t.id)} onChange={() => toggleTask(t.id)} /><strong>{t.hostname}</strong></label><span className="text-xs">{statusLabel[t.status] || t.status} · попытка {t.attempt}/{t.max_attempts}</span></div><div className="mt-2 h-1.5 rounded bg-muted"><div className="h-1.5 rounded bg-primary" style={{ width: `${t.progress_percent || 0}%` }} /></div>{t.last_error_message && <p className="mt-2 text-xs text-destructive">{t.last_error_code ? `${t.last_error_code}: ` : ""}{t.last_error_message}</p>}<div className="mt-2 flex gap-2">{t.result_id && onOpenResult ? <Button size="sm" variant="outline" onClick={() => onOpenResult(t.result_id!)}>Открыть forensic</Button> : null}{["failed", "expired"].includes(t.status) && t.attempt < t.max_attempts ? <Button size="sm" onClick={() => void retry(t)}>Повторить</Button> : null}</div></div>)}{!visibleTasks.length && <p className="text-sm text-muted-foreground">Заданий по фильтру нет.</p>}</div></div></div>}</CardContent></Card>
    </div>
  </div>
}
