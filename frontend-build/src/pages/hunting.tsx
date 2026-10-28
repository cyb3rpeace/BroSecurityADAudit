import { useEffect, useMemo, useRef, useState } from "react"
import { Dialog, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { useApp } from "@/app-state"
import { api } from "@/lib/api"
import { PageHead } from "@/components/bits"
import { HuntingResults } from "@/components/hunting-results"
import { HuntingDashboard } from "@/components/hunting-dashboard"
import { HuntingCampaigns } from "@/components/hunting-campaigns"
import { HuntingCollectionGuide } from "@/components/hunting-collection-guide"
import { HuntingCoverage } from "@/components/hunting-coverage"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

type Artifact = { id: string; title: string; platforms: string[]; note: string; status?: string; max_rows?: number }
type Profile = { id: string; name: string; platform: string; artifacts: string[]; timeout_seconds: number; event_days: number }
type Tab = "overview" | "profiles" | "campaigns" | "dashboard" | "imports"
type Section = "hq" | "investigations" | "analytics" | "collection"
const sectionTitles: Record<Section, string> = { hq: "Штаб безопасности", investigations: "Анализ и расследования", analytics: "Аналитика и отчёты", collection: "Сбор и импорт" }

export function Hunting({ section = "hq" }: { section?: Section }) {
  const { companyId } = useApp()
  return <TenantHunting key={companyId ?? "none"} companyId={companyId} section={section} />
}

function TenantHunting({ companyId, section }: { companyId: number | null; section: Section }) {
  const { setView } = useApp()
  const collection = section === "collection"
  function navigateTab(next: Tab) {
    if (next === "dashboard" || next === "overview") { setView(next === "overview" ? "hunting" : "hunting-investigations"); return }
    setTab(next); setView("hunting-collection")
  }
  const [catalog, setCatalog] = useState<Artifact[]>([])
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [buildPlatforms, setBuildPlatforms] = useState<string[]>([])
  const [platform, setPlatform] = useState("windows")
  const [picked, setPicked] = useState<string[]>(["host", "processes", "network"])
  const [name, setName] = useState("Базовый сбор")
  const [timeout, setTimeout] = useState(600)
  const [days, setDays] = useState(7)
  const [revision, setRevision] = useState(0)
  const [activeResult, setActiveResult] = useState<string | null>(null)
  function resultsChanged() { setActiveResult(null); setRevision(value => value + 1) }
  function openInvestigation(id: string) { setActiveResult(id); setView("hunting-investigations"); setTab("dashboard"); window.setTimeout(() => document.getElementById("hunting-investigation")?.scrollIntoView({ block: "start" }), 0) }
  const [upload, setUpload] = useState<File | null>(null)
  const [summary, setSummary] = useState<{ total_rows: number; sha256: string; sources: { source: string; rows: number }[]; limitations: string[] } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const tabKey = `brosec-hunting-collection-tab:${companyId ?? "none"}`
  const [tab, setTab] = useState<Tab>(() => {
    try { const saved = sessionStorage.getItem(tabKey); return saved === "campaigns" || saved === "imports" ? saved : "profiles" } catch { return "profiles" }
  })
  useEffect(() => { if (collection && ["profiles", "campaigns", "imports"].includes(tab)) { try { sessionStorage.setItem(tabKey, tab) } catch { /* Storage may be disabled. */ } } }, [collection, tab, tabKey])
  useEffect(() => { if (collection && (tab === "dashboard" || tab === "overview")) setTab("profiles") }, [collection, tab])
  const [showHelp, setShowHelp] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [activeAction, setActiveAction] = useState(0)
  const paletteTrigger = useRef<HTMLButtonElement>(null)
  const [catalogState, setCatalogState] = useState<"loading" | "loaded" | "error">("loading")

  useEffect(() => {
    function shortcut(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k" && !event.repeat) {
        event.preventDefault()
        setPaletteOpen(open => !open)
        setQuery(""); setActiveAction(0)
      }
    }
    document.addEventListener("keydown", shortcut)
    return () => document.removeEventListener("keydown", shortcut)
  }, [])
  function changePalette(open: boolean) {
    setPaletteOpen(open)
    if (open) { setQuery(""); setActiveAction(0) }
  }
  const actions = [
    { id: "overview", title: "Открыть обзор", hint: "Навигация", run: () => navigateTab("overview") },
    { id: "profiles", title: "Открыть профили сбора", hint: "Создание и скачивание сборщика", run: () => navigateTab("profiles") },
    { id: "campaigns", title: "Открыть массовый сбор", hint: "Сбор артефактов с нескольких хостов и повтор ошибок", run: () => navigateTab("campaigns") },
    { id: "imports", title: "Открыть импорт и историю", hint: "Загрузка и удаление архивов", run: () => navigateTab("imports") },
    { id: "investigations", title: "Открыть расследования", hint: "Хосты, сигналы и доказательства", run: () => navigateTab("dashboard") },
    { id: "analytics", title: "Открыть аналитику", hint: "Риски и объём доказательств", run: () => setView("hunting-analytics") },
    { id: "help", title: "Показать инструкцию", hint: "Рабочий процесс", run: () => setShowHelp(true) },
  ].filter(action => `${action.title} ${action.hint}`.toLocaleLowerCase("ru").includes(query.toLocaleLowerCase("ru")))
  function runAction(index: number) {
    const action = actions[index]
    if (!action) return
    action.run()
    setPaletteOpen(false)
  }

  useEffect(() => {
    const abort = new AbortController()
    if (companyId) {
      Promise.all([
        api<{ artifacts: Artifact[]; build_platforms?: string[] }>("/api/threat-hunting/catalog", { signal: abort.signal }),
        api<Profile[]>("/api/threat-hunting/profiles?company_id=" + companyId, { signal: abort.signal }),
      ]).then(([c, p]) => { setCatalog(c.artifacts); setBuildPlatforms(c.build_platforms || []); setProfiles(p); setCatalogState("loaded") }).catch(e => { if (!abort.signal.aborted) { setError(String(e.message)); setCatalogState("error") } })
    }
    return () => abort.abort()
  }, [companyId])

  const availableArtifacts = useMemo(() => catalog.filter(a => a.platforms.includes(platform)), [catalog, platform])
  const selectedRowBudget = catalog.filter(a => picked.includes(a.id)).reduce((sum, a) => sum + (a.max_rows || 0), 0)
  async function save() {
    if (!companyId) return
    const target = companyId
    setBusy(true); setError("")
    try {
      await api<Profile>("/api/threat-hunting/profiles", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ company_id: target, name, platform, artifacts: picked, timeout_seconds: timeout, event_days: days }) })
      setProfiles(await api<Profile[]>("/api/threat-hunting/profiles?company_id=" + target))
      setTab("profiles")
    } catch(e) { setError(e instanceof Error ? e.message : "Не удалось сохранить профиль") }
    finally { setBusy(false) }
  }
  async function removeProfile(profile: Profile) {
    if (!companyId || !window.confirm(`Удалить профиль «${profile.name}»? Профиль будет скрыт из списка. Уже созданные кампании и собранные архивы сохранятся.`)) return
    setBusy(true); setError("")
    try {
      await api(`/api/threat-hunting/profiles/${profile.id}?company_id=${companyId}`, { method: "DELETE" })
      setProfiles(await api<Profile[]>("/api/threat-hunting/profiles?company_id=" + companyId))
    } catch (e) { setError(e instanceof Error ? e.message : "Не удалось удалить профиль") }
    finally { setBusy(false) }
  }

  async function build(profile: Profile) {
    if (!companyId) return
    setBusy(true); setError("")
    try {
      const response = await fetch("/api/threat-hunting/profiles/" + profile.id + "/package", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ company_id: companyId }) })
      if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(typeof body.detail === "string" ? body.detail : "Не удалось создать сборщик") }
      const url = URL.createObjectURL(await response.blob())
      const link = document.createElement("a"); link.href = url; link.download = "brosec-collector-" + profile.id + ".zip"; link.click(); window.setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch(e) { setError(e instanceof Error ? e.message : "Ошибка сборки") }
    finally { setBusy(false) }
  }
  async function importResult() {
    if (!companyId || !upload) return
    if (upload.size > 128 * 1024 * 1024) { setError("Архив превышает 128 МиБ"); return }
    setBusy(true); setError(""); setSummary(null)
    try { const form = new FormData(); form.append("company_id", String(companyId)); form.append("file", upload); setSummary(await api("/api/threat-hunting/import", { method: "POST", body: form })); setRevision(r => r + 1); setTab("imports") }
    catch(e) { setError(e instanceof Error ? e.message : "Ошибка импорта") }
    finally { setBusy(false) }
  }
  return <div className="hunting-workspace space-y-4">
    <section aria-label="Операционный центр Threat Hunting" className="space-y-5 text-foreground">
      <div className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3"><PageHead title={sectionTitles[section]} sub="Сбор → импорт → анализ → проверка evidence → решение аналитика" /><span className="rounded-md border bg-muted/40 px-2.5 py-1.5 text-xs text-muted-foreground">{!companyId ? "Выберите компанию" : catalogState === "loading" ? "Загрузка каталога…" : catalogState === "error" ? "Ошибка загрузки" : `Компания ${companyId} · защищённый workspace`}</span></div>
    {section === "hq" && <div className="grid gap-3 sm:grid-cols-3">
      <div className="rounded-lg border bg-card p-4"><p className="text-xs uppercase tracking-wide text-muted-foreground">Упаковщики</p><p className="mt-1 text-2xl font-semibold">{buildPlatforms.length}/2</p><p className="text-xs text-muted-foreground">{buildPlatforms.length ? buildPlatforms.join(" · ") : "не установлены"}</p></div>
      <div className="rounded-lg border bg-card p-4"><p className="text-xs uppercase tracking-wide text-muted-foreground">Профили</p><p className="mt-1 text-2xl font-semibold">{profiles.length}</p><p className="text-xs text-muted-foreground">для выбранной компании</p></div>
      <div className="rounded-lg border bg-card p-4"><p className="text-xs uppercase tracking-wide text-muted-foreground">Лимиты</p><p className="mt-1 text-2xl font-semibold">128 МиБ</p><p className="text-xs text-muted-foreground">архив · 2 ГиБ хранения</p></div>
    </div>}
    <div className="flex flex-wrap items-center gap-2">
      {(collection ? [["profiles", "Сборщики"], ["campaigns", "Массовый сбор"], ["imports", "Импорт и история"]] as [Tab, string][] : []).map(([id, label]) => <Button key={id} variant={tab === id ? "default" : "ghost"} onClick={() => navigateTab(id)}>{label}</Button>)}
      <Dialog open={paletteOpen} onOpenChange={changePalette}>
        <DialogTrigger asChild><Button ref={paletteTrigger} className="ml-auto gap-3" variant="outline">Действия <kbd className="rounded border px-1 text-xs">Ctrl+K</kbd></Button></DialogTrigger>
        <DialogContent className="sm:max-w-lg motion-reduce:animate-none" onCloseAutoFocus={event => { event.preventDefault(); paletteTrigger.current?.focus() }}>
          <DialogTitle>Палитра действий</DialogTitle>
          <DialogDescription>Только навигация в ThreatHunting. Системные команды не выполняются.</DialogDescription>
          <Input role="combobox" aria-label="Найти действие" aria-expanded="true" aria-autocomplete="list" aria-controls="hunting-action-list" aria-activedescendant={actions[activeAction] ? `hunting-action-${actions[activeAction].id}` : undefined} value={query} onChange={event => { setQuery(event.target.value); setActiveAction(0) }} onKeyDown={event => {
            if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); setActiveAction(index => actions.length ? (index + (event.key === "ArrowDown" ? 1 : -1) + actions.length) % actions.length : 0) }
            if (event.key === "Enter") { event.preventDefault(); runAction(activeAction) }
          }} placeholder="Обзор, профили, импорт…" />
          <div id="hunting-action-list" role="listbox" aria-label="Доступные действия" className="space-y-1">
            {actions.map((action, index) => <div key={action.id} id={`hunting-action-${action.id}`} role="option" aria-selected={index === activeAction} className={`cursor-pointer rounded-lg p-3 text-sm ${index === activeAction ? "bg-accent text-accent-foreground" : "hover:bg-muted"}`} onMouseMove={() => setActiveAction(index)} onClick={() => runAction(index)}><span className="block font-medium">{action.title}</span><span className="text-xs text-muted-foreground">{action.hint}</span></div>)}
            {!actions.length && <p className="p-3 text-sm text-muted-foreground">Действий не найдено</p>}
          </div>
          <p className="text-xs text-muted-foreground">↑ ↓ выбор · Enter открыть · Esc закрыть</p>
        </DialogContent>
      </Dialog>
      <Button variant="outline" onClick={() => setShowHelp(value => !value)}>{showHelp ? "Скрыть подсказку" : "Как это работает"}</Button>
    </div>
    {collection && <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border bg-muted/30 p-3"><p className="text-sm"><b>Маршрут сбора:</b> 1. Создать → 2. Запустить на одном хосте или группе → 3. Загрузить ZIP → 4. Расследовать</p><div className="flex gap-2"><Button size="sm" variant="outline" onClick={() => navigateTab("profiles")}>Создать сборщик</Button><Button size="sm" variant="outline" onClick={() => setShowHelp(true)}>Инструкции GPO / Ansible</Button></div></div>}
    {showHelp && <HuntingCollectionGuide />}
    {!companyId && <p>Выберите компанию.</p>}
    {error && <p role="alert" className="rounded-xl border border-destructive/40 p-3 text-sm text-destructive">{error}</p>}
    {section === "hq" && <Card><CardHeader><CardTitle>Быстрый запуск</CardTitle></CardHeader><CardContent className="grid gap-3 sm:grid-cols-2"><Button disabled={!companyId} onClick={() => navigateTab("profiles")}>Создать профиль сбора</Button><Button variant="outline" disabled={!companyId} onClick={() => navigateTab("imports")}>Открыть импорт и историю</Button></CardContent></Card>}
    {collection && tab === "profiles" && <>
      <HuntingCoverage />
      <Card><CardHeader><CardTitle>Новый профиль</CardTitle></CardHeader><CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2"><label className="text-sm">Название<Input value={name} maxLength={120} onChange={e => setName(e.target.value)} /></label><label className="text-sm">ОС<select className="mt-1 block w-full rounded border bg-background p-2" value={platform} onChange={e => { setPlatform(e.target.value); setPicked(["host", "processes", "network"]) }}><option value="windows">Windows</option><option value="linux">Linux</option></select></label></div>
        <div className="grid gap-2 sm:grid-cols-3">{availableArtifacts.map(a => <label key={a.id} className="flex gap-2 rounded-lg border p-3 text-sm"><input type="checkbox" disabled={a.status === "candidate"} checked={picked.includes(a.id)} onChange={e => setPicked(e.target.checked ? [...picked, a.id] : picked.filter(x => x !== a.id))} /><span><strong>{a.title}</strong>{a.status === "candidate" && <span className="ml-2 text-xs text-amber-500">Ещё не доступно для сборки</span>}<span className="mt-1 block text-xs text-muted-foreground">{a.note}</span></span></label>)}</div>
        <div className="flex flex-wrap gap-3"><label className="text-sm">Время, сек.<Input type="number" min={60} max={3600} value={timeout} onChange={e => setTimeout(Number(e.target.value))} /></label><label className="text-sm">Окно событий, дней (для будущих event-профилей)<Input type="number" min={1} max={30} value={days} onChange={e => setDays(Number(e.target.value))} /></label></div>
        <p className="text-xs text-muted-foreground" role="status">Лимит нормализованных источников: {selectedRowBudget.toLocaleString("ru-RU")} / 90 000 строк. Лимит не гарантирует полноту сбора и не ограничивает объём чтения.</p>
        <Button disabled={busy || selectedRowBudget > 90000 || !companyId || !name.trim() || !picked.length || timeout < 60 || timeout > 3600 || days < 1 || days > 30} onClick={() => void save()}>{busy ? "Сохранение…" : "Сохранить профиль"}</Button>
      </CardContent></Card>
      <section><div className="mb-2 flex items-center justify-between"><h2 className="text-lg font-semibold">Сохранённые профили</h2><span className="text-sm text-muted-foreground">{profiles.length}</span></div>{profiles.length === 0 ? <p className="rounded-xl border p-4 text-sm text-muted-foreground">Пока нет профилей.</p> : profiles.map(p => <div key={p.id} className="mb-2 flex flex-wrap items-center justify-between gap-3 rounded-xl border p-3"><div><strong>{p.name}</strong><p className="text-xs text-muted-foreground">{p.platform} · {p.artifacts.length} сбора · {p.timeout_seconds} сек. · {p.event_days} дн.</p></div><div className="flex gap-2"><a className="self-center text-xs underline" href={`/api/threat-hunting/profiles/${p.id}/spec?company_id=${companyId}`}>JSON</a><Button size="sm" disabled={busy || !buildPlatforms.includes(p.platform) || p.artifacts.some(a => !(p.platform === "windows" ? ["host", "processes", "network", "services", "tasks", "startup"] : ["host", "processes", "network", "linux_services", "linux_crontab", "linux_suid"]).includes(a))} onClick={() => void build(p)}>{busy ? "Создание…" : "Скачать сборщик"}</Button><Button size="sm" variant="outline" disabled={busy} onClick={() => void removeProfile(p)}>Удалить</Button></div></div>)}</section>
    </>}
    {collection && tab === "campaigns" && companyId && <div className="space-y-4"><div className="rounded-xl border bg-card p-4"><h2 className="font-semibold">Массовый сбор с нескольких хостов</h2><p className="mt-1 text-sm text-muted-foreground">Выберите профиль и список хостов, создайте задания сбора и отслеживайте прогресс. После получения архивов откройте результат для расследования; ошибочные задания можно повторить.</p></div><HuntingCampaigns companyId={companyId} profiles={profiles} onOpenResult={openInvestigation} /></div>}
    {!collection && companyId && <><HuntingDashboard mode={section === "hq" ? "hq" : section === "analytics" ? "analytics" : "investigations"} companyId={companyId} revision={revision} onOpenResult={openInvestigation} />{section === "investigations" && activeResult && <div id="hunting-investigation" className="space-y-3 rounded-lg border bg-card p-4"><div className="flex flex-wrap items-center justify-between gap-2"><h2 className="font-semibold">Расследование выбранного архива</h2><Button variant="outline" onClick={() => setActiveResult(null)}>Закрыть расследование</Button></div><HuntingResults key={activeResult} companyId={companyId} revision={revision} resultId={activeResult} onDeleted={resultsChanged} /></div>}</>}
    {collection && tab === "imports" && <>
      <Card><CardHeader><CardTitle>Загрузка результата</CardTitle></CardHeader><CardContent className="flex flex-wrap items-end gap-3"><Input className="min-w-64 flex-1" aria-label="Архив результатов" type="file" accept=".zip" onChange={e => setUpload(e.target.files?.[0] || null)} /><Button disabled={busy || !companyId || !upload} onClick={() => void importResult()}>{busy ? "Проверка…" : "Проверить и сохранить"}</Button>{summary && <span className="text-sm text-muted-foreground">Прочитано строк: {summary.total_rows}</span>}</CardContent></Card>
      {companyId && <HuntingResults key={companyId} companyId={companyId} revision={revision} historyOnly onOpenResult={openInvestigation} onDeleted={resultsChanged} />}
    </>}
      </div>
      <div role="status" aria-live="polite" className="flex flex-wrap items-center gap-2 border-t px-1 pt-3 text-xs text-muted-foreground"><span className={`h-1.5 w-1.5 rounded-full ${busy ? "motion-safe:animate-pulse bg-primary" : "bg-muted-foreground"}`} /><span>{busy ? "Обработка запроса" : "Нет активной операции профиля/импорта"}</span><span aria-hidden="true">·</span><span>tenant: {companyId || "не выбран"}</span><span aria-hidden="true">·</span><span>local collector · integrity verification</span></div>
    </section>
  </div>
}
