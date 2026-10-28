import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react"
import { toast } from "sonner"
import { ApiError, api } from "@/lib/api"
import { translate } from "@/lib/i18n"
import type { ScanProgressData } from "@/components/scan-progress"
import type { Company, Compare, DirectoryLink, Filters, Finding, Lang, Me, MitreChip, Notice, Remedy, ScanRow, Scheduler, Theme, TimelinePoint, View } from "@/lib/types"

type Dashboard = {
  company: Company
  kpis: { scheduler: Scheduler }
  timeline: TimelinePoint[]
  inventory: Finding[]
  demo_profile: boolean
  compare: Compare | null
  mitre: MitreChip[]
}

type Ctx = {
  loading: boolean
  me: Me | null
  companies: Company[]
  companyId: number | null
  companySwitching: boolean
  company: Company | null
  inventory: Finding[]
  timeline: TimelinePoint[]
  compare: Compare | null
  mitre: MitreChip[]
  demo: boolean
  scheduler: Scheduler | null
  view: View
  lang: Lang
  theme: Theme
  filters: Filters
  remedy: Remedy | null
  focus: Finding | null
  statusTick: number
  notices: Notice[]
  directory: DirectoryLink | null
  live: ScanProgressData | null
  liveStatus: string
  watchScan: (id: number) => void
  t: (key: string) => string
  login: (username: string, password: string) => Promise<"ok" | "totp">
  confirmTotp: (code: string) => Promise<void>
  logout: () => Promise<void>
  refreshMe: () => Promise<void>
  setView: (view: View) => void
  setLang: (lang: Lang) => void
  setTheme: (theme: Theme) => void
  patchFilters: (patch: Partial<Filters>) => void
  setCompany: (id: number) => Promise<void>
  reload: () => Promise<void>
  openFinding: (row: Finding) => Promise<void>
  closeFinding: () => void
  bumpStatus: () => void
  markNotice: (id: number) => Promise<void>
  markAllNotices: () => Promise<void>
  deleteNotice: (id: number) => Promise<void>
}

const AppCtx = createContext<Ctx | null>(null)

const THEMES: Theme[] = ["dark", "light"]

function storedTheme(): Theme {
  const saved = localStorage.getItem("brosec-theme")
  return THEMES.includes(saved as Theme) ? (saved as Theme) : "dark"
}

function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme
  document.documentElement.classList.toggle("dark", theme !== "light")
  localStorage.setItem("brosec-theme", theme)
}

const emptyFilters: Filters = { q: "", sev: "", status: "", category: "", source: "", tactic: "" }

const VIEWS: readonly View[] = ["overview", "incidents", "accounts", "paths", "devices", "reports", "docs", "scan", "notices", "settings", "assistant", "notes", "catalog", "profile", "security", "hunting", "hunting-investigations", "hunting-analytics", "hunting-collection"]

function viewFromLocation(): View {
  const raw = (window.history.state?.view || window.location.hash.replace("#", "")) as string
  return (VIEWS as readonly string[]).includes(raw) ? (raw as View) : "overview"
}

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [loading, setLoading] = useState(true)
  const [me, setMe] = useState<Me | null>(null)
  const [companies, setCompanies] = useState<Company[]>([])
  const [companyId, setCompanyId] = useState<number | null>(null)
  const [companySwitching, setCompanySwitching] = useState(false)
  const [company, setCompanyState] = useState<Company | null>(null)
  const [inventory, setInventory] = useState<Finding[]>([])
  const [timeline, setTimeline] = useState<TimelinePoint[]>([])
  const [compare, setCompare] = useState<Compare | null>(null)
  const [mitre, setMitre] = useState<MitreChip[]>([])
  const [demo, setDemo] = useState(false)
  const [scheduler, setScheduler] = useState<Scheduler | null>(null)
  const [view, setViewState] = useState<View>(viewFromLocation)
  const viewRef = useRef(view)
  viewRef.current = view
  const setView = useCallback((next: View) => {
    if (viewRef.current === next) return
    viewRef.current = next
    setViewState(next)
    const url = window.location.pathname + window.location.search + "#" + next
    window.history.pushState({ view: next }, "", url)
  }, [])
  const [lang, setLangState] = useState<Lang>((localStorage.getItem("brosec-lang") as Lang) || "ru")
  const [theme, setThemeState] = useState<Theme>(storedTheme)
  const [filters, setFilters] = useState<Filters>(emptyFilters)
  const [remedy, setRemedy] = useState<Remedy | null>(null)
  const [focus, setFocus] = useState<Finding | null>(null)
  const [statusTick, setStatusTick] = useState(0)
  const [notices, setNotices] = useState<Notice[]>([])
  const [directory, setDirectory] = useState<DirectoryLink | null>(null)
  const [live, setLive] = useState<ScanProgressData | null>(null)
  const [liveStatus, setLiveStatus] = useState("")
  const scanStamp = useRef("")
  const watchToken = useRef(0)
  const watchedId = useRef(0)
  const activeCompany = useRef<number | null>(null)
  const dashboardRequest = useRef(0)
  const findingRequest = useRef(0)
  const switchRequest = useRef(0)

  const clearTenant = useCallback(() => {
    ++dashboardRequest.current
    ++findingRequest.current
    ++watchToken.current
    watchedId.current = 0
    scanStamp.current = ""
    setCompanyState(null)
    setInventory([])
    setTimeline([])
    setCompare(null)
    setMitre([])
    setScheduler(null)
    setDemo(false)
    setDirectory(null)
    setLive(null)
    setLiveStatus("")
    setFocus(null)
    setRemedy(null)
    setFilters(emptyFilters)
  }, [])

  useEffect(() => {
    const onPop = () => {
      const next = viewFromLocation()
      viewRef.current = next
      setViewState(next)
    }
    window.addEventListener("popstate", onPop)
    const start = viewFromLocation()
    window.history.replaceState({ view: start }, "", window.location.pathname + window.location.search + "#" + start)
    return () => window.removeEventListener("popstate", onPop)
  }, [])

  const watchScan = useCallback((id: number) => {
    watchedId.current = id
    const token = ++watchToken.current
    const tick = async () => {
      if (watchToken.current !== token) return
      try {
        const scan = await api<{ status: string; progress: ScanProgressData | null }>("/api/scans/" + id)
        if (watchToken.current !== token) return
        setLiveStatus(scan.status || "")
        if (scan.progress) setLive({ ...scan.progress, status: scan.status })
        if (scan.status === "queued" || scan.status === "running") {
          window.setTimeout(() => void tick(), 2000)
        } else if (watchedId.current === id) {
          watchedId.current = 0
        }
      } catch {
        if (watchToken.current === token) setLiveStatus("")
      }
    }
    void tick()
  }, [])

  const t = useCallback((key: string) => translate(lang, key), [lang])

  const loadDashboard = useCallback(async (id: number) => {
    if (activeCompany.current !== id) return
    const request = ++dashboardRequest.current
    const data = await api<Dashboard>("/api/dashboard?company_id=" + id)
    if (activeCompany.current !== id || dashboardRequest.current !== request) return
    if (data.company.id !== id) throw new Error("Ответ не соответствует выбранной компании")
    setCompanyState(data.company)
    setInventory(data.inventory || [])
    setTimeline(data.timeline || [])
    setCompare(data.compare || null)
    setMitre(data.mitre || [])
    setDemo(!!data.demo_profile)
    setScheduler(data.kpis?.scheduler || null)
  }, [])

  const loadCompanies = useCallback(async (user: Me, preferred?: number | null) => {
    const rows = await api<Company[]>("/api/companies")
    setCompanies(rows)
    if (!rows.length) {
      activeCompany.current = null
      clearTenant()
      setCompanyId(null)
      setCompanyState(null)
      setInventory([])
      return
    }
    const id = preferred || user.company_id || rows[0].id
    const chosen = rows.some((row) => row.id === id) ? id : rows[0].id
    if (activeCompany.current !== chosen) clearTenant()
    activeCompany.current = chosen
    setCompanyId(chosen)
    await loadDashboard(chosen)
  }, [clearTenant, loadDashboard])

  const boot = useCallback(async () => {
    const user = await api<Me>("/api/me")
    setMe(user)
    await loadCompanies(user)
  }, [loadCompanies])

  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  useEffect(() => {
    api<Me>("/api/me")
      .then((user) => {
        setMe(user)
        return loadCompanies(user)
      })
      .catch((error: unknown) => {
        if (!(error instanceof ApiError && error.status === 401)) {
          toast.error(error instanceof Error ? error.message : "Сессия не открылась")
        }
        setMe(null)
      })
      .finally(() => setLoading(false))
  }, [loadCompanies])

  const login = useCallback(async (username: string, password: string) => {
    const data = await api<{ need_totp?: boolean }>("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    })
    if (data.need_totp) return "totp" as const
    setLoading(true)
    try {
      await boot()
    } finally {
      setLoading(false)
    }
    return "ok" as const
  }, [boot])

  const confirmTotp = useCallback(async (code: string) => {
    await api("/api/login/totp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    })
    setLoading(true)
    try {
      await boot()
    } finally {
      setLoading(false)
    }
  }, [boot])

  const refreshMe = useCallback(async () => {
    const user = await api<Me>("/api/me")
    setMe(user)
  }, [])

  const logout = useCallback(async () => {
    await api("/api/logout", { method: "POST" })
    ++switchRequest.current
    activeCompany.current = null
    clearTenant()
    setCompanyId(null)
    setCompanySwitching(false)
    setMe(null)
  }, [clearTenant])

  const setLang = useCallback((next: Lang) => {
    localStorage.setItem("brosec-lang", next)
    document.documentElement.lang = next
    setLangState(next)
  }, [])

  const setTheme = useCallback((next: Theme) => {
    applyTheme(next)
    setThemeState(next)
  }, [])

  const patchFilters = useCallback((patch: Partial<Filters>) => {
    setFilters((current) => ({ ...current, ...patch }))
  }, [])

  const setCompany = useCallback(async (id: number) => {
    if (!Number.isSafeInteger(id) || !companies.some(row => row.id === id) || id === activeCompany.current) return
    const request = ++switchRequest.current
    clearTenant()
    activeCompany.current = id
    setCompanySwitching(true)
    setCompanyId(id)
    try {
      await loadDashboard(id)
    } catch (error) {
      if (switchRequest.current !== request) return
      activeCompany.current = null
      clearTenant()
      setCompanyId(null)
      toast.error(error instanceof Error ? error.message : "Компания не загрузилась")
    } finally {
      if (switchRequest.current === request) setCompanySwitching(false)
    }
  }, [companies, clearTenant, loadDashboard])

  const reload = useCallback(async () => {
    if (!me) return
    await loadCompanies(me, companyId)
  }, [companyId, loadCompanies, me])

  const refreshNotices = useCallback(async () => {
    const rows = await api<Notice[]>("/api/notices")
    setNotices(rows)
  }, [])

  const markNotice = useCallback(async (id: number) => {
    await api("/api/notices/" + id + "/read", { method: "POST" })
    setNotices((current) => current.map((row) => row.id === id ? { ...row, read: true } : row))
  }, [])

  const markAllNotices = useCallback(async () => {
    await api("/api/notices/read-all", { method: "POST" })
    setNotices((current) => current.map((row) => ({ ...row, read: true })))
  }, [])

  const deleteNotice = useCallback(async (id: number) => {
    await api("/api/notices/" + id, { method: "DELETE" })
    setNotices((current) => current.filter((row) => row.id !== id))
  }, [])

  const openFinding = useCallback(async (row: Finding) => {
    if (!row?.vuln_id) return
    const request = ++findingRequest.current
    const tenant = activeCompany.current
    setFocus(row)
    setRemedy(null)
    try {
      const data = await api<Remedy>("/api/remediation/" + encodeURIComponent(row.vuln_id))
      if (findingRequest.current === request && activeCompany.current === tenant) setRemedy(data)
    } catch (error) {
      if (findingRequest.current !== request || activeCompany.current !== tenant) return
      toast.error(error instanceof Error ? error.message : "Инструкция не открылась")
    }
  }, [])

  useEffect(() => {
    if (!me || !companyId) return
    let alive = true
    scanStamp.current = ""
    const tick = async () => {
      if (document.visibilityState !== "visible") return
      try {
        const rows = await api<ScanRow[]>("/api/scans?company_id=" + companyId)
        if (!alive || activeCompany.current !== companyId) return
        const active = rows.find((row) => row.status === "running" || row.status === "queued")
        if (alive && active && watchedId.current !== active.id) watchScan(active.id)
        const latest = rows.find((row) => row.status === "success" || row.status === "partial" || row.status === "failed")
        const next = latest ? latest.id + ":" + latest.status + ":" + latest.finished_at : ""
        if (alive && scanStamp.current && next && next !== scanStamp.current) {
          await loadDashboard(companyId)
        }
        if (!alive || activeCompany.current !== companyId) return
        if (next) scanStamp.current = next
        if (alive) await refreshNotices()
        if (alive) {
          const link = await api<DirectoryLink>("/api/directory/status?company_id=" + companyId)
          if (alive && activeCompany.current === companyId) setDirectory(link)
        }
      } catch {
        /* следующий цикл повторит запрос */
      }
    }
    void tick()
    const timer = window.setInterval(() => void tick(), 15000)
    return () => {
      alive = false
      window.clearInterval(timer)
    }
  }, [companyId, loadDashboard, me, refreshNotices, watchScan])

  const value = useMemo<Ctx>(() => ({
    loading, me, companies, companyId, companySwitching, company, inventory, timeline, compare, mitre, demo, scheduler,
    view, lang, theme, filters, remedy, focus, statusTick, notices, directory, live, liveStatus, watchScan, t, login, confirmTotp, logout, refreshMe, setView, setLang, setTheme,
    patchFilters, setCompany, reload, openFinding, closeFinding: () => { ++findingRequest.current; setRemedy(null); setFocus(null) },
    bumpStatus: () => setStatusTick((n) => n + 1),
    markNotice, markAllNotices, deleteNotice,
  }), [
    loading, me, companies, companyId, companySwitching, company, inventory, timeline, compare, mitre, demo, scheduler,
    view, lang, theme, filters, remedy, focus, statusTick, notices, directory, live, liveStatus, watchScan, t, login, confirmTotp, logout, refreshMe, setLang, setTheme,
    patchFilters, setCompany, reload, openFinding, markNotice, markAllNotices, deleteNotice,
  ])

  return <AppCtx.Provider value={value}>{children}</AppCtx.Provider>
}

export function useApp() {
  const ctx = useContext(AppCtx)
  if (!ctx) throw new Error("useApp")
  return ctx
}
