import { useEffect, useRef, useState } from "react"
import { Bell, BookOpen, Bot, FileText, LayoutDashboard, LoaderCircle, Menu, Monitor, Network, Palette, Radar, Settings, Siren, Crosshair, Users, UserRound, Waypoints } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import type { Theme, View } from "@/lib/types"
import { useApp } from "@/app-state"
import { Overview } from "@/pages/overview"
import { Incidents } from "@/pages/incidents"
import { Accounts, Devices } from "@/pages/lists"
import { Paths } from "@/pages/paths"
import { Reports } from "@/pages/reports"
import { Docs } from "@/pages/docs"
import { Scan } from "@/pages/scan"
import { Settings as SettingsPage } from "@/pages/settings"
import { Notices } from "@/pages/notices"
import { AssistantPage } from "@/components/assistant"
import { FindingCard } from "@/components/finding-card"
import { Notes } from "@/pages/notes"
import { Catalog } from "@/pages/catalog"
import { ProfilePage, SecurityPage } from "@/pages/profile"
import { RELEASES } from "@/lib/releases"
import { ScanDock } from "@/components/scan-progress"
import { Hunting } from "@/pages/hunting"

const NAV: { group: string; items: { id: View; icon: typeof LayoutDashboard }[] }[] = [
  { group: "nav.g.overview", items: [
    { id: "overview", icon: LayoutDashboard },
    { id: "catalog", icon: Network },
    { id: "incidents", icon: Siren },
    { id: "accounts", icon: Users },
    { id: "paths", icon: Waypoints },
    { id: "devices", icon: Monitor },
    { id: "reports", icon: FileText },
  ] },
  { group: "nav.g.platform", items: [
    { id: "scan", icon: Radar },
    { id: "hunting", icon: Crosshair },
    { id: "assistant", icon: Bot },
  ] },
]

const PINNED: { id: View; icon: typeof BookOpen }[] = [
  { id: "docs", icon: BookOpen },
  { id: "settings", icon: Settings },
]

export function Shell() {
  const app = useApp()
  const version = app.me?.version || "2.1.0"
  const [menu, setMenu] = useState(false)
  const [huntingExpanded, setHuntingExpanded] = useState(app.view.startsWith("hunting"))
  useEffect(() => { if (app.view.startsWith("hunting")) setHuntingExpanded(true) }, [app.view])
  const [bell, setBell] = useState(false)
  const [deliveryTick, setDeliveryTick] = useState(0)
  const [welcome, setWelcome] = useState(false)
  const [userMenu, setUserMenu] = useState(false)
  const userBox = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (app.me && localStorage.getItem("brosec-welcome") !== version) setWelcome(true)
  }, [app.me, version])
  const unread = app.notices.filter((row) => !row.read).length
  useEffect(() => {
    function close(event: MouseEvent) {
      if (!userBox.current?.contains(event.target as Node)) setUserMenu(false)
    }
    document.addEventListener("mousedown", close)
    return () => document.removeEventListener("mousedown", close)
  }, [])
  const pages: Record<View, React.ReactNode> = {
    overview: <Overview />,
    catalog: <Catalog />,
    incidents: <Incidents />,
    accounts: <Accounts />,
    paths: <Paths />,
    devices: <Devices />,
    reports: <Reports />,
    docs: <Docs />,
    scan: <Scan />,
    notices: <Notices deliveryTick={deliveryTick} />,
    settings: <SettingsPage />,
    assistant: <AssistantPage />,
    notes: <Notes />,
    profile: <ProfilePage />,
    security: <SecurityPage />,
    hunting: <Hunting key={app.companyId} section="hq" />,
    "hunting-investigations": <Hunting key={app.companyId} section="investigations" />,
    "hunting-analytics": <Hunting key={app.companyId} section="analytics" />,
    "hunting-collection": <Hunting key={app.companyId} section="collection" />,
  }

  function choose(view: View) {
    app.setView(view)
    setMenu(false)
    setBell(false)
  }

  function closeWelcome() {
    localStorage.setItem("brosec-welcome", version)
    setWelcome(false)
  }

  const nav = (
    <div className="flex h-full flex-col">
      <ScrollArea className="min-h-0 flex-1">
        <div className="flex items-center gap-3 px-2 pb-4">
          <img src="/static/logo.png" alt="" className="size-12 rounded-xl object-contain" />
          <div>
            <strong className="block text-sm">BroSec Audit AD</strong>
            <button type="button" className="text-muted-foreground hover:text-foreground text-left text-xs underline-offset-2 hover:underline" onClick={() => choose("notes")}>v{version}</button>
          </div>
        </div>
        {NAV.map((group) => (
          <div key={group.group} className="mb-3">
            <div className="text-muted-foreground px-3 py-1 text-[11px] tracking-wide uppercase">{app.t(group.group)}</div>
            {group.items.map((item) => {
              const Icon = item.icon
              if (item.id === "hunting") return <div key={item.id} className="mb-2">
                <div className="flex items-center gap-1">
                  <Button variant={app.view.startsWith("hunting") ? "secondary" : "ghost"} className="min-w-0 flex-1 justify-start" aria-expanded={huntingExpanded} aria-controls="hunting-subnav" onClick={() => { setHuntingExpanded(app.view.startsWith("hunting") ? !huntingExpanded : true); choose("hunting") }}><Icon />Threat Hunting</Button>
                  
                </div>
                {huntingExpanded && <nav id="hunting-subnav" aria-label="Разделы Threat Hunting" className="ml-4 mt-1 space-y-1 border-l pl-2">
                  {([ ["hunting", "Штаб безопасности"], ["hunting-investigations", "Анализ и расследования"], ["hunting-analytics", "Аналитика и отчёты"], ["hunting-collection", "Сбор и импорт"] ] as [View, string][]).map(([id, label]) => <Button key={id} variant={app.view === id ? "secondary" : "ghost"} aria-current={app.view === id ? "page" : undefined} className="h-auto min-h-9 w-full justify-start whitespace-normal py-2 text-left text-xs" onClick={() => choose(id)}>{label}</Button>)}
                </nav>}
              </div>
              return (
                <Button key={item.id} variant={app.view === item.id ? "secondary" : "ghost"} className="mb-1 w-full justify-start" onClick={() => choose(item.id)}>
                  <Icon />
                  {app.t("nav." + item.id)}
                </Button>
              )
            })}
          </div>
        ))}
      </ScrollArea>
      <div className="bg-muted/50 mt-2 grid gap-1 rounded-xl border p-1">
        {PINNED.map((item) => {
          const Icon = item.icon
          return (
            <Button key={item.id} variant={app.view === item.id ? "secondary" : "ghost"} className="w-full justify-start" onClick={() => choose(item.id)}>
              <Icon />
              {app.t("nav." + item.id)}
            </Button>
          )
        })}
      </div>
      <DomainStatus />
    </div>
  )

  return (
    <div className="bg-background flex min-h-svh">
      <aside className="bg-sidebar sticky top-0 hidden h-svh w-60 shrink-0 flex-col border-r p-3 lg:flex">{nav}</aside>
      <div className="min-w-0 flex-1">
        <header className="flex flex-wrap items-center gap-2 border-b px-3 py-3 md:px-5">
          <Button variant="outline" size="icon" className="lg:hidden" onClick={() => setMenu(true)}><Menu /></Button>
          <Input className="max-w-xl rounded-full" value={app.filters.q} placeholder={app.t("search")} onChange={(event) => app.patchFilters({ q: event.target.value })} />
          {app.me?.is_superadmin ? (
            <Select value={String(app.companyId || "")} onValueChange={(value) => void app.setCompany(Number(value))}>
              <SelectTrigger className="hidden w-48 sm:flex" disabled={app.companySwitching} aria-label="Активная компания">
                {app.companySwitching ? <span className="flex items-center gap-2"><LoaderCircle className="size-4 animate-spin" />Загрузка…</span> : <SelectValue />}
              </SelectTrigger>
              <SelectContent>
                {app.companies.map((row) => <SelectItem key={row.id} value={String(row.id)}>{row.name}</SelectItem>)}
              </SelectContent>
            </Select>
          ) : <span className="text-muted-foreground hidden truncate text-sm sm:block">{app.company?.name}</span>}
          {app.companySwitching ? <span className="text-muted-foreground hidden items-center gap-1 text-xs md:flex"><LoaderCircle className="size-3 animate-spin" />Контекст компании обновляется</span> : null}
          <div className="ml-auto flex items-center gap-1">
            <Button variant="outline" size="icon" className="relative" onClick={() => setBell(true)} aria-label={app.t("nav.notices")}>
              <Bell />
              {unread ? <span className="absolute -top-1 -right-1 grid min-w-5 place-items-center rounded-full bg-red-500 px-1 text-[10px] text-white">{unread}</span> : null}
            </Button>
            <Button variant="outline" size="sm" onClick={() => choose("assistant")}><Bot />{app.t("nav.assistant")}</Button>
            <ThemePalette />
            <Select value={app.lang} onValueChange={(value) => app.setLang(value as "ru" | "en")}>
              <SelectTrigger className="w-16"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="ru">RU</SelectItem>
                <SelectItem value="en">EN</SelectItem>
              </SelectContent>
            </Select>
            <div className="relative" ref={userBox}>
              <Button variant="outline" className="max-w-56 gap-2" onClick={() => setUserMenu((value) => !value)}>
                <span className="grid size-6 shrink-0 place-items-center rounded-full bg-gradient-to-br from-fuchsia-500 to-cyan-400 text-white shadow-[0_0_12px_rgba(217,70,239,0.45)]">
                  <UserRound className="size-3.5" />
                </span>
                <span className="truncate">{app.me?.full_name || app.me?.username || "Профиль"}</span>
              </Button>
              {userMenu ? (
                <div className="bg-popover absolute right-0 z-50 mt-1 w-56 rounded-xl border p-1 shadow">
                  <button type="button" className="hover:bg-muted w-full rounded-lg px-3 py-2 text-left text-sm" onClick={() => { setUserMenu(false); choose("profile") }}>Профиль пользователя</button>
                  <button type="button" className="hover:bg-muted w-full rounded-lg px-3 py-2 text-left text-sm" onClick={() => { setUserMenu(false); choose("security") }}>Безопасность</button>
                  <button type="button" className="hover:bg-muted w-full rounded-lg px-3 py-2 text-left text-sm" onClick={() => { setUserMenu(false); void app.logout() }}>{app.t("logout")}</button>
                </div>
              ) : null}
            </div>
          </div>
        </header>
        <main className="p-3 pb-24 md:p-5">
          {app.companySwitching ? <div className="mb-3 flex items-center gap-2 rounded-xl border border-sky-500/40 bg-sky-500/10 px-3 py-2 text-sm text-sky-700 dark:text-sky-300" role="status"><LoaderCircle className="size-4 animate-spin" /> Загружаем изолированный контекст выбранной компании…</div> : null}
          {app.directory && !app.directory.ok ? (
            <div className="mb-3 rounded-xl border border-red-500/50 bg-red-500/10 px-3 py-2 text-sm">Каталог не отвечает. {app.directory.detail || "Проверьте LDAP в настройках."}</div>
          ) : null}
          {app.notices.filter((row) => !row.read && row.kind === "error").slice(0, 2).map((row) => (
            <button key={row.id} type="button" className="mb-3 block w-full rounded-xl border border-red-500/50 bg-red-500/10 px-3 py-2 text-left text-sm" onClick={() => app.setView("notices")}>
              <span className="font-medium">{row.title}</span>
              <span className="text-muted-foreground mt-1 block text-xs">{row.body}</span>
            </button>
          ))}
          {pages[app.view]}
        </main>
      </div>
      {app.view !== "scan" && app.live && (app.liveStatus === "running" || app.liveStatus === "queued" || app.liveStatus === "failed" || (app.live.modules || []).some((item) => item.state === "error")) ? (
        <ScanDock data={app.live} fault={app.liveStatus === "failed" || (app.live.modules || []).some((item) => item.state === "error")} onOpen={() => app.setView("scan")} />
      ) : null}
      <Sheet open={menu} onOpenChange={setMenu}>
        <SheetContent side="left" className="w-72">
          <SheetHeader><SheetTitle>BroSec Audit AD</SheetTitle></SheetHeader>
          {nav}
        </SheetContent>
      </Sheet>
      <Sheet open={bell} onOpenChange={setBell}>
        <SheetContent className="w-full sm:max-w-md">
          <SheetHeader>
            <SheetTitle className="pr-10">{app.t("nav.notices")}{unread ? " · " + unread : ""}</SheetTitle>
          </SheetHeader>
          <div className="grid gap-2 px-4">
            <div className="flex gap-2">
              <Button variant="outline" size="icon" aria-label="Доставка" onClick={() => { setDeliveryTick((value) => value + 1); choose("notices"); setBell(false) }}>
                <Settings className="size-4" />
              </Button>
              <Button variant="outline" className="h-auto flex-1 whitespace-normal" onClick={() => void app.markAllNotices()}>{app.t("bell.read")}</Button>
            </div>
            <Button className="h-auto w-full whitespace-normal" onClick={() => choose("notices")}>{app.t("bell.open")}</Button>
          </div>
          <ScrollArea className="h-[calc(100vh-9rem)] px-4">
            <div className="grid gap-2 pb-6">
              {app.notices.length ? app.notices.slice(0, 20).map((row) => (
                <div key={row.id} className="rounded-lg border p-3">
                  <div className="flex items-start gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium">{row.title}</div>
                      <p className="text-muted-foreground text-xs">{row.body}</p>
                      <p className="text-muted-foreground mt-1 text-xs">{row.at}{row.read ? "" : " · новое"}</p>
                    </div>
                    <Button variant="ghost" size="sm" onClick={() => void app.deleteNotice(row.id)}>{app.t("bell.delete")}</Button>
                  </div>
                </div>
              )) : <p className="text-muted-foreground text-sm">{app.t("bell.empty")}</p>}
            </div>
          </ScrollArea>
        </SheetContent>
      </Sheet>
      <Dialog open={!!app.focus} onOpenChange={(open) => { if (!open) app.closeFinding() }}>
        <DialogContent className="max-h-[85vh] overflow-auto sm:max-w-3xl">
          <DialogHeader>
            <DialogTitle>{app.focus?.title}</DialogTitle>
            <DialogDescription>{app.focus?.category}</DialogDescription>
          </DialogHeader>
          {app.focus ? <FindingCard finding={app.focus} remedy={app.remedy} /> : null}
        </DialogContent>
      </Dialog>
      <Dialog open={welcome} onOpenChange={(open) => { if (!open) closeWelcome() }}>
        <DialogContent className="max-h-[85vh] overflow-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <span className="animate-pulse text-xl" aria-hidden="true">⚠️</span>
              Последние обновления
            </DialogTitle>
            <DialogDescription>BroSec Audit AD {version}</DialogDescription>
          </DialogHeader>
          <ul className="list-disc space-y-2 pl-4 text-sm">
            {(app.lang === "en" ? RELEASES[0].en : RELEASES[0].ru).map((line) => <li key={line}>{line}</li>)}
          </ul>
          <DialogFooter>
            <Button variant="outline" onClick={() => { closeWelcome(); choose("notes") }}>Посмотреть все обновления</Button>
            <Button onClick={closeWelcome}>{app.t("welcome.close")}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function ThemePalette() {
  const app = useApp()
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    function close(event: MouseEvent) {
      if (!box.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener("mousedown", close)
    return () => document.removeEventListener("mousedown", close)
  }, [])
  return (
    <div className="relative" ref={box}>
      <Button variant="outline" size="icon" aria-label="Тема" onClick={() => setOpen((value) => !value)}><Palette /></Button>
      {open ? (
        <div className="bg-popover absolute right-0 z-40 mt-2 w-44 rounded-lg border p-1">
          {(["dark", "light"] as Theme[]).map((theme) => (
            <Button key={theme} variant={app.theme === theme ? "secondary" : "ghost"} className="w-full justify-start" onClick={() => { app.setTheme(theme); setOpen(false) }}>
              <span className={"size-3 rounded-full " + (theme === "dark" ? "bg-zinc-700" : theme === "light" ? "bg-white ring-1 ring-zinc-300" : "bg-pink-500")} />
              {app.t("theme." + theme)}
            </Button>
          ))}
        </div>
      ) : null}
    </div>
  )
}

function DomainStatus() {
  const { directory, company } = useApp()
  const domain = directory?.domain || company?.domain || "Домен не задан"
  const online = !!directory?.ok
  return (
    <div className="mt-3 rounded-xl border px-3 py-2">
      <div className="flex items-center gap-2 text-sm font-medium">
        <span className="relative flex size-2.5 shrink-0">
          <span className={"absolute inline-flex size-full rounded-full opacity-70 " + (online ? "animate-ping bg-emerald-400" : "bg-red-400")} />
          <span className={"relative inline-flex size-2.5 rounded-full " + (online ? "bg-emerald-500" : "bg-red-500")} />
        </span>
        {online ? "Домен онлайн" : "Домен недоступен"}
      </div>
      <div className="mt-1 truncate text-xs">{domain}</div>
      <div className="text-muted-foreground truncate text-[11px]">
        {directory ? `${directory.mode} · ${directory.host || "хост не задан"}:${directory.port}` : "Проверяем каталог из настроек"}
      </div>
    </div>
  )
}
