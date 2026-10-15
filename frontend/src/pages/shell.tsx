import { useEffect, useState } from "react"
import { Bell, BookOpen, FileText, LayoutDashboard, Menu, Monitor, Radar, Settings, Siren, Upload, Users, Waypoints, Archive } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { incidentsOf } from "@/lib/findings"
import type { Theme, View } from "@/lib/types"
import { useApp } from "@/app-state"
import { Overview } from "@/pages/overview"
import { Incidents } from "@/pages/incidents"
import { Accounts, Devices } from "@/pages/lists"
import { Paths } from "@/pages/paths"
import { Reports } from "@/pages/reports"
import { Docs } from "@/pages/docs"
import { Scan } from "@/pages/scan"
import { PingCastle, SharpHound } from "@/pages/collectors"
import { Settings as SettingsPage } from "@/pages/settings"
import { Notices } from "@/pages/notices"
import { Assistant } from "@/components/assistant"

const NAV: { group: string; items: { id: View; icon: typeof LayoutDashboard }[] }[] = [
  { group: "nav.g.overview", items: [
    { id: "overview", icon: LayoutDashboard },
    { id: "incidents", icon: Siren },
    { id: "accounts", icon: Users },
    { id: "paths", icon: Waypoints },
    { id: "devices", icon: Monitor },
    { id: "reports", icon: FileText },
  ] },
  { group: "nav.g.manual", items: [
    { id: "pingcastle", icon: Upload },
    { id: "sharphound", icon: Archive },
  ] },
  { group: "nav.g.platform", items: [
    { id: "scan", icon: Radar },
    { id: "docs", icon: BookOpen },
    { id: "settings", icon: Settings },
  ] },
]

const CHANGELOG = {
  ru: [
    "Расписание сканирования задается днями недели и временем.",
    "Гигиена каталога дополнительно читает квоту компьютеров, делегирование, политику паролей, историю SID, режим домена и соседние признаки. Билеты и хеши не запрашиваются.",
    "Справочник показывает уровень риска. Правила PingCastle появляются только по найденным в отчете проблемам.",
    "Названия выпусков Windows больше не теряют русские буквы.",
    "Версия продукта теперь видна при входе. Это окно показывается один раз для каждой версии.",
    "История сканирований: когда и кем запущена проверка, в том числе по расписанию.",
    "В настройках журнал аудита: входы в консоль и изменения настроек. Пароли туда не пишутся.",
    "Колокольчик показывает непрочитанные события: конец сканирования и загрузка отчетов.",
    "Настройки сворачиваются. Суперадминистратор может удалить компанию и пользователя.",
    "Блок «что исчезло» сравнивает только два отчета PingCastle. Живые графики показывают текущий каталог.",
    "Живой статус каталога внизу меню: зеленый, если домен из настроек отвечает.",
    "Справочник PingCastle открывается карточками: что проверяется, на что влияет и как исправить.",
    "Настрой LDAP/LDAPS, установи BloodHound и PingCastle и приступай к сканированию!",
  ],
  en: [
    "The product version is shown at sign-in. This window appears once for each version.",
    "Scan history records when a check ran and who started it, including the schedule.",
    "Settings has an audit log of console sign-ins and setting changes. Passwords are not stored there.",
    "The bell counts unread events: a finished scan and an uploaded report.",
    "Settings sections collapse. A superadmin can delete a company and a user.",
    "The appeared and disappeared lists compare two PingCastle reports only. Live charts show the current directory.",
    "The directory status sits at the bottom of the menu and turns green when the configured domain answers.",
    "PingCastle reference cards explain the check, the impact, and the fix.",
    "Set LDAP or LDAPS, install BloodHound and PingCastle, and start the scan.",
  ],
} as const

export function Shell() {
  const app = useApp()
  const version = app.me?.version || "2.1.0"
  const [menu, setMenu] = useState(false)
  const [bell, setBell] = useState(false)
  const [welcome, setWelcome] = useState(false)
  useEffect(() => {
    if (app.me && localStorage.getItem("brosec-welcome") !== version) setWelcome(true)
  }, [app.me, version])
  const crit = incidentsOf(app.inventory).filter((row) => row.severity === "critical").length
  const unread = app.notices.filter((row) => !row.read).length
  const pages: Record<View, React.ReactNode> = {
    overview: <Overview />,
    incidents: <Incidents />,
    accounts: <Accounts />,
    paths: <Paths />,
    devices: <Devices />,
    reports: <Reports />,
    docs: <Docs />,
    scan: <Scan />,
    pingcastle: <PingCastle />,
    sharphound: <SharpHound />,
    notices: <Notices />,
    settings: <SettingsPage />,
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
          <img src="/static/logo.png" alt="" className="size-10 rounded-xl object-cover" />
          <div>
            <strong className="block text-sm">BroSec Audit AD</strong>
            <span className="text-muted-foreground text-xs">v{version}</span>
          </div>
        </div>
        {NAV.map((group) => (
          <div key={group.group} className="mb-3">
            <div className="text-muted-foreground px-3 py-1 text-[11px] tracking-wide uppercase">{app.t(group.group)}</div>
            {group.items.map((item) => {
              const Icon = item.icon
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
              <SelectTrigger className="hidden w-48 sm:flex"><SelectValue /></SelectTrigger>
              <SelectContent>
                {app.companies.map((row) => <SelectItem key={row.id} value={String(row.id)}>{row.name}</SelectItem>)}
              </SelectContent>
            </Select>
          ) : <span className="text-muted-foreground hidden truncate text-sm sm:block">{app.company?.name}</span>}
          <div className="ml-auto flex items-center gap-1">
            <Button variant="outline" size="sm" onClick={() => { app.patchFilters({ sev: "critical", status: "", category: "", source: "", tactic: "" }); choose("incidents") }}>
              {crit} {app.t("crit.badge")}
            </Button>
            <Button variant="outline" size="icon" className="relative" onClick={() => setBell(true)} aria-label={app.t("nav.notices")}>
              <Bell />
              {unread ? <span className="absolute -top-1 -right-1 grid min-w-5 place-items-center rounded-full bg-red-500 px-1 text-[10px] text-white">{unread}</span> : null}
            </Button>
            {(["dark", "light", "cyber"] as Theme[]).map((theme) => (
              <Button key={theme} size="sm" variant={app.theme === theme ? "secondary" : "outline"} onClick={() => app.setTheme(theme)}>{app.t("theme." + theme)}</Button>
            ))}
            <Select value={app.lang} onValueChange={(value) => app.setLang(value as "ru" | "en")}>
              <SelectTrigger className="w-16"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="ru">RU</SelectItem>
                <SelectItem value="en">EN</SelectItem>
              </SelectContent>
            </Select>
            <span className="text-muted-foreground hidden max-w-32 truncate text-sm md:block">{app.me?.full_name || app.me?.username}</span>
            <Button variant="outline" onClick={() => void app.logout()}>{app.t("logout")}</Button>
          </div>
        </header>
        <main className="p-3 pb-16 md:p-5">{pages[app.view]}</main>
      </div>
      <Sheet open={menu} onOpenChange={setMenu}>
        <SheetContent side="left" className="w-72">
          <SheetHeader><SheetTitle>BroSec Audit AD</SheetTitle></SheetHeader>
          {nav}
        </SheetContent>
      </Sheet>
      <Assistant />
      <Sheet open={bell} onOpenChange={setBell}>
        <SheetContent className="w-full sm:max-w-md">
          <SheetHeader>
            <SheetTitle>{app.t("nav.notices")}{unread ? " · " + unread : ""}</SheetTitle>
          </SheetHeader>
          <div className="grid gap-2 px-4">
            <Button variant="outline" className="h-auto w-full whitespace-normal" onClick={() => void app.markAllNotices()}>{app.t("bell.read")}</Button>
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
      <Dialog open={!!app.remedy} onOpenChange={(open) => { if (!open) app.closeFinding() }}>
        <DialogContent className="max-h-[85vh] overflow-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{app.remedy?.title}</DialogTitle>
            <DialogDescription>{app.remedy?.cis} · {app.remedy?.gost}</DialogDescription>
          </DialogHeader>
          <p className="text-sm">{app.remedy?.mitre} · {app.remedy?.tactic} · {app.remedy?.technique}</p>
          <p className="text-sm">{app.remedy?.impact} {app.remedy?.closure}</p>
          <p className="text-sm">{app.remedy?.summary}</p>
          <ol className="list-decimal space-y-1 pl-4 text-sm">
            {(app.remedy?.steps || []).map((stepText) => <li key={stepText}>{stepText}</li>)}
          </ol>
          <pre className="bg-muted overflow-auto rounded-lg p-3 text-xs whitespace-pre-wrap">{app.remedy?.powershell}</pre>
          <DialogFooter>
            <Button onClick={() => void navigator.clipboard.writeText(app.remedy?.powershell || "")}>{app.t("copy.ps")}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={welcome} onOpenChange={(open) => { if (!open) closeWelcome() }}>
        <DialogContent className="max-h-[85vh] overflow-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <span className="relative flex size-2.5 shrink-0" aria-hidden="true">
                <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-70" />
                <span className="relative inline-flex size-2.5 rounded-full bg-emerald-500" />
              </span>
              <span className="animate-pulse" aria-hidden="true">⚠️</span>
              BroSec Audit AD {version}
            </DialogTitle>
            <DialogDescription>
              {app.lang === "en" ? "What changed in this version." : "Что изменилось в этой версии."}
            </DialogDescription>
          </DialogHeader>
          <ul className="list-disc space-y-2 pl-4 text-sm">
            {CHANGELOG[app.lang].map((line) => <li key={line}>{line}</li>)}
          </ul>
          <DialogFooter>
            <Button onClick={closeWelcome}>{app.t("welcome.close")}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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
