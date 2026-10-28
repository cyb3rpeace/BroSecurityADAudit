import { useEffect, useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { PageHead } from "@/components/bits"
import { Donut, Bars } from "@/components/charts"
import { api } from "@/lib/api"
import { palette } from "@/lib/findings"
import { useApp } from "@/app-state"

type Picture = {
  ok: boolean
  message?: string
  domain?: string
  level?: string
  policy?: { length: string; history: string; lockout: string; max_age_days: string }
  roles?: string[]
  dcs?: { name: string; host: string; os: string }[]
  sites?: { name: string; servers: string[] }[]
  subnets?: { name: string; site: string }[]
  zones?: string[]
  ous?: string[]
  ou_nodes?: { name: string; path: string; blocked?: boolean; links?: { guid: string; enabled: boolean; enforced: boolean }[] }[]
  domains?: string[]
  groups?: { name: string; security: boolean; members?: string[]; member_count?: number }[]
  gpos?: { id?: string; name: string; state: string; wmi?: string }[]
  wmi?: { id: string; name: string; note: string; query: string }[]
  service_accounts?: { name: string; host: string; kind: string; disabled: boolean }[]
  domain_links?: { guid: string; enabled: boolean; enforced: boolean }[]
  domain_block?: boolean
  coverage?: Coverage
  trusts?: { name: string; direction: string; kind: string; sid_filter: boolean | null; selective: boolean | null; trust_attributes?: number | null; trust_type?: number | null; direction_value?: number | null; supported_encryption_types?: number | null; sid_filter_mode?: string; assessment?: { code: string; severity: string; title: string; detail: string }[]; limitations?: string[] }[]
}

type ControllerCard = {
  host: string
  ok?: boolean
  detail?: string
  failed_24h?: string
  locked_24h?: string
  maker?: string
  model?: string
  ram_gb?: string
  ram_free_pct?: string
  cpu?: string
  disk_free_pct?: string
  bios?: string
  volumes?: { drive: string; size_gb: string; free_pct: string }[]
  nics?: { name: string; address: string }[]
  diag?: { test: string; ok: boolean }[]
  ntds_mb?: string
  boot_days?: string
  hotfix_ms14?: string
}

type ZoneRow = {
  name: string
  type: string
  scope: string
  dynamic: string
  transfer: string
  aging: boolean | null
  reverse: boolean
  signed?: boolean | null
}

type CoverageSection = { state: string; method?: string; limitations?: string[] }
type Coverage = { contract?: string; meaning?: string; scope?: { discovered_dcs?: number; probed_dcs?: number; readable_dcs?: number }; sections?: Record<string, CoverageSection> }

type WindowsView = {
  gpo_collection?: { link_metadata?: { state: string; scopes_read: number; parse_errors: number; limit_reached: boolean; limitations: string[]; scopes: { structural_inheritance?: { state: string; missing_ancestors: string[]; candidate_links: { name: string; source_dn: string; inherited: boolean; enforced: boolean }[]; blocked_links: unknown[] }; dn: string; block_inheritance: boolean; links: { name: string; order: number; enabled: boolean; enforced: boolean }[] }[] }; ok?: boolean; collection_state?: string; effective_policy_verified?: boolean; collection?: { inf_files_read?: number; registry_files_read?: number; read_or_parse_errors?: number; limits_reached?: boolean; settings_compared?: number; conflicts_truncated?: boolean; baseline_truncated?: boolean }; limitations?: string[] }
  ok: boolean
  message?: string
  controllers?: ControllerCard[]
  conflicts?: { key: string; title?: string; values: { gpo: string; value: string }[] }[]
  replication?: { source: string; partner: string; partition: string; hours: string; state: string }[]
  dns?: { ok: boolean; message?: string; zones?: ZoneRow[]; locator?: { name: string; ok: boolean }[]; wildcard?: boolean | null; collection_state?: string; forwarders_collected?: boolean; acl?: { state: string; aces_checked?: number | null; broad_write_principals?: number | null; unresolved_aces?: number | null; zones_checked?: number | null; acl_errors?: number | null; message?: string }; resolver_state?: string; forwarder_probe_state?: string; probe_method?: string; resolvers?: { server: string; position: number | null; is_self: boolean | null; reachable: boolean | null; interface_index?: string | null }[]; forwarder_probes?: { server: string; kind?: string; reachable: boolean | null }[]; advanced_assessment?: { code: string; severity: string; title: string; detail: string; evidence: Record<string, unknown> }[]; assessment?: { zone: string; code: string; severity: string; title: string; detail: string; evidence: Record<string, string> }[]; limitations?: string[]; composition?: Record<string, Record<string, number>>; forwarders?: string[]; conditional?: { name: string; masters: string }[]; stale?: { name: string; target: string }[]; scavenging?: { enabled: boolean | null; interval: string; no_refresh: string; refresh: string } }
  baseline?: { key: string; title: string; gpo: string; value: string; expected: string; ok: boolean }[]
  trusts?: { name: string; reachable: boolean }[]
  coverage?: Coverage
}

type Pick = { title: string; lines: string[] }

const POSTURE = ["ldap_signing_not_required", "smb_signing_off", "ldap_channel_binding", "ntlmv1_allowed", "llmnr_enabled", "print_spooler_on_dc", "webclient_running", "time_skew"]
const SECTIONS = [
  ["suite", "Обзор"],
  ["topology", "Топология"],
  ["accounts", "Учётные записи"],
  ["groups", "Группы и OU"],
  ["dns", "DNS"],
  ["trusts", "Доверия"],
  ["gpo", "Политики"],
  ["dcs", "Контроллеры"],
  ["posture", "Защита контроллеров"],
] as const

function tone(ok: boolean) {
  return ok ? "border-emerald-500/40 bg-emerald-500/10" : "border-red-500/40 bg-red-500/10"
}

function shortName(value: string) {
  return value.split(".")[0].replace(/^CN=/i, "").replace(/^DC=/i, "").toLowerCase()
}

function dnsName(value: string) {
  if (!value) return ""
  if (!/DC=/i.test(value)) return value
  return value.split(",").filter((part) => part.toUpperCase().startsWith("DC=")).map((part) => part.slice(3)).join(".")
}

function sameHost(left: string, right: string) {
  if (!left || !right) return false
  return left.toLowerCase() === right.toLowerCase() || shortName(left) === shortName(right)
}

function Meter({ label, used }: { label: string; used: number }) {
  const width = Math.max(0, Math.min(100, used))
  const tone = width >= 90 ? "bg-red-500" : width >= 75 ? "bg-amber-400" : "bg-cyan-400"
  return (
    <div>
      <div className="mb-1 flex justify-between text-[11px]"><span>{label}</span><span>{width}%</span></div>
      <div className="bg-muted h-2 overflow-hidden rounded-full"><div className={"h-full " + tone} style={{ width: width + "%" }} /></div>
    </div>
  )
}

function OuTree({ nodes, gpos, onPick }: { nodes: { name: string; path: string; blocked?: boolean; links?: { guid: string; enabled: boolean; enforced: boolean }[] }[]; gpos: { id?: string; name: string }[]; onPick: (item: Pick) => void }) {
  type Node = { name: string; path: string; blocked?: boolean; links?: { guid: string; enabled: boolean; enforced: boolean }[]; children: Node[] }
  const index = new Map<string, Node>()
  const roots: Node[] = []
  const titleOf = (guid: string) => gpos.find((row) => (row.id || "").toLowerCase() === guid.toLowerCase())?.name || guid || "политика без имени"
  for (const item of [...nodes].sort((left, right) => left.path.localeCompare(right.path))) {
    const node: Node = { name: item.name, path: item.path, blocked: item.blocked, links: item.links, children: [] }
    index.set(item.path, node)
    const parentPath = item.path.includes("/") ? item.path.slice(0, item.path.lastIndexOf("/")) : ""
    const parent = parentPath ? index.get(parentPath) : undefined
    if (parent) parent.children.push(node)
    else roots.push(node)
  }
  const draw = (list: Node[], depth: number) => list.map((node) => (
    <div key={node.path}>
      <button type="button" className="hover:bg-muted/50 block w-full border-b py-2 text-left text-sm" style={{ paddingLeft: 12 + depth * 16 }} onClick={() => onPick({ title: node.name, lines: ["Путь: " + node.path, node.blocked ? "Наследование политик заблокировано" : "Наследование политик не блокируется", ...(node.links || []).map((link) => (link.enabled ? "Включена" : "Выключена") + (link.enforced ? ", принудительно" : "") + ": " + titleOf(link.guid)), (node.links || []).length ? "Показаны привязки этого подразделения." : "Своих привязок нет. Действуют унаследованные."] })}>
        <span>{node.name}</span>
        <span className="text-muted-foreground ml-2 text-xs">{(node.links || []).length ? (node.links || []).length + " пол." : ""}{node.blocked ? " блок" : ""}</span>
      </button>
      {draw(node.children, depth + 1)}
    </div>
  ))
  return <div>{draw(roots, 0)}</div>
}

function Kpis({ items }: { items: { label: string; value: string; bad?: boolean }[] }) {
  return (
    <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
      {items.map((item) => (
        <div key={item.label} className={"rounded-xl border px-3 py-2 " + (item.bad ? "border-red-500/40" : "")}>
          <div className="text-muted-foreground text-xs">{item.label}</div>
          <div className="text-xl font-medium">{item.value}</div>
        </div>
      ))}
    </div>
  )
}

type LinkRow = { source: string; partner: string; partition: string; hours: string; state: string }

function Topology({
  domain,
  domains,
  sites,
  subnets,
  roles,
  links,
  onPick,
}: {
  domain: string
  domains: string[]
  sites: { name: string; servers: string[] }[]
  subnets: { name: string; site: string }[]
  roles: string[]
  links: LinkRow[]
  onPick: (item: Pick) => void
}) {
  const [mode, setMode] = useState<"all" | "fail" | "fsmo">("all")
  const current = dnsName(domain)
  const others = domains.filter((name) => name.toLowerCase() !== current.toLowerCase())
  const fsmo = new Set(roles.map((name) => shortName(name)))
  const knownSites = new Set(sites.map((site) => site.name.toLowerCase()))
  const loose = subnets.filter((row) => !row.site || !knownSites.has(row.site.toLowerCase()))
  const worst = (server: string) => {
    const mine = links.filter((link) => shortName(link.source) === shortName(server) || shortName(link.partner) === shortName(server))
    if (!mine.length) return "нет данных"
    if (mine.some((link) => link.state !== "норма")) return "сбой"
    return "норма"
  }
  const shown = sites.filter((site) => {
    if (mode === "fsmo") return site.servers.some((server) => fsmo.has(shortName(server)))
    if (mode === "fail") return site.servers.some((server) => worst(server) === "сбой")
    return true
  })
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" size="sm" variant={mode === "all" ? "default" : "outline"} onClick={() => setMode("all")}>Все сайты</Button>
        <Button type="button" size="sm" variant={mode === "fail" ? "default" : "outline"} onClick={() => setMode("fail")}>Только сбой репликации</Button>
        <Button type="button" size="sm" variant={mode === "fsmo" ? "default" : "outline"} onClick={() => setMode("fsmo")}>Только FSMO</Button>
      </div>
      <p className="text-muted-foreground text-xs">Карта показывает, в каком сайте стоит контроллер, какие подсети к нему ходят и дошла ли репликация. В списке только контроллеры: у них в сайте есть служба NTDS. Обычный сервер, зарегистрированный в том же сайте, контроллером не становится и сюда не попадает. Имена других доменов леса — только справка.</p>
      <div className="rounded-xl border border-fuchsia-500/40 p-3">
        <div className="text-xs text-fuchsia-400">Домен, который читаем</div>
        <button type="button" className="text-left text-lg font-medium" onClick={() => onPick({ title: current || "Домен", lines: ["Это имя каталога, не три разных домена.", roles.length ? "Роли FSMO: " + roles.join(", ") : "Роли FSMO не прочитаны", others.length ? "Другие домены леса: " + others.join(", ") : "Других доменов в лесу не найдено."] })}>{current || "имя не прочитано"}</button>
        {others.length ? <p className="text-muted-foreground mt-1 text-xs">В лесу ещё: {others.join(", ")}</p> : null}
      </div>
      {loose.length ? (
        <button type="button" className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 text-left text-sm" onClick={() => onPick({ title: "Подсети без сайта", lines: loose.map((row) => row.name + (row.site ? " · указан чужой сайт " + row.site : " · сайт не назначен")) })}>
          Подсети без своего сайта: {loose.length}. Клиенты из них могут ходить на случайный контроллер.
        </button>
      ) : null}
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {shown.map((site) => {
          const nets = subnets.filter((row) => row.site.toLowerCase() === site.name.toLowerCase())
          const servers = site.servers.filter((server) => mode !== "fsmo" || fsmo.has(shortName(server)))
          return (
            <div key={site.name} className="rounded-xl border">
              <button type="button" className="hover:bg-muted/40 w-full px-3 py-2 text-left" onClick={() => onPick({ title: site.name, lines: ["Сайт", "Контроллеры: " + (site.servers.join(", ") || "нет"), "Подсети: " + (nets.map((row) => row.name).join(", ") || "не привязаны")] })}>
                <div className="text-xs text-cyan-400">Сайт</div>
                <div className="font-medium">{site.name}</div>
                <div className="text-muted-foreground text-xs">{nets.length ? nets.map((row) => row.name).join(", ") : "подсети не привязаны"}</div>
              </button>
              <div className="grid gap-1 border-t p-2">
                {servers.length ? servers.map((server) => {
                  const state = worst(server)
                  const holds = fsmo.has(shortName(server))
                  return (
                    <button key={server} type="button" className="hover:bg-muted/40 flex items-center justify-between rounded-lg px-2 py-1 text-left text-sm" onClick={() => onPick({ title: server, lines: ["Сайт " + site.name, holds ? "Держит роль FSMO" : "Роль FSMO не отмечена", "Репликация: " + state, "Зелёный статус значит, что последняя репликация свежая и без кода ошибки."] })}>
                      <span>{server}{holds ? " · FSMO" : ""}</span>
                      <span className={"rounded-full px-2 py-0.5 text-[11px] " + (state === "норма" ? "bg-emerald-500/15" : state === "сбой" ? "bg-red-500/15" : "bg-muted")}>{state}</span>
                    </button>
                  )
                }) : <p className="text-muted-foreground px-2 py-1 text-xs">Контроллеров в сайте нет.</p>}
              </div>
            </div>
          )
        })}
      </div>
      {!shown.length ? <p className="text-muted-foreground text-sm">{sites.length ? "По фильтру сайтов нет." : "Сайты не прочитаны. Без них карта не показывает, куда ходит клиент."}</p> : null}
    </div>
  )
}

export function Catalog() {
  const { companyId, inventory, theme } = useApp()
  const colors = palette(theme)
  const [picture, setPicture] = useState<Picture | null>(null)
  const [windows, setWindows] = useState<WindowsView | null>(null)
  const [error, setError] = useState("")
  const [windowsLoading, setWindowsLoading] = useState(false)
  const [windowsError, setWindowsError] = useState("")
  const [gpoScopeSearch, setGpoScopeSearch] = useState("")
  const [gpoScopePage, setGpoScopePage] = useState(1)
  const [tab, setTab] = useState<(typeof SECTIONS)[number][0]>("suite")
  const [query, setQuery] = useState("")
  const [sidOff, setSidOff] = useState(false)
  const [conflictsOnly, setConflictsOnly] = useState(false)
  const [groupKind, setGroupKind] = useState<"all" | "security" | "mail">("all")
  const [pick, setPick] = useState<Pick | null>(null)
  const [acct, setAcct] = useState<"policy" | "pso" | "laps" | "krb" | "never" | "aes" | "quiet" | "os" | "gmsa">("policy")
  const [matrix, setMatrix] = useState(true)
  const coverage = windows?.coverage || picture?.coverage
  const coverageSection = (key: string) => coverage?.sections?.[key]
  const coverageLabel = (state?: string) => ({ collected: "собрано", partial: "частично", unavailable: "недоступно", not_tested: "не проверялось", unknown: "неизвестно" }[state || "unknown"] || state || "неизвестно")
  const coverageClass = (state?: string) => state === "collected" ? "bg-emerald-500/15 text-emerald-700" : state === "partial" ? "bg-amber-500/15 text-amber-700" : state === "unavailable" ? "bg-red-500/15 text-red-700" : "bg-muted text-muted-foreground"
  const dnsReady = windows?.dns?.ok === true
  const wildcardLabel = windows?.dns?.wildcard == null ? "не проверено" : windows.dns.wildcard ? "есть" : "нет"
  const needle = query.trim().toLowerCase()
  const hit = (value: string) => !needle || value.toLowerCase().includes(needle)

  useEffect(() => {
    if (!companyId) return
    let alive = true
    setPicture(null)
    setWindows(null)
    setWindowsLoading(true)
    setWindowsError("")
    setPick(null)
    setError("")
    void api<Picture>("/api/directory/picture?company_id=" + companyId)
      .then((data) => { if (alive) setPicture(data) })
      .catch((reason: unknown) => { if (alive) setError(reason instanceof Error ? reason.message : "Каталог не прочитан") })
    void api<WindowsView>("/api/directory/windows?company_id=" + companyId + "&part=hw")
      .then((data) => { if (alive) setWindows(current => current?.coverage ? current : data) })
      .catch(() => { if (alive) setWindows(current => current || { ok: false, message: "Железо контроллеров не получено" }) })
    void api<WindowsView>("/api/directory/windows?company_id=" + companyId)
      .then((data) => {
        if (!alive) return
        setWindows((current) => {
          const fresh = (data.controllers || []).some((row) => row.cpu || row.ram_gb)
          return { ...data, controllers: fresh ? data.controllers : (current?.controllers || data.controllers) }
        })
      })
      .catch((reason: unknown) => { if (alive) setWindowsError(reason instanceof Error ? reason.message : "Запрос Windows-проверок завершился ошибкой") })
      .finally(() => { if (alive) setWindowsLoading(false) })
    return () => { alive = false }
  }, [companyId])

  const posture = inventory.filter((row) => POSTURE.includes(row.vuln_id) && row.status !== "closed")
  const trusts = useMemo(() => (picture?.trusts || []).filter((row) => (!sidOff || row.sid_filter === false) && hit(row.name + row.kind)), [picture, sidOff, needle])
  const groups = (picture?.groups || []).filter((row) => hit(row.name) && (groupKind === "all" || (groupKind === "security" ? row.security : !row.security)))
  const ous = (picture?.ous || []).filter((name) => hit(name))
  const zones = (picture?.zones || []).filter((name) => hit(name))
  const gpos = (picture?.gpos || []).filter((row) => hit(row.name + row.state))
  const gpoScopes = (windows?.gpo_collection?.link_metadata?.scopes || []).filter(scope => (scope.dn + " " + scope.links.map(link => link.name).join(" ")).toLowerCase().includes(gpoScopeSearch.toLowerCase()))
  const gpoScopePages = Math.max(1, Math.ceil(gpoScopes.length / 10))
  const currentGpoScopePage = Math.min(gpoScopePage, gpoScopePages)
  const conflicts = (windows?.conflicts || []).filter((row) => hit(row.key + row.values.map((item) => item.gpo).join(" ")))
  const weakTrusts = (picture?.trusts || []).filter((row) => row.sid_filter === false).length
  const length = Number(picture?.policy?.length || 0)
  const lockout = picture?.policy?.lockout
  const age = picture?.policy?.max_age_days || ""
  const acctIds: Record<string, string[]> = {
    pso: ["weak_pso"],
    laps: ["laps_gap", "laps_missing"],
    krb: ["krbtgt_old"],
    never: ["priv_password_never_expires"],
    aes: ["rc4_only", "des_enabled"],
    quiet: ["inactive_stale", "stale_password"],
    os: ["obsolete_os", "stale_computer", "machine_password_old"],
  }
  const acctRows = inventory.filter((row) => (acctIds[acct] || []).includes(row.vuln_id) && row.status !== "closed")
  const gpoColumns = [...new Set(conflicts.flatMap((row) => row.values.map((item) => item.gpo)))].slice(0, 8)

  return (
    <div>
      <PageHead title="Каталог" sub="Каталог AD: топология, учётные записи, группы, DNS, доверия, политики и защита контроллеров. Статусы показывают полноту сбора, а не готовое заключение о безопасности." />
      {error ? <p className="text-sm text-red-600">{error}</p> : null}
      {!picture && !error ? <p className="text-muted-foreground text-sm">Читаем каталог...</p> : null}
      {picture && !picture.ok ? <p className="text-sm">{picture.message}</p> : null}
      {picture?.ok ? (
        <div className="grid gap-4 lg:grid-cols-[220px_1fr]">
          <nav className="flex gap-1 overflow-auto lg:flex-col">
            {SECTIONS.map(([id, label]) => (
              <Button key={id} variant={tab === id ? "default" : "ghost"} className="justify-start" onClick={() => setTab(id)}>{label}</Button>
            ))}
          </nav>
          <div className="grid gap-3 xl:grid-cols-[1fr_280px]">
            <div className="min-w-0">
              <div className="mb-3 flex flex-wrap gap-2">
                <Input className="max-w-sm" value={query} placeholder="Поиск по имени, зоне, политике" onChange={(event) => setQuery(event.target.value)} />
                <Button variant="outline" onClick={() => { setSidOff(false); setConflictsOnly(false); setGroupKind("all"); setQuery("") }}>Сбросить фильтры</Button>
              </div>
              <div role="status" className="mb-3 rounded-lg border p-3 text-sm">
                {windowsLoading ? "Проверки WinRM/SSH выполняются. LDAP-срез уже доступен; DNS, GPO и диагностика контроллеров могут занять несколько минут." : windowsError ? "Ошибка Windows-проверок: " + windowsError : windows?.ok === false ? "Windows-проверки не получили данные: " + (windows.message || "причина не передана") : windows ? "Windows-проверки завершены. Полнота отдельных разделов указана ниже." : "Windows-проверки не запускались."}
              </div>
              {(["dns", "trusts", "gpo", "posture"] as string[]).includes(tab) ? (() => {
                const item = coverageSection(tab === "posture" ? "dc_posture" : tab)
                return <section aria-label="Полнота проверки раздела" className="mb-3 rounded-xl border p-3">
                  <div className="flex flex-wrap items-center gap-2"><h2 className="text-sm font-medium">Полнота проверки</h2><span className={"rounded-full px-2 py-0.5 text-xs " + coverageClass(item?.state)}>{coverageLabel(item?.state)}</span></div>
                  <p className="text-muted-foreground mt-2 text-xs">Метод: {item?.method || "данные о методе не получены"}. Статус сбора не является оценкой безопасности.</p>
                  {(item?.limitations || ["Полнота сбора не подтверждена."]).map(line => <p key={line} className="text-muted-foreground mt-1 text-xs">{line}</p>)}
                </section>
              })() : null}
              {tab === "suite" ? (
                <div className="grid gap-3 sm:grid-cols-2">
                  {[
                    ["Топология", String((picture.sites || []).length) + " сайтов · " + String((picture.dcs || []).length) + " контроллеров", "topology"],
                    ["Учётные записи", "Длина пароля " + (picture.policy?.length || "—") + ", блокировка " + (picture.policy?.lockout || "—"), "accounts"],
                    ["Группы и OU", String(picture.groups?.length || 0) + " групп · " + String(picture.ous?.length || 0) + " подразделений", "groups"],
                    ["DNS", String(windows?.dns?.zones?.length || picture.zones?.length || 0) + " зон · подстановка " + wildcardLabel, "dns"],
                    ["Доверия", String(picture.trusts?.length || 0) + " связей · без карантина SID " + weakTrusts, "trusts"],
                    ["Политики", String(picture.gpos?.length || 0) + " объектов · расхождений " + String(windows?.conflicts?.length ?? "…"), "gpo"],
                    ["Контроллеры", String((windows?.controllers || []).filter((row) => row.ok).length) + " ответили из " + String(picture.dcs?.length || 0), "dcs"],
                    ["Защита контроллеров", String(posture.length) + " открытых отметок · " + coverageLabel(coverageSection("dc_posture")?.state), "posture"],
                  ].map(([title, value, id]) => (
                    <button key={id} type="button" className="hover:bg-muted/40 rounded-xl border p-4 text-left" onClick={() => setTab(id as (typeof SECTIONS)[number][0])}>
                      <div className="text-sm font-medium">{title}</div>
                      <div className="text-muted-foreground mt-1 text-sm">{value}</div>
                    </button>
                  ))}
                  <div className="rounded-xl border p-4 sm:col-span-2">
                    <div className="mb-2 text-sm font-medium">Полнота сбора AD</div>
                    <p className="text-muted-foreground mb-3 text-xs">{coverage?.meaning || "Статус отражает доступность данных, а не подтверждение безопасности."}</p>
                    <div className="grid gap-2 sm:grid-cols-3">
                      {[['dns', 'DNS'], ['trusts', 'Доверия'], ['gpo', 'GPO'], ['dc_posture', 'Защита контроллеров']].map(([key, label]) => { const item = coverageSection(key); return <button type="button" key={key} className="rounded-lg border p-2 text-left" onClick={() => setTab(key === "dc_posture" ? "posture" : key as (typeof SECTIONS)[number][0])}><div className="text-xs">{label}</div><span className={"mt-1 inline-block rounded-full px-2 py-0.5 text-[11px] " + coverageClass(item?.state)}>{coverageLabel(item?.state)}</span></button> })}
                    </div>
                  </div>
                  <div className="rounded-xl border p-4 sm:col-span-2">
                    <div className="mb-2 text-sm font-medium">Состав каталога</div>
                    <div className="grid items-center gap-4 lg:grid-cols-2">
                      <Donut
                        slices={[
                          { name: "Подразделения", value: picture.ous?.length || 0, fill: colors.bar[0] },
                          { name: "Группы", value: picture.groups?.length || 0, fill: colors.bar[1] },
                          { name: "Политики", value: picture.gpos?.length || 0, fill: colors.bar[2] },
                          { name: "Контроллеры", value: picture.dcs?.length || 0, fill: colors.bar[3] },
                          { name: "Доверия", value: picture.trusts?.length || 0, fill: colors.donut[0] },
                          { name: "Зоны DNS", value: windows?.dns?.zones?.length || picture.zones?.length || 0, fill: colors.donut[2] },
                        ].filter((slice) => slice.value > 0)}
                        onSlice={(name) => {
                          const tabOf: Record<string, (typeof SECTIONS)[number][0]> = { "Подразделения": "groups", "Группы": "groups", "Политики": "gpo", "Контроллеры": "dcs", "Доверия": "trusts", "Зоны DNS": "dns" }
                          const next = tabOf[name]
                          if (next) setTab(next)
                        }}
                      />
                      <div>
                        <div className="mb-2 text-sm font-medium">ОС контроллеров</div>
                        <Bars
                          rows={Object.entries((picture.dcs || []).reduce<Record<string, number>>((bucket, row) => {
                            const name = (row.os || "не прочитана").replace("Windows Server", "WS")
                            bucket[name] = (bucket[name] || 0) + 1
                            return bucket
                          }, {})).map(([name, value]) => ({ name, value }))}
                          active=""
                          colors={colors.bar}
                          onPick={() => setTab("dcs")}
                        />
                      </div>
                    </div>
                    <p className="text-muted-foreground mt-2 text-xs">Кольцо считает прочитанные объекты каталога. Доля открывается своей вкладкой. Полоса — операционная система контроллера, не всех компьютеров домена.</p>
                  </div>
                  <div className="rounded-xl border p-4 sm:col-span-2">
                    <div className="mb-2 text-sm font-medium">Состав групп</div>
                    {(() => {
                      const security = (picture.groups || []).filter((row) => row.security).length
                      const mail = (picture.groups || []).length - security
                      const total = security + mail || 1
                      return (
                        <div className="flex h-3 overflow-hidden rounded-full">
                          <div className="h-full bg-fuchsia-500" style={{ width: (security / total * 100) + "%" }} title={"Безопасность " + security} />
                          <div className="h-full bg-cyan-400" style={{ width: (mail / total * 100) + "%" }} title={"Рассылка " + mail} />
                        </div>
                      )
                    })()}
                    <p className="text-muted-foreground mt-2 text-xs">Розовая доля — группы безопасности, голубая — рассылки. Участники открываются на вкладке «Группы и OU».</p>
                  </div>
                </div>
              ) : null}
              {tab === "topology" ? (
                <div className="grid gap-3">
                  <Topology domain={picture.domain || ""} domains={picture.domains || []} sites={picture.sites || []} subnets={picture.subnets || []} roles={picture.roles || []} links={windows?.replication || []} onPick={setPick} />
                  <div className="overflow-auto rounded-xl border">
                    <div className="border-b px-3 py-2 text-sm font-medium">Репликация · {(windows?.replication || []).length}</div>
                    <table className="w-full min-w-[640px] text-left text-sm">
                      <thead className="bg-muted/50 text-xs">
                        <tr>{["Источник", "Партнёр", "Раздел", "Часы", "Состояние"].map((head) => <th key={head} className="px-3 py-2 font-medium">{head}</th>)}</tr>
                      </thead>
                      <tbody>
                        {(windows?.replication || []).filter((row) => hit(row.source + row.partner + row.partition + row.state)).map((row) => (
                          <tr key={row.source + row.partner + row.partition} className="hover:bg-muted/40 cursor-pointer border-t" onClick={() => setPick({ title: row.source + " → " + row.partner, lines: ["Раздел: " + row.partition, "Часов с успеха: " + (row.hours === "-1" ? "нет отметки" : row.hours), "Состояние: " + row.state, "Текст ошибки репликации не сохраняется."] })}>
                            <td className="px-3 py-2">{row.source}</td>
                            <td className="px-3 py-2">{row.partner}</td>
                            <td className="px-3 py-2">{row.partition}</td>
                            <td className="px-3 py-2">{row.hours === "-1" ? "—" : row.hours}</td>
                            <td className="px-3 py-2"><span className={"rounded-full px-2 py-0.5 text-xs " + (row.state === "норма" ? "bg-emerald-500/15" : "bg-red-500/15")}>{row.state}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {!windows?.replication?.length ? <p className="text-muted-foreground p-3 text-sm">{windows ? "Связей репликации нет либо модуль Active Directory на контроллере не ответил." : "Матрица ещё читается."}</p> : null}
                  </div>
                </div>
              ) : null}
              {tab === "accounts" ? (
                <div className="grid gap-3">
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" variant={acct === "policy" ? "default" : "outline"} onClick={() => setAcct("policy")}>Политика</Button>
                    {([
                      ["pso", "Точечные"],
                      ["laps", "LAPS"],
                      ["krb", "krbtgt"],
                      ["never", "Пароль не истекает"],
                      ["aes", "Без AES"],
                      ["quiet", "Давно не входили"],
                      ["os", "Компьютеры"],
                      ["gmsa", "gMSA"],
                    ] as const).map(([id, label]) => (
                      <Button key={id} size="sm" variant={acct === id ? "default" : "outline"} onClick={() => setAcct(id)}>{label} · {id === "gmsa" ? (picture.service_accounts || []).length : inventory.filter((row) => acctIds[id].includes(row.vuln_id) && row.status !== "closed").length}</Button>
                    ))}
                  </div>
                  {acct === "gmsa" ? (
                    <div className="grid gap-2">
                      {(picture.service_accounts || []).map((row) => (
                        <button key={row.name} type="button" className="hover:bg-muted/40 rounded-xl border px-3 py-2 text-left text-sm" onClick={() => setPick({ title: row.name, lines: [row.kind, row.host || "DNS-имя не задано", row.disabled ? "Учётная запись отключена" : "Учётная запись включена", "Управляемый пароль не читается и в отчёт не попадает."] })}>
                          <div className="font-medium">{row.name}</div>
                          <div className="text-muted-foreground text-xs">{row.kind}{row.host ? " · " + row.host : ""}{row.disabled ? " · отключена" : ""}</div>
                        </button>
                      ))}
                      {!(picture.service_accounts || []).length ? <p className="text-muted-foreground text-sm">Управляемых служебных записей в каталоге нет.</p> : null}
                    </div>
                  ) : acct === "policy" ? (
                    <div className="grid gap-3 sm:grid-cols-2">
                      {[
                        ["Длина пароля", picture.policy?.length || "—", length >= 12],
                        ["История", picture.policy?.history || "—", Number(picture.policy?.history || 0) >= 10],
                        ["Порог блокировки", lockout || "—", lockout !== "0" && !!lockout],
                        ["Срок, дни", age || "—", age !== "не ограничен" && Number(age || 999) <= 365],
                      ].map(([title, value, ok]) => (
                        <button key={String(title)} type="button" className={"rounded-xl border p-4 text-left " + tone(Boolean(ok))} onClick={() => setPick({ title: String(title), lines: [String(value), "Доменная политика по умолчанию. Пароли не читаются."] })}>
                          <div className="text-muted-foreground text-xs">{title}</div>
                          <div className="mt-1 text-2xl font-medium">{value}</div>
                        </button>
                      ))}
                      <p className="text-muted-foreground text-xs sm:col-span-2">Режим домена: {picture.level || "не прочитан"}.</p>
                    </div>
                  ) : (
                    <div className="grid gap-2">
                      {acctRows.slice(0, 24).map((row) => (
                        <button key={row.id} type="button" className="hover:bg-muted/40 rounded-xl border px-3 py-2 text-left text-sm" onClick={() => setPick({ title: row.title, lines: [row.hostname, row.detail || "Подробности в инциденте"] })}>
                          <div className="font-medium">{row.title}</div>
                          <div className="text-muted-foreground text-xs">{row.hostname}</div>
                        </button>
                      ))}
                      {acctRows.length > 24 ? <p className="text-muted-foreground text-xs">ещё {acctRows.length - 24}. Полный список остаётся в инцидентах.</p> : null}
                      {!acctRows.length ? <p className="text-muted-foreground text-sm">В текущих инцидентах таких отметок нет. Они появляются после сканирования гигиены.</p> : null}
                    </div>
                  )}
                </div>
              ) : null}
              {tab === "groups" ? (
                <div className="grid gap-3">
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" variant={groupKind === "all" ? "default" : "outline"} onClick={() => setGroupKind("all")}>Все</Button>
                    <Button size="sm" variant={groupKind === "security" ? "default" : "outline"} onClick={() => setGroupKind("security")}>Безопасность</Button>
                    <Button size="sm" variant={groupKind === "mail" ? "default" : "outline"} onClick={() => setGroupKind("mail")}>Рассылка</Button>
                  </div>
                  <div className="overflow-hidden rounded-xl border">
                    {groups.map((row) => (
                      <div key={row.name} className="border-b last:border-b-0">
                        <button type="button" className="hover:bg-muted/50 flex w-full items-center justify-between px-3 py-2 text-left text-sm" onClick={() => setPick({ title: row.name, lines: [row.security ? "Группа безопасности" : "Группа рассылки", "Участников: " + (row.member_count ?? row.members?.length ?? 0), ...(row.members || []).slice(0, 8)] })}>
                          <span>{row.name}</span>
                          <span className="text-muted-foreground text-xs">{row.member_count ?? row.members?.length ?? 0}</span>
                        </button>
                        {(row.members || []).length ? (
                          <div className="grid gap-1 px-6 pb-2">
                            {row.members?.map((name) => (
                              <button key={name} type="button" className="text-muted-foreground hover:text-foreground text-left text-xs" onClick={() => setPick({ title: name, lines: ["Участник группы " + row.name] })}>{name}</button>
                            ))}
                            {(row.member_count || 0) > (row.members || []).length ? <div className="text-muted-foreground text-xs">ещё {(row.member_count || 0) - (row.members || []).length}</div> : null}
                          </div>
                        ) : null}
                      </div>
                    ))}
                    {!groups.length ? <p className="text-muted-foreground p-3 text-sm">Групп по фильтру нет.</p> : null}
                  </div>
                  <div className="overflow-hidden rounded-xl border">
                    <div className="border-b px-3 py-2 text-sm font-medium">Подразделения · {(picture.ou_nodes || []).length || ous.length}</div>
                    {(picture.ou_nodes || []).length ? <OuTree nodes={picture.ou_nodes || []} gpos={picture.gpos || []} onPick={setPick} /> : ous.map((name) => (
                      <button key={name} type="button" className="hover:bg-muted/50 block w-full border-b px-3 py-2 text-left text-sm last:border-b-0" onClick={() => setPick({ title: name, lines: ["Подразделение. Пустые подразделения отмечает гигиена."] })}>{name}</button>
                    ))}
                  </div>
                </div>
              ) : null}
              {tab === "dns" ? (
                <div className="grid gap-3">
                  <section className="rounded-xl border p-3" aria-label="Оценка безопасности DNS">
                    <h2 className="text-sm font-medium">Риски конфигурации DNS</h2>
                    {!dnsReady ? <p className="text-muted-foreground mt-2 text-sm">{windows?.dns?.message || "Проверка DNS не завершена. Отсутствие находок не означает отсутствие рисков."}</p> : null}
                    {(windows?.dns?.assessment || []).filter(row => hit(row.zone + row.title)).map(row => <button type="button" key={row.zone + row.code} className="hover:bg-muted/40 mt-2 block w-full rounded-lg border border-red-500/30 p-3 text-left" onClick={() => setPick({ title: row.zone, lines: [row.title, row.detail, ...Object.entries(row.evidence).map(([key, value]) => key + "=" + value)] })}><div className="text-sm">{row.zone}: {row.title}</div><p className="text-muted-foreground mt-1 text-xs">{row.detail}</p></button>)}
                    {dnsReady && !windows?.dns?.assessment?.length ? <p className="text-muted-foreground mt-2 text-xs">В собранных свойствах нет этих двух признаков риска. Это не полная проверка безопасности DNS.</p> : null}
                    {(windows?.dns?.advanced_assessment || []).map(row => <button type="button" key={row.code + JSON.stringify(row.evidence)} className="hover:bg-muted/40 mt-2 block w-full rounded-lg border border-amber-500/30 p-3 text-left" onClick={() => setPick({ title: row.title, lines: [row.detail, ...Object.entries(row.evidence).map(([key, value]) => key + "=" + String(value))] })}><div className="text-sm">{row.title}</div><p className="text-muted-foreground mt-1 text-xs">{row.detail}</p></button>)}
                    <div className="mt-3 grid gap-2 md:grid-cols-3">
                      <div className="rounded-lg border p-2 text-xs"><div className="font-medium">ADIDNS ACL</div><div className="text-muted-foreground mt-1">{coverageLabel(windows?.dns?.acl?.state)} · зон: {windows?.dns?.acl?.zones_checked ?? "—"} · ACE: {windows?.dns?.acl?.aces_checked ?? "—"}</div><div className="mt-1">ACE для проверки: {windows?.dns?.acl?.broad_write_principals ?? "—"}; ошибок чтения: {windows?.dns?.acl?.acl_errors ?? "—"}. Effective access не вычислялся.</div></div>
                      <div className="rounded-lg border p-2 text-xs"><div className="font-medium">Порядок резолверов</div><div className="text-muted-foreground mt-1">{windows?.dns?.resolvers?.length ? windows.dns.resolvers.map(row => row.server + " [интерфейс " + (row.interface_index ?? "—") + ", позиция " + (row.position ?? "—") + "]" + (row.is_self ? " self" : "") + (row.reachable == null ? " TCP не проверен" : row.reachable ? " TCP/53 отвечает" : " TCP/53 таймаут/ошибка")).join("; ") : "не проверено"}</div></div>
                      <div className="rounded-lg border p-2 text-xs"><div className="font-medium">Пересылки</div><div className="text-muted-foreground mt-1">{windows?.dns?.forwarder_probes?.length ? windows.dns.forwarder_probes.map(row => (row.kind === "conditional" ? "conditional " : "global ") + row.server + ": " + (row.reachable == null ? "TCP не проверен" : row.reachable ? "TCP/53 отвечает" : "TCP/53 таймаут/ошибка")).join("; ") : windows?.dns?.forwarder_probe_state === "collected" ? "Проверка завершена; целей пересылки в срезе нет." : "не проверено"}</div></div>
                    </div>
                    <p className="text-muted-foreground mt-2 text-xs">Метод: {windows?.dns?.probe_method || "не получен"}. TCP не заменяет проверку UDP/DNS-ответов. Self DNS после другого DC — не доказательство DNS island.</p>
                    {(windows?.dns?.limitations || []).map(line => <p key={line} className="text-muted-foreground mt-2 text-xs">{line}</p>)}
                  </section>
                  <Kpis items={[
                    { label: "Зоны", value: String(windows?.dns?.zones?.length || zones.length) },
                    { label: "Служебные SRV", value: (windows?.dns?.locator || []).filter((row) => row.ok).length + " из " + ((windows?.dns?.locator || []).length || "…") },
                    { label: "Подстановка", value: wildcardLabel, bad: !!windows?.dns?.wildcard },
                    { label: "Открытая передача", value: dnsReady ? String((windows?.dns?.assessment || []).filter(row => row.code === "dns_open_transfer").length) : "не проверено", bad: dnsReady && (windows?.dns?.assessment || []).some(row => row.code === "dns_open_transfer") },
                    { label: "Без DNSSEC", value: dnsReady ? String((windows?.dns?.zones || []).filter((row) => row.signed === false).length) : "не проверено" },
                  ]} />
                  <div className="flex flex-wrap gap-2">
                    {(windows?.dns?.locator || []).map((row) => (
                      <span key={row.name} className={"rounded-full px-2 py-1 text-xs " + (row.ok ? "bg-emerald-500/15" : "bg-red-500/15")}>{row.name}: {row.ok ? "отвечает" : "нет ответа"}</span>
                    ))}
                    {windows?.dns ? <span className="bg-muted rounded-full px-2 py-1 text-xs">Подстановка: {wildcardLabel}</span> : null}
                  </div>
                  <div className="grid gap-2 rounded-xl border p-3">
                    <div className="text-sm font-medium">Очистка на сервере</div>
                    {dnsReady && windows?.dns?.scavenging?.enabled != null ? (
                      <button type="button" className={"rounded-lg px-2 py-1 text-left text-xs " + (windows.dns.scavenging.enabled ? "bg-emerald-500/10" : "bg-amber-500/10")} onClick={() => setPick({ title: "Очистка DNS", lines: [windows.dns?.scavenging?.enabled ? "Служба очистки на этом сервере включена" : "Служба очистки на этом сервере выключена", "Интервал: " + (windows.dns?.scavenging?.interval || "не прочитан"), "Без обновления: " + (windows.dns?.scavenging?.no_refresh || "не прочитан"), "Обновление: " + (windows.dns?.scavenging?.refresh || "не прочитан"), "Имена записей при этом не копируются. Очистка зоны в таблице — отдельный признак."] })}>
                        {windows.dns.scavenging.enabled ? "включена" : "выключена"}
                        {windows.dns.scavenging.interval ? " · интервал " + windows.dns.scavenging.interval : ""}
                      </button>
                    ) : <p className="text-muted-foreground text-xs">Состояние очистки не получено; это не означает, что она выключена.</p>}
                  </div>
                  {windows?.dns?.composition && Object.keys(windows.dns.composition).length ? (
                    <div className="grid gap-2 rounded-xl border p-3">
                      <div className="text-sm font-medium">Состав зон по типам записей</div>
                      {Object.entries(windows.dns.composition).slice(0, 8).map(([zone, bag]) => {
                        const total = Object.values(bag).reduce((sum, value) => sum + value, 0) || 1
                        return (
                          <div key={zone}>
                            <div className="text-muted-foreground mb-1 text-xs">{zone}</div>
                            <div className="flex h-3 overflow-hidden rounded-full">
                              {Object.entries(bag).map(([kind, value], index) => (
                                <div key={kind} title={kind + " " + value} className="h-full" style={{ width: (value / total * 100) + "%", background: ["#7c3aed", "#06b6d4", "#10b981", "#f59e0b", "#ef4444", "#64748b"][index % 6] }} />
                              ))}
                            </div>
                          </div>
                        )
                      })}
                      <p className="text-muted-foreground text-xs">Имена отдельных записей не копируются. Полоса показывает долю типов.</p>
                    </div>
                  ) : null}
                  <div className="grid gap-2 rounded-xl border p-3">
                    <div className="text-sm font-medium">Пересылки</div>
                    <div className="flex flex-wrap gap-2">
                      {(windows?.dns?.forwarders || []).map((address) => <span key={address} className="bg-muted rounded-full px-2 py-1 text-xs">{address}</span>)}
                      {dnsReady && windows?.dns?.forwarders_collected && !(windows.dns.forwarders || []).length ? <span className="text-muted-foreground text-xs">Серверных пересылок нет: внешние имена идут через корневые ссылки, если рекурсия включена.</span> : null}
                      {!windows?.dns?.forwarders_collected ? <span className="text-muted-foreground text-xs">Данные о пересылках не получены. Доступность серверов пересылки не проверялась.</span> : null}
                    </div>
                    {(windows?.dns?.conditional || []).length ? (
                      <div className="grid gap-1">
                        {windows?.dns?.conditional?.map((row) => (
                          <button key={row.name} type="button" className="hover:bg-muted/40 rounded-lg px-2 py-1 text-left text-xs" onClick={() => setPick({ title: row.name, lines: ["Условная пересылка", "Серверы: " + (row.masters || "не прочитаны"), "Имена записей этой зоны не копируются."] })}>
                            <span className="font-medium">{row.name}</span>
                            <span className="text-muted-foreground"> · {row.masters || "серверы не прочитаны"}</span>
                          </button>
                        ))}
                      </div>
                    ) : <p className="text-muted-foreground text-xs">Условные пересылки не обнаружены в текущем срезе; полнота проверки не подтверждена.</p>}
                  </div>
                  <div className="grid gap-2 rounded-xl border p-3">
                    <div className="text-sm font-medium">Устаревшие цели контроллеров</div>
                    {(windows?.dns?.stale || []).length ? windows?.dns?.stale?.map((row) => (
                      <button key={row.name + row.target} type="button" className="hover:bg-muted/40 rounded-lg px-2 py-1 text-left text-xs" onClick={() => setPick({ title: row.target, lines: ["Служебная запись " + row.name + " указывает на имя, которого нет среди текущих контроллеров.", "Остальные записи зоны не копируются."] })}>
                        {row.name} · {row.target}
                      </button>
                    )) : <p className="text-muted-foreground text-xs">{"В текущем срезе нет отметок. Проверка ограничена; отсутствие расхождений не подтверждено."}</p>}
                  </div>
                  {windows?.dns?.zones?.length ? (
                    <div className="overflow-auto rounded-xl border">
                      <table className="w-full min-w-[760px] text-left text-sm">
                        <thead className="bg-muted/50 text-xs">
                          <tr>{["Зона", "Тип", "Область", "Обновления", "Передача", "Очистка", "DNSSEC"].map((head) => <th key={head} className="px-3 py-2 font-medium">{head}</th>)}</tr>
                        </thead>
                        <tbody>
                          {windows.dns.zones.filter((row) => hit(row.name + row.type + row.dynamic)).map((row) => {
                            const openTransfer = /^(transferanyserver|nosecurity|any)$/i.test(row.transfer)
                            const openUpdate = /nonsecure/i.test(row.dynamic)
                            return (
                              <tr key={row.name} className="hover:bg-muted/40 cursor-pointer border-t" onClick={() => setPick({ title: row.name, lines: [row.type + (row.reverse ? ", обратная" : ""), "Область: " + (row.scope || "не указана"), "Обновления: " + (row.dynamic || "не прочитаны"), "Передача: " + (row.transfer || "не прочитана"), row.aging == null ? "Очистка: не прочитано" : row.aging ? "Очистка устаревших записей включена" : "Очистка устаревших записей выключена", row.signed == null ? "DNSSEC: не прочитано" : row.signed ? "DNSSEC включён" : "DNSSEC не включён", "Имена записей не копировались."] })}>
                                <td className="px-3 py-2">{row.name}</td>
                                <td className="px-3 py-2">{row.type}</td>
                                <td className="px-3 py-2">{row.scope || "—"}</td>
                                <td className="px-3 py-2"><span className={openUpdate ? "text-red-600" : ""}>{row.dynamic || "—"}</span></td>
                                <td className="px-3 py-2"><span className={openTransfer ? "text-red-600" : ""}>{row.transfer || "—"}</span></td>
                                <td className="px-3 py-2">{row.aging == null ? "не прочитано" : row.aging ? "включена" : "выключена"}</td>
                                <td className="px-3 py-2">{row.signed == null ? "не прочитано" : row.signed ? "да" : "нет"}</td>
                              </tr>
                            )
                          })}
                        </tbody>
                      </table>
                    </div>
                  ) : <p className="text-muted-foreground text-sm">{windows?.dns?.message || "Свойства зон ещё читаются. Ниже имена зон из каталога."}</p>}
                <div className="overflow-hidden rounded-xl border">
                  {zones.map((name) => {
                    const wild = name.includes("*")
                    return (
                      <button key={name} type="button" className="hover:bg-muted/50 flex w-full items-center justify-between border-b px-3 py-2 text-left text-sm last:border-b-0" onClick={() => setPick({ title: name, lines: [wild ? "В имени есть подстановка" : "Обычное имя зоны", "Записи зоны и двоичные свойства в этот срез не читаются."] })}>
                        <span>{name}</span>
                        <span className={"rounded-full px-2 py-0.5 text-xs " + (wild ? "bg-red-500/15" : "bg-muted")}>{wild ? "подстановка" : "зона"}</span>
                      </button>
                    )
                  })}
                  {!zones.length ? <p className="text-muted-foreground p-3 text-sm">Зон по фильтру нет.</p> : null}
                </div>
                </div>
              ) : null}
              {tab === "trusts" ? (
                <div className="grid gap-3">
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" variant={sidOff ? "default" : "outline"} onClick={() => setSidOff((value) => !value)}>Только без карантина SID · {weakTrusts}</Button>
                  </div>
                  <div className="grid gap-2">
                    {trusts.map(row => <button key={row.name} type="button" className="hover:bg-muted/40 rounded-xl border p-3 text-left" onClick={() => setPick({ title: row.name, lines: [row.kind + " · " + row.direction, "trustAttributes: " + (row.trust_attributes ?? "не прочитано") + "; trustType: " + (row.trust_type ?? "не прочитано") + "; trustDirection: " + (row.direction_value ?? "не прочитано"), "msDS-SupportedEncryptionTypes: " + (row.supported_encryption_types ?? "не прочитано"), "Режим SID: " + (row.sid_filter_mode || "неизвестно"), ...(row.assessment || []).map(item => item.title + ": " + item.detail), ...(row.limitations || [])] })}>
                      <div className="text-sm font-medium">{row.name} · {row.kind}</div>
                      <p className="text-muted-foreground mt-1 text-xs">{row.direction} · Режим SID: {row.sid_filter_mode || "неизвестно"}</p>
                      {(row.assessment || []).map(item => <p key={item.code} className={"mt-1 text-xs " + (item.severity === "high" ? "text-red-500" : item.severity === "medium" ? "text-amber-500" : "text-muted-foreground")}>{item.severity}: {item.title}</p>)}
                      {!row.assessment?.length ? <p className="text-muted-foreground mt-1 text-xs">Явных отклонений по доступным атрибутам нет; безопасность не подтверждена.</p> : null}
                    </button>)}
                    <p className="text-muted-foreground text-xs">quarantine — флаг карантина SID; within_forest — связь внутри леса; forest_boundary — граница лесов, не отсутствие фильтрации; external_no_quarantine — внешнее AD-доверие без флага карантина; unknown — недостаточно данных. Серый цвет схемы не означает безопасность.</p>
                  </div>
                  <svg viewBox="0 0 720 420" className="bg-muted/20 h-[420px] w-full rounded-xl border">
                    {trusts.map((row, index) => {
                      const angle = (Math.PI * 2 * index) / Math.max(trusts.length, 1) - Math.PI / 2
                      const x = 360 + Math.cos(angle) * 220
                      const y = 210 + Math.sin(angle) * 140
                      const reach = (windows?.trusts || []).find((item) => item.name.toLowerCase() === row.name.toLowerCase())
                      const color = row.assessment?.some(item => item.severity === "high") ? "#ef4444" : row.assessment?.some(item => item.severity === "medium") ? "#f59e0b" : "#64748b"
                      return (
                        <g key={row.name} onClick={() => setPick({ title: row.name, lines: [row.kind, row.direction, "Режим SID: " + (row.sid_filter_mode || "неизвестно"), row.selective == null ? "Selective authentication: не прочитано" : row.selective ? "CROSS_ORGANIZATION=1" : "CROSS_ORGANIZATION=0", reach ? (reach.reachable ? "Порт LDAP 389 с контроллера открыт" : "Порт LDAP 389 с контроллера не открылся за 2 секунды") : "Доступность ещё читается", "Вход на партнёра не выполняется."] })}>
                          <line x1={360} y1={210} x2={x} y2={y} stroke={color} strokeWidth={2} />
                          <rect x={x - 70} y={y - 18} width={140} height={36} rx={10} fill="var(--card)" stroke={color} />
                          <text x={x} y={y + 4} textAnchor="middle" fill="var(--foreground)" fontSize={11}>{row.name.length > 18 ? row.name.slice(0, 18) + "…" : row.name}</text>
                        </g>
                      )
                    })}
                    <rect x={250} y={188} width={220} height={44} rx={12} fill="var(--card)" stroke="var(--border)" />
                    <text x={360} y={214} textAnchor="middle" fill="var(--foreground)" fontSize={12}>{picture.domain || "Домен"}</text>
                  </svg>
                  <div className="flex flex-wrap gap-2">
                    {trusts.map((row) => {
                      const reach = (windows?.trusts || []).find((item) => item.name.toLowerCase() === row.name.toLowerCase())
                      const label = !reach ? "доступность читается" : reach.reachable ? "LDAP открыт" : "LDAP не открылся"
                      return <span key={row.name} className={"rounded-full px-2 py-1 text-xs " + (!reach ? "bg-muted" : reach.reachable ? "bg-emerald-500/15" : "bg-amber-500/15")}>{row.name}: {label}</span>
                    })}
                  </div>
                  {!trusts.length ? <p className="text-muted-foreground text-sm">По фильтру доверий нет.</p> : null}
                </div>
              ) : null}
              {tab === "gpo" ? (
                <div className="grid gap-3">
                  <section className="rounded-xl border p-4" aria-label="Охват анализа GPO">
                    <h2 className="font-medium">Сохранённые настройки GPO — не результирующая политика</h2>
                    <p className="text-muted-foreground mt-2 text-sm">Расхождения показывают разные значения в исходных GPO. Они могут быть намеренными для разных OU. Без RSoP/gpresult нельзя определить, какое значение действует на конкретном узле.</p>
                    <p className="mt-2 text-xs">INF прочитано: {windows?.gpo_collection?.collection?.inf_files_read ?? "—"}; Registry.pol прочитано: {windows?.gpo_collection?.collection?.registry_files_read ?? "—"}; ошибок чтения/заголовка: {windows?.gpo_collection?.collection?.read_or_parse_errors ?? "—"}; параметров сравнено: {windows?.gpo_collection?.collection?.settings_compared ?? "—"}.</p>
                    {windows?.gpo_collection?.collection?.limits_reached ? <p className="mt-2 text-xs text-amber-500">Достигнуто ограничение сбора или разбора. Результат частичный.</p> : null}
                    {windows?.gpo_collection?.collection?.baseline_truncated || windows?.gpo_collection?.collection?.conflicts_truncated ? <p className="mt-2 text-xs text-amber-500">Список baseline или расхождений ограничен; счётчики не отражают все параметры.</p> : null}
                    <div className="mt-3 rounded-lg border p-3 text-xs">
                      <h3 className="font-medium">Привязки GPO и наследование — метаданные AD</h3>
                      <p className="mt-2">{coverageLabel(windows?.gpo_collection?.link_metadata?.state)} · scopes: {windows?.gpo_collection?.link_metadata?.scopes_read ?? "—"}; ошибок разбора: {windows?.gpo_collection?.link_metadata?.parse_errors ?? "—"}.</p>
                      {(windows?.gpo_collection?.link_metadata?.limitations || []).map(line => <p key={line} className="mt-2 text-muted-foreground">{line}</p>)}
                      <details className="mt-2"><summary className="cursor-pointer">Привязки domain/OU — поиск и просмотр</summary>
                        <input aria-label="Поиск привязок GPO" className="mt-2 w-full rounded border bg-transparent p-2" placeholder="Поиск по DN или имени прямой GPO" value={gpoScopeSearch} onChange={event => { setGpoScopeSearch(event.target.value); setGpoScopePage(1) }} />
                        <div className="mt-2 flex items-center gap-3"><button type="button" disabled={currentGpoScopePage <= 1} onClick={() => setGpoScopePage(currentGpoScopePage - 1)}>Назад</button><span>{currentGpoScopePage} / {gpoScopePages} · найдено {gpoScopes.length} · по 10</span><button type="button" disabled={currentGpoScopePage >= gpoScopePages} onClick={() => setGpoScopePage(currentGpoScopePage + 1)}>Далее</button></div>
                        {gpoScopes.slice((currentGpoScopePage - 1) * 10, currentGpoScopePage * 10).map(scope => <div key={scope.dn} className="mt-2 border-t pt-2 break-all">
                          <div className="font-medium">{scope.dn}</div><div>Block inheritance: {scope.block_inheritance ? "да" : "нет"}</div>
                          <p className="mt-2">Структурное наследование: {coverageLabel(scope.structural_inheritance?.state)} · кандидатов: {scope.structural_inheritance?.candidate_links.length ?? "—"}; исключено block inheritance: {scope.structural_inheritance?.blocked_links.length ?? "—"}. Не effective policy.</p>
                          {scope.structural_inheritance?.missing_ancestors.length ? <p className="text-amber-500">Не прочитаны предки: {scope.structural_inheritance.missing_ancestors.join("; ")}</p> : null}
                          {(scope.structural_inheritance?.candidate_links || []).map((link, i) => <p key={"candidate-" + i} className="text-muted-foreground">Кандидат: {link.name} · {link.inherited ? "унаследован от " + link.source_dn : "прямая ссылка"}{link.enforced ? " · enforced" : ""}</p>)}
                          {scope.links.length ? scope.links.map((link, i) => <p key={i}>#{link.order} {link.name} · {link.enabled ? "enabled" : "disabled"} · enforced: {link.enforced ? "да" : "нет"}</p>) : <p>Прямых ссылок нет; структурные кандидаты показаны выше.</p>}
                        </div>)}
                      </details>
                    </div>
                    {(windows?.gpo_collection?.limitations || ["Данные о полноте SYSVOL ещё не получены."]).map(line => <p key={line} className="text-muted-foreground mt-2 text-xs">{line}</p>)}
                  </section>
                  <div className="flex flex-wrap items-center gap-2">
                    <Button size="sm" variant={conflictsOnly ? "default" : "outline"} onClick={() => setConflictsOnly((value) => !value)}>Только расхождения · {windows?.conflicts?.length ?? "…"}</Button>
                    <Button size="sm" variant={matrix ? "default" : "outline"} onClick={() => setMatrix(true)}>По политикам</Button>
                    <Button size="sm" variant={!matrix ? "default" : "outline"} onClick={() => setMatrix(false)}>Сведено</Button>
                    <span className="text-muted-foreground text-xs">{windows?.message || "Сравнение параметров ещё читается."}</span>
                  </div>
                  <div className="grid gap-2 rounded-xl border p-3">
                    <div className="text-sm font-medium">WMI-фильтры · {(picture.wmi || []).length}</div>
                    {(picture.wmi || []).length ? (picture.wmi || []).map((row) => {
                      const used = (picture.gpos || []).filter((item) => (item.wmi || "").toLowerCase() === (row.id || "").toLowerCase()).map((item) => item.name)
                      return (
                        <button key={row.id || row.name} type="button" className="hover:bg-muted/40 rounded-lg px-2 py-1 text-left text-xs" onClick={() => setPick({ title: row.name || "Фильтр WMI", lines: [row.note || "Описание не задано", row.query || "Запрос не прочитан", used.length ? "Политики: " + used.join(", ") : "К прочитанным политикам не привязан"] })}>
                          <span className="font-medium">{row.name || row.id}</span>
                          <span className="text-muted-foreground"> · {used.length ? used.length + " пол." : "не привязан"}</span>
                        </button>
                      )
                    }) : <p className="text-muted-foreground text-xs">Фильтров WMI в контейнере политик нет.</p>}
                  </div>
                  <div className="grid gap-2 rounded-xl border p-3">
                    <div className="text-sm font-medium">Baseline отдельных сохранённых параметров</div>
                    {(windows?.baseline || []).length ? (windows?.baseline || []).slice(0, 16).map((row) => (
                      <button key={row.key + row.gpo} type="button" className="hover:bg-muted/40 flex items-center justify-between rounded-lg px-2 py-1 text-left text-xs" onClick={() => setPick({ title: row.title, lines: [row.gpo, "Сейчас: " + row.value, "Линия: " + row.expected, row.ok ? "Сохранённое значение соответствует правилу baseline" : "Сохранённое значение не соответствует правилу baseline", "Проверка отдельных числовых настроек, не весь каталог ADMX. Отсутствующие настройки не оценены. Применение на узле не проверено."] })}>
                        <span>{row.title}</span>
                        <span className={row.ok ? "text-emerald-500" : "text-amber-500"}>{row.ok ? "соответствует" : "отклонение"}</span>
                      </button>
                    )) : <p className="text-muted-foreground text-xs">{windows ? "Оценённых параметров baseline нет: настройки могли отсутствовать, быть недоступны или не войти в ограниченный срез. Безопасность не подтверждена." : "Сверка ещё читается."}</p>}
                  </div>
                  {conflictsOnly && matrix ? (
                    <div className="overflow-auto rounded-xl border">
                      <table className="w-full min-w-[640px] text-left text-xs">
                        <thead className="bg-muted/50">
                          <tr>
                            <th className="px-3 py-2 font-medium">Параметр</th>
                            {gpoColumns.map((name) => <th key={name} className="px-3 py-2 font-medium">{name}</th>)}
                          </tr>
                        </thead>
                        <tbody>
                          {conflicts.map((row) => (
                            <tr key={row.key} className="hover:bg-muted/40 cursor-pointer border-t" onClick={() => setPick({ title: row.title || row.key, lines: [row.key, ...row.values.map((item) => item.gpo + ": " + item.value)] })}>
                              <td className="px-3 py-2">{row.title || row.key}</td>
                              {gpoColumns.map((name) => <td key={name} className="px-3 py-2">{row.values.find((item) => item.gpo === name)?.value || "—"}</td>)}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : conflictsOnly ? conflicts.map((row) => (
                    <button key={row.key} type="button" className="hover:bg-muted/40 rounded-xl border p-3 text-left text-sm" onClick={() => setPick({ title: row.title || row.key, lines: [row.key, ...row.values.map((item) => item.gpo + ": " + item.value)] })}>
                      <div className="font-medium">{row.title || row.key}</div>
                      {row.values.map((item) => <div key={item.gpo} className="text-muted-foreground">{item.gpo}: {item.value}</div>)}
                    </button>
                  )) : (
                    <div className="overflow-hidden rounded-xl border">
                      {gpos.map((row) => (
                        <button key={row.id || row.name} type="button" className="hover:bg-muted/50 flex w-full items-center justify-between border-b px-3 py-2 text-left text-sm last:border-b-0" onClick={() => setPick({ title: row.name, lines: [row.state, row.id || "идентификатор не прочитан"] })}>
                          <span>{row.name}</span>
                          <span className="text-muted-foreground text-xs">{row.state}</span>
                        </button>
                      ))}
                    </div>
                  )}
                  {conflictsOnly && !conflicts.length ? <p className="text-muted-foreground text-sm">В текущем ограниченном срезе расхождений не показано. Это не подтверждает отсутствие конфликтов или безопасную effective policy.</p> : null}
                </div>
              ) : null}
              {tab === "dcs" ? (
                <div className="grid gap-3">
                  <Kpis items={[
                    { label: "Контроллеры", value: String(picture.dcs?.length || 0) },
                    { label: "Ответили", value: String((windows?.controllers || []).filter((row) => row.ok).length) },
                    { label: "Связи не в норме", value: String((windows?.replication || []).filter((row) => row.state !== "норма").length), bad: (windows?.replication || []).some((row) => row.state !== "норма") },
                    { label: "Журнал недоступен", value: String((windows?.controllers || []).filter((row) => row.failed_24h === "-1").length), bad: (windows?.controllers || []).some((row) => row.failed_24h === "-1") },
                  ]} />
                  <div className="grid gap-3 md:grid-cols-2">
                    {(picture.dcs || []).filter((row) => hit(row.name + row.host + row.os)).map((row) => {
                      const extra = (windows?.controllers || []).find((item) => sameHost(item.host, row.host) || sameHost(item.host, row.name))
                      const ramFree = Number(extra?.ram_free_pct)
                      const diskFree = Number(extra?.disk_free_pct)
                      return (
                        <button key={row.name} type="button" className="hover:bg-muted/40 rounded-xl border p-3 text-left" onClick={() => setPick({ title: row.name, lines: [row.host || "имя узла не прочитано", row.os || "ОС не прочитана", extra?.maker ? extra.maker + " " + (extra.model || "") : "Модель ещё читается", extra?.bios ? "BIOS " + extra.bios : "BIOS ещё читается", extra?.cpu || "Процессор не прочитан", extra?.ntds_mb ? "Файл базы каталога " + extra.ntds_mb + " МБ" : "Размер базы ещё читается", extra?.boot_days ? "С загрузки " + extra.boot_days + " дн." : "Срок работы ещё читается", extra?.hotfix_ms14 === "no" ? "На старой версии нет KB3011780" : extra?.hotfix_ms14 === "yes" ? "KB3011780 установлен" : "Для текущей версии отдельный пакет Kerberos не требуется", ...(extra?.volumes || []).map((item) => item.drive + " " + item.size_gb + " ГБ, свободно " + item.free_pct + "%"), ...(extra?.nics || []).map((item) => item.name + (item.address ? " · " + item.address : "")), "Содержимое базы и текст событий не читаются"] })}>
                          <div className="font-medium">{row.name}</div>
                          <div className="text-muted-foreground mt-1 text-xs">{row.os || "ОС не прочитана"}{extra?.bios ? " · BIOS " + extra.bios : ""}</div>
                          <div className="mt-2 text-xs">{extra?.cpu || (extra ? "Процессор не прочитан" : windows ? "Контроллер не ответил по WinRM" : "Процессор ещё читается")}</div>
                          <div className="text-muted-foreground mt-1 text-xs">{extra?.ntds_mb ? "База каталога " + extra.ntds_mb + " МБ" : extra ? "Размер базы не прочитан" : "Размер базы ещё читается"}</div>
                          <div className="mt-3 grid gap-2">
                            {extra?.ram_gb ? <Meter label={"Память занята, всего " + extra.ram_gb + " ГБ"} used={Number.isFinite(ramFree) ? 100 - ramFree : 0} /> : <p className="text-muted-foreground text-xs">{windows ? "Память не прочитана" : "Память ещё читается."}</p>}
                            {(extra?.volumes || []).length ? extra?.volumes?.map((item) => <Meter key={item.drive} label={item.drive + " занят, " + item.size_gb + " ГБ"} used={100 - Number(item.free_pct || 0)} />) : extra?.disk_free_pct ? <Meter label="Диск занят" used={Number.isFinite(diskFree) ? 100 - diskFree : 0} /> : <p className="text-muted-foreground text-xs">Тома ещё читаются.</p>}
                          </div>
                          {(extra?.nics || []).length ? <div className="text-muted-foreground mt-2 text-xs">{extra?.nics?.map((item) => item.name + (item.address ? " · " + item.address : "")).join("; ")}</div> : null}
                          {(extra?.diag || []).length ? (
                            <div className="mt-2 flex flex-wrap gap-1">
                              {extra?.diag?.map((item) => <span key={item.test} className={"rounded-full px-2 py-0.5 text-[11px] " + (item.ok ? "bg-emerald-500/15" : "bg-red-500/15")}>{item.test}</span>)}
                            </div>
                          ) : null}
                        </button>
                      )
                    })}
                  </div>
                <div className="overflow-auto rounded-xl border">
                  <table className="w-full min-w-[720px] text-left text-sm">
                    <thead className="bg-muted/50 text-xs">
                      <tr>
                        {["Имя", "ОС", "Процессор", "Память", "Диск", "Входы 24 ч", "Блокировки"].map((head) => <th key={head} className="px-3 py-2 font-medium">{head}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {(picture.dcs || []).filter((row) => hit(row.name + row.host + row.os)).map((row) => {
                        const extra = (windows?.controllers || []).find((item) => sameHost(item.host, row.host) || sameHost(item.host, row.name))
                        const failed = extra?.failed_24h
                        const locked = extra?.locked_24h
                        const show = (value?: string) => value == null ? "…" : value === "-1" ? "журнал недоступен" : value
                        return (
                          <tr key={row.name} className="hover:bg-muted/40 cursor-pointer border-t" onClick={() => setPick({ title: row.name, lines: [row.host || "имя узла не прочитано", row.os || "ОС не прочитана", extra?.maker ? extra.maker + " " + (extra.model || "") : "Модель ещё читается", extra?.cpu || "Процессор не прочитан", "Текст событий не читается"] })}>
                            <td className="px-3 py-2">{row.name}</td>
                            <td className="px-3 py-2">{row.os || "—"}</td>
                            <td className="px-3 py-2">{extra?.cpu || extra?.model || "—"}</td>
                            <td className="px-3 py-2">{extra?.ram_gb ? extra.ram_gb + " ГБ, свободно " + extra.ram_free_pct + "%" : "—"}</td>
                            <td className="px-3 py-2">{extra?.disk_free_pct ? extra.disk_free_pct + "%" : "—"}</td>
                            <td className="px-3 py-2">{show(failed)}</td>
                            <td className="px-3 py-2">{show(locked)}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
                </div>
              ) : null}
              {tab === "posture" ? (
                <div className="grid gap-2">
                  <div className="rounded-xl border p-4">
                    <h2 className="font-medium">Защита контроллеров</h2>
                    <p className="text-muted-foreground mt-2 text-sm">Проверки подписи LDAP/SMB, NTLM, служб и времени из результатов сканирования, а также диагностика dcdiag. Это не полная аттестация безопасности леса.</p>
                    <p className="text-muted-foreground mt-2 text-xs">Отсутствие открытых отметок не доказывает безопасность. Доступность узла не подтверждает выполнение всех проверок реестра и журналов.</p>
                    <p className="mt-2 text-xs">Контроллеров обнаружено: {coverage?.scope?.discovered_dcs ?? picture.dcs?.length ?? "—"}; опрошено: {coverage?.scope?.probed_dcs ?? "—"}; ответили: {coverage?.scope?.readable_dcs ?? "—"}.</p>
                  </div>
                  {(windows?.controllers || []).filter((row) => (row.diag || []).length).map((row) => (
                    <div key={row.host} className="rounded-xl border p-3">
                      <div className="mb-2 text-sm font-medium">{row.host}</div>
                      <div className="flex flex-wrap gap-1">
                        {row.diag?.map((item) => <span key={item.test} className={"rounded-full px-2 py-0.5 text-[11px] " + (item.ok ? "bg-emerald-500/15" : "bg-red-500/15")}>{item.test}: {item.ok ? "норма" : "сбой"}</span>)}
                      </div>
                      <p className="text-muted-foreground mt-2 text-xs">Пять тестов dcdiag. Полный журнал не сохраняется.</p>
                    </div>
                  ))}
                  {posture.length ? posture.map((row) => (
                    <button key={row.id} type="button" className="hover:bg-muted/40 rounded-xl border px-3 py-2 text-left text-sm" onClick={() => setPick({ title: row.title, lines: [row.detail || "Подробности в карточке инцидента", "Критичность: " + row.severity] })}>
                      {row.title}
                    </button>
                  )) : (windows?.controllers || []).some((row) => (row.diag || []).length) ? null : <p className="text-muted-foreground text-sm">В текущих инцидентах нет отметок по подписи, LLMNR, печати, WebClient и времени. Тесты dcdiag появятся, когда контроллер ответит.</p>}
                </div>
              ) : null}
            </div>
            <aside className="bg-card h-fit rounded-xl border p-4 text-sm">
              <div className="font-medium">{pick?.title || "Объект не выбран"}</div>
              <div className="mt-2 grid gap-2">
                {(pick?.lines || ["Нажмите сайт, сервер, доверие, зону или строку таблицы. Панель остаётся здесь и не закрывает схему."]).map((line) => <p key={line}>{line}</p>)}
              </div>
              <div className="text-muted-foreground mt-4 grid gap-1 text-xs">
                <div>Сайты {picture.sites?.length || 0}</div>
                <div>Контроллеры {picture.dcs?.length || 0}</div>
                <div>Внешние без карантина SID {weakTrusts}</div>
                <div>Расхождения политик {windows?.conflicts?.length ?? "…"}</div>
              </div>
            </aside>
          </div>
        </div>
      ) : null}
    </div>
  )
}
