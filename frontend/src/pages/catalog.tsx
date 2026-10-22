import { useEffect, useMemo, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { PageHead } from "@/components/bits"
import { api } from "@/lib/api"
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
  groups?: { name: string; security: boolean; members?: string[]; member_count?: number }[]
  gpos?: { id?: string; name: string; state: string }[]
  trusts?: { name: string; direction: string; kind: string; sid_filter: boolean; selective: boolean }[]
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
}

type ZoneRow = {
  name: string
  type: string
  scope: string
  dynamic: string
  transfer: string
  aging: boolean
  reverse: boolean
}

type WindowsView = {
  ok: boolean
  message?: string
  controllers?: ControllerCard[]
  conflicts?: { key: string; values: { gpo: string; value: string }[] }[]
  replication?: { source: string; partner: string; partition: string; hours: string; state: string }[]
  dns?: { ok: boolean; message?: string; zones?: ZoneRow[]; locator?: { name: string; ok: boolean }[]; wildcard?: boolean; composition?: Record<string, Record<string, number>> }
}

type Pick = { title: string; lines: string[] }

const POSTURE = ["ldap_signing_not_required", "smb_signing_off", "ldap_channel_binding", "ntlmv1_allowed", "llmnr_enabled", "print_spooler_on_dc", "webclient_running", "time_skew"]
const SECTIONS = [
  ["topology", "Топология"],
  ["accounts", "Учётные записи"],
  ["groups", "Группы и OU"],
  ["dns", "DNS"],
  ["trusts", "Доверия"],
  ["gpo", "Политики"],
  ["dcs", "Контроллеры"],
  ["posture", "Поза"],
] as const

function tone(ok: boolean) {
  return ok ? "border-emerald-500/40 bg-emerald-500/10" : "border-red-500/40 bg-red-500/10"
}

function shortName(value: string) {
  return value.split(".")[0].replace(/^CN=/i, "").replace(/^DC=/i, "").toLowerCase()
}

function sameHost(left: string, right: string) {
  if (!left || !right) return false
  return left.toLowerCase() === right.toLowerCase() || shortName(left) === shortName(right)
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
  sites,
  subnets,
  roles,
  links,
  onPick,
}: {
  domain: string
  sites: { name: string; servers: string[] }[]
  subnets: { name: string; site: string }[]
  roles: string[]
  links: LinkRow[]
  onPick: (item: Pick) => void
}) {
  const [mode, setMode] = useState<"all" | "fail" | "fsmo">("all")
  const frame = useRef<HTMLDivElement>(null)
  const drag = useRef<{ x: number; y: number; cx: number; cy: number } | null>(null)
  const moved = useRef(false)
  const [cam, setCam] = useState({ x: 28, y: 28, scale: 1 })
  const width = Math.max(760, Math.max(1, sites.length) * 280 + 40)
  const height = 520
  const fsmo = new Set(roles.map((name) => shortName(name)))
  const nodes = sites.flatMap((site, index) => site.servers.map((server, order) => ({
    id: shortName(server),
    label: server,
    site: site.name,
    x: 70 + index * 280,
    y: 150 + order * 54,
    fsmo: fsmo.has(shortName(server)),
  })))
  const byId = new Map(nodes.map((node) => [node.id, node]))
  const drawn = links.flatMap((link) => {
    const from = byId.get(shortName(link.source))
    const to = byId.get(shortName(link.partner))
    if (!from || !to || from.id === to.id) return []
    if (mode === "fail" && link.state === "норма") return []
    return [{ ...link, x1: from.x, y1: from.y, x2: to.x, y2: to.y }]
  })
  const visible = nodes.filter((node) => {
    if (mode === "fsmo") return node.fsmo
    if (mode === "fail") return drawn.some((link) => shortName(link.source) === node.id || shortName(link.partner) === node.id)
    return true
  })

  function place(next: { x: number; y: number; scale: number }) {
    const box = frame.current
    const viewW = box?.clientWidth ?? 900
    const viewH = box?.clientHeight ?? 520
    const scaledW = width * next.scale
    const scaledH = height * next.scale
    const minX = Math.min(28, viewW - scaledW - 28)
    const minY = Math.min(28, viewH - scaledH - 28)
    return {
      scale: next.scale,
      x: Math.min(28, Math.max(minX, next.x)),
      y: Math.min(28, Math.max(minY, next.y)),
    }
  }

  useEffect(() => {
    const node = frame.current
    if (!node) return
    const onWheel = (event: WheelEvent) => {
      event.preventDefault()
      setCam((current) => place({ ...current, scale: Math.min(1.8, Math.max(0.6, current.scale + (event.deltaY < 0 ? 0.08 : -0.08))) }))
    }
    node.addEventListener("wheel", onWheel, { passive: false })
    return () => node.removeEventListener("wheel", onWheel)
  }, [width])

  return (
    <div className="overflow-hidden rounded-xl border">
      <div className="flex flex-wrap items-center gap-2 border-b px-3 py-2">
        <span className="text-sm font-medium">{domain || "Домен"}</span>
        <Button type="button" size="sm" variant={mode === "all" ? "default" : "outline"} onClick={() => setMode("all")}>Все</Button>
        <Button type="button" size="sm" variant={mode === "fail" ? "default" : "outline"} onClick={() => setMode("fail")}>Только сбой</Button>
        <Button type="button" size="sm" variant={mode === "fsmo" ? "default" : "outline"} onClick={() => setMode("fsmo")}>Только FSMO</Button>
        <div className="ml-auto flex gap-1">
          <Button type="button" size="sm" variant="outline" onClick={() => setCam((current) => place({ ...current, scale: Math.min(1.8, current.scale + 0.12) }))}>+</Button>
          <Button type="button" size="sm" variant="outline" onClick={() => setCam((current) => place({ ...current, scale: Math.max(0.6, current.scale - 0.12) }))}>−</Button>
          <Button type="button" size="sm" variant="outline" onClick={() => setCam({ x: 28, y: 28, scale: 1 })}>Сбросить</Button>
        </div>
      </div>
      <div
        ref={frame}
        className="relative h-[520px] cursor-grab touch-none select-none active:cursor-grabbing"
        style={{ backgroundImage: "radial-gradient(circle, color-mix(in oklab, var(--foreground) 18%, transparent) 1px, transparent 1px)", backgroundSize: "22px 22px" }}
        onDragStart={(event) => event.preventDefault()}
        onPointerDown={(event) => {
          event.preventDefault()
          moved.current = false
          drag.current = { x: event.clientX, y: event.clientY, cx: cam.x, cy: cam.y }
        }}
        onPointerMove={(event) => {
          if (!drag.current) return
          const dx = event.clientX - drag.current.x
          const dy = event.clientY - drag.current.y
          if (Math.abs(dx) + Math.abs(dy) > 4) moved.current = true
          setCam(place({ x: drag.current.cx + dx, y: drag.current.cy + dy, scale: cam.scale }))
        }}
        onPointerUp={() => { drag.current = null }}
        onPointerCancel={() => { drag.current = null }}
      >
        <svg className="absolute left-0 top-0" width={width} height={height} style={{ transform: `translate(${cam.x}px, ${cam.y}px) scale(${cam.scale})`, transformOrigin: "0 0" }}>
          {drawn.map((link) => (
            <line key={link.source + link.partner + link.partition} x1={link.x1} y1={link.y1} x2={link.x2} y2={link.y2} stroke={link.state === "норма" ? "#10b981" : "#ef4444"} strokeWidth={2} />
          ))}
          {sites.map((site, index) => {
            const nets = subnets.filter((row) => row.site === site.name)
            return (
              <g key={site.name} onClick={() => { if (!moved.current) onPick({ title: site.name, lines: ["Сайт", "Серверы: " + (site.servers.join(", ") || "нет"), "Подсети: " + (nets.map((row) => row.name).join(", ") || "не привязаны")] }) }}>
                <rect x={24 + index * 280} y={96} width={220} height={36} rx={10} fill="var(--card)" stroke="var(--border)" />
                <text x={36 + index * 280} y={119} fill="var(--foreground)" fontSize={12}>{site.name}</text>
              </g>
            )
          })}
          {visible.map((node) => (
            <g key={node.id} onClick={() => { if (!moved.current) onPick({ title: node.label, lines: ["Сайт " + node.site, node.fsmo ? "Держит роль FSMO" : "Роль FSMO не отмечена", "Связи репликации окрашены: зелёная в норме, красная со сбоем или задержкой."] }) }}>
              <circle cx={node.x} cy={node.y} r={16} fill={node.fsmo ? "#7c3aed" : "var(--card)"} stroke={node.fsmo ? "#7c3aed" : "var(--border)"} />
              <text x={node.x + 22} y={node.y + 4} fill="var(--foreground)" fontSize={12}>{node.label}</text>
            </g>
          ))}
          <g onClick={() => { if (!moved.current) onPick({ title: domain || "Домен", lines: ["Корень схемы.", roles.length ? "FSMO: " + roles.join(", ") : "Роли FSMO не прочитаны"] }) }}>
            <rect x={24} y={24} width={280} height={48} rx={12} fill="var(--card)" stroke="var(--border)" />
            <text x={36} y={44} fill="var(--muted-foreground)" fontSize={11}>Домен</text>
            <text x={36} y={62} fill="var(--foreground)" fontSize={12}>{domain || "имя не прочитано"}</text>
          </g>
        </svg>
      </div>
    </div>
  )
}

export function Catalog() {
  const { companyId, inventory } = useApp()
  const [picture, setPicture] = useState<Picture | null>(null)
  const [windows, setWindows] = useState<WindowsView | null>(null)
  const [error, setError] = useState("")
  const [tab, setTab] = useState<(typeof SECTIONS)[number][0]>("topology")
  const [query, setQuery] = useState("")
  const [sidOff, setSidOff] = useState(false)
  const [conflictsOnly, setConflictsOnly] = useState(false)
  const [groupKind, setGroupKind] = useState<"all" | "security" | "mail">("all")
  const [pick, setPick] = useState<Pick | null>(null)
  const [acct, setAcct] = useState<"policy" | "pso" | "laps" | "krb">("policy")
  const [matrix, setMatrix] = useState(true)
  const needle = query.trim().toLowerCase()
  const hit = (value: string) => !needle || value.toLowerCase().includes(needle)

  useEffect(() => {
    if (!companyId) return
    let alive = true
    setPicture(null)
    setError("")
    void api<Picture>("/api/directory/picture?company_id=" + companyId)
      .then((data) => { if (alive) setPicture(data) })
      .catch((reason: unknown) => { if (alive) setError(reason instanceof Error ? reason.message : "Каталог не прочитан") })
    void api<WindowsView>("/api/directory/windows?company_id=" + companyId)
      .then((data) => { if (alive) setWindows(data) })
      .catch(() => { if (alive) setWindows({ ok: false, message: "Срез WinRM не получен" }) })
    return () => { alive = false }
  }, [companyId])

  const posture = inventory.filter((row) => POSTURE.includes(row.vuln_id) && row.status !== "closed")
  const trusts = useMemo(() => (picture?.trusts || []).filter((row) => (!sidOff || !row.sid_filter) && hit(row.name + row.kind)), [picture, sidOff, needle])
  const groups = (picture?.groups || []).filter((row) => hit(row.name) && (groupKind === "all" || (groupKind === "security" ? row.security : !row.security)))
  const ous = (picture?.ous || []).filter((name) => hit(name))
  const zones = (picture?.zones || []).filter((name) => hit(name))
  const gpos = (picture?.gpos || []).filter((row) => hit(row.name + row.state))
  const conflicts = (windows?.conflicts || []).filter((row) => hit(row.key + row.values.map((item) => item.gpo).join(" ")))
  const weakTrusts = (picture?.trusts || []).filter((row) => !row.sid_filter).length
  const length = Number(picture?.policy?.length || 0)
  const lockout = picture?.policy?.lockout
  const age = picture?.policy?.max_age_days || ""
  const openRows = (id: string) => inventory.filter((row) => row.vuln_id === id && row.status !== "closed")
  const psoRows = openRows("weak_pso")
  const lapsRows = inventory.filter((row) => (row.vuln_id === "laps_gap" || row.vuln_id === "laps_missing") && row.status !== "closed")
  const krbRows = openRows("krbtgt_old")
  const gpoColumns = [...new Set(conflicts.flatMap((row) => row.values.map((item) => item.gpo)))].slice(0, 8)

  return (
    <div>
      <PageHead title="Каталог" sub="Схема домена, учётные записи, группы, DNS, доверия, политики и контроллеры. Перетаскивание не уводит блоки за край." />
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
              {tab === "topology" ? (
                <div className="grid gap-3">
                  <Topology domain={picture.domain || ""} sites={picture.sites || []} subnets={picture.subnets || []} roles={picture.roles || []} links={windows?.replication || []} onPick={setPick} />
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
                    <Button size="sm" variant={acct === "pso" ? "default" : "outline"} onClick={() => setAcct("pso")}>Точечные · {psoRows.length}</Button>
                    <Button size="sm" variant={acct === "laps" ? "default" : "outline"} onClick={() => setAcct("laps")}>LAPS · {lapsRows.length}</Button>
                    <Button size="sm" variant={acct === "krb" ? "default" : "outline"} onClick={() => setAcct("krb")}>krbtgt · {krbRows.length}</Button>
                  </div>
                  {acct === "policy" ? (
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
                      {(acct === "pso" ? psoRows : acct === "laps" ? lapsRows : krbRows).map((row) => (
                        <button key={row.id} type="button" className="hover:bg-muted/40 rounded-xl border px-3 py-2 text-left text-sm" onClick={() => setPick({ title: row.title, lines: [row.hostname, row.detail || "Подробности в инциденте"] })}>
                          <div className="font-medium">{row.title}</div>
                          <div className="text-muted-foreground text-xs">{row.hostname}</div>
                        </button>
                      ))}
                      {!(acct === "pso" ? psoRows : acct === "laps" ? lapsRows : krbRows).length ? <p className="text-muted-foreground text-sm">В текущих инцидентах таких отметок нет. Они появляются после сканирования гигиены.</p> : null}
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
                    <div className="border-b px-3 py-2 text-sm font-medium">Подразделения · {ous.length}</div>
                    {ous.map((name) => (
                      <button key={name} type="button" className="hover:bg-muted/50 block w-full border-b px-3 py-2 text-left text-sm last:border-b-0" onClick={() => setPick({ title: name, lines: ["Подразделение. Пустые подразделения отмечает гигиена."] })}>{name}</button>
                    ))}
                  </div>
                </div>
              ) : null}
              {tab === "dns" ? (
                <div className="grid gap-3">
                  <Kpis items={[
                    { label: "Зоны", value: String(windows?.dns?.zones?.length || zones.length) },
                    { label: "Служебные SRV", value: (windows?.dns?.locator || []).filter((row) => row.ok).length + " из " + ((windows?.dns?.locator || []).length || "…") },
                    { label: "Подстановка", value: windows?.dns?.wildcard ? "есть" : "нет", bad: !!windows?.dns?.wildcard },
                    { label: "Открытая передача", value: String((windows?.dns?.zones || []).filter((row) => /any/i.test(row.transfer)).length), bad: (windows?.dns?.zones || []).some((row) => /any/i.test(row.transfer)) },
                  ]} />
                  <div className="flex flex-wrap gap-2">
                    {(windows?.dns?.locator || []).map((row) => (
                      <span key={row.name} className={"rounded-full px-2 py-1 text-xs " + (row.ok ? "bg-emerald-500/15" : "bg-red-500/15")}>{row.name}: {row.ok ? "отвечает" : "нет ответа"}</span>
                    ))}
                    {windows?.dns ? <span className={"rounded-full px-2 py-1 text-xs " + (windows.dns.wildcard ? "bg-red-500/15" : "bg-muted")}>{windows.dns.wildcard ? "есть запись-подстановка" : "подстановки в зоне домена нет"}</span> : null}
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
                  {windows?.dns?.zones?.length ? (
                    <div className="overflow-auto rounded-xl border">
                      <table className="w-full min-w-[760px] text-left text-sm">
                        <thead className="bg-muted/50 text-xs">
                          <tr>{["Зона", "Тип", "Область", "Обновления", "Передача", "Очистка"].map((head) => <th key={head} className="px-3 py-2 font-medium">{head}</th>)}</tr>
                        </thead>
                        <tbody>
                          {windows.dns.zones.filter((row) => hit(row.name + row.type + row.dynamic)).map((row) => {
                            const openTransfer = /any/i.test(row.transfer)
                            const openUpdate = /nonsecure/i.test(row.dynamic)
                            return (
                              <tr key={row.name} className="hover:bg-muted/40 cursor-pointer border-t" onClick={() => setPick({ title: row.name, lines: [row.type + (row.reverse ? ", обратная" : ""), "Область: " + (row.scope || "не указана"), "Обновления: " + (row.dynamic || "не прочитаны"), "Передача: " + (row.transfer || "не прочитана"), row.aging ? "Очистка устаревших записей включена" : "Очистка устаревших записей выключена", "Содержимое зоны не выгружалось."] })}>
                                <td className="px-3 py-2">{row.name}</td>
                                <td className="px-3 py-2">{row.type}</td>
                                <td className="px-3 py-2">{row.scope || "—"}</td>
                                <td className="px-3 py-2"><span className={openUpdate ? "text-red-600" : ""}>{row.dynamic || "—"}</span></td>
                                <td className="px-3 py-2"><span className={openTransfer ? "text-red-600" : ""}>{row.transfer || "—"}</span></td>
                                <td className="px-3 py-2">{row.aging ? "включена" : "выключена"}</td>
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
                    <Button size="sm" variant={sidOff ? "default" : "outline"} onClick={() => setSidOff((value) => !value)}>Только без фильтрации SID · {weakTrusts}</Button>
                  </div>
                  <svg viewBox="0 0 720 420" className="bg-muted/20 h-[420px] w-full rounded-xl border">
                    {trusts.map((row, index) => {
                      const angle = (Math.PI * 2 * index) / Math.max(trusts.length, 1) - Math.PI / 2
                      const x = 360 + Math.cos(angle) * 220
                      const y = 210 + Math.sin(angle) * 140
                      const color = row.sid_filter ? "#10b981" : "#ef4444"
                      return (
                        <g key={row.name} onClick={() => setPick({ title: row.name, lines: [row.kind, row.direction, row.sid_filter ? "Фильтрация SID включена" : "Фильтрация SID выключена", row.selective ? "Выборочная проверка включена" : "Выборочная проверка не отмечена"] })}>
                          <line x1={360} y1={210} x2={x} y2={y} stroke={color} strokeWidth={2} />
                          <rect x={x - 70} y={y - 18} width={140} height={36} rx={10} fill="var(--card)" stroke={color} />
                          <text x={x} y={y + 4} textAnchor="middle" fill="var(--foreground)" fontSize={11}>{row.name.length > 18 ? row.name.slice(0, 18) + "…" : row.name}</text>
                        </g>
                      )
                    })}
                    <rect x={250} y={188} width={220} height={44} rx={12} fill="var(--card)" stroke="var(--border)" />
                    <text x={360} y={214} textAnchor="middle" fill="var(--foreground)" fontSize={12}>{picture.domain || "Домен"}</text>
                  </svg>
                  {!trusts.length ? <p className="text-muted-foreground text-sm">По фильтру доверий нет.</p> : null}
                </div>
              ) : null}
              {tab === "gpo" ? (
                <div className="grid gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Button size="sm" variant={conflictsOnly ? "default" : "outline"} onClick={() => setConflictsOnly((value) => !value)}>Только расхождения · {windows?.conflicts?.length ?? "…"}</Button>
                    <Button size="sm" variant={matrix ? "default" : "outline"} onClick={() => setMatrix(true)}>По политикам</Button>
                    <Button size="sm" variant={!matrix ? "default" : "outline"} onClick={() => setMatrix(false)}>Сведено</Button>
                    <span className="text-muted-foreground text-xs">{windows?.message || "Сравнение параметров ещё читается."}</span>
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
                            <tr key={row.key} className="hover:bg-muted/40 cursor-pointer border-t" onClick={() => setPick({ title: row.key, lines: row.values.map((item) => item.gpo + ": " + item.value) })}>
                              <td className="px-3 py-2">{row.key}</td>
                              {gpoColumns.map((name) => <td key={name} className="px-3 py-2">{row.values.find((item) => item.gpo === name)?.value || "—"}</td>)}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : conflictsOnly ? conflicts.map((row) => (
                    <button key={row.key} type="button" className="hover:bg-muted/40 rounded-xl border p-3 text-left text-sm" onClick={() => setPick({ title: row.key, lines: row.values.map((item) => item.gpo + ": " + item.value) })}>
                      <div className="font-medium">{row.key}</div>
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
                  {conflictsOnly && !conflicts.length ? <p className="text-muted-foreground text-sm">Расхождений в шаблоне безопасности нет либо SYSVOL ещё не сравнен.</p> : null}
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
                  {posture.length ? posture.map((row) => (
                    <button key={row.id} type="button" className="hover:bg-muted/40 rounded-xl border px-3 py-2 text-left text-sm" onClick={() => setPick({ title: row.title, lines: [row.detail || "Подробности в карточке инцидента", "Критичность: " + row.severity] })}>
                      {row.title}
                    </button>
                  )) : <p className="text-muted-foreground text-sm">В текущих инцидентах нет отметок по подписи, LLMNR, печати, WebClient и времени.</p>}
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
                <div>Доверия без SID {weakTrusts}</div>
                <div>Расхождения политик {windows?.conflicts?.length ?? "…"}</div>
              </div>
            </aside>
          </div>
        </div>
      ) : null}
    </div>
  )
}
