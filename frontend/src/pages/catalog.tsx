import { useEffect, useMemo, useRef, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
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
  groups?: { name: string; security: boolean }[]
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

type WindowsView = {
  ok: boolean
  message?: string
  controllers?: ControllerCard[]
  conflicts?: { key: string; values: { gpo: string; value: string }[] }[]
}

const POSTURE = ["ldap_signing_not_required", "smb_signing_off", "ldap_channel_binding", "ntlmv1_allowed", "llmnr_enabled", "print_spooler_on_dc", "webclient_running", "time_skew"]

function SiteMap({ sites, subnets }: { sites: { name: string; servers: string[] }[]; subnets: { name: string; site: string }[] }) {
  const frame = useRef<HTMLDivElement>(null)
  const drag = useRef<{ x: number; y: number; cx: number; cy: number } | null>(null)
  const [cam, setCam] = useState({ x: 24, y: 24, scale: 1 })
  useEffect(() => {
    const node = frame.current
    if (!node) return
    const onWheel = (event: WheelEvent) => {
      event.preventDefault()
      setCam((current) => ({ ...current, scale: Math.min(2.4, Math.max(0.45, current.scale + (event.deltaY < 0 ? 0.08 : -0.08))) }))
    }
    node.addEventListener("wheel", onWheel, { passive: false })
    return () => node.removeEventListener("wheel", onWheel)
  }, [])
  return (
    <div
      ref={frame}
      className="bg-muted/40 relative h-[440px] cursor-grab overflow-hidden rounded-xl border active:cursor-grabbing"
      onPointerDown={(event) => { drag.current = { x: event.clientX, y: event.clientY, cx: cam.x, cy: cam.y }; event.currentTarget.setPointerCapture(event.pointerId) }}
      onPointerMove={(event) => { if (!drag.current) return; setCam((current) => ({ ...current, x: drag.current!.cx + event.clientX - drag.current!.x, y: drag.current!.cy + event.clientY - drag.current!.y })) }}
      onPointerUp={() => { drag.current = null }}
    >
      <div className="absolute flex gap-4" style={{ transform: `translate(${cam.x}px, ${cam.y}px) scale(${cam.scale})`, transformOrigin: "0 0" }}>
        {sites.map((site) => (
          <div key={site.name} className="bg-card w-72 shrink-0 rounded-xl border p-3 text-sm">
            <div className="mb-2 font-medium">{site.name}</div>
            <div>{site.servers.join(", ") || "серверов в сайте нет"}</div>
            <div className="text-muted-foreground mt-2 text-xs">{subnets.filter((row) => row.site === site.name).map((row) => row.name).join(", ") || "подсети не привязаны"}</div>
          </div>
        ))}
      </div>
      <div className="text-muted-foreground absolute bottom-2 left-3 text-xs">Колесо меняет масштаб, перетаскивание двигает схему</div>
    </div>
  )
}

export function Catalog() {
  const { companyId, inventory } = useApp()
  const [picture, setPicture] = useState<Picture | null>(null)
  const [windows, setWindows] = useState<WindowsView | null>(null)
  const [error, setError] = useState("")
  const [tab, setTab] = useState("topology")
  const [query, setQuery] = useState("")
  const [sidOff, setSidOff] = useState(false)
  const [detail, setDetail] = useState<{ title: string; lines: string[] } | null>(null)
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
  const trusts = useMemo(() => (picture?.trusts || []).filter((row) => (!sidOff || !row.sid_filter) && hit(row.name + row.kind + row.direction)), [picture, sidOff, needle])
  const groups = (picture?.groups || []).filter((row) => hit(row.name))
  const ous = (picture?.ous || []).filter((name) => hit(name))
  const zones = (picture?.zones || []).filter((name) => hit(name))
  const gpos = (picture?.gpos || []).filter((row) => hit(row.name + row.state))
  const conflicts = (windows?.conflicts || []).filter((row) => hit(row.key + row.values.map((item) => item.gpo).join(" ")))
  const weakTrusts = (picture?.trusts || []).filter((row) => !row.sid_filter).length

  return (
    <div>
      <PageHead title="Каталог" sub="Топология с масштабом, учётные записи, группы, DNS, доверия, сравнение политик и контроллеры с железом и счётчиками входов. Текст чужих сессий не читается." />
      {error ? <p className="text-sm text-red-600">{error}</p> : null}
      {!picture && !error ? <p className="text-muted-foreground text-sm">Читаем каталог...</p> : null}
      {picture && !picture.ok ? <p className="text-sm">{picture.message}</p> : null}
      {picture?.ok ? (
        <>
        <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          <Button variant="outline" className="h-auto justify-start py-3" onClick={() => setTab("topology")}>Сайты · {picture.sites?.length || 0}</Button>
          <Button variant="outline" className="h-auto justify-start py-3" onClick={() => setTab("dcs")}>Контроллеры · {picture.dcs?.length || 0}</Button>
          <Button variant="outline" className="h-auto justify-start py-3" onClick={() => { setSidOff(true); setTab("trusts") }}>Доверия без фильтрации SID · {weakTrusts}</Button>
          <Button variant="outline" className="h-auto justify-start py-3" onClick={() => setTab("gpo")}>Расхождения политик · {windows?.conflicts?.length ?? "…"}</Button>
        </div>
        <div className="mb-3 flex flex-wrap gap-2">
          <Input className="max-w-sm" value={query} placeholder="Поиск по имени, зоне, политике" onChange={(event) => setQuery(event.target.value)} />
          {sidOff ? <Button variant="secondary" onClick={() => setSidOff(false)}>Показать все доверия</Button> : null}
        </div>
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList className="mb-4 flex h-auto flex-wrap">
            <TabsTrigger value="topology">Топология</TabsTrigger>
            <TabsTrigger value="accounts">Учётные записи</TabsTrigger>
            <TabsTrigger value="groups">Группы и OU</TabsTrigger>
            <TabsTrigger value="dns">DNS</TabsTrigger>
            <TabsTrigger value="trusts">Доверия</TabsTrigger>
            <TabsTrigger value="gpo">Политики</TabsTrigger>
            <TabsTrigger value="dcs">Контроллеры</TabsTrigger>
            <TabsTrigger value="posture">Поза</TabsTrigger>
          </TabsList>
          <TabsContent value="topology" className="grid gap-3">
            <SiteMap sites={picture.sites || []} subnets={picture.subnets || []} />
            <Card>
              <CardHeader><CardTitle className="text-base">Домен</CardTitle></CardHeader>
              <CardContent className="grid gap-1 text-sm">
                <div>{picture.domain}</div>
                <div>Режим: {picture.level || "не прочитан"}</div>
                <div>Роли FSMO: {(picture.roles || []).join(", ") || "не прочитаны"}</div>
              </CardContent>
            </Card>
          </TabsContent>
          <TabsContent value="accounts">
            <Card>
              <CardHeader><CardTitle className="text-base">Доменная политика паролей</CardTitle></CardHeader>
              <CardContent className="grid gap-1 text-sm">
                <div>Минимальная длина: {picture.policy?.length || "—"}</div>
                <div>История: {picture.policy?.history || "—"}</div>
                <div>Порог блокировки: {picture.policy?.lockout || "—"}</div>
                <div>Максимальный срок, дни: {picture.policy?.max_age_days || "—"}</div>
                <p className="text-muted-foreground text-xs">Точечные политики, LAPS и возраст пароля компьютера остаются в инцидентах гигиены. Пароли не читаются.</p>
              </CardContent>
            </Card>
          </TabsContent>
          <TabsContent value="groups" className="grid gap-3 md:grid-cols-2">
            <Card>
              <CardHeader><CardTitle className="text-base">Группы, первые {picture.groups?.length || 0}</CardTitle></CardHeader>
              <CardContent className="grid gap-1 text-sm">
                {groups.map((row) => (
              <button key={row.name} type="button" className="hover:bg-muted/50 rounded px-1 text-left" onClick={() => setDetail({ title: row.name, lines: [row.security ? "Группа безопасности" : "Группа рассылки", "Состав участников в этот срез не копируется."] })}>
                {row.name} · {row.security ? "безопасность" : "рассылка"}
              </button>
            ))}
                <p className="text-muted-foreground text-xs">Участники и полный граф вложенности не копируются. Пустые группы и циклы ищет гигиена.</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-base">Подразделения, первые {picture.ous?.length || 0}</CardTitle></CardHeader>
              <CardContent className="grid gap-1 text-sm">
                {ous.map((name) => <div key={name}>{name}</div>)}
              </CardContent>
            </Card>
          </TabsContent>
          <TabsContent value="dns">
            <Card>
              <CardHeader><CardTitle className="text-base">Имена зон</CardTitle></CardHeader>
              <CardContent className="grid gap-1 text-sm">
                {zones.map((name) => <button key={name} type="button" className="hover:bg-muted/50 rounded text-left" onClick={() => setDetail({ title: name, lines: ["Имя зоны. Записи и двоичные свойства DNS в этот срез не читаются."] })}>{name}</button>)}
                {!picture.zones?.length ? <p>Зоны не прочитаны или их нет в этом разделе.</p> : null}
                <p className="text-muted-foreground text-xs">Записи зон, динамические обновления из двоичного свойства и живая проверка разрешения имён не читаются.</p>
              </CardContent>
            </Card>
          </TabsContent>
          <TabsContent value="trusts" className="grid gap-3">
            {trusts.map((row) => (
              <button key={row.name} type="button" className="hover:bg-muted/40 rounded-xl border p-4 text-left" onClick={() => setDetail({ title: row.name, lines: [row.kind, row.direction, row.sid_filter ? "Фильтрация SID включена" : "Фильтрация SID выключена", row.selective ? "Выборочная проверка включена" : "Выборочная проверка не отмечена"] })}>
                <div className="font-medium">{row.name}</div>
                <div className="text-muted-foreground text-sm">{row.kind} · {row.direction} · фильтрация SID {row.sid_filter ? "включена" : "выключена"}</div>
              </button>
            ))}
            {!trusts.length ? <p className="text-muted-foreground text-sm">По фильтру доверий нет.</p> : null}
          </TabsContent>
          <TabsContent value="gpo" className="grid gap-2">
            {gpos.map((row) => (
              <button key={row.id || row.name} type="button" className="hover:bg-muted/50 flex items-center justify-between rounded-lg border px-3 py-2 text-left text-sm" onClick={() => setDetail({ title: row.name, lines: [row.state, row.id || "идентификатор не прочитан"] })}>
                <span>{row.name}</span>
                <span className="text-muted-foreground">{row.state}</span>
              </button>
            ))}
            <p className="text-muted-foreground text-xs">{windows?.message || "Сравнение параметров ещё читается."}</p>
            {conflicts.map((row) => (
              <div key={row.key} className="rounded-lg border p-3 text-sm">
                <div className="font-medium">{row.key}</div>
                {row.values.map((item) => <div key={item.gpo} className="text-muted-foreground">{item.gpo}: {item.value}</div>)}
              </div>
            ))}
            {windows && !windows.conflicts?.length ? <p className="text-muted-foreground text-xs">Расхождений в параметрах безопасности политик нет либо SYSVOL ещё не сравнен.</p> : null}
          </TabsContent>
          <TabsContent value="dcs" className="grid gap-3 md:grid-cols-2">
            {(picture.dcs || []).map((row) => {
              const extra = (windows?.controllers || []).find((item) => item.host === row.host || item.host === row.name)
              const failed = extra?.failed_24h
              const locked = extra?.locked_24h
              return (
                <Card key={row.name}>
                  <CardHeader><CardTitle className="text-base">{row.name}</CardTitle></CardHeader>
                  <CardContent className="grid gap-1 text-sm">
                    <div>{row.host || "имя узла не прочитано"}</div>
                    <div>{row.os || "ОС не прочитана"}</div>
                    {extra?.maker ? <div>{extra.maker} {extra.model}</div> : null}
                    {extra?.cpu ? <div>{extra.cpu}</div> : null}
                    {extra?.ram_gb ? <div>Память {extra.ram_gb} ГБ, свободно {extra.ram_free_pct}%</div> : null}
                    {extra?.disk_free_pct ? <div>Свободно на диске {extra.disk_free_pct}%</div> : null}
                    {failed != null ? <div>Неудачные входы за 24 ч: {failed === "-1" ? "журнал недоступен" : failed}. Блокировки: {locked === "-1" ? "журнал недоступен" : locked}. Текст событий не читается.</div> : <div className="text-muted-foreground">{extra?.detail || "Железо и счётчики ещё читаются по WinRM."}</div>}
                  </CardContent>
                </Card>
              )
            })}
          </TabsContent>
          <TabsContent value="posture" className="grid gap-2 text-sm">
            {posture.length ? posture.map((row) => <div key={row.id} className="rounded-lg border px-3 py-2">{row.title}</div>) : <p>В текущих инцидентах нет отметок по подписи, LLMNR, печати, WebClient и времени. Это не значит, что проверка ещё не запускалась.</p>}
          </TabsContent>
        </Tabs>
        <Sheet open={!!detail} onOpenChange={(open) => { if (!open) setDetail(null) }}>
          <SheetContent>
            <SheetHeader><SheetTitle>{detail?.title}</SheetTitle></SheetHeader>
            <div className="grid gap-2 px-4 text-sm">
              {detail?.lines.map((line) => <p key={line}>{line}</p>)}
            </div>
          </SheetContent>
        </Sheet>
        </>
      ) : null}
    </div>
  )
}
