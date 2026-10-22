import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

export type ProgressModule = {
  id: string
  title: string
  state: "wait" | "now" | "done" | "error"
  note: string
  at: string
}

export type ScanProgressData = {
  elapsed_sec?: number
  status?: string
  modules: ProgressModule[]
  hosts?: { total: number; seen: number; read: number; closed: number; error: number } | null
}

function clock(seconds: number) {
  const safe = Math.max(0, seconds)
  const min = Math.floor(safe / 60)
  const sec = safe % 60
  return min + " мин " + String(sec).padStart(2, "0") + " с"
}

function HostBar({ total, read, closed, error }: { total: number; read: number; closed: number; error: number }) {
  const width = Math.max(total, 1)
  const parts = [
    { key: "read", value: read, className: "bg-primary" },
    { key: "closed", value: closed, className: "bg-muted-foreground/40" },
    { key: "error", value: error, className: "bg-destructive" },
  ]
  return (
    <div className="bg-muted flex h-2 overflow-hidden rounded-full" aria-hidden="true">
      {parts.map((part) => (
        <div key={part.key} className={part.className} style={{ width: (part.value / width) * 100 + "%" }} />
      ))}
    </div>
  )
}

export function ScanProgress({ data }: { data: ScanProgressData }) {
  const modules = data.modules || []
  const hosts = data.hosts
  const done = modules.filter((item) => item.state === "done" || item.state === "error").length
  const current = modules.find((item) => item.state === "now") || modules.find((item) => item.state !== "wait")
  const waiting = modules.filter((item) => item.state === "wait").map((item) => item.title)
  const hostTotal = hosts?.total || 0
  const hostSeen = hosts?.seen || 0
  const hostPct = hostTotal ? Math.round((hostSeen / hostTotal) * 100) : Math.round((done / Math.max(modules.length, 1)) * 100)
  const journal = modules.filter((item) => item.state !== "wait")

  return (
    <div className="grid gap-4">
      <div className="grid gap-3 sm:grid-cols-3">
        <Card><CardContent className="pt-4"><div className="text-2xl font-semibold">{clock(data.elapsed_sec || 0)}</div><div className="text-muted-foreground text-xs">Прошло с старта</div></CardContent></Card>
        <Card><CardContent className="pt-4"><div className="text-2xl font-semibold">{Math.min(done + (current?.state === "now" ? 1 : 0), modules.length)} из {modules.length}</div><div className="text-muted-foreground text-xs">Модулей завершено или в работе</div></CardContent></Card>
        <Card><CardContent className="pt-4"><div className="text-2xl font-semibold">{hostPct}%</div><div className="text-muted-foreground text-xs">{hostTotal ? "Компьютеров аудита ПО" : "Модулей"}</div></CardContent></Card>
      </div>
      <div>
        <h2 className="mb-2 text-sm font-semibold">Лента модулей</h2>
        <div className="divide-y rounded-lg border">
          {modules.map((item) => (
            <div key={item.id} className="px-3 py-2">
              <div className="flex items-center justify-between gap-3 text-sm">
                <span className={item.state === "now" ? "font-semibold" : ""}>{item.title}</span>
                <span className="text-muted-foreground text-xs">
                  {item.state === "done" ? "готово · " : item.state === "now" ? "идёт · " : item.state === "error" ? "ошибка · " : ""}
                  {item.note || "ждёт"}
                </span>
              </div>
              {item.id === "software_audit" && hosts && item.state === "now" ? (
                <div className="mt-2 grid gap-1">
                  <div className="text-muted-foreground flex justify-between text-xs"><span>Компьютеры аудита ПО</span><span>{hosts.seen} из {hosts.total}</span></div>
                  <HostBar total={hosts.total} read={hosts.read} closed={hosts.closed} error={hosts.error} />
                  <div className="text-muted-foreground text-xs">прочитано {hosts.read} · WinRM закрыт {hosts.closed} · ошибки {hosts.error}</div>
                </div>
              ) : null}
            </div>
          ))}
        </div>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle className="text-base">{current?.title || "Сканирование"}</CardTitle>
            <span className="bg-secondary rounded-full px-2 py-0.5 text-xs">{current?.state === "now" ? "идёт" : data.status === "success" ? "готово" : data.status || "идёт"}</span>
          </CardHeader>
          <CardContent className="grid gap-2 text-sm">
            <p>{hostTotal ? hosts!.seen + " из " + hosts!.total + " компьютеров" : (current?.note || "Модули в очереди")} · прошло {clock(data.elapsed_sec || 0)}</p>
            {hosts ? <HostBar total={hosts.total} read={hosts.read} closed={hosts.closed} error={hosts.error} /> : null}
            <p className="text-muted-foreground text-xs">{waiting.length ? "Дальше: " + waiting.join(", ") + "." : "Очередь модулей пуста."}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-base">Ход проверки</CardTitle></CardHeader>
          <CardContent className="grid gap-2">
            <div className="text-muted-foreground flex justify-between text-xs"><span>Модули</span><span>{done} готов</span></div>
            <div className="bg-muted h-2 overflow-hidden rounded-full"><div className="h-full bg-emerald-500" style={{ width: (done / Math.max(modules.length, 1)) * 100 + "%" }} /></div>
            {journal.length ? journal.map((item) => (
              <div key={item.id} className="grid grid-cols-[3.5rem_4.5rem_1fr] gap-2 text-xs">
                <span>{item.at || "—"}</span>
                <span className="font-semibold">{item.state === "done" ? "готово" : item.state === "error" ? "ошибка" : "идёт"}</span>
                <span className="truncate">{item.title}{item.note ? " · " + item.note : ""}</span>
              </div>
            )) : <p className="text-muted-foreground text-xs">Журнал появится, когда первый модуль начнётся.</p>}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
