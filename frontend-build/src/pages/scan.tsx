import { useEffect, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { PageHead } from "@/components/bits"
import { ScanProgress, type ScanProgressData } from "@/components/scan-progress"
import { api } from "@/lib/api"
import type { ScanRow } from "@/lib/types"
import { useApp } from "@/app-state"

const MODULES = [
  ["ad_cs", "AD CS · LDAP"],
  ["software_audit", "Аудит ПО · Windows"],
  ["gpp_passwords", "Пароли в GPO · Windows"],
  ["dc_hardening", "Харденинг · LDAPS или Windows"],
  ["trusts", "Доверия и SID · LDAP"],
  ["time_sync", "Время · Windows"],
  ["baseline_hygiene", "Гигиена · LDAP"],
  ["protocols", "Протоколы · LDAP и WinRM"],
] as const

const DAYS = [
  ["mon", "Пн"],
  ["tue", "Вт"],
  ["wed", "Ср"],
  ["thu", "Чт"],
  ["fri", "Пт"],
  ["sat", "Сб"],
  ["sun", "Вс"],
] as const

function queuedProgress(ids: string[]): ScanProgressData {
  return {
    elapsed_sec: 0,
    status: "ожидание",
    modules: MODULES.filter(([id]) => ids.includes(id)).map(([id, label]) => ({
      id,
      title: label.split(" · ")[0],
      state: "wait" as const,
      note: "ждёт запуска",
      at: "",
    })),
    hosts: null,
  }
}

function readSchedule(raw: string | undefined) {
  const hourly = (raw || "").match(/^hourly@(\d{2})$/)
  if (hourly) return { mode: "hourly" as const, days: ["mon"], time: "02:00", minute: hourly[1] }
  if (raw === "daily") return { mode: "days" as const, days: DAYS.map((row) => row[0]), time: "02:00", minute: "00" }
  const match = (raw || "").match(/^((?:mon|tue|wed|thu|fri|sat|sun)(?:,(?:mon|tue|wed|thu|fri|sat|sun))*)@(\d{2}:\d{2})$/)
  if (match) return { mode: "days" as const, days: match[1].split(","), time: match[2], minute: "00" }
  return { mode: "days" as const, days: ["mon"], time: "02:00", minute: "00" }
}

export function Scan() {
  const { t, company, companyId, scheduler, reload, watchScan, live } = useApp()
  const initial = readSchedule(company?.schedule)
  const [picked, setPicked] = useState<string[]>(MODULES.map((row) => row[0]))
  const [mode, setMode] = useState<"days" | "hourly">(initial.mode)
  const [days, setDays] = useState<string[]>(initial.days)
  const [time, setTime] = useState(initial.time)
  const [minute, setMinute] = useState(initial.minute)
  const [enabled, setEnabled] = useState(company?.scheduler_enabled ? "true" : "false")
  const [log, setLog] = useState(scheduler?.label || "")
  const [progress, setProgress] = useState<ScanProgressData | null>(null)
  const [busy, setBusy] = useState(false)
  const [history, setHistory] = useState<ScanRow[]>([])

  useEffect(() => {
    if (!companyId) return
    void api<ScanRow[]>("/api/scans?company_id=" + companyId).then((rows) => {
      setHistory(rows)
      const latest = rows[0]
      if (!latest || busy) return
      void api<{ status: string; summary: string; progress: ScanProgressData | null }>("/api/scans/" + latest.id)
        .then((scan) => { if (scan.progress) setProgress(scan.progress) })
        .catch(() => undefined)
    }).catch(() => setHistory([]))
  }, [companyId, busy])

  useEffect(() => {
    const next = readSchedule(company?.schedule)
    setMode(next.mode)
    setDays(next.days)
    setTime(next.time)
    setMinute(next.minute)
    setEnabled(company?.scheduler_enabled ? "true" : "false")
  }, [company?.schedule, company?.scheduler_enabled])

  function toggle(id: string, on: boolean) {
    setPicked((current) => on ? [...new Set([...current, id])] : current.filter((item) => item !== id))
  }

  function toggleDay(id: string, on: boolean) {
    setDays((current) => on ? [...new Set([...current, id])] : current.filter((item) => item !== id))
  }

  async function run() {
    if (!companyId) return
    setBusy(true)
    setLog(t("run") + "...")
    try {
      const started = await api<{ scan_id: number }>("/api/run-task", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ company_id: companyId, domain_controller: company?.dc_host || "", modules: picked }),
      })
      watchScan(started.scan_id)
      const watch = async () => {
        const scan = await api<{ status: string; summary: string; progress: ScanProgressData | null }>("/api/scans/" + started.scan_id)
        if (scan.progress) setProgress(scan.progress)
        setLog(scan.summary || scan.status)
        if (scan.status === "queued" || scan.status === "running") {
          window.setTimeout(() => void watch(), 2000)
        } else {
          setBusy(false)
          await reload()
        }
      }
      window.setTimeout(() => void watch(), 1000)
    } catch (error) {
      setBusy(false)
      const message = error instanceof Error ? error.message : "Сканирование не запустилось"
      setLog(message)
      toast.error(message)
    }
  }

  async function saveSchedule() {
    if (!companyId) return
    const hourlyMinute = minute.padStart(2, "0")
    if (mode === "hourly" && (!/^\d{2}$/.test(hourlyMinute) || Number(hourlyMinute) > 59)) {
      toast.error("Укажите минуту часа от 00 до 59")
      return
    }
    if (mode === "days" && (!days.length || !/^\d{2}:\d{2}$/.test(time))) {
      toast.error("Выберите хотя бы один день и время")
      return
    }
    const interval = mode === "hourly"
      ? "hourly@" + hourlyMinute
      : DAYS.map((row) => row[0]).filter((id) => days.includes(id)).join(",") + "@" + time
    try {
      const data = await api<{ label: string }>("/api/schedule", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ company_id: companyId, interval, enabled: enabled === "true" }),
      })
      setLog(data.label)
      toast.success(data.label)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Расписание не сохранилось")
    }
  }

  return (
    <div>
      <PageHead title={t("nav.scan")} sub={t("scan.sub")} />
      <Card>
        <CardHeader><CardTitle>{t("nav.scan")}</CardTitle></CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid gap-3 sm:grid-cols-2">
            {MODULES.map(([id, label]) => (
              <Label key={id} className="flex items-center gap-2">
                <Checkbox checked={picked.includes(id)} onCheckedChange={(value) => toggle(id, value === true)} />
                {label}
              </Label>
            ))}
          </div>
          <div className="grid gap-2">
            <p className="text-sm font-medium">Когда запускать</p>
            <Select value={mode} onValueChange={(value) => setMode(value === "hourly" ? "hourly" : "days")}>
              <SelectTrigger className="w-56"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="days">По дням недели</SelectItem>
                <SelectItem value="hourly">Каждый час</SelectItem>
              </SelectContent>
            </Select>
            {mode === "hourly" ? (
              <Label className="flex items-center gap-2 text-sm">
                Минута часа
                <Input className="w-24" inputMode="numeric" maxLength={2} value={minute} onChange={(event) => setMinute(event.target.value.replace(/\D/g, "").slice(0, 2))} />
              </Label>
            ) : (
              <div className="flex flex-wrap gap-2">
                {DAYS.map(([id, label]) => (
                  <Label key={id} className="flex items-center gap-2">
                    <Checkbox checked={days.includes(id)} onCheckedChange={(value) => toggleDay(id, value === true)} />
                    {label}
                  </Label>
                ))}
                <Input className="w-32" type="time" value={time} onChange={(event) => setTime(event.target.value)} />
              </div>
            )}
            <p className="text-muted-foreground text-xs">{mode === "hourly" ? "Проверка стартует каждый час в выбранную минуту. Следующий запуск виден в строке расписания после сохранения." : "Проверка стартует в выбранные дни в указанное время."}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button disabled={busy || !picked.length} onClick={() => void run()}>{t("run")}</Button>
            <Select value={enabled} onValueChange={setEnabled}>
              <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="false">Выключен</SelectItem>
                <SelectItem value="true">Включен</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" onClick={() => void saveSchedule()}>{t("sch.save")}</Button>
          </div>
          {log ? <p className="text-muted-foreground text-xs whitespace-pre-wrap">{log}</p> : null}
        </CardContent>
      </Card>
      <div className="mt-4">
        <ScanProgress data={live || progress || queuedProgress(picked)} />
      </div>
      <Card className="mt-4">
        <CardHeader><CardTitle>{t("scan.history")}</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Когда</TableHead>
                <TableHead>{t("scan.actor")}</TableHead>
                <TableHead>Модули</TableHead>
                <TableHead>Статус</TableHead>
                <TableHead>Индекс</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {history.length ? history.map((row) => (
                <TableRow key={row.id}>
                  <TableCell>{row.finished_at || row.started_at}</TableCell>
                  <TableCell>{row.actor}</TableCell>
                  <TableCell className="max-w-64 truncate">{row.module}</TableCell>
                  <TableCell>{row.status}</TableCell>
                  <TableCell>{row.risk_score ?? "—"}</TableCell>
                </TableRow>
              )) : <TableRow><TableCell colSpan={5} className="text-muted-foreground">Записей еще нет.</TableCell></TableRow>}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
