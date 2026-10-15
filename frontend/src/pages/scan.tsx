import { useEffect, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { PageHead } from "@/components/bits"
import { api } from "@/lib/api"
import type { ScanRow } from "@/lib/types"
import { useApp } from "@/app-state"

const MODULES = [
  ["ad_cs", "AD CS · Windows"],
  ["software_audit", "Аудит ПО · Windows"],
  ["gpp_passwords", "Пароли в GPO · Windows"],
  ["dc_hardening", "Харденинг · LDAPS или Windows"],
  ["trusts", "Доверия и SID · LDAP"],
  ["time_sync", "Время · Windows"],
  ["baseline_hygiene", "Гигиена · LDAP"],
  ["protocols", "Протоколы · LDAP и WinRM"],
] as const

export function Scan() {
  const { t, company, companyId, scheduler, reload } = useApp()
  const [picked, setPicked] = useState<string[]>(MODULES.map((row) => row[0]))
  const [interval, setInterval] = useState(company?.schedule || "weekly")
  const [enabled, setEnabled] = useState(company?.scheduler_enabled ? "true" : "false")
  const [log, setLog] = useState(scheduler?.label || "")
  const [busy, setBusy] = useState(false)
  const [history, setHistory] = useState<ScanRow[]>([])

  useEffect(() => {
    if (!companyId) return
    void api<ScanRow[]>("/api/scans?company_id=" + companyId).then(setHistory).catch(() => setHistory([]))
  }, [companyId, busy])

  function toggle(id: string, on: boolean) {
    setPicked((current) => on ? [...new Set([...current, id])] : current.filter((item) => item !== id))
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
      const watch = async () => {
        const scan = await api<{ status: string; summary: string }>("/api/scans/" + started.scan_id)
        setLog(scan.status + "\n" + (scan.summary || ""))
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
          <div className="flex flex-wrap gap-2">
            <Button disabled={busy || !picked.length} onClick={() => void run()}>{t("run")}</Button>
            <Select value={interval} onValueChange={setInterval}>
              <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="daily">Каждый день</SelectItem>
                <SelectItem value="weekly">Каждую неделю</SelectItem>
                <SelectItem value="monthly">Каждый месяц</SelectItem>
              </SelectContent>
            </Select>
            <Select value={enabled} onValueChange={setEnabled}>
              <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="false">Выключен</SelectItem>
                <SelectItem value="true">Включен</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" onClick={() => void saveSchedule()}>{t("sch.save")}</Button>
          </div>
          {log ? <pre className="bg-muted overflow-auto rounded-lg p-3 text-xs whitespace-pre-wrap">{log}</pre> : null}
        </CardContent>
      </Card>
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
