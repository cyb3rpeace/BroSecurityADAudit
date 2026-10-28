import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { PageHead } from "@/components/bits"
import { ExportButtons } from "@/components/export-buttons"
import { useApp } from "@/app-state"

const MODULES: { id: string; title: string }[] = [
  { id: "baseline_hygiene", title: "Базовая гигиена" },
  { id: "trusts", title: "Доверия и фильтрация SID" },
  { id: "time_sync", title: "Время контроллеров" },
  { id: "protocols", title: "Опасные протоколы" },
  { id: "dc_hardening", title: "Харденинг контроллера" },
  { id: "gpp_passwords", title: "Пароли в GPO" },
  { id: "ad_cs", title: "AD CS" },
  { id: "software_audit", title: "Аудит ПО" },
]

export function Reports() {
  const { t, compare, timeline, companyId } = useApp()
  const ready = !!compare?.ready
  const [picked, setPicked] = useState<string[]>(MODULES.map((item) => item.id))

  function flip(id: string) {
    setPicked((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id])
  }

  return (
    <div>
      <PageHead title={t("rep.title")} sub={t("rep.sub")} />
      <p className="text-muted-foreground mb-4 text-sm">{compare?.message || t("rep.none")}</p>
      <Card className="mb-4">
        <CardHeader><CardTitle className="text-base">Что включить в файл</CardTitle></CardHeader>
        <CardContent className="grid gap-3">
          <p className="text-muted-foreground text-sm">Отметьте модули проверки. В Excel и PDF попадут только находки этих модулей. На вкладках инцидентов, учётных записей, путей и устройств файл собирается по фильтрам, которые там уже выбраны.</p>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="outline" onClick={() => setPicked(MODULES.map((item) => item.id))}>Все модули</Button>
            <Button type="button" size="sm" variant="outline" onClick={() => setPicked([])}>Снять</Button>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {MODULES.map((item) => (
              <label key={item.id} className="flex items-center gap-2 rounded-lg border px-3 py-2 text-sm">
                <input type="checkbox" checked={picked.includes(item.id)} onChange={() => flip(item.id)} />
                {item.title}
              </label>
            ))}
          </div>
          {companyId && picked.length ? <ExportButtons modules={picked} /> : <p className="text-muted-foreground text-sm">Отметьте хотя бы один модуль.</p>}
        </CardContent>
      </Card>
      <div className="mb-4 grid gap-3 xl:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>{t("rep.added")}</CardTitle></CardHeader>
          <CardContent className="grid gap-2 text-sm">
            <p className="text-muted-foreground">{ready ? `${compare?.left?.label || ""} → ${compare?.right?.label || ""}` : t("rep.none")}</p>
            {ready && (compare?.added || []).length ? compare?.added.map((row, index) => (
              <div key={index} className="rounded-lg border p-3">
                <div className="font-medium">{row.title}</div>
                <div className="text-muted-foreground text-xs">{row.hostname} · {row.detail}</div>
              </div>
            )) : <p className="text-muted-foreground">{ready ? t("rep.new") : ""}</p>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>{t("rep.removed")}</CardTitle></CardHeader>
          <CardContent className="grid gap-2 text-sm">
            {(ready && (compare?.removed || []).length) ? compare?.removed.map((row, index) => (
              <div key={index} className="rounded-lg border p-3">
                <div className="font-medium">{row.title}</div>
                <div className="text-muted-foreground text-xs">{row.hostname} · {row.detail}</div>
              </div>
            )) : <p className="text-muted-foreground">{ready ? t("rep.closed") : ""}</p>}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader><CardTitle>{t("rep.history")}</CardTitle></CardHeader>
        <CardContent>
          <p className="text-muted-foreground mb-3 text-sm">Это сохраненные паспорта сканирований выбранной компании.</p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Когда</TableHead>
                <TableHead>Что это</TableHead>
                <TableHead>Кто</TableHead>
                <TableHead>Индекс</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {timeline.length ? [...timeline].reverse().map((point) => (
                <TableRow key={point.scan_id}>
                  <TableCell>{point.when || point.label}</TableCell>
                  <TableCell>Паспорт сканирования</TableCell>
                  <TableCell>{point.actor || "—"}</TableCell>
                  <TableCell>{point.score}</TableCell>
                  <TableCell><Button variant="outline" size="sm" onClick={() => window.open("/api/reports/" + point.scan_id, "_blank")}>Открыть</Button></TableCell>
                </TableRow>
              )) : <TableRow><TableCell colSpan={5} className="text-muted-foreground">{t("chart.empty")}</TableCell></TableRow>}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
