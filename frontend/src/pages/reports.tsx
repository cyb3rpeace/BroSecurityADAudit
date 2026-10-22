import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { PageHead } from "@/components/bits"
import { useApp } from "@/app-state"

export function Reports() {
  const { t, compare, timeline, companyId } = useApp()
  const ready = !!compare?.ready
  return (
    <div>
      <PageHead title={t("rep.title")} sub={t("rep.sub")} />
      <p className="text-muted-foreground mb-4 text-sm">{compare?.message || t("rep.none")}</p>
      <div className="mb-4 flex flex-wrap gap-2">
        <Button onClick={() => { window.location.href = "/api/export/excel?company_id=" + companyId }}>{t("rep.excel")}</Button>
        <Button variant="outline" onClick={() => { window.location.href = "/api/export/pdf?company_id=" + companyId }}>{t("rep.pdf")}</Button>
      </div>
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
