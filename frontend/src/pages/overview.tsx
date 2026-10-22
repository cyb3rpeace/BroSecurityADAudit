import { ShieldAlert, TriangleAlert, UserRound, Box } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Kpi, PageHead, Severity } from "@/components/bits"
import { Donut, Bars, LegendButtons, TrendChart } from "@/components/charts"
import { ACCOUNT_IDS, DEVICE_IDS, PATH_IDS, deltaOf, driftText, incidentsOf, matchesQuery, palette, rank } from "@/lib/findings"
import { api } from "@/lib/api"
import { useApp } from "@/app-state"

export function Overview() {
  const { t, theme, inventory, timeline, compare, mitre, filters, patchFilters, openFinding, demo, companyId, company, reload } = useApp()
  const rows = incidentsOf(inventory)
  const colors = palette(theme)
  const crit = rows.filter((row) => row.severity === "critical").length
  const high = rows.filter((row) => row.severity === "high").length
  const exposed = inventory.filter((row) => ["ordinary_privileged", "stale_password", "kerberoasting", "asrep_preauth", "gpp_password"].includes(row.vuln_id)).length
  const stale = inventory.filter((row) => ["obsolete_os", "inactive_stale"].includes(row.vuln_id)).length
  const order = ["critical", "high", "medium", "low"]
  const areaRows = [
    { name: "Учетные записи", value: rows.filter((row) => ACCOUNT_IDS.has(row.vuln_id)).length },
    { name: "Устройства", value: rows.filter((row) => DEVICE_IDS.has(row.vuln_id)).length },
    { name: "Пути", value: rows.filter((row) => PATH_IDS.has(row.vuln_id)).length },
  ]
  const health = [
    ["Подпись LDAP", "ldap_signing_not_required"],
    ["Подпись SMB", "smb_signing_off"],
    ["Привязка канала", "ldap_channel_binding"],
    ["Время", "time_skew"],
    ["WebClient", "webclient_running"],
  ].map(([label, id]) => ({ label, open: rows.some((row) => row.vuln_id === id) }))
  const slices = order.map((key, index) => ({ name: t("sev." + key), value: rows.filter((row) => row.severity === key).length, fill: colors.donut[index] }))
  const top = rows
    .filter((row) => matchesQuery(row, filters.q) && (!filters.tactic || row.tactic === filters.tactic))
    .sort((a, b) => rank(a) - rank(b))
    .slice(0, 8)

  async function clearDemo() {
    if (!companyId) return
    await api("/api/demo-profile?company_id=" + companyId, { method: "DELETE" })
    await reload()
  }

  return (
    <div>
      <PageHead title={t("overview.title")} sub={company?.domain || company?.name || ""} />
      {demo ? (
        <Card className="mb-4 border-amber-500/50">
          <CardContent className="flex flex-wrap items-center justify-between gap-3">
            <span>{t("demo")}</span>
            <Button variant="outline" onClick={() => void clearDemo()}>{t("demo.clear")}</Button>
          </CardContent>
        </Card>
      ) : null}
      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi color={colors.donut[0]} icon={<ShieldAlert />} label={t("kpi.crit")} value={crit} delta={driftText(crit, deltaOf(compare, (row) => row.severity === "critical"), t("drift.none"))} />
        <Kpi color={colors.donut[1]} icon={<TriangleAlert />} label={t("kpi.high")} value={high} delta={driftText(high, deltaOf(compare, (row) => row.severity === "high"), t("drift.none"))} />
        <Kpi color={colors.bar[3]} icon={<UserRound />} label={t("kpi.exp")} value={exposed} delta={driftText(exposed, deltaOf(compare, (row) => ["ordinary_privileged", "stale_password", "kerberoasting"].includes(row.vuln_id || "")), t("drift.none"))} />
        <Kpi color={colors.donut[2]} icon={<Box />} label={t("kpi.stale")} value={stale} delta={driftText(stale, deltaOf(compare, (row) => ["obsolete_os", "inactive_stale"].includes(row.vuln_id || "")), t("drift.none"))} />
      </div>
      <div className="mb-4 flex flex-wrap gap-2">
        <Button size="sm" variant={filters.tactic ? "outline" : "secondary"} onClick={() => patchFilters({ tactic: "" })}>{t("mitre.all")}</Button>
        {mitre.map((item) => (
          <Button key={item.tactic} size="sm" variant={filters.tactic === item.tactic ? "secondary" : "outline"} onClick={() => patchFilters({ tactic: item.tactic })}>
            {item.tactic} · {item.count}
          </Button>
        ))}
      </div>
      <div className="mb-4 grid gap-3 xl:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>{t("chart.trend")}</CardTitle></CardHeader>
          <CardContent>
            {timeline.length ? <TrendChart points={timeline} color={colors.line} onPoint={(id) => window.open("/api/reports/" + id, "_blank")} /> : <p className="text-muted-foreground text-sm">{t("chart.empty")}</p>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>{t("chart.dist")}</CardTitle></CardHeader>
          <CardContent>
            <Donut slices={slices} />
            <LegendButtons items={slices} active="" onPick={() => undefined} />
          </CardContent>
        </Card>
      </div>
      <div className="mb-4 grid gap-3 xl:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Области каталога</CardTitle></CardHeader>
          <CardContent>
            <Bars rows={areaRows} active="" colors={colors.bar} onPick={() => undefined} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Контроллер в текущих инцидентах</CardTitle></CardHeader>
          <CardContent className="grid gap-2 text-sm">
            {health.map((item) => (
              <div key={item.label} className="flex items-center justify-between rounded-lg border px-3 py-2">
                <span>{item.label}</span>
                <span className={item.open ? "text-red-600 dark:text-red-400" : "text-muted-foreground"}>{item.open ? "есть отклонение" : "не отмечено"}</span>
              </div>
            ))}
            <p className="text-muted-foreground text-xs">«Не отмечено» значит, что такого инцидента нет в текущем каталоге. Это не заменяет повторную проверку, если модуль ещё не запускали.</p>
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader><CardTitle>{t("table.top")}</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("col.risk")}</TableHead>
                <TableHead>{t("col.type")}</TableHead>
                <TableHead>{t("col.object")}</TableHead>
                <TableHead>{t("col.level")}</TableHead>
                <TableHead>MITRE</TableHead>
                <TableHead>{t("col.seen")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {top.length ? top.map((row) => (
                <TableRow key={row.id} className="cursor-pointer" onClick={() => void openFinding(row)}>
                  <TableCell>
                    <div className="font-medium">{row.title}</div>
                    <div className="text-muted-foreground max-w-md truncate text-xs">{row.detail}</div>
                  </TableCell>
                  <TableCell>{row.category}</TableCell>
                  <TableCell>{row.hostname}</TableCell>
                  <TableCell><Severity row={row} theme={theme} /></TableCell>
                  <TableCell>{row.mitre}<div className="text-muted-foreground text-xs">{row.tactic}</div></TableCell>
                  <TableCell>{row.detected_at}</TableCell>
                </TableRow>
              )) : <TableRow><TableCell colSpan={6} className="text-muted-foreground">{t("empty")}</TableCell></TableRow>}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
