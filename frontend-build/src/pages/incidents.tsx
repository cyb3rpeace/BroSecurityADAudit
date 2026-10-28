import { useEffect, useState } from "react"
import { Siren, TriangleAlert, Box, Search } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Kpi, PageHead, Severity, StatusButton } from "@/components/bits"
import { Pager } from "@/components/pager"
import { Bars, Donut, LegendButtons } from "@/components/charts"
import { countBy, incidentsOf, matchesQuery, palette, rowStatus, sourceName } from "@/lib/findings"
import { ExportButtons } from "@/components/export-buttons"
import { useApp } from "@/app-state"

export function Incidents() {
  const { t, theme, inventory, filters, patchFilters, openFinding, statusTick } = useApp()
  void statusTick
  const colors = palette(theme)
  const rows = incidentsOf(inventory)
  const shown = rows.filter((row) =>
    matchesQuery(row, filters.q) &&
    (!filters.sev || row.severity === filters.sev) &&
    (!filters.status || rowStatus(row) === filters.status) &&
    (!filters.category || row.category === filters.category) &&
    (!filters.source || sourceName(row) === filters.source) &&
    (!filters.tactic || row.tactic === filters.tactic)
  )
  const crit = rows.filter((row) => row.severity === "critical").length
  const high = rows.filter((row) => row.severity === "high").length
  const hosts = new Set(inventory.map((row) => row.hostname)).size
  const openCount = rows.filter((row) => rowStatus(row) === "open").length
  const cats = [...new Set(rows.map((row) => row.category))].sort()
  const tactics = [...new Set(rows.map((row) => row.tactic).filter(Boolean))].sort()
  const bars = countBy(shown, (row) => row.category)
  const sources = countBy(shown, sourceName).map((item, index) => ({ ...item, fill: colors.bar[index % colors.bar.length] }))
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(10)
  const filterKey = [filters.q, filters.sev, filters.status, filters.category, filters.source, filters.tactic].join("|")
  useEffect(() => { setPage(1) }, [filterKey])
  const pages = Math.max(1, Math.ceil(shown.length / size) || 1)
  const safePage = Math.min(page, pages)
  const slice = shown.slice((safePage - 1) * size, safePage * size)

  return (
    <div>
      <PageHead title={t("inc.title")} sub={t("inc.sub")} />
      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi color={colors.donut[0]} icon={<Siren />} label={t("kpi.alerts")} value={rows.length} />
        <Kpi color={colors.donut[1]} icon={<TriangleAlert />} label={t("kpi.highsev")} value={crit + high} />
        <Kpi color={colors.bar[3]} icon={<Box />} label={t("kpi.objects")} value={hosts} />
        <Kpi color={colors.donut[2]} icon={<Search />} label={t("kpi.open")} value={openCount} />
      </div>
      <div className="mb-4 flex flex-wrap gap-2">
        {["", "critical", "high", "medium", "low"].map((key) => (
          <Button key={key || "all"} size="sm" variant={filters.sev === key ? "secondary" : "outline"} onClick={() => patchFilters({ sev: key })}>
            {key ? t("sev." + key) : t("all")}
          </Button>
        ))}
        {["", "open", "investigating", "closed"].map((key) => (
          <Button key={key || "st"} size="sm" variant={filters.status === key ? "secondary" : "outline"} onClick={() => patchFilters({ status: key })}>
            {key ? t("st." + key) : t("all")}
          </Button>
        ))}
        <Select value={filters.category || "all"} onValueChange={(value) => patchFilters({ category: value === "all" ? "" : value })}>
          <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t("all")}</SelectItem>
            {cats.map((cat) => <SelectItem key={cat} value={cat}>{cat}</SelectItem>)}
          </SelectContent>
        </Select>
        <ExportButtons ids={shown.map((row) => row.id)} />
        <Select value={filters.tactic || "all"} onValueChange={(value) => patchFilters({ tactic: value === "all" ? "" : value })}>
          <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">MITRE</SelectItem>
            {tactics.map((name) => <SelectItem key={name} value={name}>{name}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      <div className="mb-4 grid gap-3 xl:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>{t("inc.volume")}</CardTitle></CardHeader>
          <CardContent>
            {bars.length ? <Bars rows={bars} active={filters.category} colors={colors.bar} onPick={(name) => patchFilters({ category: filters.category === name ? "" : name })} /> : <p className="text-muted-foreground text-sm">{t("empty")}</p>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>{t("inc.source")}</CardTitle></CardHeader>
          <CardContent>
            {sources.length ? <Donut slices={sources} onSlice={(name) => patchFilters({ source: filters.source === name ? "" : name })} /> : <p className="text-muted-foreground text-sm">{t("empty")}</p>}
            <LegendButtons items={sources} active={filters.source} onPick={(name) => patchFilters({ source: filters.source === name ? "" : name })} />
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader><CardTitle>{t("inc.recent")}</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("col.when")}</TableHead>
                <TableHead>{t("col.event")}</TableHead>
                <TableHead>{t("col.type")}</TableHead>
                <TableHead>{t("col.object")}</TableHead>
                <TableHead>{t("col.level")}</TableHead>
                <TableHead>MITRE</TableHead>
                <TableHead>{t("col.status")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {slice.length ? slice.map((row) => (
                <TableRow key={row.id} className="cursor-pointer" onClick={() => void openFinding(row)}>
                  <TableCell>{row.detected_at}</TableCell>
                  <TableCell>
                    <div className="font-medium">{row.title}</div>
                    <div className="text-muted-foreground max-w-md truncate text-xs">{row.detail}</div>
                  </TableCell>
                  <TableCell>{row.category}</TableCell>
                  <TableCell>{row.hostname}</TableCell>
                  <TableCell><Severity row={row} theme={theme} /></TableCell>
                  <TableCell>{row.mitre}</TableCell>
                  <TableCell><StatusButton row={row} /></TableCell>
                </TableRow>
              )) : <TableRow><TableCell colSpan={7} className="text-muted-foreground">{t("empty")}</TableCell></TableRow>}
            </TableBody>
          </Table>
          <Pager page={safePage} pages={pages} size={size} total={shown.length} onPage={setPage} onSize={(next) => { setSize(next); setPage(1) }} />
        </CardContent>
      </Card>
    </div>
  )
}
