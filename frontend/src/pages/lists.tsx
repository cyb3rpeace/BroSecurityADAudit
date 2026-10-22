import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { PageHead, Severity } from "@/components/bits"
import { Pager } from "@/components/pager"
import { isAccount, isDevice, matchesQuery, rank } from "@/lib/findings"
import type { Finding } from "@/lib/types"
import { useApp } from "@/app-state"

function FilterRow() {
  const { t, filters, patchFilters } = useApp()
  return (
    <div className="mb-4 flex flex-wrap gap-2">
      {["", "critical", "high", "medium", "low"].map((key) => (
        <Button key={key || "all"} size="sm" variant={filters.sev === key ? "secondary" : "outline"} onClick={() => patchFilters({ sev: key })}>
          {key ? t("sev." + key) : t("all")}
        </Button>
      ))}
    </div>
  )
}

function Rows({ rows, hostLabel }: { rows: Finding[]; hostLabel: string }) {
  const { t, theme, openFinding, filters } = useApp()
  const sorted = [...rows].sort((a, b) => rank(a) - rank(b))
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(10)
  const filterKey = filters.q + "|" + filters.sev + "|" + rows.length
  useEffect(() => { setPage(1) }, [filterKey])
  const pages = Math.max(1, Math.ceil(sorted.length / size) || 1)
  const safePage = Math.min(page, pages)
  const slice = sorted.slice((safePage - 1) * size, safePage * size)
  return (
    <Card>
      <CardHeader><CardTitle>{hostLabel}</CardTitle></CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{hostLabel}</TableHead>
              <TableHead>{t("col.problem")}</TableHead>
              <TableHead>{t("col.type")}</TableHead>
              <TableHead>{t("col.level")}</TableHead>
              <TableHead>{t("col.seen")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {slice.length ? slice.map((row) => (
              <TableRow key={row.id} className="cursor-pointer" onClick={() => void openFinding(row)}>
                <TableCell>{row.hostname}</TableCell>
                <TableCell>
                  <div className="font-medium">{row.title}</div>
                  <div className="text-muted-foreground max-w-xl truncate text-xs">{row.detail}</div>
                </TableCell>
                <TableCell>{row.category}</TableCell>
                <TableCell><Severity row={row} theme={theme} /></TableCell>
                <TableCell>{row.detected_at}</TableCell>
              </TableRow>
            )) : <TableRow><TableCell colSpan={5} className="text-muted-foreground">{t("empty")}</TableCell></TableRow>}
          </TableBody>
          </Table>
          <Pager page={safePage} pages={pages} size={size} total={sorted.length} onPage={setPage} onSize={(next) => { setSize(next); setPage(1) }} />
      </CardContent>
    </Card>
  )
}

export function Accounts() {
  const { t, inventory, filters } = useApp()
  const rows = inventory.filter((row) => isAccount(row) && matchesQuery(row, filters.q) && (!filters.sev || row.severity === filters.sev))
  return (
    <div>
      <PageHead title={t("acc.title")} sub={t("acc.sub")} />
      <FilterRow />
      <Rows rows={rows} hostLabel={t("col.account")} />
    </div>
  )
}

export function Devices() {
  const { t, inventory, filters } = useApp()
  const rows = inventory.filter((row) => isDevice(row) && matchesQuery(row, filters.q) && (!filters.sev || row.severity === filters.sev))
  return (
    <div>
      <PageHead title={t("dev.title")} sub={t("dev.sub")} />
      <FilterRow />
      <Rows rows={rows} hostLabel={t("col.host")} />
    </div>
  )
}
