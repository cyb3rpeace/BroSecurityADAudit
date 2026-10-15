import type { ReactNode } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { cycleStatus, rowStatus, sevColor } from "@/lib/findings"
import type { Finding, Theme } from "@/lib/types"
import { useApp } from "@/app-state"

export function Severity({ row, theme }: { row: Finding; theme: Theme }) {
  const { lang, t } = useApp()
  const color = sevColor(theme, row.severity)
  const label = lang === "en" ? t("sev." + row.severity) : row.severity_label
  return (
    <Badge variant="outline" style={{ color, borderColor: color }}>
      <span className="size-1.5 rounded-full" style={{ background: color }} />
      {label}
    </Badge>
  )
}

export function StatusButton({ row }: { row: Finding }) {
  const { t, bumpStatus, statusTick } = useApp()
  void statusTick
  const key = rowStatus(row)
  return (
    <Button
      type="button"
      size="sm"
      variant="outline"
      onClick={(event) => {
        event.stopPropagation()
        cycleStatus(row.id)
        bumpStatus()
      }}
    >
      {t("st." + key)}
    </Button>
  )
}

export function Kpi({ color, icon, label, value, delta }: { color: string; icon: ReactNode; label: string; value: number; delta?: string }) {
  const up = delta?.startsWith("+")
  const down = delta?.startsWith("-")
  return (
    <Card style={{ borderColor: color }}>
      <CardContent className="flex items-center gap-3">
        <div className="grid size-10 shrink-0 place-items-center rounded-xl" style={{ color, background: `${color}22` }}>
          {icon}
        </div>
        <div className="min-w-0">
          <div className="text-muted-foreground text-sm">{label}</div>
          <div className="text-3xl font-semibold leading-none">{value}</div>
          {delta ? <div className={up ? "text-xs text-red-400" : down ? "text-xs text-emerald-400" : "text-muted-foreground text-xs"}>{delta}</div> : null}
        </div>
      </CardContent>
    </Card>
  )
}

export function PageHead({ title, sub }: { title: string; sub?: string }) {
  return (
    <div className="mb-4">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      {sub ? <p className="text-muted-foreground mt-1 text-sm">{sub}</p> : null}
    </div>
  )
}
