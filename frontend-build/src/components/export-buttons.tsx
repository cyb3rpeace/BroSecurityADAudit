import { useState } from "react"
import { Button } from "@/components/ui/button"
import { downloadFile } from "@/lib/download"
import { useApp } from "@/app-state"

export function ExportButtons({ ids, modules }: { ids?: number[]; modules?: string[] }) {
  const { companyId } = useApp()
  const [note, setNote] = useState("")
  const [busy, setBusy] = useState("")
  const [format, setFormat] = useState<"excel" | "pdf">("pdf")

  async function run(kind: "excel" | "pdf") {
    if (!companyId) return
    setNote("")
    setBusy(kind)
    try {
      await downloadFile(
        "/api/export/" + kind,
        { company_id: companyId, ids: ids ?? null, modules: modules || [] },
        kind === "excel" ? "report.xlsx" : "report.pdf",
      )
    } catch (reason: unknown) {
      setNote(reason instanceof Error ? reason.message : "Файл не собран")
    } finally {
      setBusy("")
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <label className="flex items-center gap-2 text-sm"><span className="text-muted-foreground">Формат отчёта</span><select value={format} onChange={event => setFormat(event.target.value as "excel" | "pdf")} disabled={!!busy} className="h-9 min-w-36 rounded-lg border border-input bg-background px-3 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"><option value="pdf">PDF</option><option value="excel">Excel</option></select></label>
      <Button size="sm" disabled={!!busy} onClick={() => void run(format)}>{busy ? "Собирается…" : "Сформировать отчёт"}</Button>
      {note ? <span className="text-sm text-red-400">{note}</span> : null}
    </div>
  )
}
