import { useState } from "react"
import { Button } from "@/components/ui/button"
import { downloadFile } from "@/lib/download"
import { useApp } from "@/app-state"

export function ExportButtons({ ids, modules }: { ids?: number[]; modules?: string[] }) {
  const { companyId } = useApp()
  const [note, setNote] = useState("")
  const [busy, setBusy] = useState("")

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
      <Button size="sm" disabled={!!busy} onClick={() => void run("excel")}>{busy === "excel" ? "Собирается…" : "Excel"}</Button>
      <Button size="sm" variant="outline" disabled={!!busy} onClick={() => void run("pdf")}>{busy === "pdf" ? "Собирается…" : "PDF"}</Button>
      {note ? <span className="text-sm text-red-400">{note}</span> : null}
    </div>
  )
}
