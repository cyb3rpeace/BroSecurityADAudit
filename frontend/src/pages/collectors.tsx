import { useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { PageHead } from "@/components/bits"
import { api } from "@/lib/api"
import { useApp } from "@/app-state"

export function SharpHound() {
  const { t, companyId, reload } = useApp()
  const [file, setFile] = useState<File | null>(null)
  const [status, setStatus] = useState("")
  async function upload() {
    if (!file || !companyId) return
    const body = new FormData()
    body.append("company_id", String(companyId))
    body.append("upload", file)
    setStatus("Архив передается в BloodHound CE...")
    try {
      const data = await api<{ message: string }>("/api/import/sharphound", { method: "POST", body })
      setStatus(data.message || "Архив принят.")
      toast.success(data.message || "Архив принят.")
      await reload()
    } catch (error) {
      const message = error instanceof Error ? error.message : "Архив не принят"
      setStatus(message)
      toast.error(message)
    }
  }
  return (
    <div>
      <PageHead title="SharpHound" sub={t("sh.sub")} />
      <div className="grid gap-3 xl:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Как собрать граф</CardTitle></CardHeader>
          <CardContent className="grid gap-3 text-sm">
            <ol className="list-decimal space-y-2 pl-4">
              <li>На Windows-хосте откройте обычную доменную сессию, не WinRM.</li>
              <li>Запустите SharpHound методами DCOnly, Session, LocalAdmin и CA.</li>
              <li>Загрузите zip справа. Сервер передаст его в BloodHound CE и обновит пути атак.</li>
            </ol>
            <pre className="bg-muted overflow-auto rounded-lg p-3 text-xs">C:\Tools\SharpHound\SharpHound.exe -c DCOnly,Session,LocalAdmin,CA --zipfilename brosec --nosavecache</pre>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Загрузка архива</CardTitle></CardHeader>
          <CardContent className="grid gap-3">
            <p className="text-muted-foreground text-sm">Zip коллекции, не больше 80 МБ</p>
            <Input type="file" accept=".zip" onChange={(event) => setFile(event.target.files?.[0] || null)} />
            <Button onClick={() => void upload()}>Загрузить zip</Button>
            {status ? <p className="text-sm">{status}</p> : null}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
