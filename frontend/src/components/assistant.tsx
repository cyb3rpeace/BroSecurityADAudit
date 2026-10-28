import { Bot } from "lucide-react"
import { AssistantAnswer } from "@/components/assistant-answer"
import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { PageHead } from "@/components/bits"
import { api } from "@/lib/api"
import { useApp } from "@/app-state"

type Bubble = { kind: "user" | "bot"; text: string }

export function AssistantPage() {
  const { t, companyId } = useApp()
  const [text, setText] = useState("")
  const [busy, setBusy] = useState(false)
  const generation = useRef(0)
  const inFlight = useRef(false)
  useEffect(() => { generation.current += 1; inFlight.current = false; setBusy(false); setText(""); setLog([{ kind: "bot", text: t("ai.hello") }]); return () => { generation.current += 1 } }, [companyId])
  const [log, setLog] = useState<Bubble[]>([{ kind: "bot", text: t("ai.hello") }])

  async function ask(event: React.FormEvent) {
    event.preventDefault()
    const message = text.trim()
    if (!message || !companyId || inFlight.current) return
    const requestGeneration = generation.current
    inFlight.current = true; setBusy(true)
    setText("")
    setLog((current) => [...current, { kind: "user", text: message }, { kind: "bot", text: t("ai.wait") }])
    try {
      const data = await api<{ answer: string }>("/api/ai-chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ company_id: companyId, message }),
      })
      if (requestGeneration !== generation.current) return
      setLog((current) => current.map((item, index) => index === current.length - 1 ? { kind: "bot", text: data.answer } : item))
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Ассистент недоступен"
      if (requestGeneration !== generation.current) return
      setLog((current) => current.map((item, index) => index === current.length - 1 ? { kind: "bot", text: detail } : item))
    } finally {
      if (requestGeneration === generation.current) { inFlight.current = false; setBusy(false) }
    }
  }

  return (
    <div className="mx-auto grid max-w-3xl gap-4">
      <PageHead title={t("ai.title")} sub="Спросите про открытые находки выбранной компании. Ответ остаётся в этой вкладке." />
      <div className="grid gap-3">
        {log.map((item, index) => item.kind === "user" ? (
          <div key={index} className="bg-muted ml-auto max-w-[80%] rounded-2xl px-4 py-2 text-sm">{item.text}</div>
        ) : (
          <Card key={index}><CardContent className="pt-4 text-sm"><AssistantAnswer text={item.text} /></CardContent></Card>
        ))}
      </div>
      <form className="flex gap-2" onSubmit={(event) => void ask(event)}>
        <Input disabled={busy} aria-label="Вопрос AI-ассистенту" maxLength={4000} value={text} placeholder={t("ai.ph")} onChange={(event) => setText(event.target.value)} />
        <Button type="submit" disabled={busy || !companyId || !text.trim()}><Bot aria-hidden="true" />{t("ai.ask")}</Button>
      </form>
    </div>
  )
}
