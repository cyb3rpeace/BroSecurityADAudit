import { Bot } from "lucide-react"
import { AssistantAnswer } from "@/components/assistant-answer"
import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { api } from "@/lib/api"
import { useApp } from "@/app-state"
import type { Finding } from "@/lib/types"

type Turn = { role: "user" | "assistant"; content: string }

export function ContextChat({ finding }: { finding: Finding }) {
  const { companyId } = useApp()
  const [open, setOpen] = useState(false)
  const [text, setText] = useState("")
  const [turns, setTurns] = useState<Turn[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const generation = useRef(0)
  useEffect(() => {
    generation.current += 1
    setTurns([]); setText(""); setError(""); setBusy(false); setOpen(false)
    return () => { generation.current += 1 }
  }, [companyId, finding.id])

  async function ask(event: React.FormEvent) {
    event.preventDefault()
    const message = text.trim()
    if (!message || !companyId || busy) return
    const current = generation.current
    const history = turns.slice(-12)
    setBusy(true); setError("")
    try {
      const result = await api<{ answer: string }>("/api/ai-chat", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ company_id: companyId, finding_id: finding.id, message, history }),
      })
      if (current !== generation.current) return
      setTurns((previous) => [...previous, { role: "user", content: message }, { role: "assistant", content: result.answer }])
      setText("")
    } catch (err) {
      if (current === generation.current) setError(err instanceof Error ? err.message : "Ассистент недоступен")
    } finally {
      if (current === generation.current) setBusy(false)
    }
  }

  return <section className="grid gap-3 rounded-xl border p-3">
    <Button variant="outline" aria-expanded={open} onClick={() => setOpen(!open)}><Bot aria-hidden="true" />{open ? "Свернуть AI-ассистента" : "AI-ассистент"}</Button>
    {open && <>
      <p className="text-muted-foreground text-xs">Контекст: {finding.hostname} · {finding.title}. Вопрос и сведения об объекте будут переданы настроенной администратором модели. История хранится только в открытой карточке.</p>
      <div className="grid max-h-80 gap-3 overflow-auto text-sm" aria-live="polite">
        {!turns.length && <p>Спросите о влиянии риска, приоритете или безопасном порядке исправления.</p>}
        {turns.map((turn, index) => <div key={index} className={"whitespace-pre-wrap break-words rounded-lg p-3 " + (turn.role === "user" ? "bg-muted ml-4" : "border mr-4")}><div className="mb-1 text-xs font-semibold">{turn.role === "user" ? "Вы" : "AI-ассистент"}</div>{turn.role === "assistant" ? <AssistantAnswer text={turn.content} /> : turn.content}</div>)}
        {busy && <p role="status">Готовлю ответ…</p>}
      </div>
      {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
      <form className="flex gap-2" onSubmit={(event) => void ask(event)}>
        <Input value={text} maxLength={4000} disabled={busy} onChange={(event) => setText(event.target.value)} placeholder="Вопрос по этому объекту" aria-label="Вопрос AI-ассистенту" />
        <Button type="submit" disabled={busy || !text.trim() || !companyId}><Bot aria-hidden="true" />Отправить</Button>
      </form>
    </>}
  </section>
}
