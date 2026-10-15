import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { api } from "@/lib/api"
import { useApp } from "@/app-state"

type Bubble = { kind: "user" | "bot"; text: string }

function Markdown({ text }: { text: string }) {
  const lines = text.replace(/\r\n/g, "\n").split("\n")
  const blocks: React.ReactNode[] = []
  let index = 0
  while (index < lines.length) {
    if (lines[index].trim().startsWith("|")) {
      const rows: string[][] = []
      while (index < lines.length && lines[index].trim().startsWith("|")) {
        rows.push(lines[index].trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim()))
        index += 1
      }
      const kept = rows.filter((cells) => !cells.every((cell) => /^:?-+:?$/.test(cell)))
      blocks.push(
        <table key={index} className="my-2 w-full text-xs">
          <tbody>
            {kept.map((cells, rowIndex) => (
              <tr key={rowIndex}>{cells.map((cell, cellIndex) => <td key={cellIndex} className="border px-2 py-1">{cell}</td>)}</tr>
            ))}
          </tbody>
        </table>
      )
      continue
    }
    if (/^\s*[-*]\s+/.test(lines[index])) {
      const items: string[] = []
      while (index < lines.length && /^\s*[-*]\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^\s*[-*]\s+/, ""))
        index += 1
      }
      blocks.push(<ul key={index} className="list-disc pl-4">{items.map((item) => <li key={item}>{item}</li>)}</ul>)
      continue
    }
    if (!lines[index].trim()) { index += 1; continue }
    const paragraph: string[] = []
    while (index < lines.length && lines[index].trim() && !lines[index].trim().startsWith("|") && !/^\s*[-*]\s+/.test(lines[index])) {
      paragraph.push(lines[index])
      index += 1
    }
    blocks.push(<p key={index}>{paragraph.join(" ")}</p>)
  }
  return <div className="grid gap-1">{blocks}</div>
}

export function Assistant() {
  const { t, companyId } = useApp()
  const [open, setOpen] = useState(false)
  const [text, setText] = useState("")
  const [log, setLog] = useState<Bubble[]>([{ kind: "bot", text: t("ai.hello") }])

  async function ask(event: React.FormEvent) {
    event.preventDefault()
    const message = text.trim()
    if (!message || !companyId) return
    setText("")
    setLog((current) => [...current, { kind: "user", text: message }, { kind: "bot", text: t("ai.wait") }])
    try {
      const data = await api<{ answer: string }>("/api/ai-chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ company_id: companyId, message }),
      })
      setLog((current) => current.map((item, index) => index === current.length - 1 ? { kind: "bot", text: data.answer } : item))
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Ассистент недоступен"
      setLog((current) => current.map((item, index) => index === current.length - 1 ? { kind: "bot", text: detail } : item))
    }
  }

  return (
    <>
      <Button className="fixed right-4 bottom-4 z-30 size-12 rounded-full" onClick={() => setOpen(true)}>AI</Button>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent className="flex w-full flex-col sm:max-w-md">
          <SheetHeader><SheetTitle>{t("ai.title")}</SheetTitle></SheetHeader>
          <ScrollArea className="min-h-0 flex-1 pr-3">
            <div className="grid gap-2">
              {log.map((item, index) => (
                <Card key={index} className={item.kind === "user" ? "ml-8" : "mr-8"}>
                  <CardContent className="text-sm">{item.kind === "bot" ? <Markdown text={item.text} /> : item.text}</CardContent>
                </Card>
              ))}
            </div>
          </ScrollArea>
          <form className="flex gap-2" onSubmit={(event) => void ask(event)}>
            <Input value={text} placeholder={t("ai.ph")} onChange={(event) => setText(event.target.value)} />
            <Button type="submit">{t("ai.ask")}</Button>
          </form>
        </SheetContent>
      </Sheet>
    </>
  )
}
