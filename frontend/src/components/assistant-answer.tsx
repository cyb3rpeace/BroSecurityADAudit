import { Fragment } from "react"

function inline(text: string) {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, index) => part.startsWith("**") && part.endsWith("**") ? <strong key={index}>{part.slice(2, -2)}</strong> : part.startsWith("`") && part.endsWith("`") ? <code key={index} className="rounded bg-muted px-1 font-mono text-[0.9em]">{part.slice(1, -1)}</code> : <Fragment key={index}>{part}</Fragment>)
}

export function AssistantAnswer({ text }: { text: string }) {
  const lines = text.replace(/\r\n/g, "\n").split("\n")
  return <div className="space-y-3 break-words text-sm leading-7">{lines.map((line, index) => {
    const value = line.trim()
    if (!value || /^(?:[-*_]\s*){3,}$/.test(value)) return null
    const heading = value.match(/^#{1,6}\s+(.+)/)
    if (heading) return <p key={index} className="pt-2 font-semibold text-foreground">{inline(heading[1])}</p>
    const bullet = value.match(/^(?:[-*•]|\d+[.)])\s+(.+)/)
    if (bullet) return <p key={index} className="pl-4">{inline(bullet[1])}</p>
    return <p key={index}>{inline(line)}</p>
  })}</div>
}
