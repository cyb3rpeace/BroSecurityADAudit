import { useEffect, useId, useMemo, useRef, useState } from "react"
import { ArrowDownToLine, ChevronRight, CircleHelp, FileSearch, GitBranch, Globe, Monitor, RotateCcw, Search, Terminal, X, ZoomIn, ZoomOut } from "lucide-react"

export type HuntingEvidenceRef = { source: string; row_number: number }
export type HuntingEvidenceGraphData = {
  nodes: { id: string; kind: string; label: string; role?: string; reason?: string; command_line?: string; signal_rules?: string[]; evidence_refs?: HuntingEvidenceRef[] }[]
  edges: { source: string; target: string; relation: string; confidence: string }[]
  scope?: string
  truncated: boolean
}
export type HuntingEvidenceGraphProps = {
  graph: HuntingEvidenceGraphData | undefined
  onEvidence: (ref: HuntingEvidenceRef) => void
}

const MAX_NODES = 60
const MAX_EDGES = 100
const MAX_REFS = 24
const CARD_W = 256
const CARD_H = 88
const COL = 430
const ROW = 132
const PAD = 58
const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0
const clip = (value: string, length: number) => value.length > length ? `${value.slice(0, length - 1)}…` : value
const kindInfo = (kind: string) => {
  switch (kind.toLowerCase()) {
    case "process": return { label: "Процесс", Icon: Terminal, color: "text-cyan-600 dark:text-cyan-300" }
    case "network": case "socket": case "endpoint": return { label: "Сетевой endpoint", Icon: Globe, color: "text-violet-600 dark:text-violet-300" }
    case "persistence": case "service": case "task": case "startup": return { label: "Автозапуск / persistence", Icon: ArrowDownToLine, color: "text-amber-600 dark:text-amber-300" }
    case "host": return { label: "Хост из данных", Icon: Monitor, color: "text-emerald-600 dark:text-emerald-300" }
    default: return { label: kind || "Другой объект", Icon: CircleHelp, color: "text-muted-foreground" }
  }
}
const relationText = (relation: string) => ({ parent_child: "parent_child · родитель → потомок", network_connection: "network_connection · процесс → endpoint", executes: "executes · совпал путь запуска", observed_on: "observed_on · наблюдается на хосте" })[relation] || relation
const controlClass = "inline-flex h-9 items-center justify-center gap-2 rounded-lg border bg-background px-3 text-xs transition hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary disabled:cursor-not-allowed disabled:opacity-40"

/** Read-only graph: never infers a host, remote machine identity, or attack verdict. */
export function HuntingEvidenceGraph({ graph, onEvidence }: HuntingEvidenceGraphProps) {
  const [query, setQuery] = useState("")
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [zoom, setZoom] = useState(1)
  const drag = useRef<{ x: number; y: number; left: number; top: number } | null>(null)
  const viewport = useRef<HTMLDivElement>(null)
  const nodeElements = useRef(new Map<string, SVGGElement>())
  const uid = useId().replace(/:/g, "")
  const helpId = `${uid}-help`
  const searchId = `${uid}-search`
  const model = useMemo(() => {
    // Stable ordering, then bounded rendering; supplied arrays are never mutated.
    const unique = new Map<string, NonNullable<HuntingEvidenceGraphData>["nodes"][number]>()
    for (const node of graph?.nodes || []) if (!unique.has(node.id)) unique.set(node.id, node)
    const ordered = [...unique.values()].sort((a, b) => Number(b.role === "signal") - Number(a.role === "signal") || compare(a.id, b.id))
    const needle = query.trim().toLocaleLowerCase()
    const matched = ordered.filter(node => !needle || `${node.label} ${node.command_line || ""} ${node.reason || ""} ${node.kind} ${node.id} ${(node.evidence_refs || []).map(ref => ref.source).join(" ")}`.toLocaleLowerCase().includes(needle))
    // Search includes one-hop context, keeping matching nodes ahead of their neighbours.
    const matchIds = new Set(matched.map(node => node.id))
    const contextIds = new Set<string>()
    if (needle) for (const edge of graph?.edges || []) {
      if (matchIds.has(edge.source)) contextIds.add(edge.target)
      if (matchIds.has(edge.target)) contextIds.add(edge.source)
    }
    const candidates = needle ? [...matched, ...ordered.filter(node => !matchIds.has(node.id) && contextIds.has(node.id))] : ordered
    const nodes = candidates.slice(0, MAX_NODES)
    const ids = new Set(nodes.map(node => node.id))
    const eligible = (graph?.edges || []).filter(edge => ids.has(edge.source) && ids.has(edge.target))
      .slice().sort((a, b) => compare(`${a.source}\0${a.target}\0${a.relation}\0${a.confidence}`, `${b.source}\0${b.target}\0${b.relation}\0${b.confidence}`))
    const edges = eligible.slice(0, MAX_EDGES)
    const degree = new Map(nodes.map(node => [node.id, 0]))
    const ranks = new Map(nodes.map(node => [node.id, 0]))
    const outbound = new Map(nodes.map(node => [node.id, [] as string[]]))
    for (const edge of edges) {
      if (edge.source === edge.target) continue
      degree.set(edge.target, (degree.get(edge.target) || 0) + 1)
      outbound.get(edge.source)?.push(edge.target)
    }
    // Bounded Kahn traversal: break cycles at the first stable ID, at most N passes.
    // Capped ranks keep cyclic/deep chains finite; disconnected nodes remain valid.
    const remaining = new Set(nodes.map(node => node.id).sort(compare))
    for (let pass = 0; pass < nodes.length; pass++) {
      const id = [...remaining].find(value => degree.get(value) === 0) ?? remaining.values().next().value
      if (id === undefined) break
      remaining.delete(id)
      for (const target of outbound.get(id) || []) if (remaining.has(target)) {
        ranks.set(target, Math.min(7, Math.max(ranks.get(target) || 0, (ranks.get(id) || 0) + 1)))
        degree.set(target, (degree.get(target) || 0) - 1)
      }
    }
    const rows = new Map<number, number>()
    const positions = new Map<string, { x: number; y: number }>()
    for (const node of nodes.slice().sort((a, b) => (ranks.get(a.id) || 0) - (ranks.get(b.id) || 0) || compare(a.id, b.id))) {
      const rank = ranks.get(node.id) || 0
      const row = rows.get(rank) || 0
      positions.set(node.id, { x: PAD + rank * COL, y: PAD + row * ROW })
      rows.set(rank, row + 1)
    }
    return { nodes, edges, positions, matchIds, matches: matched.length, candidates: candidates.length, eligible: eligible.length,
      duplicateNodes: (graph?.nodes.length || 0) - unique.size,
      width: Math.max(840, PAD * 2 + Math.max(0, ...ranks.values()) * COL + CARD_W),
      height: Math.max(360, PAD * 2 + (Math.max(1, ...rows.values()) - 1) * ROW + CARD_H) }
  }, [graph, query])
  const selected = model.nodes.find(node => node.id === selectedId)
  useEffect(() => { setSelectedId(null); setQuery(""); setZoom(1); viewport.current?.scrollTo({ top: 0, left: 0 }) }, [graph])
  const connected = useMemo(() => {
    const ids = new Set<string>(selected ? [selected.id] : [])
    if (selected) for (const edge of model.edges) {
      if (edge.source === selected.id) ids.add(edge.target)
      if (edge.target === selected.id) ids.add(edge.source)
    }
    return ids
  }, [selected, model.edges])
  const refs = selected?.evidence_refs || []
  const adjacent = selected ? model.edges.filter(edge => edge.source === selected.id || edge.target === selected.id) : []
  const resetView = () => { setZoom(1); viewport.current?.scrollTo({ top: 0, left: 0, behavior: "smooth" }) }
  const selectNode = (id: string, focus = false) => {
    setSelectedId(id)
    if (focus) { const element = nodeElements.current.get(id); element?.focus(); element?.scrollIntoView({ block: "nearest", inline: "nearest", behavior: "smooth" }) }
  }
  return <section className="min-w-0 overflow-hidden rounded-lg border bg-card" aria-label="Граф доказательных связей">
    <header className="flex flex-wrap items-start justify-between gap-3 border-b bg-muted/20 p-4">
      <div><p className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.18em] text-primary"><GitBranch className="h-4 w-4" aria-hidden="true" /> BEHAVIORAL EVIDENCE</p><h3 className="mt-1 text-base font-semibold">Подозрительные действия и связанные объекты</h3><p className="mt-1 max-w-3xl text-xs leading-5 text-muted-foreground">Отношения из точечного сбора, не хронология и не подтверждение атаки. Endpoint не означает участие удалённого хоста; имя и роль хоста не восстанавливаются по IP.</p></div>
      <span className="rounded-md border bg-background px-2 py-1 font-mono text-[10px] text-muted-foreground">READ ONLY · EVIDENCE FIRST</span>
    </header>
    <div className="flex flex-wrap items-center gap-2 border-b p-3">
      <label htmlFor={searchId} className="relative min-w-48 flex-1"><Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" aria-hidden="true" /><input id={searchId} type="search" value={query} onChange={event => { setQuery(event.target.value); setSelectedId(null) }} placeholder="Процесс, IP, ID или источник…" aria-label="Поиск узлов графа" className="h-9 w-full rounded-lg border bg-background pl-9 pr-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary" /></label>
      <div className="flex items-center gap-1" role="group" aria-label="Масштаб графа">
        <button type="button" className={controlClass} aria-label="Уменьшить масштаб" disabled={zoom <= 0.5} onClick={() => setZoom(value => Math.max(0.5, Math.round((value - 0.15) * 100) / 100))}><ZoomOut className="h-4 w-4" aria-hidden="true" /></button>
        <output className="w-12 text-center font-mono text-xs" aria-live="polite">{Math.round(zoom * 100)}%</output>
        <button type="button" className={controlClass} aria-label="Увеличить масштаб" disabled={zoom >= 1.75} onClick={() => setZoom(value => Math.min(1.75, Math.round((value + 0.15) * 100) / 100))}><ZoomIn className="h-4 w-4" aria-hidden="true" /></button>
        <button type="button" className={controlClass} onClick={resetView}><RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />Сброс вида</button>
      </div>
    </div>
    <div className="space-y-1 border-b px-4 py-3 text-xs text-muted-foreground" aria-live="polite">
      <p>Показано <b className="text-foreground">{model.nodes.length} / {graph?.nodes.length || 0}</b> узлов и <b className="text-foreground">{model.edges.length} / {graph?.edges.length || 0}</b> связей · предел отображения: {MAX_NODES} / {MAX_EDGES}.</p>
      {query.trim() && <p>Совпадений: {model.matches}. Добавлен контекст на один переход; поиск выполняется по всем полученным узлам.</p>}
      {(model.candidates > MAX_NODES || model.eligible > MAX_EDGES) && <p className="text-amber-700 dark:text-amber-300">Локальное ограничение: скрыто {Math.max(0, model.candidates - MAX_NODES)} подходящих узлов и {Math.max(0, model.eligible - MAX_EDGES)} связей между показанными узлами. Уточните поиск; связи к скрытым узлам не рисуются.</p>}
      {!!model.duplicateNodes && <p>Повторных ID узлов объединено: {model.duplicateNodes}; используется первое описание.</p>}
      {graph?.truncated && <p className="text-amber-700 dark:text-amber-300">Источник уже ограничил граф. Счётчики относятся только к полученным данным; полный размер неизвестен.</p>}
    </div>
    <div className="grid min-w-0 xl:grid-cols-[minmax(0,1fr)_320px]">
      <div className="min-w-0">
        <div className="flex flex-wrap gap-x-4 gap-y-2 border-b px-4 py-2 text-[10px] text-muted-foreground">{["process", "network", "persistence", "host"].map(kind => { const info = kindInfo(kind); return <span key={kind} className="inline-flex items-center gap-1.5"><info.Icon className={`h-3.5 w-3.5 ${info.color}`} aria-hidden="true" />{info.label}</span> })}<span>→ направление отношения, не поток атаки</span></div>
        <p id={helpId} className="px-4 py-2 text-[11px] text-muted-foreground">Tab — узел; Enter / пробел — инспектор; стрелки — соседний узел в списке; Esc — снять выбор. Зажмите левую кнопку мыши на фоне и перемещайте граф в любую сторону; колёсико/панель масштаба изменяют размер. Область также прокручивается по обеим осям.</p>
        {!model.nodes.length ? <div className="flex min-h-80 flex-col items-center justify-center gap-3 p-8 text-center"><GitBranch className="h-9 w-9 text-muted-foreground" aria-hidden="true" /><h4 className="font-medium">{query.trim() ? "Совпадений нет" : "Сильных поведенческих связей не выявлено"}</h4><p className="max-w-lg text-sm text-muted-foreground">{query.trim() ? "Попробуйте имя процесса, адрес или путь источника. Поиск не создаёт новых связей." : "В основном графе скрыт обычный фон. Показаны только поведенческие сигналы и их доказательный контекст. Проверьте полноту сбора и исходные данные: пустой граф не доказывает безопасность."}</p>{query && <button type="button" className={controlClass} onClick={() => setQuery("")}>Очистить поиск</button>}</div>
          : <div ref={viewport} tabIndex={0} role="region" aria-label="Перетаскиваемая схема связей" aria-describedby={helpId} className="h-[540px] max-w-full cursor-grab overflow-auto bg-muted/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary" onPointerDown={event => { if (event.button !== 0 || !viewport.current) return; drag.current = { x: event.clientX, y: event.clientY, left: viewport.current.scrollLeft, top: viewport.current.scrollTop }; viewport.current.setPointerCapture(event.pointerId); viewport.current.style.cursor = "grabbing" }} onPointerMove={event => { const start = drag.current; if (!start || !viewport.current) return; viewport.current.scrollLeft = start.left - (event.clientX - start.x); viewport.current.scrollTop = start.top - (event.clientY - start.y) }} onPointerUp={event => { drag.current = null; viewport.current?.releasePointerCapture(event.pointerId); if (viewport.current) viewport.current.style.cursor = "grab" }} onPointerCancel={() => { drag.current = null; if (viewport.current) viewport.current.style.cursor = "grab" }}>
            <svg width={model.width * zoom} height={model.height * zoom} viewBox={`0 0 ${model.width} ${model.height}`} className="block max-w-none" role="group" aria-label="Направленный граф отношений">
              <defs><pattern id={`${uid}-grid`} width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="0.7" fill="currentColor" className="text-muted-foreground/20" /></pattern><marker id={`${uid}-arrow`} markerWidth="9" markerHeight="9" refX="8" refY="4" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L8,4 L0,8 Z" fill="currentColor" /></marker></defs>
              <rect width="100%" height="100%" fill={`url(#${uid}-grid)`} aria-hidden="true" />
              {model.edges.map((edge, index) => {
                const from = model.positions.get(edge.source)!
                const to = model.positions.get(edge.target)!
                const forward = to.x > from.x
                const startX = forward ? from.x + CARD_W : from.x + CARD_W / 2
                const startY = forward ? from.y + CARD_H / 2 : from.y
                const endX = forward ? to.x - 3 : to.x + CARD_W / 2
                const endY = forward ? to.y + CARD_H / 2 : to.y - 3
                const lane = 24 + (index % 5) * 5
                const path = forward ? `M${startX},${startY} C${startX + 90},${startY} ${endX - 90},${endY} ${endX},${endY}` : `M${startX},${startY} C${startX + 95},${startY - lane - 50} ${endX - 95},${endY - lane - 50} ${endX},${endY}`
                const active = !!selected && (edge.source === selected.id || edge.target === selected.id)
                const labelX = (startX + endX) / 2
                const labelY = forward ? (startY + endY) / 2 : Math.min(startY, endY) - lane
                return <g key={`${edge.source}-${edge.target}-${index}`} className={active ? "text-primary" : "text-muted-foreground"} opacity={selected && !active ? 0.2 : 1}>
                  <title>{`${edge.source} → ${edge.target}: ${edge.relation}; confidence: ${edge.confidence}`}</title>
                  <path d={path} fill="none" stroke="currentColor" strokeWidth={active ? 2 : 1.3} markerEnd={`url(#${uid}-arrow)`} strokeDasharray={edge.confidence === "context" ? "5 4" : undefined} />
                  <rect x={labelX - 78} y={labelY - 15} width="156" height="31" rx="5" className="fill-card stroke-border" />
                  <text x={labelX} y={labelY - 3} textAnchor="middle" fill="currentColor" fontSize="10" fontFamily="monospace">{clip(edge.relation, 23)}</text><text x={labelX} y={labelY + 10} textAnchor="middle" fill="currentColor" fontSize="9">confidence: {clip(edge.confidence, 17)}</text>
                </g>
              })}
              {model.nodes.map((node, index) => {
                const point = model.positions.get(node.id)!
                const info = kindInfo(node.kind)
                const active = selected?.id === node.id
                return <g key={node.id} ref={element => { if (element) nodeElements.current.set(node.id, element); else nodeElements.current.delete(node.id) }} transform={`translate(${point.x},${point.y})`} tabIndex={0} role="button" aria-pressed={active} aria-label={`${info.label}: ${node.label}; ID ${node.id}; источников: ${node.evidence_refs?.length || 0}`} onClick={() => selectNode(node.id)} onKeyDown={event => {
                  if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectNode(node.id) }
                  else if (event.key === "Escape") { event.preventDefault(); setSelectedId(null) }
                  else if (["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp", "Home", "End"].includes(event.key)) {
                    event.preventDefault()
                    const next = event.key === "Home" ? 0 : event.key === "End" ? model.nodes.length - 1 : Math.max(0, Math.min(model.nodes.length - 1, index + (["ArrowRight", "ArrowDown"].includes(event.key) ? 1 : -1)))
                    selectNode(model.nodes[next].id, true)
                  }
                }} className="group cursor-pointer outline-none" opacity={selected && !connected.has(node.id) ? 0.4 : 1}>
                  <title>{`${node.label}\n${node.id}\n${info.label}`}</title>
                  <rect width={CARD_W} height={CARD_H} rx="12" strokeWidth={active ? 2 : 1} className={`${active ? "fill-card stroke-primary" : "fill-card stroke-border"} group-hover:stroke-primary group-focus-visible:stroke-primary group-focus-visible:[stroke-width:3]`} />
                  <rect x="12" y="14" width="28" height="28" rx="8" className="fill-muted" /><info.Icon x="18" y="20" width="16" height="16" className={info.color} aria-hidden="true" />
                  <text x="49" y="25" fontSize="9" fill="currentColor" className="text-muted-foreground">{info.label}</text>
                  <text x="49" y="43" fontSize="12" fontWeight="600" fill="currentColor">{clip(node.label || node.id, 25)}</text>
                  <text x="14" y="66" fontSize="10" fontFamily="monospace" fill="currentColor" className="text-muted-foreground">{clip(node.id, 27)}</text>
                  <text x={CARD_W - 13} y="78" textAnchor="end" fontSize="9" fill="currentColor" className="text-muted-foreground">refs: {node.evidence_refs?.length || 0}{query.trim() && model.matchIds.has(node.id) ? " · match" : ""}</text>
                </g>
              })}
            </svg>
          </div>}
      </div>
      <aside className="min-w-0 border-t bg-muted/10 p-4 xl:border-l xl:border-t-0" aria-label="Инспектор выбранного узла" aria-live="polite">
        <div className="flex items-center justify-between"><h4 className="text-sm font-semibold">Инспектор узла</h4>{selected && <button type="button" className={controlClass} onClick={() => setSelectedId(null)} aria-label="Снять выбор узла"><X className="h-3.5 w-3.5" aria-hidden="true" /></button>}</div>
        {!selected ? <div className="mt-5 space-y-3 text-xs leading-5 text-muted-foreground"><FileSearch className="h-7 w-7" aria-hidden="true" /><p>Выберите узел: в инспекторе показаны причина включения, полная команда и исходные доказательства. Обычные процессы исключены; соседние объекты — контекст, не доказанная атака.</p><p>Стрелки повторяют source → target из анализа. Confidence — тип обоснования связи, а не вероятность атаки. Отсутствующая связь может означать неполноту снимка.</p></div> : <div className="mt-4 space-y-4">
          <div><span className={`text-[10px] font-medium uppercase ${kindInfo(selected.kind).color}`}>{kindInfo(selected.kind).label}</span><p className="mt-1 break-all text-sm font-semibold">{selected.label || selected.id}</p><p className="mt-2 break-all font-mono text-[11px] text-muted-foreground">{selected.id}</p></div>
          {selected.reason && <div className="rounded-lg border p-3 text-xs leading-5"><p className="font-medium">{selected.role === "signal" ? "Поведенческий сигнал" : "Связанный контекст"}</p><p className="mt-1 break-words text-muted-foreground">{selected.reason}</p></div>}
          {selected.command_line && <div><h5 className="text-xs font-medium">Командная строка</h5><pre className="mt-2 max-h-52 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-muted p-3 text-[11px]">{selected.command_line}</pre></div>}
          <div><h5 className="text-xs font-medium">Исходные строки · {refs.length}</h5><p className="mt-1 text-[11px] text-muted-foreground">Ссылка открывает строку источника, не подтверждает причинность.</p><div className="mt-2 max-h-52 space-y-1 overflow-y-auto">{refs.slice(0, MAX_REFS).map((ref, index) => <button type="button" key={`${ref.source}-${ref.row_number}-${index}`} onClick={() => onEvidence(ref)} disabled={!ref.source || !Number.isInteger(ref.row_number) || ref.row_number < 1} className="flex w-full items-center gap-2 rounded-lg border bg-background p-2 text-left text-xs hover:border-primary/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary disabled:opacity-40"><FileSearch className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" /><span className="min-w-0 flex-1"><span className="block break-all">{ref.source}</span><span className="text-muted-foreground">строка {ref.row_number}</span></span><ChevronRight className="h-3.5 w-3.5 shrink-0" aria-hidden="true" /></button>)}</div>{!refs.length && <p className="mt-2 text-xs text-muted-foreground">Прямой ссылки на строку нет: объект может присутствовать только как контекст отношения.</p>}{refs.length > MAX_REFS && <p className="mt-2 text-xs text-muted-foreground">Показаны первые {MAX_REFS} ссылок из {refs.length}.</p>}</div>
          <div><h5 className="text-xs font-medium">Связи в текущем виде · {adjacent.length}</h5><div className="mt-2 max-h-64 space-y-2 overflow-y-auto">{adjacent.map((edge, index) => {
            const otherId = edge.source === selected.id ? edge.target : edge.source
            const other = model.nodes.find(node => node.id === otherId)
            return <button type="button" key={index} onClick={() => selectNode(otherId, true)} className="w-full rounded-lg border bg-background p-2 text-left text-xs hover:border-primary/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"><span className="block break-words font-medium">{edge.source === selected.id ? "→ " : "← "}{relationText(edge.relation)}</span><span className="mt-1 block break-all text-muted-foreground">{other?.label || otherId}</span><span className="mt-1 block font-mono text-[10px] text-muted-foreground">confidence: {edge.confidence}</span></button>
          })}</div>{!adjacent.length && <p className="mt-2 text-xs text-muted-foreground">Нет связей в текущем виде. Поиск или ограничения могли скрыть соседние узлы.</p>}</div>
        </div>}
      </aside>
    </div>
  </section>
}

export default HuntingEvidenceGraph
