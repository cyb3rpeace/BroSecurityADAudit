import { useEffect, useMemo, useState } from "react"
import { BookOpen, ChevronRight, FileText, Search } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { PageHead } from "@/components/bits"
import type { WikiItem } from "@/lib/types"
import { KNOWLEDGE } from "@/lib/knowledge"
import { HANDBOOK } from "@/lib/handbook"
import { technicalOf } from "@/lib/check-depth"
import { useApp } from "@/app-state"

function loadWiki() {
  if (window.BROSEC_WIKI) return Promise.resolve(window.BROSEC_WIKI)
  return new Promise<WikiItem[]>((resolve) => {
    const script = document.createElement("script")
    script.src = "/static/wiki.js?v=14"
    script.onload = () => resolve(window.BROSEC_WIKI || [])
    script.onerror = () => resolve([])
    document.body.appendChild(script)
  })
}

declare global {
  interface Window {
    BROSEC_WIKI?: WikiItem[]
  }
}

const DOCS = {
  ru: [
    ["start", "С чего начать", "Каталог читает Linux по LDAP или LDAPS. Настрой LDAP/LDAPS и приступай к сканированию!"],
    ["ldap", "Каталог: LDAPS 636 и простой LDAP 389", "В настройках укажите DNS-имя контроллера и служебную учетную запись этого же домена. Формат DOMAIN\\user или user@domain. Права администратора домена не нужны, достаточно чтения. LDAPS 636 — если на контроллере есть сертификат. LDAP 389 — обычный канал без шифрования, только внутри доверенной сети. Гигиена, доверия и типы шифрования Kerberos идут этим каналом."],
    ["areas", "Области аудита", "Учетные записи: пароли, блокировка, служебные записи, точечные политики. Устройства: устаревшие ОС, пароль компьютера, покрытие LAPS без чтения пароля, пустые подразделения. Пути: делегирование, SPN, шаблоны сертификатов, только признаки. Группы: пустые, слишком большие и слишком глубоко вложенные, без списка участников. DNS: свойства зоны без содержимого. Контроллеры: процессор, память, диск и счётчики входов за сутки без текста чужих сессий."],
    ["link", "Как связать программу с сервером", "Каталог читается по LDAP или LDAPS. Реестр, время, SYSVOL и установленные программы сервер читает по WinRM. Значение cpassword не расшифровывается."],
    ["mail", "Почта и автоматические уведомления", "SMTP настраивает суперадминистратор. Диагностику выполняйте по этапам: DNS, TCP, TLS, аутентификация, разрешение отправителя и адрес получателя. Не отключайте проверку сертификатов ради подключения. Успех соединения ещё не подтверждает доставку: проверяйте ответ SMTP, очередь и фактическое получение. Пароль не должен возвращаться в браузер или попадать в журнал."],
    ["hunting-navigation", "Threat Hunting: четыре рабочих раздела", "Штаб безопасности показывает оперативный срез архивов и приоритеты. Анализ и расследования содержит поиск, фильтры, исходные строки и решения аналитика. Аналитика и отчёты показывает распределение приоритетов и объём данных. Сбор и импорт содержит сборщики, планы массового сбора, загрузку и историю. Основные разделы имеют собственный URL; расследование не скрывает меню."],
    ["hunting-workflow", "Порядок расследования и доказательства", "Выберите компанию, создайте профиль, выполните согласованный сбор на одном хосте, проверьте результат и только затем масштабируйте. После импорта откройте хост, проверьте источник и номер строки каждой находки, сопоставьте процессы, соединения и персистентность. Статусы подтверждено, легитимно и недостаточно данных — решения аналитика, а риск-балл лишь приоритет проверки. Отсутствие находок не доказывает безопасность."],
    ["hunting-coverage", "Сборщики: возможности и ограничения", "Нормализованный снимок процессов и сети не заменяет историю событий. Полная эквивалентность KAPE и easy_triage не заявляется: требуются проверенные EVTX, реестр, файловая история и Linux-журналы, cron/systemd и другие источники. Пункты candidate не включаются в сборщик. RAM, NTDS, секреты, почта и пользовательское содержимое не должны попадать в массовый профиль по умолчанию. Применяйте лимиты времени, объёма и окна событий."],
    ["hunting-ai", "ИИ: контекст, выводы и ограничения", "ИИ получает только контекст, подготовленный сервером для выбранной компании и архива. Это не означает анализ всех событий или всех соседних хостов. Требуйте разделения наблюдений и гипотез, цитат source и row_number, таймлайна с часовым поясом, альтернативных объяснений и списка недостающих данных. Не выполняйте команды из ответа автоматически. Внешняя модель может получать чувствительные данные: перед подключением согласуйте передачу и политику хранения."],
    ["hunting-fleet", "Массовый сбор: GPO и Ansible", "План массового сбора помогает организовать задания, но не означает автоматический удалённый запуск. Полные инструкции находятся в Сбор и импорт → Инструкции GPO / Ansible. Для Windows используйте согласованный startup script под SYSTEM, проверку SHA-256 и отдельную SMB-папку с минимальными правами. Для Linux используйте SSH-ключи, ограниченный inventory и поэтапный запуск. Сначала проверьте один хост и малую группу."],
    ["hunting-chain", "Цепочка событий: как читать граф", "В расследовании откройте цепочку событий. Узлы показывают процессы, сетевые endpoints и механизмы автозапуска из доступных артефактов. Стрелки отражают parent/child, сетевую ассоциацию или совпадение команды запуска. Выберите узел для просмотра исходных строк, используйте поиск и масштаб. Ограниченный срез не является полной цепочкой атаки; сетевой endpoint не идентифицирует автоматически участвующий хост. Для доказательства перемещения между хостами нужны сопоставимые журналы обеих сторон и проверенные времена."],
    ["hunting-ai-export", "Заключение ИИ: Markdown и PDF", "После успешного AI-анализа доступны выгрузки MD и PDF. Отчёт должен сохранять исходный текст заключения, область анализа, SHA-256 архива, правила, таймлайн и ограничения. Перед передачей подтвердите выводы по исходным источникам. Пометка UNREVIEWED означает, что это непроверенный текст ИИ, а не подписанное экспертное заключение. Отчёт одного архива нельзя выдавать за анализ всех хостов; общий отчёт требует явно выбранных и проверенных источников каждого хоста."],
    ["hunting-integrity", "Архивы, целостность и удаление", "Сохраняйте исходный архив и SHA-256 по политике дела. Не считайте ZIP-пароль полноценной моделью контроля доступа. Импорт имеет лимиты размера и хранения; большие наборы KAPE не следует считать совместимыми без отдельной проверки формата. Удаление истории может удалить исходный архив, отчёты и связанные решения; перед подтверждением проверьте требования хранения доказательств. Активная обработка может блокировать удаление."],
    ["platform-architecture", "Техническое устройство платформы", "Веб-интерфейс React/TypeScript собирается Vite в контейнере Node. API работает в FastAPI; основной контейнер ad-security-core, фоновая hunting-обработка выполняется отдельным pipeline worker. Для эксплуатации проверяйте readiness, права на data/reports, состояние worker и резервные копии SQLite и доказательств. Изменения в образе не заменяют резервное копирование постоянных данных."],
    ["platform-release", "Проверка перед релизом", "Релиз требует успешных тестов и сборки, проверки tenant-изоляции, авторизации, загрузки и удаления, восстановления резервной копии, работы фоновых заданий и доставки уведомлений. Отдельно проверяйте Windows/Linux сбор на тестовых хостах и ложные срабатывания. Не заявляйте коммерческий уровень или полный анализ флота без нагрузочных испытаний, проверки масштаба, телеметрии и документированных ограничений."],
  ],
  en: [
    ["start", "Start here", "The directory is read from Linux over LDAP or LDAPS. Set LDAP or LDAPS and start the scan."],
    ["ldap", "LDAP 389 and LDAPS 636", "A domain read account is enough. Use DOMAIN\\user or user@domain. Pick LDAPS 636 when the controller has a certificate. Pick plain LDAP 389 only on a trusted network."],
    ["areas", "Audit areas", "Accounts, devices, delegation, groups, and DNS zone names. Group member lists and binary DNS records stay out of the report. Full GPO diffs, live logon events, and hardware inventory are not part of the product."],
  ],
} as const

const SEV: Record<string, string> = {
  critical: "Критический",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  info: "Информация",
}

function sevClass(sev: string) {
  if (sev === "critical") return "bg-red-500/15 text-red-700 dark:text-red-300"
  if (sev === "high") return "bg-orange-500/15 text-orange-700 dark:text-orange-300"
  if (sev === "medium") return "bg-amber-500/15 text-amber-800 dark:text-amber-200"
  if (sev === "low") return "bg-sky-500/15 text-sky-800 dark:text-sky-200"
  return "bg-muted text-muted-foreground"
}

const DOC_SECTIONS = [
  { id: "all", label: "Все материалы" },
  { id: "hunting", label: "Threat Hunting" },
  { id: "operations", label: "Эксплуатация" },
  { id: "platform", label: "Проверки платформы" },
] as const

export function Docs() {
  const { t, lang, setView } = useApp()
  const [items, setItems] = useState<WikiItem[]>([])
  const [query, setQuery] = useState("")
  const [group, setGroup] = useState<string>("all")
  const [selected, setSelected] = useState<string>("hunting-navigation")
  const [card, setCard] = useState<WikiItem | null>(null)
  const [copied, setCopied] = useState("")

  useEffect(() => { void loadWiki().then(setItems) }, [])

  const wiki = useMemo(() => {
    const base = items.filter(item => item.g !== "pingcastle" && item.g !== "graph")
    const ids = new Set(base.map(item => item.id))
    const extra: WikiItem[] = [...KNOWLEDGE, ...HANDBOOK].filter(item => !ids.has(item.id)).map(item => ({
      id: item.id, title: item.title, text: item.what, g: "platform", what: item.what,
      impact: item.impact, fix: item.defense.join(" "), sev: item.severity,
    }))
    return [...base, ...extra]
  }, [items])

  const articles = useMemo(() => DOCS[lang].map(([id, title, text]) => ({
    id, title, text, g: id.startsWith("hunting-") ? "hunting" : "operations",
  })), [lang])
  const allMaterials = useMemo<Array<{ id: string; title: string; text: string; g: string; kind: "guide" | "check"; family?: string; what?: string; impact?: string; fix?: string; sev?: string }>>(() => [
    ...articles.map(item => ({ ...item, kind: "guide" as const })),
    ...wiki.filter((item): item is WikiItem & { id: string } => typeof item.id === "string").map(item => ({ ...item, kind: "check" as const })),
  ], [articles, wiki])
  const filtered = useMemo(() => {
    const q = query.trim().toLocaleLowerCase(lang === "ru" ? "ru" : "en")
    return allMaterials.filter(item =>
      (group === "all" || item.g === group) &&
      (!q || [item.id, item.title, item.text, item.family, item.what, item.impact, item.fix].filter(Boolean).join(" ").toLocaleLowerCase().includes(q))
    )
  }, [allMaterials, group, lang, query])
  const current = filtered.find(item => item.id === selected) || filtered[0]
  const checks = current?.kind === "check" ? wiki.find(item => item.id === current.id) : undefined

  return <div className="docs-page space-y-5">
    <PageHead title={t("nav.docs")} sub="Техническая документация, эксплуатационные процедуры и каталог проверок" />
    <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-4">
      <div className="flex items-center gap-2 text-sm text-muted-foreground"><BookOpen className="size-4" aria-hidden="true" /><span>Документация платформы</span><ChevronRight className="size-4" aria-hidden="true" /><span className="text-foreground">Справочник</span></div>
      <Button variant="outline" onClick={() => setView("notes")}>Примечания к обновлению</Button>
    </div>
    <div className="grid gap-5 lg:grid-cols-[230px_minmax(0,1fr)] xl:grid-cols-[250px_minmax(0,1fr)_280px]">
      <aside className="docs-sidebar space-y-4 lg:sticky lg:top-4 lg:max-h-[calc(100svh-2rem)] lg:overflow-auto">
        <label className="relative block"><Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" /><Input className="pl-9" aria-label="Поиск документации" value={query} placeholder="Поиск по документации" onChange={event => setQuery(event.target.value)} /></label>
        <nav aria-label="Разделы документации" className="grid gap-1 sm:grid-cols-2 lg:grid-cols-1">
          {DOC_SECTIONS.map(section => <button key={section.id} type="button" onClick={() => { setGroup(section.id); setSelected(filtered.find(item => section.id === "all" || item.g === section.id)?.id || "") }} aria-current={group === section.id ? "page" : undefined} className={`min-h-10 rounded-md px-3 py-2 text-left text-sm ${group === section.id ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted hover:text-foreground"}`}>{section.label}</button>)}
        </nav>
        <div className="border-t pt-3"><p className="mb-2 px-2 text-xs font-semibold uppercase text-muted-foreground">Материалы · {filtered.length}</p><div className="grid gap-1" role="listbox" aria-label="Материалы документации">{filtered.map(item => <button key={`${item.kind}-${item.id}`} type="button" role="option" aria-selected={current?.id === item.id} onClick={() => setSelected(item.id)} className={`min-h-10 rounded-md px-3 py-2 text-left text-sm ${current?.id === item.id ? "bg-muted font-medium text-foreground" : "text-muted-foreground hover:bg-muted/70 hover:text-foreground"}`}><span className="flex items-start gap-2"><FileText className="mt-0.5 size-4 shrink-0" aria-hidden="true" /><span className="min-w-0 break-words">{item.title}</span></span></button>)}{!filtered.length && <p className="px-3 py-4 text-sm text-muted-foreground">Материалы не найдены.</p>}</div></div>
      </aside>
      <main className="min-w-0" aria-live="polite">
        {current ? <article className="min-w-0 space-y-5">
          <header className="border-b pb-5"><p className="text-xs font-medium uppercase text-muted-foreground">{current.kind === "guide" ? (current.g === "hunting" ? "Threat Hunting · руководство" : "Эксплуатация · руководство") : "Каталог проверок"}</p><h1 className="mt-2 break-words text-2xl font-semibold">{current.title}</h1><p className="mt-3 max-w-3xl text-sm leading-6 text-muted-foreground">{current.text}</p>{checks?.sev && <span className={`mt-3 inline-flex rounded-sm px-2 py-1 text-xs ${sevClass(checks.sev)}`}>{SEV[checks.sev] || checks.sev}</span>}</header>
          {current.kind === "guide" ? <div className="grid gap-5 text-sm leading-7"><section><h2 className="mb-2 text-base font-semibold">Процедура и область применения</h2><p className="max-w-4xl whitespace-pre-line text-muted-foreground">{current.text}</p></section>{current.id.startsWith("hunting-") && <div className="rounded-md border-l-2 border-primary bg-muted/40 p-4 text-sm"><strong>Правило работы с evidence</strong><p className="mt-1 text-muted-foreground">Проверяйте исходный архив, источник и номер строки. Различайте факт, гипотезу и пробел; конфигурация и эвристика не подтверждают выполнение или компрометацию.</p></div>}</div> : checks ? <CheckArticle item={checks} copied={copied} onCopy={setCopied} /> : null}
        </article> : <p className="rounded-md border p-6 text-sm text-muted-foreground">Выберите раздел или уточните поиск.</p>}
      </main>
      <aside className="hidden xl:block"><div className="sticky top-4 space-y-3 border-l pl-4 text-sm"><p className="font-semibold">В этом разделе</p><p className="text-muted-foreground">{current?.kind === "guide" ? "Назначение · процедура · ограничения" : "Назначение · техническая детализация · влияние · исправление"}</p>{current?.kind === "check" && <Button className="w-full" variant="outline" onClick={() => setCard(checks || null)}>Открыть карточку проверки</Button>}</div></aside>
    </div>
    <Dialog open={!!card} onOpenChange={next => { if (!next) setCard(null) }}><DialogContent className="max-h-[85dvh] overflow-auto sm:max-w-2xl"><DialogHeader><DialogTitle>{card?.title}</DialogTitle><DialogDescription>{[card?.id, card?.family].filter(Boolean).join(" · ")}</DialogDescription></DialogHeader>{card && <CheckArticle item={card} copied={copied} onCopy={setCopied} />}</DialogContent></Dialog>
  </div>
}

function CheckArticle({ item, copied, onCopy }: { item: WikiItem; copied: string; onCopy: (id: string) => void }) {
  const rich = [...KNOWLEDGE, ...HANDBOOK].find((row) => row.id === item.id)
  const depth = technicalOf(item)
  const links = [...(rich?.links || []), ...depth.links.filter((link) => !(rich?.links || []).some((row) => row.href === link.href))]
  const letter = rich?.letter || `Коллеги, проверка «${item.title}» отмечена в BroSec. ${item.impact || item.text} Просьба: ${item.fix || "закрыть замечание и сообщить, когда можно перепроверить"}.`
  return (
    <div className="grid gap-4 text-sm">
      <section><h3 className="font-medium">Простым языком</h3><p className="text-muted-foreground">{rich?.what || item.what || item.text}</p></section>
      <section><h3 className="font-medium">Технически</h3><p>{depth.tech}</p></section>
      <section><h3 className="font-medium">Зачем это существует</h3><p>{rich?.why || "Параметр или программа оставлены в состоянии, которое ослабляет контроль домена."}</p></section>
      <section><h3 className="font-medium">Чем кончается</h3><p>{rich?.impact || item.impact || item.text}</p></section>
      <section>
        <h3 className="font-medium">Что передать в работу</h3>
        {rich ? <ol className="mt-1 list-decimal space-y-1 pl-5">{rich.defense.map((line) => <li key={line}>{line}</li>)}</ol> : <p>{item.fix || item.text}</p>}
      </section>
      <section className="grid gap-2">
        <h3 className="font-medium">Письмо администраторам</h3>
        <p className="bg-muted rounded-lg p-3 whitespace-pre-wrap">{letter}</p>
        <Button variant="outline" onClick={() => { void navigator.clipboard.writeText(letter).then(() => onCopy(item.id || item.title)) }}>
          {copied === (item.id || item.title) ? "Скопировано" : "Скопировать текст письма"}
        </Button>
      </section>
      <section className="grid gap-1">
        <h3 className="font-medium">Источники</h3>
        {links.map((link) => <a key={link.href} className="text-primary underline" href={link.href} target="_blank" rel="noreferrer">{link.title}</a>)}
      </section>
    </div>
  )
}
