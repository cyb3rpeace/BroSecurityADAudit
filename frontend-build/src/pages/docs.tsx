import { useEffect, useMemo, useState } from "react"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
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

export function Docs() {
  const { t, lang, setView } = useApp()
  const [items, setItems] = useState<WikiItem[]>([])
  const [query, setQuery] = useState("")
  const [group, setGroup] = useState("all")
  const [open, setOpen] = useState<string[]>(["start"])
  const [card, setCard] = useState<WikiItem | null>(null)
  const [copied, setCopied] = useState("")

  useEffect(() => {
    void loadWiki().then(setItems)
  }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    const wiki = items.filter((item) => item.g !== "pingcastle" && item.g !== "graph")
    const ids = new Set(wiki.map((item) => item.id))
    const articles = [...KNOWLEDGE, ...HANDBOOK]
    const extra: WikiItem[] = articles.filter((item) => !ids.has(item.id)).map((item) => ({
      id: item.id,
      title: item.title,
      text: item.what,
      g: "platform",
      what: item.what,
      impact: item.impact,
      fix: item.defense.join(" "),
      sev: item.severity,
    }))
    return [...wiki, ...extra].filter((item) => (group === "all" || item.g === group) && (!q || [item.id, item.title, item.text, item.family, item.what, item.impact, item.fix].join(" ").toLowerCase().includes(q)))
  }, [group, items, query])

  const docs = DOCS[lang].filter(row => !query || row.join(" ").toLowerCase().includes(query.toLowerCase()))

  return (
    <div>
      <PageHead title={t("nav.docs")} sub={t("docs.lead")} />
      <Button className="mb-4" variant="secondary" onClick={() => setView("notes")}>Примечания к обновлению</Button>
      <div className="mb-4 flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => setOpen(docs.map((row) => row[0]))}>Развернуть все</Button>
        <Button variant="outline" onClick={() => setOpen([])}>Свернуть все</Button>
        <Input className="max-w-sm" value={query} placeholder="Поиск по справочнику: SMB, LDAP, GPO..." onChange={(event) => setQuery(event.target.value)} />
      </div>
      <p className="text-muted-foreground mb-4 text-sm">Документация по работе и эксплуатации — в разделах ниже. Поиск также находит проверки платформы: назначение, влияние, исправление и источники.</p>
      <Accordion type="multiple" value={query ? docs.map(row => row[0]) : open} onValueChange={setOpen} className="mb-6">
        {docs.map(([id, title, text]) => (
          <AccordionItem key={id} value={id}>
            <AccordionTrigger>{title}</AccordionTrigger>
            <AccordionContent>{text}</AccordionContent>
          </AccordionItem>
        ))}
      </Accordion>
      <Tabs value={group} onValueChange={setGroup}>
        <TabsList>
          <TabsTrigger value="all">{t("all")}</TabsTrigger>
          <TabsTrigger value="platform">Наши проверки</TabsTrigger>
        </TabsList>
      </Tabs>
      <div className="mt-4 grid gap-2">
        {query ? <div className="grid gap-2 sm:grid-cols-2">{filtered.map((item) => <WikiCard key={(item.id || "") + item.title} item={item} onOpen={setCard} />)}</div> : (
          <>
            {["platform"].filter((key) => group === "all" || group === key).map((key) => (
              <WikiBlock key={key} title="Проверки платформы" items={filtered.filter((item) => item.g === key)} onOpen={setCard} />
            ))}
          </>
        )}
        {!filtered.length ? <p className="text-muted-foreground text-sm">В справочнике ничего не найдено.</p> : null}
      </div>
      <Dialog open={!!card} onOpenChange={(next) => { if (!next) setCard(null) }}>
        <DialogContent className="max-h-[85vh] overflow-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex flex-wrap items-center gap-2">
              {card?.title}
              {card?.sev ? <span className={"rounded-full px-2 py-0.5 text-xs " + sevClass(card.sev)}>{SEV[card.sev] || card.sev}</span> : null}
            </DialogTitle>
            <DialogDescription>{[card?.id, card?.family].filter(Boolean).join(" · ")}</DialogDescription>
          </DialogHeader>
          {card ? <CheckArticle item={card} copied={copied} onCopy={setCopied} /> : null}
        </DialogContent>
      </Dialog>
    </div>
  )
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

function WikiBlock({ title, items, onOpen }: { title: string; items: WikiItem[]; onOpen: (item: WikiItem) => void }) {
  if (!items.length) return null
  return (
    <Accordion type="single" collapsible>
      <AccordionItem value={title}>
        <AccordionTrigger>{title} · {items.length}</AccordionTrigger>
        <AccordionContent>
          <div className="grid gap-2 sm:grid-cols-2">
            {items.map((item) => <WikiCard key={(item.id || "") + item.title} item={item} onOpen={onOpen} />)}
          </div>
        </AccordionContent>
      </AccordionItem>
    </Accordion>
  )
}

function WikiCard({ item, onOpen }: { item: WikiItem; onOpen: (item: WikiItem) => void }) {
  return (
    <button type="button" className="hover:bg-muted/60 rounded-xl border p-3 text-left" onClick={() => onOpen(item)}>
      <div className="flex items-center justify-between gap-2">
        <code className="text-muted-foreground text-xs">{item.id}</code>
        {item.sev ? <span className={"rounded-full px-2 py-0.5 text-[11px] " + sevClass(item.sev)}>{SEV[item.sev] || item.sev}</span> : null}
      </div>
      <div className="font-medium">{item.title}</div>
      <p className="text-muted-foreground line-clamp-2 text-xs">{item.impact || item.text}</p>
    </button>
  )
}
