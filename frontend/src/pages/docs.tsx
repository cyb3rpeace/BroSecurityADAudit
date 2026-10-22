import { useEffect, useMemo, useState } from "react"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { PageHead } from "@/components/bits"
import type { WikiItem } from "@/lib/types"
import { KNOWLEDGE } from "@/lib/knowledge"
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
    ["start", "С чего начать", "Каталог читает Linux по LDAP или LDAPS. SharpHound ставится на любой Windows-компьютер в домене. На контроллер его ставить не обязательно. Настрой LDAP/LDAPS, установи BloodHound и приступай к сканированию!"],
    ["ldap", "Каталог: LDAPS 636 и простой LDAP 389", "В настройках укажите DNS-имя контроллера и служебную учетную запись этого же домена. Формат DOMAIN\\user или user@domain. Права администратора домена не нужны, достаточно чтения. LDAPS 636 — если на контроллере есть сертификат. LDAP 389 — обычный канал без шифрования, только внутри доверенной сети. Гигиена, доверия и типы шифрования Kerberos идут этим каналом."],
    ["areas", "Области аудита", "Учетные записи: пароли, блокировка, служебные записи, точечные политики. Устройства: устаревшие ОС, пароль компьютера, покрытие LAPS без чтения пароля, пустые подразделения. Пути: делегирование, SPN, шаблоны сертификатов, только признаки. Группы: пустые, слишком большие и слишком глубоко вложенные, без списка участников. DNS: свойства зоны без содержимого. Контроллеры: процессор, память, диск и счётчики входов за сутки без текста чужих сессий."],
    ["sh", "Как установить SharpHound", "Возьмите SharpHound.exe из выпусков SpecterOps той же ветки, что понимает BloodHound CE. Распакуйте в C:\\Tools\\SharpHound. Сбор: SharpHound.exe -c DCOnly,Session,LocalAdmin,CA --zipfilename brosec --nosavecache. Хеши и билеты не выгружаются. Zip загружается в пункт меню SharpHound."],
    ["link", "Как связать программу с сервером", "SharpHound запускается вручную на компьютере, где офицер уже вошел в домен, и загружается со своей страницы. Реестр, время, SYSVOL и установленные программы сервер читает по WinRM. Значение cpassword не расшифровывается. Сборщик в настройках не содержит пароль домена."],
    ["mail", "Почта, Telegram и ассистент", "Суперадминистратор задает SMTP и бота Telegram. Пароль и токен обратно в браузер не возвращаются. После сканирования уходят письмо и сообщение, если каналы настроены. Модель ассистента подключается адресом в формате OpenAI, путь заканчивается на /v1."],
  ],
  en: [
    ["start", "Start here", "The directory is read from Linux over LDAP or LDAPS. SharpHound runs on any domain-joined Windows host. Set LDAP or LDAPS, install BloodHound, and start the scan."],
    ["ldap", "LDAP 389 and LDAPS 636", "A domain read account is enough. Use DOMAIN\\user or user@domain. Pick LDAPS 636 when the controller has a certificate. Pick plain LDAP 389 only on a trusted network."],
    ["areas", "Audit areas", "Accounts, devices, delegation, groups, and DNS zone names. Group member lists and binary DNS records stay out of the report. Full GPO diffs, live logon events, and hardware inventory are not part of the product."],
    ["tools", "Install SharpHound", "Unzip SharpHound to C:\\Tools. Run it on a computer where you are already signed in to the domain and upload the zip from the SharpHound page. The collector script does not contain the domain password."],
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
    const wiki = items.filter((item) => item.g !== "pingcastle")
    const ids = new Set(wiki.map((item) => item.id))
    const extra: WikiItem[] = KNOWLEDGE.filter((item) => !ids.has(item.id)).map((item) => ({
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

  const docs = DOCS[lang]

  return (
    <div>
      <PageHead title={t("nav.docs")} sub={t("docs.lead")} />
      <Button className="mb-4" variant="secondary" onClick={() => setView("notes")}>Примечания к обновлению</Button>
      <div className="mb-4 flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => setOpen(docs.map((row) => row[0]))}>Развернуть все</Button>
        <Button variant="outline" onClick={() => setOpen([])}>Свернуть все</Button>
        <Input className="max-w-sm" value={query} placeholder="Поиск по справочнику: SMB, LDAP, GPO..." onChange={(event) => setQuery(event.target.value)} />
      </div>
      <p className="text-muted-foreground mb-4 text-sm">Один список проверок. В карточке: что это, зачем, чем кончается, как закрыть и текст для администраторов. Команд в разборе нет.</p>
      <Accordion type="multiple" value={open} onValueChange={setOpen} className="mb-6">
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
          <TabsTrigger value="bloodhound">BloodHound</TabsTrigger>
        </TabsList>
      </Tabs>
      <div className="mt-4 grid gap-2">
        {query ? <div className="grid gap-2 sm:grid-cols-2">{filtered.map((item) => <WikiCard key={(item.id || "") + item.title} item={item} onOpen={setCard} />)}</div> : (
          <>
            {["platform", "bloodhound"].filter((key) => group === "all" || group === key).map((key) => (
              <WikiBlock key={key} title={key === "platform" ? "Проверки платформы" : "BloodHound"} items={filtered.filter((item) => item.g === key)} onOpen={setCard} />
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
  const rich = KNOWLEDGE.find((row) => row.id === item.id)
  const letter = rich?.letter || `Коллеги, проверка «${item.title}» отмечена в BroSec. ${item.impact || item.text} Просьба: ${item.fix || "закрыть замечание и сообщить, когда можно перепроверить"}.`
  return (
    <div className="grid gap-4 text-sm">
      <section><h3 className="font-medium">Что это</h3><p className="text-muted-foreground">{rich?.what || item.what || item.text}</p></section>
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
      {rich?.links.length ? (
        <section className="grid gap-1">
          <h3 className="font-medium">Источники</h3>
          {rich.links.map((link) => <a key={link.href} className="text-primary underline" href={link.href} target="_blank" rel="noreferrer">{link.title}</a>)}
        </section>
      ) : null}
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
