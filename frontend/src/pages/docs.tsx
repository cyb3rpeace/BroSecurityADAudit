import { useEffect, useMemo, useState } from "react"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { PageHead } from "@/components/bits"
import type { WikiItem } from "@/lib/types"
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
    ["start", "С чего начать", "Каталог читает Linux по LDAP или LDAPS. PingCastle и SharpHound ставятся на любой Windows-компьютер в домене: Windows Server 2019 или рабочая станция офицера безопасности. На контроллер их ставить не обязательно. Настрой LDAP/LDAPS, установи BloodHound и PingCastle и приступай к сканированию!"],
    ["ldap", "Каталог: LDAPS 636 и простой LDAP 389", "В настройках укажите DNS-имя контроллера и служебную учетную запись этого же домена. Формат DOMAIN\\user или user@domain. Права администратора домена не нужны, достаточно чтения. LDAPS 636 — если на контроллере есть сертификат. LDAP 389 — обычный канал без шифрования, только внутри доверенной сети. Гигиена, доверия и типы шифрования Kerberos идут этим каналом."],
    ["pc", "Как установить PingCastle", "На Windows-хосте возьмите последний zip с PingCastle.exe из выпусков Netwrix. Распакуйте в C:\\Tools\\PingCastle. Запуск: PingCastle.exe --healthcheck --server ИМЯ-КОНТРОЛЛЕРА. Пароль в командную строку не кладите. XML загружается в пункт меню PingCastle."],
    ["sh", "Как установить SharpHound", "Возьмите SharpHound.exe из выпусков SpecterOps той же ветки, что понимает BloodHound CE. Распакуйте в C:\\Tools\\SharpHound. Сбор: SharpHound.exe -c DCOnly,Session,LocalAdmin,CA --zipfilename brosec --nosavecache. Хеши и билеты не выгружаются. Zip загружается в пункт меню SharpHound."],
    ["link", "Как связать программы с сервером", "PingCastle и SharpHound пока запускаются вручную на компьютере, где офицер уже вошел в домен, и загружаются со своих страниц. Отдельный Windows-хост для них в настройках не задается: удаленный запуск этих программ вернется вместе с Velociraptor. Реестр, время, SYSVOL и установленные программы сервер читает по WinRM. Значение cpassword не расшифровывается. Сборщик в настройках не содержит пароль домена."],
    ["mail", "Почта, Telegram и ассистент", "Суперадминистратор задает SMTP и бота Telegram. Пароль и токен обратно в браузер не возвращаются. После сканирования уходят письмо и сообщение, если каналы настроены. Модель ассистента подключается адресом в формате OpenAI, путь заканчивается на /v1."],
  ],
  en: [
    ["start", "Start here", "The directory is read from Linux over LDAP or LDAPS. PingCastle and SharpHound run on any domain-joined Windows host. Set LDAP or LDAPS, install BloodHound and PingCastle, and start the scan."],
    ["ldap", "LDAP 389 and LDAPS 636", "A domain read account is enough. Use DOMAIN\\user or user@domain. Pick LDAPS 636 when the controller has a certificate. Pick plain LDAP 389 only on a trusted network."],
    ["tools", "Install and connect the tools", "Unzip PingCastle and SharpHound to C:\\Tools. Either point WinRM at that Windows host, or build the collector in Settings and run it there. The script does not contain the domain password. Upload the XML and the zip from their menu pages."],
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
  const { t, lang, inventory } = useApp()
  const [items, setItems] = useState<WikiItem[]>([])
  const [query, setQuery] = useState("")
  const [group, setGroup] = useState("all")
  const [open, setOpen] = useState<string[]>(["start"])
  const [card, setCard] = useState<WikiItem | null>(null)

  useEffect(() => {
    void loadWiki().then(setItems)
  }, [])

  const foundRules = useMemo(() => {
    const ids = new Set<string>()
    const pattern = /\b(?:pc:)?([ASPT]-[A-Za-z0-9_-]+)\b/g
    for (const row of inventory) {
      const blob = [row.title, row.detail, row.tags, row.vuln_id].join(" ")
      for (const match of blob.matchAll(pattern)) ids.add(match[1])
    }
    return ids
  }, [inventory])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return items.filter((item) => {
      if (item.g === "pingcastle" && (!item.id || !foundRules.has(item.id))) return false
      return (group === "all" || item.g === group) && (!q || [item.id, item.title, item.text, item.family, item.what, item.impact, item.fix].join(" ").toLowerCase().includes(q))
    })
  }, [foundRules, group, items, query])

  const families = ["Устаревшее", "Привилегии", "Аномалии", "Доверия"]
  const docs = DOCS[lang]

  return (
    <div>
      <PageHead title={t("nav.docs")} sub={t("docs.lead")} />
      <div className="mb-4 flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => setOpen(docs.map((row) => row[0]))}>Развернуть все</Button>
        <Button variant="outline" onClick={() => setOpen([])}>Свернуть все</Button>
        <Input className="max-w-sm" value={query} placeholder="Поиск по справочнику: SMB, LDAP, GPO..." onChange={(event) => setQuery(event.target.value)} />
      </div>
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
          <TabsTrigger value="pingcastle">PingCastle</TabsTrigger>
          <TabsTrigger value="bloodhound">BloodHound</TabsTrigger>
        </TabsList>
      </Tabs>
      <div className="mt-4 grid gap-2">
        {query ? <div className="grid gap-2 sm:grid-cols-2">{filtered.map((item) => <WikiCard key={(item.id || "") + item.title} item={item} onOpen={setCard} />)}</div> : (
          <>
            {["platform", "bloodhound"].filter((key) => group === "all" || group === key).map((key) => (
              <WikiBlock key={key} title={key === "platform" ? "Проверки платформы" : "BloodHound"} items={filtered.filter((item) => item.g === key)} onOpen={setCard} />
            ))}
            {(group === "all" || group === "pingcastle") && !filtered.some((item) => item.g === "pingcastle") ? (
              <p className="text-muted-foreground mt-3 text-sm">Правила PingCastle появятся после загрузки отчета и только по найденным проблемам.</p>
            ) : null}
            {(group === "all" || group === "pingcastle") && filtered.some((item) => item.g === "pingcastle") ? (
              <Accordion type="single" collapsible>
                <AccordionItem value="pc">
                  <AccordionTrigger>PingCastle · {filtered.filter((item) => item.g === "pingcastle").length}</AccordionTrigger>
                  <AccordionContent>
                    <p className="mb-3">Здесь только те правила PingCastle, которые нашлись в загруженном отчете. Полный каталог из сотен проверок в справочник не выгружается. 30 баллов и выше — критический уровень, 15–29 — высокий, 5–14 — средний, меньше 5 — низкий.</p>
                    {families.map((family) => {
                      const part = filtered.filter((item) => item.g === "pingcastle" && item.family === family)
                      if (!part.length) return null
                      return <WikiBlock key={family} title={family} items={part} onOpen={setCard} />
                    })}
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            ) : null}
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
          <section className="grid gap-1">
            <h3 className="text-sm font-medium">Что это за параметр</h3>
            <p className="text-muted-foreground text-sm">{card?.what || card?.text}</p>
          </section>
          <section className="grid gap-1">
            <h3 className="text-sm font-medium">На что влияет</h3>
            <p className="text-sm">{card?.impact || card?.text}</p>
          </section>
          <section className="grid gap-1">
            <h3 className="text-sm font-medium">Как исправить</h3>
            <p className="text-sm">{card?.fix || card?.text}</p>
          </section>
        </DialogContent>
      </Dialog>
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
