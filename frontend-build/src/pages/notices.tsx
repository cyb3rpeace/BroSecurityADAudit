import { useEffect, useState } from "react"
import { Settings } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { PageHead } from "@/components/bits"
import { api } from "@/lib/api"
import { useApp } from "@/app-state"

const TOPICS: { id: string; title: string; text: string }[] = [
  { id: "scan_done", title: "Сканирование завершилось", text: "Короткий итог и индекс риска. Паспорт прикладывается, если канал включён." },
  { id: "scan_failed", title: "Сканирование остановилось с ошибкой", text: "Письмо или сообщение, что запуск не дошёл до конца." },
  { id: "software_danger", title: "Хост с опасным ПО", text: "RAT, несогласованный удалённый доступ или потребительский VPN. Это отдельное письмо администратору, даже если общий список критичных находок выключен." },
  { id: "adcs", title: "Опасный шаблон сертификатов", text: "Шаблон, где заявитель задаёт имя и выпуск не согласовывается." },
  { id: "gpp", title: "Пароль в групповой политике", text: "Только факт атрибута. Значение в письмо не входит." },
  { id: "trust", title: "Доверие без фильтрации SID", text: "Внешнее или лесное доверие, на котором фильтрация выключена." },
  { id: "critical", title: "Остальные критичные и высокие находки", text: "Всё, что не попало в отдельные переключатели выше. Повтор уже отправленной строки не дублируется." },
]

type Prefs = Record<string, { mail: boolean; telegram: boolean }>

export function Notices({ deliveryTick = 0 }: { deliveryTick?: number }) {
  const { t, notices, markAllNotices, deleteNotice } = useApp()
  const [delivery, setDelivery] = useState(false)
  const [topics, setTopics] = useState<Prefs | null>(null)
  const [ready, setReady] = useState({ mail: false, telegram: false })
  const [note, setNote] = useState("")

  useEffect(() => {
    if (deliveryTick) setDelivery(true)
  }, [deliveryTick])

  useEffect(() => {
    if (!delivery) return
    void api<{ topics: Prefs; mail_ready: boolean; telegram_ready: boolean }>("/api/notifications/prefs")
      .then((data) => {
        setTopics(data.topics)
        setReady({ mail: data.mail_ready, telegram: data.telegram_ready })
      })
      .catch((reason: unknown) => setNote(reason instanceof Error ? reason.message : "Настройки не прочитаны"))
  }, [delivery])

  async function save(next: Prefs) {
    setTopics(next)
    setNote("")
    try {
      await api("/api/notifications/prefs", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ topics: next }) })
      setNote("Сохранено. Следующее сканирование пойдёт по этим переключателям.")
    } catch (reason: unknown) {
      setNote(reason instanceof Error ? reason.message : "Не сохранилось")
    }
  }

  function flip(id: string, channel: "mail" | "telegram", value: boolean) {
    if (!topics) return
    const next = { ...topics, [id]: { ...topics[id], [channel]: value } }
    void save(next)
  }

  return (
    <div>
      <PageHead title={t("nav.notices")} sub="Колокольчик хранит события консоли. Шестерёнка выбирает, что уходит на почту и в Telegram." />
      <div className="mb-3 flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => void markAllNotices()}>{t("bell.read")}</Button>
        <Button variant={delivery ? "default" : "outline"} onClick={() => setDelivery((value) => !value)}>
          <Settings /> Доставка
        </Button>
      </div>
      {delivery ? (
        <Card className="mb-4">
          <CardHeader>
            <CardTitle className="text-base">Почта и Telegram</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4">
            <p className="text-muted-foreground text-sm">
              Почта {ready.mail ? "настроена" : "не настроена"}. Telegram {ready.telegram ? "настроен" : "не настроен"}. Каждая включённая почтовая тема уходит отдельным письмом. Общий список критичных находок не повторяет строки, которые уже ушли отдельной темой. Если доставка сорвётся, строка появится в колокольчике и красной плашкой на любой вкладке.
            </p>
            {TOPICS.map((topic) => (
              <div key={topic.id} className="grid gap-2 rounded-lg border p-3 md:grid-cols-[1fr_auto_auto] md:items-center">
                <div>
                  <div className="text-sm font-medium">{topic.title}</div>
                  <p className="text-muted-foreground text-xs">{topic.text}</p>
                </div>
                <label className="flex items-center gap-2 text-sm">
                  <Switch checked={!!topics?.[topic.id]?.mail} onCheckedChange={(value) => flip(topic.id, "mail", value)} />
                  Почта
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <Switch checked={!!topics?.[topic.id]?.telegram} onCheckedChange={(value) => flip(topic.id, "telegram", value)} />
                  Telegram
                </label>
              </div>
            ))}
            {note ? <p className="text-sm">{note}</p> : null}
          </CardContent>
        </Card>
      ) : null}
      <div className="grid gap-2">
        {notices.length ? notices.map((row) => (
          <Card key={row.id}>
            <CardContent className="flex items-start gap-3 py-4">
              <div className="min-w-0 flex-1">
                <div className="font-medium">{row.title}</div>
                <p className="text-muted-foreground text-sm">{row.body}</p>
                <p className="text-muted-foreground mt-1 text-xs">{row.at}{row.read ? "" : " · новое"}</p>
              </div>
              <Button variant="ghost" size="sm" onClick={() => void deleteNotice(row.id)}>{t("bell.delete")}</Button>
            </CardContent>
          </Card>
        )) : <p className="text-muted-foreground text-sm">{t("bell.empty")}</p>}
      </div>
    </div>
  )
}
