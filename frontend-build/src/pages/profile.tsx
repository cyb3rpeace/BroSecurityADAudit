import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { PageHead } from "@/components/bits"
import { api } from "@/lib/api"
import { useApp } from "@/app-state"

type Profile = {
  full_name: string
  username: string
  email: string
  phone: string
  locale: string
  totp_enabled: boolean
}

type Project = { id: number; name: string; domain: string; role: string }
type SessionRow = { id: number; ip: string; device: string; at: string; current: boolean }

export function ProfilePage() {
  const { refreshMe, setLang } = useApp()
  const [form, setForm] = useState<Profile | null>(null)
  const [projects, setProjects] = useState<Project[]>([])
  const [note, setNote] = useState("")

  useEffect(() => {
    void api<Profile>("/api/me").then(setForm)
    void api<Project[]>("/api/me/projects").then(setProjects)
  }, [])

  async function save(event: React.FormEvent) {
    event.preventDefault()
    if (!form) return
    setNote("")
    const saved = await api<Profile>("/api/me", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ full_name: form.full_name, email: form.email, phone: form.phone, locale: form.locale }),
    })
    setForm(saved)
    setLang(saved.locale === "en" ? "en" : "ru")
    await refreshMe()
    setNote("Сохранено")
  }

  return (
    <div className="grid max-w-3xl gap-4">
      <PageHead title="Профиль пользователя" sub="Персональная информация и проекты, в которых вы состоите." />
      {form ? (
        <form className="grid gap-3 rounded-xl border p-4" onSubmit={(event) => void save(event)}>
          <div className="text-sm font-medium">Персональная информация</div>
          <Label htmlFor="fio">ФИО</Label>
          <Input id="fio" value={form.full_name} onChange={(event) => setForm({ ...form, full_name: event.target.value })} />
          <Label htmlFor="user">Username</Label>
          <Input id="user" value={form.username} readOnly />
          <Label htmlFor="mail">E-mail</Label>
          <Input id="mail" type="email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} />
          <Label htmlFor="phone">Телефон</Label>
          <Input id="phone" value={form.phone} onChange={(event) => setForm({ ...form, phone: event.target.value })} />
          <Label htmlFor="lang">Язык</Label>
          <div className="flex gap-2">
            <Button type="button" variant={form.locale === "ru" ? "default" : "outline"} onClick={() => setForm({ ...form, locale: "ru" })}>Русский</Button>
            <Button type="button" variant={form.locale === "en" ? "default" : "outline"} onClick={() => setForm({ ...form, locale: "en" })}>English</Button>
          </div>
          {note ? <p className="text-sm">{note}</p> : null}
          <Button type="submit" className="w-fit">Сохранить</Button>
        </form>
      ) : <p className="text-muted-foreground text-sm">Читаем профиль...</p>}
      <div className="overflow-auto rounded-xl border">
        <div className="border-b px-3 py-2 text-sm font-medium">Проекты</div>
        <table className="w-full text-left text-sm">
          <thead className="bg-muted/50 text-xs">
            <tr>{["Проект", "Домен", "Роль"].map((head) => <th key={head} className="px-3 py-2 font-medium">{head}</th>)}</tr>
          </thead>
          <tbody>
            {projects.map((row) => (
              <tr key={row.id} className="border-t">
                <td className="px-3 py-2">{row.name}</td>
                <td className="px-3 py-2">{row.domain || "—"}</td>
                <td className="px-3 py-2">{row.role}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!projects.length ? <p className="text-muted-foreground p-3 text-sm">Проектов нет.</p> : null}
      </div>
    </div>
  )
}

export function SecurityPage() {
  const { refreshMe } = useApp()
  const [current, setCurrent] = useState("")
  const [next, setNext] = useState("")
  const [again, setAgain] = useState("")
  const [note, setNote] = useState("")
  const [enabled, setEnabled] = useState(false)
  const [setup, setSetup] = useState<{ secret: string; svg: string } | null>(null)
  const [code, setCode] = useState("")
  const [offPassword, setOffPassword] = useState("")
  const [sessions, setSessions] = useState<SessionRow[]>([])

  function load() {
    void api<Profile>("/api/me").then((row) => setEnabled(row.totp_enabled))
    void api<SessionRow[]>("/api/me/sessions").then(setSessions)
  }

  useEffect(() => { load() }, [])

  async function changePassword(event: React.FormEvent) {
    event.preventDefault()
    setNote("")
    if (next !== again) {
      setNote("Новый пароль и повтор не совпадают")
      return
    }
    await api("/api/me/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current, new: next }),
    })
    setCurrent("")
    setNext("")
    setAgain("")
    setNote("Пароль изменён")
  }

  async function startTotp() {
    setNote("")
    const data = await api<{ secret: string; svg: string }>("/api/me/totp/start", { method: "POST" })
    setSetup(data)
  }

  async function confirmTotp(event: React.FormEvent) {
    event.preventDefault()
    await api("/api/me/totp/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    })
    setSetup(null)
    setCode("")
    setEnabled(true)
    await refreshMe()
    setNote("Код приложения включён")
  }

  async function disableTotp(event: React.FormEvent) {
    event.preventDefault()
    await api("/api/me/totp/disable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: offPassword }),
    })
    setOffPassword("")
    setEnabled(false)
    setNote("Код приложения выключен")
  }

  async function revoke() {
    await api("/api/me/sessions/revoke-others", { method: "POST" })
    load()
    setNote("Другие сеансы завершены")
  }

  return (
    <div className="grid max-w-3xl gap-4">
      <PageHead title="Безопасность" sub="Пароль, код приложения и сеансы входа." />
      <form className="grid gap-3 rounded-xl border p-4" onSubmit={(event) => void changePassword(event)}>
        <div className="text-sm font-medium">Изменить пароль</div>
        <Input type="password" value={current} placeholder="Текущий пароль" autoComplete="current-password" onChange={(event) => setCurrent(event.target.value)} />
        <Input type="password" value={next} placeholder="Новый пароль, от 10 символов" autoComplete="new-password" onChange={(event) => setNext(event.target.value)} />
        <Input type="password" value={again} placeholder="Повтор нового пароля" autoComplete="new-password" onChange={(event) => setAgain(event.target.value)} />
        <Button type="submit" className="w-fit">Сохранить пароль</Button>
      </form>
      <div className="grid gap-3 rounded-xl border p-4">
        <div className="text-sm font-medium">Двухфакторная аутентификация</div>
        <p className="text-muted-foreground text-sm">Код показывается на этой странице. Отсканируйте его в Яндекс Ключе или Google Authenticator. На почту секрет не отправляется.</p>
        {enabled ? (
          <form className="grid gap-2" onSubmit={(event) => void disableTotp(event)}>
            <p className="text-sm">Код приложения включён.</p>
            <Input type="password" value={offPassword} placeholder="Пароль, чтобы выключить" onChange={(event) => setOffPassword(event.target.value)} />
            <Button type="submit" variant="outline" className="w-fit">Выключить</Button>
          </form>
        ) : (
          <div className="grid gap-3">
            <Button type="button" variant="outline" className="w-fit" onClick={() => void startTotp()}>Показать QR</Button>
            {setup ? (
              <form className="grid gap-3" onSubmit={(event) => void confirmTotp(event)}>
                <div className="bg-white w-fit rounded-xl p-3" dangerouslySetInnerHTML={{ __html: setup.svg }} />
                <p className="text-xs break-all">Если камера не читает код, введите ключ вручную: {setup.secret}</p>
                <Input value={code} inputMode="numeric" placeholder="Код из приложения" onChange={(event) => setCode(event.target.value)} />
                <Button type="submit" className="w-fit">Подтвердить</Button>
              </form>
            ) : null}
          </div>
        )}
      </div>
      <div className="grid gap-3 rounded-xl border p-4">
        <div className="flex flex-wrap items-center gap-2">
          <div className="text-sm font-medium">Сеансы</div>
          <Button type="button" variant="outline" className="ml-auto" onClick={() => void revoke()}>Завершить другие сеансы</Button>
        </div>
        <div className="overflow-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-muted/50 text-xs">
              <tr>{["Устройство", "IP", "Активность", ""].map((head) => <th key={head || "mark"} className="px-3 py-2 font-medium">{head}</th>)}</tr>
            </thead>
            <tbody>
              {sessions.map((row) => (
                <tr key={row.id} className="border-t">
                  <td className="px-3 py-2">{row.device}</td>
                  <td className="px-3 py-2">{row.ip}</td>
                  <td className="px-3 py-2">{row.at}</td>
                  <td className="px-3 py-2">{row.current ? "этот сеанс" : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      {note ? <p className="text-sm">{note}</p> : null}
    </div>
  )
}
