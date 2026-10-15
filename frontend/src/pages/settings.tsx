import { useEffect, useState } from "react"
import { toast } from "sonner"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { PageHead } from "@/components/bits"
import { api } from "@/lib/api"
import type { AuditRow, Company, ConsoleUser } from "@/lib/types"
import { useApp } from "@/app-state"

type Form = {
  name: string
  domain: string
  dc_host: string
  dc_user: string
  dc_password: string
  directory_mode: string
  runner_host: string
  transport: string
  ldap_port: string
  winrm_port: string
  ssh_port: string
  scan_hosts: string
  notify_email: string
  telegram_chat: string
}

function fromCompany(company: Company): Form {
  return {
    name: company.name || "",
    domain: company.domain || "",
    dc_host: company.dc_host || "",
    dc_user: company.dc_user || "",
    dc_password: "",
    directory_mode: company.directory_mode || "ldaps",
    runner_host: company.runner_host || "",
    transport: company.windows_mode || "none",
    ldap_port: String(company.ldap_port || (company.directory_mode === "ldap" ? 389 : 636)),
    winrm_port: String(company.winrm_port || 5985),
    ssh_port: String(company.ssh_port || 22),
    scan_hosts: company.scan_hosts || "",
    notify_email: company.notify_email || "",
    telegram_chat: company.telegram_chat || "",
  }
}

const WINRM = [
  "# Каталог: с сервера аудита до контроллера откройте TCP 389 или 636. Учетная запись — чтение каталога.",
  "# WinRM на контроллере нужен для реестра, времени, SYSVOL и аудита программ. PingCastle и SharpHound загружаются вручную.",
  "Enable-PSRemoting -Force",
  "Set-Item WSMan:\\localhost\\Service\\AllowUnencrypted -Value $false",
].join("\n")

export function Settings() {
  const { t, me, company, companyId, reload, setCompany } = useApp()
  const [form, setForm] = useState<Form | null>(company ? fromCompany(company) : null)
  useEffect(() => { if (company) setForm(fromCompany(company)) }, [company])
  if (!form) return <PageHead title={t("nav.settings")} sub={t("empty.company")} />
  const fields = form

  function set<K extends keyof Form>(key: K, value: Form[K]) {
    setForm((current) => current ? { ...current, [key]: value } : current)
  }

  async function saveCompany() {
    if (!companyId) return
    const payload = {
      ...fields,
      winrm_port: Number(fields.winrm_port || 5985),
      ssh_port: Number(fields.ssh_port || 22),
      ldap_port: Number(fields.ldap_port || 636),
    }
    try {
      await api("/api/companies/" + companyId, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) })
      toast.success("Карточка компании сохранена.")
      await reload()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Карточка не сохранилась")
    }
  }

  return (
    <div className="grid gap-4">
      <PageHead title={t("nav.settings")} sub={t("set.sub")} />
      <Tabs defaultValue="params">
        <TabsList>
          <TabsTrigger value="params">Параметры</TabsTrigger>
          <TabsTrigger value="audit">Аудит</TabsTrigger>
        </TabsList>
        <TabsContent value="params" className="pt-3">
          <Accordion type="multiple" defaultValue={["conn"]} className="gap-2">
            <AccordionItem value="conn" className="rounded-xl border px-4">
              <AccordionTrigger>{t("set.conn")}</AccordionTrigger>
              <AccordionContent className="grid gap-2">
                <p className="text-muted-foreground text-sm">{t("set.conn.help")}</p>
                <Input value={form.name} disabled={!me?.is_superadmin} placeholder="Название компании" onChange={(event) => set("name", event.target.value)} />
                <Input value={form.domain} placeholder="Домен DNS" onChange={(event) => set("domain", event.target.value)} />
                <Input value={form.dc_host} placeholder="Контроллер домена" onChange={(event) => set("dc_host", event.target.value)} />
                <Input value={form.dc_user} placeholder="DOMAIN\svc-audit или svc-audit@domain" onChange={(event) => set("dc_user", event.target.value)} />
                <Input type="password" value={form.dc_password} placeholder="Пароль, пусто — не менять" autoComplete="new-password" onChange={(event) => set("dc_password", event.target.value)} />
                <p className="text-muted-foreground text-xs">{company?.dc_password_set ? t("pass.set") : t("pass.miss")}</p>
                <Select value={form.directory_mode} onValueChange={(value) => { set("directory_mode", value); set("ldap_port", value === "ldap" ? "389" : "636") }}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ldaps">Каталог: LDAPS, порт 636</SelectItem>
                    <SelectItem value="ldap">Каталог: LDAP, порт 389</SelectItem>
                  </SelectContent>
            </Select>
            <Textarea rows={3} value={form.scan_hosts} placeholder="Дополнительные узлы для аудита ПО" onChange={(event) => set("scan_hosts", event.target.value)} />
                <Input value={form.notify_email} placeholder="Почта для отчета этой компании" onChange={(event) => set("notify_email", event.target.value)} />
                <Input value={form.telegram_chat} placeholder="Chat id Telegram этой компании" onChange={(event) => set("telegram_chat", event.target.value)} />
                <Button onClick={() => void saveCompany()}>{t("save")}</Button>
              </AccordionContent>
            </AccordionItem>
            {me?.is_superadmin ? (
              <AccordionItem value="channels" className="rounded-xl border px-4">
                <AccordionTrigger>Почта, Telegram и модель</AccordionTrigger>
                <AccordionContent><Channels /></AccordionContent>
              </AccordionItem>
            ) : null}
            <AccordionItem value="people" className="rounded-xl border px-4">
              <AccordionTrigger>Тенанты и пользователи</AccordionTrigger>
              <AccordionContent>
                {me?.is_superadmin ? <Admins onCreated={(id) => void setCompany(id)} /> : <p className="text-muted-foreground text-sm">Карточку компании меняет администратор компании. Тенанты и почту сервера задает суперадминистратор.</p>}
              </AccordionContent>
            </AccordionItem>
            <AccordionItem value="winrm" className="rounded-xl border px-4">
              <AccordionTrigger>Как открыть контроллер</AccordionTrigger>
              <AccordionContent><pre className="bg-muted overflow-auto rounded-lg p-3 text-xs whitespace-pre-wrap">{WINRM}</pre></AccordionContent>
            </AccordionItem>
            <AccordionItem value="scripts" className="rounded-xl border px-4">
              <AccordionTrigger>Сборщик и ловушки</AccordionTrigger>
              <AccordionContent><Scripts /></AccordionContent>
            </AccordionItem>
          </Accordion>
        </TabsContent>
        <TabsContent value="audit" className="pt-3">
          <AuditLog />
        </TabsContent>
      </Tabs>
    </div>
  )
}

function Channels() {
  const [mail, setMail] = useState({ smtp_server: "", smtp_port: "587", smtp_security: "starttls", smtp_user: "", smtp_password: "", smtp_from: "", test_to: "", pass_set: "" })
  const [tg, setTg] = useState({ token: "", chat: "", token_set: "" })
  const [ai, setAi] = useState({ enabled: false, api_url: "", model_name: "", api_key: "", note: "" })

  useEffect(() => {
    void api<Record<string, string | number | boolean>>("/api/notifications").then((data) => {
      setMail((current) => ({
        ...current,
        smtp_server: String(data.smtp_server || ""),
        smtp_port: String(data.smtp_port || 587),
        smtp_security: String(data.smtp_security || "starttls"),
        smtp_user: String(data.smtp_user || ""),
        smtp_from: String(data.smtp_from || ""),
        pass_set: data.smtp_password_set ? "Пароль SMTP сохранен" : "Пароль SMTP еще не задан",
      }))
      setTg((current) => ({ ...current, chat: String(data.telegram_chat || ""), token_set: data.telegram_token_set ? "Токен бота сохранен" : "Токен бота еще не задан" }))
    }).catch((error: unknown) => toast.error(error instanceof Error ? error.message : "Каналы не прочитаны"))
    void api<{ enabled: boolean; api_url: string; model_name: string; api_key_source: string }>("/api/assistant").then((data) => {
      const note = { saved: "Ключ сохранен в настройках", env: "Сейчас используется ключ, заданный на сервере.", none: "Ключ еще не задан" }[data.api_key_source] || "Ключ еще не задан"
      setAi((current) => ({ ...current, enabled: !!data.enabled, api_url: data.api_url || "", model_name: data.model_name || "", note }))
    }).catch(() => undefined)
  }, [])

  function notifyBody() {
    return {
      smtp_server: mail.smtp_server.trim(),
      smtp_port: Number(mail.smtp_port || 587),
      smtp_security: mail.smtp_security,
      smtp_user: mail.smtp_user.trim(),
      smtp_password: mail.smtp_password,
      smtp_from: mail.smtp_from.trim(),
      telegram_token: tg.token,
      telegram_chat: tg.chat.trim(),
    }
  }

  async function saveNotify(ok: string) {
    await api("/api/notifications", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(notifyBody()) })
    toast.success(ok)
  }

  return (
    <div className="grid gap-3 xl:grid-cols-2">
      <Card>
        <CardHeader><CardTitle>Корпоративная почта</CardTitle></CardHeader>
        <CardContent className="grid gap-2">
          <Input value={mail.smtp_server} placeholder="SMTP-сервер" onChange={(event) => setMail({ ...mail, smtp_server: event.target.value })} />
          <div className="grid gap-2 sm:grid-cols-2">
            <Input type="number" value={mail.smtp_port} onChange={(event) => setMail({ ...mail, smtp_port: event.target.value })} />
            <Select value={mail.smtp_security} onValueChange={(value) => setMail({ ...mail, smtp_security: value })}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="starttls">STARTTLS, обычно 587</SelectItem>
                <SelectItem value="ssl">SSL, обычно 465</SelectItem>
                <SelectItem value="none">Без шифрования, обычно 25</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <Input value={mail.smtp_user} placeholder="Учетная запись SMTP" onChange={(event) => setMail({ ...mail, smtp_user: event.target.value })} />
          <Input type="password" value={mail.smtp_password} placeholder="Пароль SMTP, пусто — не менять" onChange={(event) => setMail({ ...mail, smtp_password: event.target.value })} />
          <p className="text-muted-foreground text-xs">{mail.pass_set}</p>
          <Input value={mail.smtp_from} placeholder="Адрес отправителя" onChange={(event) => setMail({ ...mail, smtp_from: event.target.value })} />
          <Input value={mail.test_to} placeholder="Куда отправить проверочное письмо" onChange={(event) => setMail({ ...mail, test_to: event.target.value })} />
          <div className="flex gap-2">
            <Button onClick={() => void saveNotify("Почта сохранена").catch((error: unknown) => toast.error(error instanceof Error ? error.message : "Почта не сохранилась"))}>Сохранить почту</Button>
            <Button variant="outline" onClick={() => void saveNotify("Почта сохранена").then(() => api("/api/notifications/test-mail", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ recipient: mail.test_to.trim() }) })).then(() => toast.success("Проверочное письмо отправлено")).catch((error: unknown) => toast.error(error instanceof Error ? error.message : "Письмо не ушло"))}>Проверить</Button>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>Telegram</CardTitle></CardHeader>
        <CardContent className="grid gap-2">
          <Input type="password" value={tg.token} placeholder="Токен бота, пусто — не менять" onChange={(event) => setTg({ ...tg, token: event.target.value })} />
          <p className="text-muted-foreground text-xs">{tg.token_set}</p>
          <Input value={tg.chat} placeholder="Chat id общего чата" onChange={(event) => setTg({ ...tg, chat: event.target.value })} />
          <div className="flex gap-2">
            <Button onClick={() => void saveNotify("Telegram сохранен").catch((error: unknown) => toast.error(error instanceof Error ? error.message : "Telegram не сохранился"))}>Сохранить Telegram</Button>
            <Button variant="outline" onClick={() => void saveNotify("Telegram сохранен").then(() => api("/api/notifications/test-telegram", { method: "POST" })).then(() => toast.success("Проверочное сообщение ушло в Telegram")).catch((error: unknown) => toast.error(error instanceof Error ? error.message : "Telegram не ответил"))}>Проверить</Button>
          </div>
        </CardContent>
      </Card>
      <Card className="xl:col-span-2">
        <CardHeader><CardTitle>ИИ-ассистент</CardTitle></CardHeader>
        <CardContent className="grid gap-2">
          <Label className="flex items-center gap-2">
            <Switch checked={ai.enabled} onCheckedChange={(value) => setAi({ ...ai, enabled: value })} />
            Включить внешнюю модель. Если выключено, ассистент отвечает по уже найденным рискам.
          </Label>
          <Input value={ai.api_url} placeholder="https://api.example/v1" onChange={(event) => setAi({ ...ai, api_url: event.target.value })} />
          <Input value={ai.model_name} placeholder="Имя модели у провайдера" onChange={(event) => setAi({ ...ai, model_name: event.target.value })} />
          <Input type="password" value={ai.api_key} placeholder="Ключ API, пусто — не менять" autoComplete="new-password" onChange={(event) => setAi({ ...ai, api_key: event.target.value })} />
          <p className="text-muted-foreground text-xs">{ai.note}</p>
          <div className="flex gap-2">
            <Button onClick={() => void api("/api/assistant", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(ai) }).then(() => toast.success("Модель ассистента сохранена")).catch((error: unknown) => toast.error(error instanceof Error ? error.message : "Модель не сохранилась"))}>Сохранить модель</Button>
            <Button variant="outline" onClick={() => void api("/api/assistant", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(ai) }).then(() => api<{ answer: string }>("/api/assistant/test", { method: "POST" })).then((data) => toast.success(data.answer || "Модель ответила")).catch((error: unknown) => toast.error(error instanceof Error ? error.message : "Модель не ответила"))}>Проверить</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function Admins({ onCreated }: { onCreated: (id: number) => void }) {
  const { companyId, companies, me, reload } = useApp()
  const [tenant, setTenant] = useState({ name: "", domain: "" })
  const [user, setUser] = useState({ username: "", full_name: "", password: "", role: "company_admin" })
  const [users, setUsers] = useState<ConsoleUser[]>([])

  async function loadUsers() {
    const rows = await api<ConsoleUser[]>("/api/users")
    setUsers(rows)
  }

  useEffect(() => { void loadUsers().catch(() => setUsers([])) }, [])

  async function createTenant() {
    try {
      const created = await api<{ id: number }>("/api/companies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: tenant.name.trim(), domain: tenant.domain.trim(), dc_host: "", dc_user: "", dc_password: "", transport: "winrm", winrm_port: 5985, ssh_port: 22, scan_hosts: "", notify_email: "" }),
      })
      toast.success("Компания создана.")
      onCreated(created.id)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Компания не создана")
    }
  }

  async function createUser() {
    try {
      await api("/api/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...user, username: user.username.trim(), full_name: user.full_name.trim(), company_id: companyId }),
      })
      toast.success("Администратор создан.")
      setUser({ username: "", full_name: "", password: "", role: "company_admin" })
      await loadUsers()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Администратор не создан")
    }
  }

  async function removeCompany(id: number, name: string) {
    if (!window.confirm("Удалить компанию «" + name + "» вместе с находками и ее администраторами?")) return
    try {
      await api("/api/companies/" + id, { method: "DELETE" })
      toast.success("Компания удалена.")
      await reload()
      await loadUsers()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Компания не удалена")
    }
  }

  async function removeUser(row: ConsoleUser) {
    if (!window.confirm("Удалить пользователя " + row.username + "?")) return
    try {
      await api("/api/users/" + row.id, { method: "DELETE" })
      toast.success("Пользователь удален.")
      await loadUsers()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Пользователь не удален")
    }
  }

  const names = new Map(companies.map((row) => [row.id, row.name]))

  return (
    <div className="grid gap-4">
      <div className="grid gap-2">
        <Input value={tenant.name} placeholder="Новая компания" onChange={(event) => setTenant({ ...tenant, name: event.target.value })} />
        <Input value={tenant.domain} placeholder="domain.local" onChange={(event) => setTenant({ ...tenant, domain: event.target.value })} />
        <Button onClick={() => void createTenant()}>Создать компанию</Button>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Компания</TableHead>
            <TableHead>Домен</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {companies.map((row) => (
            <TableRow key={row.id}>
              <TableCell>{row.name}</TableCell>
              <TableCell>{row.domain}</TableCell>
              <TableCell><Button variant="ghost" size="sm" onClick={() => void removeCompany(row.id, row.name)}>Удалить</Button></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <h3 className="font-medium">Администраторы</h3>
      <Input value={user.username} placeholder="Логин" onChange={(event) => setUser({ ...user, username: event.target.value })} />
      <Input value={user.full_name} placeholder="Имя" onChange={(event) => setUser({ ...user, full_name: event.target.value })} />
      <Input type="password" value={user.password} placeholder="Пароль" onChange={(event) => setUser({ ...user, password: event.target.value })} />
      <Select value={user.role} onValueChange={(value) => setUser({ ...user, role: value })}>
        <SelectTrigger><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="company_admin">Администратор компании</SelectItem>
          <SelectItem value="superadmin">Суперадминистратор</SelectItem>
        </SelectContent>
      </Select>
      <Button onClick={() => void createUser()}>Создать</Button>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Логин</TableHead>
            <TableHead>Роль</TableHead>
            <TableHead>Компания</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {users.map((row) => (
            <TableRow key={row.id}>
              <TableCell>{row.full_name || row.username}</TableCell>
              <TableCell>{row.role === "superadmin" ? "Суперадминистратор" : "Администратор компании"}</TableCell>
              <TableCell>{row.company_id ? names.get(row.company_id) || row.company_id : "—"}</TableCell>
              <TableCell>{row.username === me?.username ? null : <Button variant="ghost" size="sm" onClick={() => void removeUser(row)}>Удалить</Button>}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function Scripts() {
  const { companyId, reload } = useApp()
  const [collector, setCollector] = useState("")
  const [honey, setHoney] = useState("")
  return (
    <Card>
      <CardHeader><CardTitle>Сборщик и ловушки</CardTitle></CardHeader>
      <CardContent className="grid gap-3">
        <p className="text-muted-foreground text-sm">Скрипт сборщика запускают на компьютере, где офицер уже вошел в домен. Он запускает PingCastle и SharpHound на этом компьютере и отправляет XML и архив на сервер. Пароль домена в скрипт не записывается. Это не инвентаризация программ: установленное ПО сервер читает сам, со вкладки «Сканирование». Скрипт ловушек создает непривилегированные приманки и не показывает пароль.</p>
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => void api<{ script: string }>("/api/collector/script?company_id=" + companyId).then((data) => setCollector(data.script)).catch((error: unknown) => setCollector(error instanceof Error ? error.message : ""))}>Собрать скрипт сборщика</Button>
          <Button variant="outline" onClick={() => void navigator.clipboard.writeText(collector)}>Копировать</Button>
        </div>
        {collector ? <pre className="bg-muted max-h-64 overflow-auto rounded-lg p-3 text-xs whitespace-pre-wrap">{collector}</pre> : null}
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => void api<{ script: string }>("/api/honeytokens/generate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ company_id: companyId }) }).then(async (data) => { setHoney(data.script); await reload() }).catch((error: unknown) => setHoney(error instanceof Error ? error.message : ""))}>Собрать скрипт ловушек</Button>
          <Button variant="outline" onClick={() => void navigator.clipboard.writeText(honey)}>Копировать</Button>
        </div>
        {honey ? <pre className="bg-muted max-h-64 overflow-auto rounded-lg p-3 text-xs whitespace-pre-wrap">{honey}</pre> : null}
      </CardContent>
    </Card>
  )
}

function AuditLog() {
  const [rows, setRows] = useState<AuditRow[]>([])
  useEffect(() => {
    void api<AuditRow[]>("/api/audit").then(setRows).catch((error: unknown) => toast.error(error instanceof Error ? error.message : "Журнал не открылся"))
  }, [])
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Когда</TableHead>
          <TableHead>Кто</TableHead>
          <TableHead>Действие</TableHead>
          <TableHead>Подробности</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.length ? rows.map((row) => (
          <TableRow key={row.id}>
            <TableCell className="whitespace-nowrap">{row.at}</TableCell>
            <TableCell>{row.username}</TableCell>
            <TableCell>{row.action}</TableCell>
            <TableCell>{row.detail}</TableCell>
          </TableRow>
        )) : <TableRow><TableCell colSpan={4} className="text-muted-foreground">Записей еще нет. Новый вход и изменение настроек появятся здесь.</TableCell></TableRow>}
      </TableBody>
    </Table>
  )
}
