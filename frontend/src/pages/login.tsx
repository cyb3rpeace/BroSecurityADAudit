import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { useApp } from "@/app-state"

export function Login() {
  const { t, login } = useApp()
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setError("")
    setBusy(true)
    try {
      await login(username.trim(), password)
    } catch (err) {
      setError(err instanceof Error && err.message !== "auth" ? err.message : "Неверный логин или пароль")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid min-h-svh place-items-center px-4">
      <Card className="w-full max-w-sm">
        <CardHeader className="items-center text-center">
          <img src="/static/logo.png" alt="" className="size-14 rounded-2xl object-cover" />
          <CardTitle className="text-xl">BroSec Audit AD</CardTitle>
          <CardDescription>{t("login.sub")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="grid gap-3" onSubmit={(event) => void submit(event)}>
            <Input value={username} placeholder={t("login.user")} autoComplete="username" onChange={(event) => setUsername(event.target.value)} />
            <Input type="password" value={password} placeholder={t("login.pass")} autoComplete="current-password" onChange={(event) => setPassword(event.target.value)} />
            {error ? <p className="text-destructive text-sm">{error}</p> : null}
            <Button type="submit" disabled={busy}>{t("login.in")}</Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
