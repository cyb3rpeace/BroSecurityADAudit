import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { useApp } from "@/app-state"

export function Login() {
  const { t, login, confirmTotp } = useApp()
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [code, setCode] = useState("")
  const [step, setStep] = useState<"password" | "totp">("password")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setError("")
    setBusy(true)
    try {
      if (step === "totp") {
        await confirmTotp(code.trim())
        return
      }
      const result = await login(username.trim(), password)
      if (result === "totp") setStep("totp")
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
          <img src="/static/logo.png" alt="BroSec" className="mx-auto size-28 rounded-2xl object-contain" />
          <CardTitle className="text-xl">BroSec Audit AD</CardTitle>
          <CardDescription>{t("login.sub")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="grid gap-3" onSubmit={(event) => void submit(event)}>
            {step === "password" ? (
              <>
                <Input value={username} placeholder={t("login.user")} autoComplete="username" onChange={(event) => setUsername(event.target.value)} />
                <Input type="password" value={password} placeholder={t("login.pass")} autoComplete="current-password" onChange={(event) => setPassword(event.target.value)} />
              </>
            ) : (
              <Input value={code} inputMode="numeric" placeholder="Код из Яндекс Ключа или Google Authenticator" autoComplete="one-time-code" onChange={(event) => setCode(event.target.value)} />
            )}
            {error ? <p className="text-destructive text-sm">{error}</p> : null}
            <Button type="submit" disabled={busy}>{t("login.in")}</Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
