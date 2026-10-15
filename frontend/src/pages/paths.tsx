import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageHead, Severity } from "@/components/bits"
import { isPath, matchesQuery } from "@/lib/findings"
import { useApp } from "@/app-state"

const NOTES: Record<string, { ru: string; en: string }> = {
  kerberoasting: {
    ru: "Служебная запись со SPN удобна для офлайн-подбора, если пароль короткий. Переведите службу на gMSA. Билет отсюда не запрашивается.",
    en: "A service account with an SPN can be targeted offline if the password is short. Move the service to a gMSA. Do not request a ticket from this screen.",
  },
  unconstrained_delegation: {
    ru: "Неограниченное делегирование оставляет на узле билеты других пользователей. Оставьте его только контроллерам.",
    en: "Unconstrained delegation keeps other users' tickets on the host. Limit it to domain controllers.",
  },
  asrep_preauth: {
    ru: "Предварительная проверка подлинности выключена. Включите ее обратно.",
    en: "Pre-authentication is off, so a request can be tested offline. Turn pre-authentication back on.",
  },
  adcs_enrollee_san: {
    ru: "Шаблон позволяет заявителю задать имя субъекта. Включите согласование или снимите флаг.",
    en: "The template lets the requester supply the subject name. Require approval or remove that flag.",
  },
}

export function Paths() {
  const { t, lang, inventory, filters, theme, openFinding } = useApp()
  const rows = inventory.filter((row) => isPath(row) && matchesQuery(row, filters.q))
  return (
    <div>
      <PageHead title={t("path.title")} sub={t("path.sub")} />
      <div className="grid gap-3">
        {rows.length ? rows.map((row) => (
          <Card key={row.id} className="cursor-pointer" onClick={() => void openFinding(row.vuln_id)}>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle>{row.title}</CardTitle>
              <Severity row={row} theme={theme} />
            </CardHeader>
            <CardContent className="text-sm">
              <p className="text-muted-foreground">{row.hostname} · {row.category}</p>
              <p className="mt-2">{row.detail}</p>
              <p className="text-muted-foreground mt-2">{NOTES[row.vuln_id]?.[lang] || ""}</p>
            </CardContent>
          </Card>
        )) : <Card><CardContent className="text-muted-foreground">{t("path.empty")}</CardContent></Card>}
      </div>
    </div>
  )
}
