import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { PageHead } from "@/components/bits"
import { useApp } from "@/app-state"

export function Notices() {
  const { t, notices, markAllNotices, deleteNotice } = useApp()
  return (
    <div>
      <PageHead title={t("nav.notices")} sub="Сюда попадают завершенные сканирования, загрузки PingCastle и SharpHound и отчеты сборщика." />
      <div className="mb-3">
        <Button variant="outline" onClick={() => void markAllNotices()}>{t("bell.read")}</Button>
      </div>
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
