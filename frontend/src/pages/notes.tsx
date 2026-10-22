import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageHead } from "@/components/bits"
import { RELEASES } from "@/lib/releases"
import { useApp } from "@/app-state"

export function Notes() {
  const { lang } = useApp()
  return (
    <div>
      <PageHead title="Примечания к обновлению" sub="Все изменения, которые уже вышли в консоли." />
      <div className="grid gap-3">
        {RELEASES.map((release) => (
          <Card key={release.version}>
            <CardHeader><CardTitle>Версия {release.version}</CardTitle></CardHeader>
            <CardContent>
              <ul className="list-disc space-y-1 pl-4 text-sm">
                {(lang === "en" ? release.en : release.ru).map((line) => <li key={line}>{line}</li>)}
              </ul>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
