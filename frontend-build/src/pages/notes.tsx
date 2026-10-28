import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { PageHead } from "@/components/bits"
import { Pager } from "@/components/pager"
import { RELEASES } from "@/lib/releases"
import { useApp } from "@/app-state"
import { useEffect, useState } from "react"

export function Notes() {
  const { lang } = useApp()
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(10)
  const pages = Math.max(1, Math.ceil(RELEASES.length / size))
  const safePage = Math.min(page, pages)
  useEffect(() => { setPage(1) }, [size])
  const slice = RELEASES.slice((safePage - 1) * size, safePage * size)
  return (
    <div>
      <PageHead title="Примечания к обновлению" sub="Все изменения, которые уже вышли в консоли." />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground text-sm">Сколько версий показывать</span>
        <Select value={String(size)} onValueChange={(value) => setSize(Number(value))}>
          <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
          <SelectContent>
            {[10, 20, 50, 100].map((count) => <SelectItem key={count} value={String(count)}>{count} строк</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      <div className="grid gap-3">
        {slice.map((release) => (
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
      <Pager page={safePage} pages={pages} size={size} total={RELEASES.length} onPage={setPage} onSize={setSize} />
    </div>
  )
}
