import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

export function Pager({
  page,
  pages,
  size,
  total,
  onPage,
  onSize,
}: {
  page: number
  pages: number
  size: number
  total: number
  onPage: (page: number) => void
  onSize: (size: number) => void
}) {
  return (
    <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
      <span className="text-muted-foreground">Всего {total} · страница {page} из {pages}</span>
      <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>Назад</Button>
      <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>Дальше</Button>
      <Select value={String(size)} onValueChange={(value) => onSize(Number(value))}>
        <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
        <SelectContent>
          {[10, 20, 50, 100].map((count) => <SelectItem key={count} value={String(count)}>{count} строк</SelectItem>)}
        </SelectContent>
      </Select>
    </div>
  )
}
