import { RELEASES } from "@/lib/releases"
import { PageHead } from "@/components/bits"

export function ReleaseNotes({ embedded = false }: { embedded?: boolean }) {
  const body = (
    <div className="grid gap-4">
      {RELEASES.map((row) => (
        <section key={row.version} className="rounded-xl border p-4">
          <h2 className="text-base font-semibold">{row.version}</h2>
          <ul className="mt-2 list-disc space-y-1 pl-4 text-sm">
            {row.ru.map((item) => <li key={item}>{item}</li>)}
          </ul>
        </section>
      ))}
    </div>
  )
  if (embedded) return body
  return (
    <div>
      <PageHead title="Примечания к обновлению" sub="Все изменения версий консоли. Отчеты и проверки по-прежнему на русском." />
      {body}
    </div>
  )
}
