import { AlertTriangle, CheckCircle2, Layers3 } from "lucide-react"

export function HuntingCoverage() {
  return <details className="rounded-lg border bg-card p-4">
    <summary className="flex cursor-pointer items-center gap-2 font-medium"><Layers3 className="size-4 text-primary" />Что собирается сейчас: покрытие и ограничения</summary>
    <div className="mt-4 space-y-4 text-sm">
      <p className="text-muted-foreground">Сравнение с предоставленным easy_triage.sh v20260120. Это описание текущего покрытия, а не обещание полной эквивалентности KAPE или Linux DFIR.</p>
      <div className="grid gap-4 lg:grid-cols-2">
        <section className="space-y-2"><h3 className="flex items-center gap-2 font-semibold"><CheckCircle2 className="size-4 text-emerald-500" />Доступно в сборщике</h3><p><b>Linux:</b> сведения об ОС, процессы и соединения; дополнительно — содержимое cron и systemd service/timer из фиксированных путей, метаданные SUID/SGID в системных bin/sbin. До 1000 конфигурационных файлов по 64 КиБ; усечение отмечается. Эти дополнительные источники доступны как evidence, без заявления о полном автоматическом детекте.</p><p><b>Windows:</b> то же, плюс службы, задания планировщика и автозапуск.</p><p className="text-muted-foreground">Новые сборщики сохраняют командные строки и время создания процессов. Старые архивы нужно собрать повторно — отсутствующие поля восстановить нельзя.</p></section>
        <section className="space-y-2"><h3 className="flex items-center gap-2 font-semibold"><AlertTriangle className="size-4 text-amber-500" />Пробелы покрытия</h3><p><b>Linux:</b> ещё нет проверенного сбора auth/audit/journal, SSH/PAM, полного файлового timeline, capabilities, целостности пакетов, BPF и deleted-executable recovery. Cron/systemd ограничены указанными путями, SUID/SGID — системными bin/sbin; это не полный Linux DFIR.</p><p><b>Windows:</b> ещё не проверены сбор сырых EVTX и hive, Prefetch, Amcache, LNK/JumpLists, SRUM, MFT/USN. Targets и Modules предоставленного KAPE изучены; эквивалентность требует проверки фактически собранных артефактов и парсеров.</p></section>
      </div>
      <p className="rounded-lg bg-muted p-3"><b>Не считать доступным:</b> источники с отметкой «candidate» пока не допускаются к упаковке. Наличие пункта в каталоге не означает, что сбор или детект уже реализован. Bounded-источник доступен только при успешной проверке итогового архива.</p>
      <p><b>Что не стоит собирать массово по умолчанию:</b> память/swap, скриншоты, почту, crash/core и все журналы без лимитов. В easy_triage также есть активные действия: внешние запросы, mount, ввод в tty и необязательная установка strace. Для них нужны отдельное согласование и профиль глубокого расследования.</p>
      <p className="text-muted-foreground">В текущем Windows-профиле есть дубли нормализованных и встроенных Services/Tasks/Startup — пока сохранены для совместимости. Публичный IP или штатный интерпретатор сами по себе не подтверждают взлом. Отсутствие находок не означает отсутствие компрометации.</p>
    </div>
  </details>
}
