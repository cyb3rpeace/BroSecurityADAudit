import { useEffect, useState } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { api } from "@/lib/api"
import type { Finding, Remedy } from "@/lib/types"
import { useApp } from "@/app-state"

type AssetRow = { label: string; value: string; tone: string }
type Asset = { found: boolean; kind: string; kind_label: string; name: string; rows: AssetRow[] }

const SEV: Record<string, string> = {
  critical: "Критическая",
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая",
  info: "Информация",
}

const STORY: Record<string, string[]> = {
  unconstrained_delegation: [
    "Условие: на сервере, который не является контроллером, включено неограниченное делегирование.",
    "Пример: пользователь или контроллер обращается к этому серверу, и билет остаётся на нём. В разборах это связывают с именами Rubeus, PetitPotam и PrinterBug.",
    "Итог: обладатель сервера получает чужой билет, вплоть до билета контроллера. Дальше в тех же разборах говорят о DCSync.",
    "Защита: снять флаг со всех узлов, кроме контроллеров. Платформа билет не забирает.",
  ],
  constrained_delegation: [
    "Условие: учётной записи разрешено делегирование только к перечисленным службам.",
    "Пример: список шире одной нужной службы. В разборах такое делегирование связывают с именем Rubeus.",
    "Итог: чужой билет доходит до лишней службы.",
    "Защита: оставить в списке только одну службу. Платформа атрибут только читает.",
  ],
  rbcd: [
    "Условие: на объекте записано, кому можно делегировать доступ к нему.",
    "Пример: в списке оказывается лишняя учётная запись. В разборах это связывают с именем Rubeus.",
    "Итог: эта запись сокращает путь к службе. Значение атрибута в карточку не копируется.",
    "Защита: очистить список и оставить только согласованную учётную запись.",
  ],
  kerberoasting: [
    "Условие: у обычной учётной записи есть имя службы, SPN.",
    "Пример: служба с паролем, который не меняли. В разборах приём называют Kerberoasting и связывают с Rubeus.",
    "Итог: стойкость служебного билета равна стойкости пароля, и пароль можно подбирать вне домена.",
    "Защита: перевести службу на gMSA. Платформа билет не запрашивает.",
  ],
  asrep_preauth: [
    "Условие: для учётки выключена предварительная проверка подлинности Kerberos.",
    "Пример: приём называют AS-REP roasting.",
    "Итог: ответ контроллера можно получить, не зная пароль, и проверять пароль отдельно от домена.",
    "Защита: включить предварительную проверку. Платформа такой запрос не отправляет.",
  ],
  adcs_enrollee_san: [
    "Условие: шаблон разрешает заявителю самому указать имя в сертификате и выпускает сертификат для входа.",
    "Пример: в разборах это связывают с Certipy. Шаблон вроде Router из живого каталога как раз про это имя.",
    "Итог: сертификат может представлять чужое имя, включая административное.",
    "Защита: запретить имя от заявителя или включить ручное согласование. Платформа сертификат не выпускает.",
  ],
  gpp_password: [
    "Условие: в предпочтении групповой политики найден атрибут cpassword.",
    "Пример: старые предпочтения GPP хранили пароль локального администратора в общем SYSVOL.",
    "Итог: любой, кто читает политику, видит место секрета. Само значение платформа не читает и не расшифровывает.",
    "Защита: удалить узел и заменить секрет на LAPS или gMSA.",
  ],
  krbtgt_old: [
    "Условие: пароль учётной записи krbtgt давно не меняли.",
    "Пример: в разборах долгоживущий билет домена называют Golden Ticket.",
    "Итог: ранее выпущенные билеты дольше остаются действительными.",
    "Защита: дважды сменить пароль krbtgt штатной процедурой с паузой. Пароль платформа не читает.",
  ],
  ldap_signing_not_required: [
    "Условие: контроллер принимает LDAP без подписи.",
    "Пример: в разборах подмену сессии между клиентом и каталогом связывают с именами ntlmrelayx и Responder.",
    "Итог: ответ каталога или чужую сессию можно подставить в сети.",
    "Защита: LDAPServerIntegrity = 2. Платформа сессию не пересылает.",
  ],
  ldap_channel_binding: [
    "Условие: для LDAPS не требуется привязка канала.",
    "Пример: сессию, принятую на одном узле, проще предъявить контроллеру. В разборах это рядом с подменой NTLM.",
    "Итог: шифрование канала само по себе не доказывает, что клиент говорил именно с этим контроллером.",
    "Защита: LdapEnforceChannelBinding = 2 после проверки приложений.",
  ],
  smb_signing_off: [
    "Условие: подпись SMB не обязательна.",
    "Пример: в разборах подмену файловой сессии связывают с ntlmrelayx.",
    "Итог: клиент может принять ответы не от того сервера.",
    "Защита: включить обязательную подпись SMB. Платформа сессию не пересылает.",
  ],
  ntlmv1_allowed: [
    "Условие: разрешён устаревший ответ NTLM.",
    "Пример: в разборах сбор таких ответов связывают с Responder.",
    "Итог: ответ слабее, чем NTLMv2, и его проще использовать повторно.",
    "Защита: LmCompatibilityLevel = 5. Платформа ответы не собирает.",
  ],
  llmnr_enabled: [
    "Условие: узел отвечает на имена, которых нет в DNS, по LLMNR.",
    "Пример: в локальном сегменте это связывают с Responder.",
    "Итог: клиент уходит на чужой узел и отдаёт попытку входа.",
    "Защита: выключить LLMNR политикой. Платформа имя не подменяет.",
  ],
  print_spooler_on_dc: [
    "Условие: на контроллере работает служба печати.",
    "Пример: в разборах вызов контроллера к другому узлу связывают с именами PrinterBug и SpoolSample.",
    "Итог: контроллер сам инициирует обращение туда, куда его позвали.",
    "Защита: отключить Spooler на контроллерах. Платформа службу только отмечает.",
  ],
  webclient_running: [
    "Условие: на контроллере запущена служба WebClient.",
    "Пример: в разборах доступ контроллера к WebDAV рассматривают как условие для подмены сессии.",
    "Итог: контроллер может сходить на узел, который ему подсказали как общий ресурс.",
    "Защита: остановить и отключить службу. Платформа такой ресурс не создаёт.",
  ],
  laps_gap: [
    "Условие: у компьютера нет срока пароля LAPS.",
    "Пример: один и тот же пароль локального администратора живёт на многих узлах.",
    "Итог: вход на один компьютер открывает такой же вход на остальные. Сам пароль платформа не читает.",
    "Защита: включить Windows LAPS и проверить, что срок появляется в каталоге.",
  ],
  null_session: [
    "Условие: анонимный сеанс не ограничен.",
    "Пример: без пароля можно перечислить имена учёток и общие папки.",
    "Итог: разведка домена проходит до любого входа.",
    "Защита: RestrictAnonymous не ниже 1.",
  ],
  trust_sid_filter: [
    "Условие: на доверии выключена фильтрация SID.",
    "Пример: из соседнего домена приходит идентификатор привилегированной группы этого домена.",
    "Итог: чужой домен может предъявить права, которых у него быть не должно.",
    "Защита: включить фильтрацию SID и, где нужно, выборочную проверку подлинности.",
  ],
  des_enabled: [
    "Условие: для Kerberos разрешён DES.",
    "Пример: билет выпускается слабым шифром.",
    "Итог: стойкость билета ниже, чем у AES.",
    "Защита: снять DES. Платформа билет не запрашивает.",
  ],
  rc4_only: [
    "Условие: для учётки остаётся только RC4.",
    "Пример: служебный билет слабее, чем при AES. В разборах это рядом с Kerberoasting.",
    "Итог: подбор пароля по билету проще.",
    "Защита: включить AES. Платформа билет не запрашивает.",
  ],
}

function toneClass(tone: string) {
  if (tone === "bad") return "text-red-600 dark:text-red-400"
  if (tone === "warn") return "text-amber-700 dark:text-amber-300"
  return ""
}

export function FindingCard({ finding, remedy }: { finding: Finding; remedy: Remedy | null }) {
  const { company, companyId } = useApp()
  const [asset, setAsset] = useState<Asset | null>(null)
  const known = STORY[finding.vuln_id]
  const impact = remedy?.impact || finding.impact || finding.detail
  const steps = known || [
    "Условие: " + finding.title + ". " + finding.detail,
    "Пример: в разборах это отклонение используют как готовую слабость каталога. Отдельное имя инструмента для этой карточки не задано.",
    "Итог: " + impact,
    "Защита: шаги на вкладке «Рекомендации». Платформа сама настройку не меняет.",
  ]

  useEffect(() => {
    if (!companyId || !finding.hostname) return
    let alive = true
    void api<Asset>("/api/asset?company_id=" + companyId + "&name=" + encodeURIComponent(finding.hostname))
      .then((data) => { if (alive) setAsset(data) })
      .catch(() => { if (alive) setAsset({ found: false, kind: "", kind_label: "", name: finding.hostname, rows: [] }) })
    return () => { alive = false }
  }, [companyId, finding.hostname])

  return (
    <div className="grid gap-3">
      <div className="grid gap-1 rounded-lg border p-3 text-sm">
        <div><span className="text-muted-foreground">Ассет: </span>{finding.hostname || "не указан"}{asset?.kind_label ? " (" + asset.kind_label + ")" : ""}</div>
        <div><span className="text-muted-foreground">Проект: </span>{company?.name || "компания не выбрана"}{company ? " · #" + company.id : ""}</div>
        <div><span className="text-muted-foreground">Критичность: </span><span className={finding.severity === "critical" || finding.severity === "high" ? "font-semibold text-red-600 dark:text-red-400" : ""}>{SEV[finding.severity] || finding.severity_label || finding.severity}</span></div>
      </div>
      <div className="rounded-lg border p-3">
        <div className="mb-2 text-xs font-medium tracking-wide uppercase">Параметры ассета</div>
        {asset?.rows?.length ? (
          <ul className="grid gap-1 text-sm">
            {asset.rows.map((row) => (
              <li key={row.label} className={toneClass(row.tone)}>{row.label}: {row.value}</li>
            ))}
          </ul>
        ) : <p className="text-muted-foreground text-sm">{asset ? "Атрибуты объекта в каталоге не найдены. Ниже остаётся текст самой находки." : "Читаем атрибуты каталога..."}</p>}
      </div>
      <Tabs defaultValue="about">
        <TabsList className="flex h-auto w-full flex-wrap">
          <TabsTrigger value="about">Описание</TabsTrigger>
          <TabsTrigger value="exploit">Способы эксплуатации</TabsTrigger>
          <TabsTrigger value="fix">Рекомендации</TabsTrigger>
          <TabsTrigger value="history">История</TabsTrigger>
        </TabsList>
        <TabsContent value="about" className="grid gap-2 text-sm">
          <p>{finding.detail}</p>
          <p>{remedy?.summary}</p>
          <p className="text-muted-foreground">{[remedy?.cis, remedy?.gost, remedy?.mitre, remedy?.tactic].filter(Boolean).join(" · ")}</p>
        </TabsContent>
        <TabsContent value="exploit" className="grid gap-2 text-sm">
          <ol className="list-decimal space-y-2 pl-4">
            {steps.map((step) => <li key={step}>{step}</li>)}
          </ol>
          <p className="text-muted-foreground">Команд и параметров нет. Шаги описывают, чем это заканчивается для домена. Карточка для защиты, не для проведения атаки.</p>
        </TabsContent>
        <TabsContent value="fix" className="grid gap-2 text-sm">
          <p>{remedy?.closure}</p>
          <ol className="list-decimal space-y-1 pl-4">
            {(remedy?.steps || []).map((step) => <li key={step}>{step}</li>)}
          </ol>
          {remedy?.powershell ? (
            <>
              <pre className="bg-muted overflow-auto rounded-lg p-3 text-xs whitespace-pre-wrap">{remedy.powershell}</pre>
              <Button variant="outline" onClick={() => void navigator.clipboard.writeText(remedy.powershell)}>Копировать сценарий исправления</Button>
            </>
          ) : <p className="text-muted-foreground">Текст исправления ещё загружается.</p>}
        </TabsContent>
        <TabsContent value="history" className="text-sm">
          <p>Обнаружено: {finding.detected_at || "время не записано"}.</p>
          <p className="text-muted-foreground mt-2">Процент изменений между срезами появится, когда эта же находка встретится в следующем сканировании. Сейчас хранится текущий каталог, без выдуманной динамики.</p>
        </TabsContent>
      </Tabs>
    </div>
  )
}
