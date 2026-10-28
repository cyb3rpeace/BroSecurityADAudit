import type { WikiItem } from "@/lib/types"

export type SourceLink = { title: string; href: string }

const LDAP: SourceLink = {
  title: "Microsoft Learn: требование подписи LDAP",
  href: "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements",
}
const KERBEROS: SourceLink = {
  title: "Microsoft Learn: типы шифрования Kerberos",
  href: "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos",
}
const LAPS: SourceLink = {
  title: "Microsoft Learn: Windows LAPS",
  href: "https://learn.microsoft.com/windows-server/identity/laps/laps-overview",
}
const DNS: SourceLink = {
  title: "Microsoft Learn: DNS и DNSSEC",
  href: "https://learn.microsoft.com/windows-server/networking/dns/dnssec",
}
const TRUST: SourceLink = {
  title: "Microsoft Learn: карантин SID на доверии",
  href: "https://learn.microsoft.com/powershell/module/activedirectory/set-adtrust",
}
const GPO: SourceLink = {
  title: "Microsoft Learn: групповая политика",
  href: "https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview",
}
const SMB: SourceLink = {
  title: "Microsoft Learn: подпись и шифрование SMB",
  href: "https://learn.microsoft.com/windows-server/storage/file-server/smb-security",
}
const ADCS: SourceLink = {
  title: "Microsoft Learn: службы сертификатов",
  href: "https://learn.microsoft.com/windows-server/identity/ad-cs/active-directory-certificate-services-overview",
}
const TIME: SourceLink = {
  title: "Microsoft Learn: служба времени Windows",
  href: "https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings",
}
const AUDIT: SourceLink = {
  title: "Microsoft Learn: рекомендации по аудиту AD DS",
  href: "https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
}
const DELEG: SourceLink = {
  title: "MITRE T1558: кража или подделка билетов Kerberos",
  href: "https://attack.mitre.org/techniques/T1558/",
}
const ACL: SourceLink = {
  title: "Microsoft Learn: права на объекты каталога",
  href: "https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups",
}
const MITRE_REMOTE: SourceLink = {
  title: "MITRE T1219: удалённый доступ",
  href: "https://attack.mitre.org/techniques/T1219/",
}

const BY_ID: Record<string, { tech: string; links: SourceLink[] }> = {
  functional_level: {
    tech: "Читается msDS-Behavior-Version на ncName домена (rootDSE defaultNamingContext). Значение 0–7 соответствует режимам от Windows 2000 до Windows Server 2016. Это не версия ОС контроллера: её смотрите в operatingSystem на объекте компьютера контроллера.",
    links: [LDAP],
  },
  display_menu: {
    tech: "Атрибут adminContextMenu у displaySpecifier пользователя. В карточку попадает только факт, что пункт добавлен. Строка команды не копируется.",
    links: [ACL],
  },
  anonymous_ldap: {
    tech: "Отдельная привязка LDAP с пустым именем. Если сервер её принимает, пишется одно отклонение. Поиск объектов этой сессией не выполняется.",
    links: [LDAP],
  },
  dangerous_ou_right: {
    tech: "У подразделений читается список доступа. Отклонение ставится, если Everyone, Authenticated Users, Domain Users или Domain Computers имеют полный доступ, запись, смену владельца или смену списка прав. Остальные записи списка не копируются.",
    links: [ACL],
  },
  adcs_weak_key: {
    tech: "msPKI-Minimal-Key-Size шаблона. Порог 2048. Открытый ключ выпущенных сертификатов не копируется, запрос в центр сертификации не отправляется.",
    links: [ADCS],
  },
  dns_zone: {
    tech: "Свойства зоны Windows DNS: динамические обновления, передача, DNSSEC, очистка и состав по типам записей. Имена здоровых записей не сохраняются.",
    links: [DNS],
  },
  replication_stale: {
    tech: "Get-ADReplicationPartnerMetadata: партнёр, раздел и давность успеха. Текст ошибки репликации не сохраняется.",
    links: [LDAP],
  },
  gpo_conflict: {
    tech: "Сравниваются GptTmpl.inf и часть Registry.pol. Значение, похожее на пароль, заменяется пометкой «скрыто».",
    links: [GPO],
  },
  machine_quota: {
    tech: "Атрибут ms-DS-MachineAccountQuota на объекте домена. По умолчанию 10: любой Authenticated Users может создать computer object, если у него нет явного запрета. Квота 0 оставляет создание компьютеров группам, которым делегирован Create Child.",
    links: [ACL],
  },
  unconstrained_delegation: {
    tech: "userAccountControl содержит TRUSTED_FOR_DELEGATION (0x80000). На контроллере флаг штатный и из проверки исключается. На рядовом сервере KDC кладёт TGT пользователя в AP-REQ, и процесс на сервере может его переиспользовать.",
    links: [DELEG],
  },
  constrained_delegation: {
    tech: "msDS-AllowedToDelegateTo — список SPN для S4U2Proxy. Флаг TRUSTED_TO_AUTH_FOR_DELEGATION включает переход протокола (S4U2Self без исходного Kerberos). RBCD смотрится отдельно по msDS-AllowedToActOnBehalfOfOtherIdentity.",
    links: [DELEG],
  },
  rbcd: {
    tech: "Атрибут msDS-AllowedToActOnBehalfOfOtherIdentity — SDDL, кто может получать билет от имени этой учётной записи. Содержимое дескриптора в карточку не копируется.",
    links: [DELEG],
  },
  asrep_preauth: {
    tech: "DONT_REQ_PREAUTH (0x400000) в userAccountControl. KDC выдаёт AS-REP без предварительной проверки, и материал ответа можно проверять офлайн. Платформа билет не запрашивает.",
    links: [KERBEROS, DELEG],
  },
  kerberoasting: {
    tech: "servicePrincipalName на user (не computer) при включённой записи. TGS шифруется ключом этой учётки. Платформа SPN и билет не сохраняет: фиксируется сам факт атрибута.",
    links: [DELEG],
  },
  des_enabled: {
    tech: "USE_DES_KEY_ONLY (0x200000). Согласование уходит в DES-CBC. Рекомендуемый набор — AES128-CTS и AES256-CTS в msDS-SupportedEncryptionTypes, биты 0x08 и 0x10.",
    links: [KERBEROS],
  },
  rc4_only: {
    tech: "msDS-SupportedEncryptionTypes: бит RC4-HMAC (0x04) есть, битов AES нет. Отсутствие атрибута у старых записей тоже часто означает RC4. Ключ не выгружается.",
    links: [KERBEROS],
  },
  reversible_encryption: {
    tech: "ENCRYPTED_TEXT_PWD_ALLOWED (0x80). Пароль хранится так, что контроллер может вернуть обратимое представление для старых протоколов. Значение не читается.",
    links: [KERBEROS],
  },
  trust_sid_filter: {
    tech: "На объекте trustedDomain смотрится TRUST_ATTRIBUTE_QUARANTINE (фильтрация SID, 0x4). Без него SID из другого домена могут пройти в лес. Исправление: Set-ADTrust -Quarantine $true. Подделывать SID не требуется.",
    links: [TRUST],
  },
  laps_gap: {
    tech: "Признак схемы Windows LAPS — наличие ms-LAPS-Password или ms-LAPS-EncryptedPassword. Значение пароля не читается. Покрытие компьютеров — отдельная проверка после политики, не чтение секрета.",
    links: [LAPS],
  },
  gpp_password: {
    tech: "В SYSVOL ищется атрибут cpassword в XML предпочтений. Содержимое атрибута скрывается. Расшифровка и смена пароля остаются администратору.",
    links: [GPO],
  },
  ldap_signing: {
    tech: "LDAPServerIntegrity = 2 (Require signing) и на клиенте LDAPClientIntegrity не ниже Negotiate. Без подписи LDAP можно вставить в сессию. Канал 389 при этом остаётся допустимым внутри доверенной сети, если подпись включена.",
    links: [LDAP],
  },
  smb_signing: {
    tech: "RequireSecuritySignature на сервере SMB (LanmanServer) и клиенте (LanmanWorkstation). Для контроллеров подпись обязательна. Шифрование SMB — отдельный параметр EncryptData и не заменяет подпись.",
    links: [SMB],
  },
  dangerous_acl: {
    tech: "На корне домена, CN=AdminSDHolder и OU=Domain Controllers ищутся ACE для Everyone, Anonymous, Authenticated Users и расширенное право DS-Replication-Get-Changes-All (GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2) вне SYSTEM, Domain Admins, Enterprise Admins, Administrators и Domain Controllers. Список ограничен.",
    links: [ACL, { title: "MITRE T1003.006: DCSync", href: "https://attack.mitre.org/techniques/T1003/006/" }],
  },
  audit_ds_changes_off: {
    tech: "auditpol по подкатегории Directory Service Changes, GUID {0cce923c-69ae-11d9-bed3-505054503030}. В строке должна быть Success. Без неё события 5136 не пишутся.",
    links: [AUDIT],
  },
  krbtgt_old: {
    tech: "pwdLastSet у CN=krbtgt. Две штатные смены с паузой не меньше максимального срока жизни билета (обычно 10 часов), чтобы оба ключа в цепочке обновились. Пароль никуда не записывается.",
    links: [KERBEROS],
  },
}

const BY_FAMILY: { test: RegExp; tech: string; links: SourceLink[] }[] = [
  { test: /kerberos|spn|krbtgt|des|rc4/i, tech: "Проверка смотрит флаги userAccountControl и msDS-SupportedEncryptionTypes. Билеты не запрашиваются, ключи не выгружаются. Закрытие — вернуть предварительную проверку, снять DES, включить AES или перевести службу на gMSA.", links: [KERBEROS, DELEG] },
  { test: /делег/i, tech: "Делегирование Kerberos: TrustedForDelegation, msDS-AllowedToDelegateTo и msDS-AllowedToActOnBehalfOfOtherIdentity. На контроллере неограниченное делегирование штатно. На остальных узлах его быть не должно.", links: [DELEG] },
  { test: /dns|зон/i, tech: "Снимаются свойства зоны: тип, динамические обновления, передача, aging и IsSigned. Имена записей не копируются. Состав зоны — счётчики типов, не выгрузка Get-DnsServerResourceRecord -Name *.", links: [DNS] },
  { test: /gpo|политик|cpassword|registry/i, tech: "Сравниваются GptTmpl.inf и ограниченный разбор Registry.pol (подпись PReg). Значения с признаком пароля заменяются на [скрыто]. Это не полный разбор ADMX и не WMI-фильтры.", links: [GPO] },
  { test: /довер|sid/i, tech: "Объект trustedDomain: направление, тип и атрибут фильтрации SID. Включение карантина не рвёт доверие, оно перестаёт принимать чужие SID.", links: [TRUST] },
  { test: /laps/i, tech: "Смотрится наличие атрибутов Windows LAPS в схеме и покрытие политикой. Пароль LAPS не читается и в отчёт не попадает.", links: [LAPS] },
  { test: /сертифик|ad cs|шаблон/i, tech: "Шаблоны читаются по LDAP: флаги CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, права Enroll и автовыпуск. Сертификат не выпускается, закрытый ключ не копируется.", links: [ADCS] },
  { test: /smb|подпис/i, tech: "Параметры LanmanServer и LanmanWorkstation: RequireSecuritySignature и EncryptData. Клиент без обязательной подписи соглашается на сессию без подписи.", links: [SMB] },
  { test: /ldap|каталог|аноним/i, tech: "Канал — LDAP 389 или LDAPS 636. Подпись и привязка канала задаются отдельно от порта. Анонимная привязка и Pre-Windows 2000 Compatible Access расширяют чтение каталога.", links: [LDAP] },
  { test: /время|час/i, tech: "Сверяется w32tm на контроллерах. Допуск Kerberos по умолчанию 5 минут. Исправление — синхронизация с источником, а не увеличение MaxClockSkew.", links: [TIME] },
  { test: /аудит|журнал/i, tech: "Категории расширенного аудита читаются через auditpol. Для разбора изменений каталога нужна подкатегория Directory Service Changes с Success.", links: [AUDIT] },
  { test: /удаленн|rat|anydesk|teamviewer/i, tech: "Совпадение по имени в списке установленных программ, с границей слова, чтобы ToDesk не срабатывал на AutoDesk. Файл не запускается и не выгружается.", links: [MITRE_REMOTE] },
]

export function technicalOf(item: WikiItem): { tech: string; links: SourceLink[] } {
  const known = item.id ? BY_ID[item.id] : undefined
  if (known) return known
  const blob = `${item.id} ${item.title} ${item.family} ${item.what || ""} ${item.text || ""}`
  const hit = BY_FAMILY.find((row) => row.test.test(blob))
  if (hit) return hit
  return {
    tech: "Проверка читает атрибут каталога, параметр политики или флаг службы и сохраняет признак, а не секрет. Пароли, билеты, хеши, содержимое зон DNS и значения cpassword в карточку не попадают.",
    links: [ACL, AUDIT],
  }
}
