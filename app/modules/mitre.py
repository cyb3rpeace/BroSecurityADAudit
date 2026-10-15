"""Сопоставление находок с MITRE ATT&CK. Только номера и защитные действия, без шагов эксплуатации."""

from __future__ import annotations

_DEFAULT = {
    "id": "T1087.002",
    "tactic": "Discovery",
    "name": "Account Discovery: Domain Account",
    "impact": "Отклонение расширяет поверхность домена. Пока оно открыто, защитные контроли работают хуже, чем задумано.",
    "closure": "Устраните причину штатной настройкой домена и повторите проверку. Карточка не содержит шагов атаки.",
}

CATALOG: dict[str, dict[str, str]] = {
    "active_smbv1": {"id": "T1210", "tactic": "Lateral Movement", "name": "Exploitation of Remote Services", "impact": "SMBv1 — устаревший протокол общего доступа. На нем держатся старые ошибки удаленного выполнения, и современная подпись SMB его не спасает.", "closure": "Выключите серверный и клиентский SMBv1 политикой и перезагрузите узел в согласованное окно."},
    "smb_signing_off": {"id": "T1557", "tactic": "Collection", "name": "Adversary-in-the-Middle", "impact": "Без обязательной подписи SMB сессию к файловому серверу можно подменить в локальной сети.", "closure": "Включите RequireSecuritySignature для сервера и клиента SMB через групповую политику."},
    "llmnr_enabled": {"id": "T1557.001", "tactic": "Collection", "name": "LLMNR/NBT-NS Poisoning", "impact": "LLMNR отвечает на имена, которых нет в DNS. В локальном сегменте это приводит к перехвату попытки входа.", "closure": "Отключите LLMNR политикой DNS Client: EnableMulticast = 0."},
    "netbios_enabled": {"id": "T1557.001", "tactic": "Collection", "name": "LLMNR/NBT-NS Poisoning", "impact": "NetBIOS поверх TCP/IP дублирует слабый канал разрешения имен рядом с LLMNR.", "closure": "На адаптерах выставьте NetbiosOptions = 2 и закрепите это политикой."},
    "wpad_enabled": {"id": "T1557", "tactic": "Collection", "name": "Adversary-in-the-Middle", "impact": "Автопоиск прокси WPAD позволяет подсунуть узлу чужой прокси в локальной сети.", "closure": "Отключите автообнаружение WPAD и задайте прокси явно, если он нужен."},
    "wdigest_clear": {"id": "T1003.001", "tactic": "Credential Access", "name": "OS Credential Dumping: LSASS Memory", "impact": "WDigest оставляет пароль в памяти процесса входа в открытом виде.", "closure": "Установите UseLogonCredential = 0 и перезайдите в систему после применения политики."},
    "ntlmv1_allowed": {"id": "T1557", "tactic": "Collection", "name": "Adversary-in-the-Middle", "impact": "NTLMv1 и слабые уровни LmCompatibilityLevel принимают устаревший ответ, который в современной сети не нужен.", "closure": "Поднимите LmCompatibilityLevel до 5: только NTLMv2, отказ от LM и NTLMv1."},
    "ldap_signing_not_required": {"id": "T1557", "tactic": "Collection", "name": "Adversary-in-the-Middle", "impact": "Неподписанный LDAP позволяет подменить ответы контроллера в сети между клиентом и доменом.", "closure": "LDAPServerIntegrity = 2 на контроллерах, затем потребуйте подпись на клиентах."},
    "ldap_channel_binding": {"id": "T1557", "tactic": "Collection", "name": "Adversary-in-the-Middle", "impact": "Без привязки канала LDAPS проще переслать сессию на другой узел.", "closure": "Включите LdapEnforceChannelBinding в режиме 2 после проверки приложений."},
    "null_session": {"id": "T1135", "tactic": "Discovery", "name": "Network Share Discovery", "impact": "Анонимный сеанс позволяет перечислить общие ресурсы и учетные записи без пароля.", "closure": "RestrictAnonymous и RestrictAnonymousSAM поставьте в значение, запрещающее анонимный перебор."},
    "powershell_v2": {"id": "T1059.001", "tactic": "Execution", "name": "Command and Scripting Interpreter: PowerShell", "impact": "PowerShell 2.0 не пишет современные журналы сценариев и обходит часть контроля.", "closure": "Удалите компонент PowerShell 2.0 и оставьте только актуальную версию."},
    "tls10_enabled": {"id": "T1557", "tactic": "Collection", "name": "Adversary-in-the-Middle", "impact": "TLS 1.0 и 1.1 считаются устаревшими и слабее актуальных наборов шифров.", "closure": "Отключите TLS 1.0 и 1.1 на сервере и клиенте Schannel, оставьте TLS 1.2 и новее."},
    "rc4_only": {"id": "T1558", "tactic": "Credential Access", "name": "Steal or Forge Kerberos Tickets", "impact": "Учетная запись соглашается на RC4 и не предлагает AES. Это слабее, чем AES для Kerberos.", "closure": "Включите AES128 и AES256 на учетной записи и снимите опору только на RC4."},
    "des_enabled": {"id": "T1558", "tactic": "Credential Access", "name": "Steal or Forge Kerberos Tickets", "impact": "DES для Kerberos устарел и не должен оставаться разрешенным типом шифрования.", "closure": "Снимите флаги DES в msDS-SupportedEncryptionTypes и в политике Kerberos."},
    "print_spooler_on_dc": {"id": "T1210", "tactic": "Lateral Movement", "name": "Exploitation of Remote Services", "impact": "Служба печати на контроллере дает лишнюю точку входа туда, где лежат секреты домена.", "closure": "Остановите и отключите Spooler на контроллерах. Печать оставьте на отдельном сервере."},
    "kerberoasting": {"id": "T1558.003", "tactic": "Credential Access", "name": "Kerberoasting", "impact": "SPN на обычной учетной записи делает ее пароль целью офлайн-подбора. Платформа билет не запрашивает.", "closure": "Переведите службу на gMSA и уберите SPN со старой записи."},
    "asrep_preauth": {"id": "T1558.004", "tactic": "Credential Access", "name": "AS-REP Roasting", "impact": "Без предварительной проверки подлинности пароль учетной записи проще проверять офлайн.", "closure": "Включите предварительную проверку подлинности Kerberos."},
    "krbtgt_old": {"id": "T1558.001", "tactic": "Credential Access", "name": "Golden Ticket", "impact": "Старый пароль krbtgt дольше сохраняет силу ранее выпущенных билетов домена.", "closure": "Дважды смените пароль krbtgt штатной процедурой с паузой не меньше 10 часов."},
    "unconstrained_delegation": {"id": "T1558", "tactic": "Credential Access", "name": "Steal or Forge Kerberos Tickets", "impact": "Неограниченное делегирование оставляет на рядовом сервере билеты других пользователей.", "closure": "Снимите флаг со всех узлов, кроме контроллеров домена."},
    "gpp_password": {"id": "T1552.006", "tactic": "Credential Access", "name": "Group Policy Preferences", "impact": "Пароль в предпочтении GPO лежит в SYSVOL в обратимом виде. Платформа его не расшифровывает.", "closure": "Удалите узлы cpassword и замените секрет на LAPS или gMSA."},
    "adcs_enrollee_san": {"id": "T1649", "tactic": "Credential Access", "name": "Steal or Forge Authentication Certificates", "impact": "Шаблон, где заявитель сам задает имя субъекта, позволяет получить сертификат чужого имени.", "closure": "Запретите SAN от заявителя или включите обязательное согласование выпуска."},
    "trust_sid_filter": {"id": "T1134.005", "tactic": "Privilege Escalation", "name": "SID-History Injection", "impact": "Доверие без фильтрации SID принимает идентификаторы чужого домена, включая привилегированные.", "closure": "Включите фильтрацию SID и, где уместно, выборочную проверку подлинности."},
    "ordinary_privileged": {"id": "T1078.002", "tactic": "Privilege Escalation", "name": "Valid Accounts: Domain Accounts", "impact": "Обычная рабочая запись в привилегированной группе совмещает повседневный вход и права домена.", "closure": "Уберите запись из группы и заведите отдельную административную учетную запись."},
    "stale_password": {"id": "T1078.002", "tactic": "Defense Evasion", "name": "Valid Accounts: Domain Accounts", "impact": "Пароль старше 90 дней при живом входе дольше остается пригодным, если он когда-либо утечет.", "closure": "Смените пароль и включите срок действия для этой записи."},
    "inactive_stale": {"id": "T1078.002", "tactic": "Defense Evasion", "name": "Valid Accounts: Domain Accounts", "impact": "Молчащая запись со старым паролем — готовый вход, за которым никто не следит.", "closure": "Отключите запись после проверки, что на нее не завязана служба."},
    "guest_enabled": {"id": "T1078", "tactic": "Initial Access", "name": "Valid Accounts", "impact": "Включенная запись Guest открывает анонимный путь в домен.", "closure": "Отключите встроенную учетную запись Guest."},
    "obsolete_os": {"id": "T1210", "tactic": "Lateral Movement", "name": "Exploitation of Remote Services", "impact": "Система без обновлений безопасности остается в сети с уже известными ошибками.", "closure": "Выведите узел из домена или обновите его до поддерживаемой версии."},
    "time_skew": {"id": "T1558", "tactic": "Credential Access", "name": "Steal or Forge Kerberos Tickets", "impact": "Сдвиг часов больше пяти минут ломает выпуск билетов Kerberos и маскирует сбои аутентификации.", "closure": "Верните контроллер к источнику времени домена командой w32tm /resync. Порог Kerberos не ослабляйте."},
    "anydesk_detected": {"id": "T1219", "tactic": "Command and Control", "name": "Remote Access Software", "impact": "Несогласованный удаленный доступ обходит корпоративный канал администрирования.", "closure": "Остановите продукт, удалите его и запретите установку политикой."},
    "teamviewer_detected": {"id": "T1219", "tactic": "Command and Control", "name": "Remote Access Software", "impact": "Несогласованный удаленный доступ обходит корпоративный канал администрирования.", "closure": "Остановите продукт, удалите его и запретите установку политикой."},
    "rustdesk_detected": {"id": "T1219", "tactic": "Command and Control", "name": "Remote Access Software", "impact": "Несогласованный удаленный доступ обходит корпоративный канал администрирования.", "closure": "Остановите продукт, удалите его и запретите установку политикой."},
    "vnc_detected": {"id": "T1021.005", "tactic": "Lateral Movement", "name": "Remote Services: VNC", "impact": "VNC часто работает со слабым паролем и без журнала корпоративного доступа.", "closure": "Удалите VNC и оставьте только утвержденное средство удаленного доступа."},
    "vpn_unauthorized": {"id": "T1572", "tactic": "Command and Control", "name": "Protocol Tunneling", "impact": "Личный VPN уводит трафик мимо корпоративного контроля.", "closure": "Удалите клиент и запретите несогласованные туннели политикой."},
    "laps_missing": {"id": "T1078.003", "tactic": "Privilege Escalation", "name": "Valid Accounts: Local Accounts", "impact": "Без LAPS пароль локального администратора часто одинаковый на многих узлах.", "closure": "Расширьте схему Windows LAPS и включите политику смены пароля. Сам пароль платформа не читает."},
    "priv_password_never_expires": {"id": "T1078.002", "tactic": "Privilege Escalation", "name": "Valid Accounts: Domain Accounts", "impact": "Привилегированный пароль без срока живет дольше, чем допустимо для административного входа.", "closure": "Снимите флаг «пароль не истекает» и смените пароль."},
    "not_in_protected_users": {"id": "T1558", "tactic": "Credential Access", "name": "Steal or Forge Kerberos Tickets", "impact": "Интерактивный администратор вне Protected Users дольше сохраняет слабые способы входа.", "closure": "Добавьте в Protected Users только интерактивных администраторов, не сервисные записи."},
    "honeytoken": {"id": "T1078", "tactic": "Discovery", "name": "Valid Accounts", "impact": "Ловушка сама по себе не уязвимость: обращение к ней — сигнал, что кто-то обходит каталог.", "closure": "Настройте оповещение на вход и чтение этой записи. Прав ей не давайте."},
    "functional_level": {"id": "T1558", "tactic": "Credential Access", "name": "Steal or Forge Kerberos Tickets", "impact": "Старый режим работы домена не дает включить современную защиту Kerberos и корзину.", "closure": "Поднимите режим после того, как все контроллеры будут на поддерживаемой версии."},
    "machine_quota": {"id": "T1136.002", "tactic": "Persistence", "name": "Create Account: Domain Account", "impact": "Обычный пользователь может сам создать учетные записи компьютеров в домене.", "closure": "Поставьте квоту 0 и выдайте ввод компьютеров отдельной группе."},
    "password_length": {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force", "impact": "Короткий пароль быстрее перебирается, если он куда-то утечет.", "closure": "Поднимите минимальную длину политикой. Подбор платформа не запускает."},
    "password_history": {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force", "impact": "Короткая история позволяет сразу вернуть прежний пароль.", "closure": "Увеличьте историю паролей хотя бы до 10."},
    "no_lockout": {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force", "impact": "Без блокировки неверный пароль можно пробовать без остановки на стороне домена.", "closure": "Задайте порог и длительность блокировки."},
    "recycle_bin": {"id": "T1485", "tactic": "Impact", "name": "Data Destruction", "impact": "Без корзины случайно удаленный объект сложнее вернуть штатно.", "closure": "Включите корзину леса один раз."},
    "tombstone": {"id": "T1485", "tactic": "Impact", "name": "Data Destruction", "impact": "Слишком короткий срок хранения удаленных объектов оставляет мало времени на восстановление.", "closure": "Верните tombstoneLifetime к 180 дням."},
    "orphan_subnet": {"id": "T1087.002", "tactic": "Discovery", "name": "Account Discovery: Domain Account", "impact": "Клиенты без привязки к сайту ходят не на ближайший контроллер.", "closure": "Назначьте подсети сайты в оснастке сайтов и служб."},
    "ntfrs_sysvol": {"id": "T1552.006", "tactic": "Credential Access", "name": "Group Policy Preferences", "impact": "Старая репликация SYSVOL хуже восстанавливается и давно не развивается.", "closure": "Переведите SYSVOL на DFSR отдельным проектом."},
    "single_dc": {"id": "T1489", "tactic": "Impact", "name": "Service Stop", "impact": "Один контроллер — единая точка отказа для входа в домен.", "closure": "Добавьте второй контроллер и проверьте репликацию."},
    "constrained_delegation": {"id": "T1550", "tactic": "Lateral Movement", "name": "Use Alternate Authentication Material", "impact": "Ограниченное делегирование позволяет службе ходить в другие службы от имени пользователя.", "closure": "Оставьте только нужную службу и не включайте переход протокола без необходимости."},
    "rbcd": {"id": "T1550", "tactic": "Lateral Movement", "name": "Use Alternate Authentication Material", "impact": "Чужая запись, которой разрешено действовать от имени компьютера, получает его права.", "closure": "Уберите лишних из атрибута. Содержимое атрибута платформа не копирует."},
    "reversible_encryption": {"id": "T1552", "tactic": "Credential Access", "name": "Unsecured Credentials", "impact": "Обратимое шифрование хранит пароль так, что его можно восстановить на контроллере.", "closure": "Снимите флаг и смените пароль. Значение платформа не читает."},
    "password_not_required": {"id": "T1078.002", "tactic": "Privilege Escalation", "name": "Valid Accounts: Domain Accounts", "impact": "Запись без требования пароля может остаться с пустым секретом.", "closure": "Снимите флаг и задайте пароль. Пустой пароль платформа не проверяет."},
    "sid_history": {"id": "T1134.005", "tactic": "Privilege Escalation", "name": "SID-History Injection", "impact": "Чужой идентификатор в истории SID сохраняет старые права после миграции.", "closure": "Очистите атрибут после проверки, что доступ уже перенесен."},
    "shadow_credential": {"id": "T1649", "tactic": "Credential Access", "name": "Steal or Forge Authentication Certificates", "impact": "Дополнительный ключ позволяет войти без знания пароля.", "closure": "Оставьте только штатные ключи Windows Hello и устройств."},
    "pre_windows_2000": {"id": "T1087.002", "tactic": "Discovery", "name": "Account Discovery: Domain Account", "impact": "Широкая группа совместимости открывает чтение каталога тем, кому оно не нужно.", "closure": "Уберите Anonymous и Everyone из группы совместимости."},
    "foreign_privileged": {"id": "T1078.002", "tactic": "Privilege Escalation", "name": "Valid Accounts: Domain Accounts", "impact": "Учетная запись другого домена в локальной привилегированной группе получает права этого домена.", "closure": "Уберите чужой принципал, если это не согласованный администратор леса."},
    "exchange_permissions": {"id": "T1078.002", "tactic": "Privilege Escalation", "name": "Valid Accounts: Domain Accounts", "impact": "Лишние участники группы прав Exchange получают широкие права на каталог.", "closure": "Оставьте в группе только учетные записи серверов почты."},
    "password_in_description": {"id": "T1552", "tactic": "Credential Access", "name": "Unsecured Credentials", "impact": "Пароль в описании читает любой, у кого есть право смотреть карточку.", "closure": "Удалите секрет из описания. Текст описания платформа не копирует."},
    "stale_computer": {"id": "T1078.002", "tactic": "Defense Evasion", "name": "Valid Accounts: Domain Accounts", "impact": "Молчащая учетная запись компьютера остается доверенной дольше, чем сам компьютер существует.", "closure": "Отключите запись после сверки с инвентаризацией."},
}


def card(vuln_id: str) -> dict[str, str]:
    item = CATALOG.get(vuln_id or "")
    if item:
        return item
    if (vuln_id or "").startswith("pc:"):
        return {
            "id": "T1087.002",
            "tactic": "Discovery",
            "name": "Domain configuration weakness",
            "impact": "Правило PingCastle показывает слабость зрелости домена. Само по себе оно не описывает атаку.",
            "closure": "Закройте причину из текста правила и повторите PingCastle.",
        }
    return dict(_DEFAULT)


def tactics_of(rows: list) -> list[dict[str, object]]:
    counts: dict[str, int] = {}
    for row in rows:
        if getattr(row, "severity", "") == "info":
            continue
        tactic = card(getattr(row, "vuln_id", "")).get("tactic") or "Discovery"
        counts[tactic] = counts.get(tactic, 0) + 1
    return [{"tactic": name, "count": counts[name]} for name in sorted(counts, key=lambda key: (-counts[key], key))]
