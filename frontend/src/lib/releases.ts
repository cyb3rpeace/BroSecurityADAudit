export const RELEASES = [
  {
    version: "2.6.16",
    ru: [
      "Граф и загрузка архива убраны. Пути атак остаются из проверок LDAP: делегирование, SPN, шаблоны сертификатов и опасные права.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "The graph and archive upload are gone. Attack paths stay on the LDAP checks: delegation, SPN, certificate templates, and dangerous rights.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.15",
    ru: [
      "Виджет сканирования на других вкладках показывает зелёную бегущую полосу. Ошибка запуска остаётся красной плашкой.",
      "Каждая тема почты уходит отдельным письмом. Сбой доставки виден в интерфейсе.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "The scan widget on other tabs shows a moving green bar. A failed run stays as a red banner.",
      "Each mail topic is its own letter. A delivery failure stays visible in the console.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.14",
    ru: [
      "Топология показывает сайты, подсети и контроллеры. Имя домена больше не выглядит как три разных домена.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "Topology shows sites, subnets, and controllers. The domain name no longer looks like three domains.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.13",
    ru: [
      "На обзоре критичность открывает инциденты с этим фильтром. Области каталога открывают учётные записи, устройства и пути атак.",
      "Память и процессор контроллера читаются отдельным коротким запросом и не ждут журнал, DNS и политики.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "Overview severity opens incidents with that filter. Catalog areas open accounts, devices, and attack paths.",
      "Controller memory and CPU arrive in a short request and no longer wait for the log, DNS, and policies.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.12",
    ru: [
      "Каталог рисует дерево подразделений и домены леса. DNS отмечает устаревшие цели служебных записей контроллеров.",
      "Известные параметры политик подписаны понятным именем. На первом контроллере выполняются пять тестов dcdiag, журнал целиком не сохраняется.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "The catalog draws the OU tree and the forest domains. DNS flags locator targets that no longer match a controller.",
      "Known policy settings use a readable name. Five dcdiag tests run on the first controller, and the full log is not stored.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.11",
    ru: [
      "Письмо на почту собрано карточкой в цветах консоли: знак, полоса, счётчики критичности и таблица находок.",
      "В каталоге у контроллера видны тома, адаптеры и BIOS. Учётные записи открывают списки из текущих инцидентов. DNS показывает пересылки без имён записей.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "The mail report uses the console card: mark, color bar, severity counts, and a findings table.",
      "Controller cards show volumes, adapters, and BIOS. Account lists come from open incidents. DNS shows forwarders without record names.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.10",
    ru: [
      "В справочнике у каждой проверки есть простое объяснение, техническое и ссылка на источник Microsoft или MITRE.",
      "Каталог на обзоре показывает, какие разделы отчётов оценки каталога уже внутри, а какие ещё частичные.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "Every reference article now has a plain explanation, a technical one, and a Microsoft or MITRE source.",
      "The catalog overview shows which assessment sections are present and which are still partial.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.9",
    ru: [
      "У контроллеров в каталоге видны процессор, память и диск. Зоны DNS показывают DNSSEC, обновления и передачу.",
      "Расхождения политик считаются и по шаблону безопасности, и по Registry.pol. Значения, похожие на пароль, скрыты.",
      "Для Telegram можно указать прокси адрес:порт. Токен берётся у BotFather, идентификатор канала виден в getUpdates.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "Controller cards show CPU, memory, and disk. DNS zones show DNSSEC, updates, and transfer.",
      "Policy differences include the security template and part of Registry.pol. Password-like values stay hidden.",
      "Telegram can use a host:port proxy. The token comes from BotFather, and the channel id comes from getUpdates.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.8",
    ru: [
      "Харденинг смотрит аудит изменений каталога и опасные права на корне домена, AdminSDHolder и подразделении контроллеров.",
      "Протоколы отмечают выключенное шифрование SMB и клиент без обязательной подписи.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "Hardening checks directory-change auditing and dangerous rights on the domain root, AdminSDHolder, and the domain controllers OU.",
      "Protocol checks flag SMB encryption that is off and an SMB client that does not require signing.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.7",
    ru: [
      "В шапке у имени стоит знак профиля. Настройки открыты сразу, в две колонки. Сборщик, Chat ID компании и дополнительные узлы убраны.",
      "Ловушки разобраны по шагам: что создаётся, кто запускает скрипт и какие события смотреть. Пароль на экран не выводится.",
      "Каталог начинается с обзора тех же областей, что в отчётах оценки каталога.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "The header name has a profile mark. Settings stay open in two columns. The collector script, company chat id, and extra hosts are gone.",
      "Honeytokens explain what is created, who runs the script, and which events to watch. The password is not shown.",
      "The catalog opens with the same areas as a directory assessment report.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.6",
    ru: [
      "У групп в каталоге видно дерево участников. У зон DNS — полоса состава по типам записей. Имена отдельных записей не копируются.",
      "На входе и в меню стоит киберкот. Справочник остаётся одним списком проверок.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "Group rows show members. DNS zones show a type composition bar. Individual record names are not copied.",
      "The cyber cat is the mark on the login page and in the menu.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.5",
    ru: [
      "Правило ToDesk больше не срабатывает на AutoDesk. В карточке сохраняется настоящее имя программы.",
      "Справочник — один список проверок. Шестерёнка в колокольчике больше не накрывает крестик. У контроллера в таблице видны процессор, память, диск и счётчики за сутки.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "The ToDesk rule no longer matches AutoDesk. The finding keeps the real program name.",
      "The reference is one list of checks. The bell gear no longer covers the close button. Controller rows show CPU, memory, disk, and daily counters.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.4",
    ru: [
      "Имя в шапке открывает профиль и безопасность. Счётчик уязвимостей из шапки убран, шестерёнка доставки осталась внутри колокольчика.",
      "В профиле — ФИО, имя входа, почта, телефон, язык и проекты. В безопасности — смена пароля, код приложения для Яндекс Ключа или Google Authenticator и завершение других сеансов.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "The header name opens profile and security. The vulnerability counter left the header, and delivery settings stay inside the bell.",
      "Profile stores name, username, mail, phone, language, and projects. Security changes the password, adds an authenticator code, and ends other sessions.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.3",
    ru: [
      "Каталог рисует схему: сайты, контроллеры и линии репликации, с фильтрами «только сбой» и «только FSMO».",
      "Доверия показаны графом: красный узел, если фильтрация SID выключена. Расхождения политик собраны в матрицу параметр на политику.",
      "Учётные записи разделены на политику, точечные политики, LAPS и krbtgt по уже найденным инцидентам. У контроллеров и DNS сверху полоса показателей.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "The directory draws sites, domain controllers, and replication lines, with failure and FSMO filters.",
      "Trusts are a graph: a red node means SID filtering is off. Policy conflicts are a parameter-by-policy matrix.",
      "Accounts split into password policy, fine-grained policies, LAPS, and krbtgt from existing findings. Controllers and DNS show a KPI strip.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.2",
    ru: [
      "В каталоге появилась матрица репликации: источник, партнёр, раздел и давность. Текст ошибки репликации не сохраняется.",
      "Зоны DNS показывают тип, область, динамические обновления, передачу и очистку. Служебные SRV проверяются ответом да или нет. Список записей зоны не выгружается.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "The directory shows a replication matrix with age and state. Error text is not stored.",
      "DNS zones show type, scope, updates, transfer, and scavenging. Zone records are not exported.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.1",
    ru: [
      "Схема каталога больше не уезжает в пустой экран: масштаб ограничен, есть кнопки плюс, минус и сброс, а выбранный объект открывается рядом, не поверх всего окна.",
      "Разделы каталога стали панелями: политика паролей, группы, зоны, доверия, расхождения политик и таблица контроллеров.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "The directory map stays on screen while dragging. The selected object opens beside the map.",
      "Directory sections are panels for passwords, groups, zones, trusts, policy differences, and controllers.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.6.0",
    ru: [
      "У колокольчика появилась шестерёнка доставки. Почту и Telegram можно включить отдельно: итог сканирования, сбой, опасное ПО, шаблон сертификатов, пароль в политике, доверие без фильтрации SID и остальные критичные находки.",
      "В справочнике открывается база знаний: что означает проверка, чем она кончается, что передать администраторам и ссылка на источник. Текст письма копируется.",
      "Каталог фильтруется поиском. Счётчики сайтов, контроллеров, доверий и расхождений политик открывают нужную вкладку. Строка открывает карточку.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "The bell has a delivery gear. Mail and Telegram are switched per event.",
      "The reference includes a knowledge base and a letter for administrators.",
      "The directory page filters by search and opens a row card.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.5.2",
    ru: [
      "Карточка объекта показывает описание, заметку и комментарий из каталога. Для компьютера по WinRM читается последний интерактивный вход, без текста сессии.",
      "На контроллерах по WinRM видны модель, память, диск и счётчики неудачных входов и блокировок за сутки. Текст журнала не сохраняется.",
      "Параметры безопасности групповых политик сравниваются между собой. Значения, похожие на пароль, скрываются.",
      "Схема сайтов двигается и масштабируется.",
      "Список опасного удалённого доступа и потребительских VPN расширен.",
      "Области аудита перенесены в справочник. На обзоре появились столбцы областей и полоса состояния контроллера.",
      "В карточке инцидента на вкладке эксплуатации есть пример и шаги последствия. Команд нет.",
      "Гигиена дополнительно читает пустые и глубоко вложенные группы, пустые подразделения и имя зоны DNS с символом подстановки.",
      "На контроллере отмечается запущенная служба WebClient. Подпись LDAP, SMB и привязка канала уже проверялись раньше.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "PingCastle is no longer part of the product.",
      "Audit areas moved into the reference. The overview shows area bars and controller status.",
      "Finding cards describe the outcome in steps, without commands.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.4.0",
    ru: [
      "Сканирование показывает ленту модулей, общую полосу и журнал строк. Если уйти с вкладки, ход остаётся в виджете внизу экрана.",
      "Тема выбирается одной кнопкой-палитрой.",
      "Ассистент открывается из меню и из шапки. Круглая кнопка убрана.",
      "Карточка находки показывает ассет, компанию, критичность и атрибуты объекта из каталога.",
      "Шаблоны AD CS читаются по LDAP, без ADSI по WinRM.",
      "Добавлены покрытие LAPS, возраст пароля компьютера, слабая PSO и роли FSMO на одном контроллере. Появятся после следующего сканирования гигиены.",
      "Во вкладке эксплуатации названы инструменты из разборов атак. Команд и порядка действий нет.",
      "Настрой LDAP/LDAPS и приступай к сканированию!",
    ],
    en: [
      "A scan shows the module tape, one progress bar, and a short journal.",
      "The theme is chosen from a single palette button.",
      "The assistant opens from the menu and from the header.",
      "A finding card shows the asset, the company, the severity, and directory attributes.",
      "AD CS templates are read over LDAP.",
      "Set LDAP or LDAPS and start the scan.",
    ],
  },
  {
    version: "2.3.0",
    ru: [
      "Расписание задается днями недели и временем.",
      "Гигиена каталога читает квоту компьютеров, делегирование, политику паролей, историю SID и соседние признаки. Билеты и хеши не запрашиваются.",
      "Справочник показывает уровень риска по нашим проверкам.",
      "Названия выпусков Windows больше не теряют русские буквы.",
    ],
    en: [
      "The schedule is a weekday and a time.",
      "Directory hygiene reads quota, delegation, password policy, and SID history. Tickets and hashes are not requested.",
      "The reference shows a risk level for our own checks.",
      "Windows captions keep their Cyrillic letters.",
    ],
  },
  {
    version: "2.2.0",
    ru: [
      "Консоль на React. Три темы и два языка интерфейса.",
      "История сканирований пишет, кто запустил проверку.",
      "Колокольчик и журнал настроек. Пароли в журнал не пишутся.",
      "Сравнение «появилось / исчезло» берётся из двух сканирований платформы.",
    ],
    en: [
      "The console is React, with three themes and two interface languages.",
      "Scan history records who started the check.",
      "A bell and a settings audit log. Passwords are not written there.",
      "Appeared and disappeared lists compare two platform scans.",
    ],
  },
] as const
