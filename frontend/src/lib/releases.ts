export const RELEASES = [
  {
    version: "2.6.6",
    ru: [
      "У групп в каталоге видно дерево участников. У зон DNS — полоса состава по типам записей. Имена отдельных записей не копируются.",
      "На входе и в меню стоит киберкот. Справочник остаётся одним списком проверок.",
      "Настрой LDAP/LDAPS, установи BloodHound и приступай к сканированию!",
    ],
    en: [
      "Group rows show members. DNS zones show a type composition bar. Individual record names are not copied.",
      "The cyber cat is the mark on the login page and in the menu.",
      "Set LDAP or LDAPS, install BloodHound, and start the scan.",
    ],
  },
  {
    version: "2.6.5",
    ru: [
      "Правило ToDesk больше не срабатывает на AutoDesk. В карточке сохраняется настоящее имя программы.",
      "Справочник — один список проверок. Шестерёнка в колокольчике больше не накрывает крестик. У контроллера в таблице видны процессор, память, диск и счётчики за сутки.",
      "Настрой LDAP/LDAPS, установи BloodHound и приступай к сканированию!",
    ],
    en: [
      "The ToDesk rule no longer matches AutoDesk. The finding keeps the real program name.",
      "The reference is one list of checks. The bell gear no longer covers the close button. Controller rows show CPU, memory, disk, and daily counters.",
      "Set LDAP or LDAPS, install BloodHound, and start the scan.",
    ],
  },
  {
    version: "2.6.4",
    ru: [
      "Имя в шапке открывает профиль и безопасность. Счётчик уязвимостей из шапки убран, шестерёнка доставки осталась внутри колокольчика.",
      "В профиле — ФИО, имя входа, почта, телефон, язык и проекты. В безопасности — смена пароля, код приложения для Яндекс Ключа или Google Authenticator и завершение других сеансов.",
      "Настрой LDAP/LDAPS, установи BloodHound и приступай к сканированию!",
    ],
    en: [
      "The header name opens profile and security. The vulnerability counter left the header, and delivery settings stay inside the bell.",
      "Profile stores name, username, mail, phone, language, and projects. Security changes the password, adds an authenticator code, and ends other sessions.",
      "Set LDAP or LDAPS, install BloodHound, and start the scan.",
    ],
  },
  {
    version: "2.6.3",
    ru: [
      "Каталог рисует схему: сайты, контроллеры и линии репликации, с фильтрами «только сбой» и «только FSMO».",
      "Доверия показаны графом: красный узел, если фильтрация SID выключена. Расхождения политик собраны в матрицу параметр на политику.",
      "Учётные записи разделены на политику, точечные политики, LAPS и krbtgt по уже найденным инцидентам. У контроллеров и DNS сверху полоса показателей.",
      "Настрой LDAP/LDAPS, установи BloodHound и приступай к сканированию!",
    ],
    en: [
      "The directory draws sites, domain controllers, and replication lines, with failure and FSMO filters.",
      "Trusts are a graph: a red node means SID filtering is off. Policy conflicts are a parameter-by-policy matrix.",
      "Accounts split into password policy, fine-grained policies, LAPS, and krbtgt from existing findings. Controllers and DNS show a KPI strip.",
      "Set LDAP or LDAPS, install BloodHound, and start the scan.",
    ],
  },
  {
    version: "2.6.2",
    ru: [
      "В каталоге появилась матрица репликации: источник, партнёр, раздел и давность. Текст ошибки репликации не сохраняется.",
      "Зоны DNS показывают тип, область, динамические обновления, передачу и очистку. Служебные SRV проверяются ответом да или нет. Список записей зоны не выгружается.",
      "Настрой LDAP/LDAPS, установи BloodHound и приступай к сканированию!",
    ],
    en: [
      "The directory shows a replication matrix with age and state. Error text is not stored.",
      "DNS zones show type, scope, updates, transfer, and scavenging. Zone records are not exported.",
      "Set LDAP or LDAPS, install BloodHound, and start the scan.",
    ],
  },
  {
    version: "2.6.1",
    ru: [
      "Схема каталога больше не уезжает в пустой экран: масштаб ограничен, есть кнопки плюс, минус и сброс, а выбранный объект открывается рядом, не поверх всего окна.",
      "Разделы каталога стали панелями: политика паролей, группы, зоны, доверия, расхождения политик и таблица контроллеров.",
      "Настрой LDAP/LDAPS, установи BloodHound и приступай к сканированию!",
    ],
    en: [
      "The directory map stays on screen while dragging. The selected object opens beside the map.",
      "Directory sections are panels for passwords, groups, zones, trusts, policy differences, and controllers.",
      "Set LDAP or LDAPS, install BloodHound, and start the scan.",
    ],
  },
  {
    version: "2.6.0",
    ru: [
      "У колокольчика появилась шестерёнка доставки. Почту и Telegram можно включить отдельно: итог сканирования, сбой, опасное ПО, шаблон сертификатов, пароль в политике, доверие без фильтрации SID и остальные критичные находки.",
      "В справочнике открывается база знаний: что означает проверка, чем она кончается, что передать администраторам и ссылка на источник. Текст письма копируется.",
      "Каталог фильтруется поиском. Счётчики сайтов, контроллеров, доверий и расхождений политик открывают нужную вкладку. Строка открывает карточку.",
      "Настрой LDAP/LDAPS, установи BloodHound и приступай к сканированию!",
    ],
    en: [
      "The bell has a delivery gear. Mail and Telegram are switched per event.",
      "The reference includes a knowledge base and a letter for administrators.",
      "The directory page filters by search and opens a row card.",
      "Set LDAP or LDAPS, install BloodHound, and start the scan.",
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
      "Настрой LDAP/LDAPS, установи BloodHound и приступай к сканированию!",
    ],
    en: [
      "PingCastle is no longer part of the product.",
      "Audit areas moved into the reference. The overview shows area bars and controller status.",
      "Finding cards describe the outcome in steps, without commands.",
      "Set LDAP or LDAPS, install BloodHound, and start the scan.",
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
      "Настрой LDAP/LDAPS, установи BloodHound и приступай к сканированию!",
    ],
    en: [
      "A scan shows the module tape, one progress bar, and a short journal.",
      "The theme is chosen from a single palette button.",
      "The assistant opens from the menu and from the header.",
      "A finding card shows the asset, the company, the severity, and directory attributes.",
      "AD CS templates are read over LDAP.",
      "Set LDAP or LDAPS, install BloodHound, and start the scan.",
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
