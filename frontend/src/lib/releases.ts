export const RELEASES = [
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
