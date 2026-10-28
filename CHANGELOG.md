## Deployment improvements — 2026-10-28

## Collector coverage update — 2026-10-28

- Added fixed-path Linux cron and systemd service/timer configuration collection (1000 rows, 64 KiB per file, truncation flag), plus SUID/SGID metadata for system bin/sbin directories. No shell commands, recursive disk scan or file uploads.
- Verified an actual encrypted Velociraptor archive through the application ingestion path. Additional Linux sources provide raw evidence, not full automatic detection coverage.
- Added tenant-scoped saved profile deletion with confirmation and audit logging. Collected evidence is retained.
- Corrected Windows startup catalog status to match existing builder support. Other Windows candidates remain gated pending execution checks.
- Validation: 217 regression tests, one skipped; TypeScript/Vite production build and lint of changed UI files passed.

- Added `install.sh` for one-command Linux x86-64 installation with Docker/Compose validation, random session secret, readiness waits and idempotent configuration.
- Default Compose now starts API and Threat Hunting worker with persistent named volumes; removed production-specific container names, certificate paths and network names.
- Added first-run TLS creation, random administrator credentials, secure file permissions and worker startup ordering.
- Updated README with actual prerequisites, first login, updates, backup requirements, troubleshooting and Threat Hunting limitations.
- Included the signal-first graph fix: routine process inventory no longer crowds out behavioral evidence; command, host, startup and private/public endpoint context is retained with evidence citations.
- Clean installation and repeat installation verified in an isolated Compose project, without production data.

## 2.6.24 — 2026-10-28

### Threat Hunting

- Default triage view now prioritizes high-fidelity suspicious behavior instead of routine baseline noise.
- AI triage correlates the complete finding inventory and requires exact evidence citations while separating facts, hypotheses, alternatives, and gaps.
- Added bounded deterministic cross-host correlation with bilateral evidence for SHA-256 and qualified domain identities.
- Excluded local and built-in principals from cross-host links to prevent false campaign relationships.
- Preserved full-context access for routine paths, services, and public endpoints without treating them as compromise or C2 proof.
- Added fail-closed collector contracts, tenant isolation coverage, bounded processing tests, and Windows persistence compilation coverage.
- Production deployment verified on `10.191.122.183`; core and worker use the same analysis code.

### Validation

- 198 automated tests passed; one Velociraptor-engine test remains skipped when the external engine is unavailable.
- Production health endpoint returned `ready`; unauthenticated Threat Hunting API access returned `401`.

# Журнал изменений

Версии отмечены тегами. В репозитории нет результатов сканирования, базы, сертификатов и секретов.

## 2.6.16

- Граф и загрузка архива убраны из консоли, меню, справочника и состава Docker. Пути атак остаются из проверок LDAP.

## 2.6.15

- Виджет хода сканирования вне вкладки «Сканирование» показывает зелёную бегущую полосу и процент. Ошибка запуска и сбой LDAP остаются красной плашкой.
- Почтовые темы уходят отдельными письмами. Пароль из групповой политики в письмо не попадает. Если SMTP не доставил сообщение, это видно в колокольчике.

## 2.6.14

- Топология собрана как в отчёте: домен, внутри него сайты, у сайта подсети и контроллеры со статусом репликации. Подсеть без сайта отмечена отдельно. Список доменов леса больше не заменяет карту.

## 2.6.13

- На обзоре доли критичности открывают инциденты уже с этим фильтром. Полосы «Учетные записи», «Устройства» и «Пути» открывают одноимённые вкладки. «Пути» — это пути атак, не сетевой маршрут.
- Железо контроллера читается отдельно от журнала, DNS и политик. Закрытый WinRM больше не ждёт таймаут сценария.
- В описании один тёмный ролик: вход, обзор, каталог. Три ролика со сменой темы убраны.

## 2.6.12

- Каталог показывает дерево подразделений и домены леса на карте. DNS сравнивает служебные записи контроллеров со списком живых контроллеров и оставляет только устаревшие цели.
- У расхождений политик появляется понятное имя, если параметр известен. Это не полный каталог ADMX. На первом контроллере проходят пять тестов dcdiag: реклама, репликация, входы, службы и FSMO. Полный журнал не сохраняется.
- Снимки обзора и каталога в описании — анимация смены тёмной, светлой и розовой темы. Они стоят сразу под входом.

## 2.6.11

- Письмо SMTP оформлено как карточка консоли: знак, цветная полоса, счётчики критичности и таблица находок. Пароли и cpassword в письмо не попадают.
- Каталог читает тома, сетевые адаптеры и версию BIOS контроллера, списки учёток из уже открытых инцидентов и пересылки DNS. Имена записей зон не копируются.

## 2.6.10

- Справочник разбирает каждую проверку простым языком и технически: атрибут, флаг или параметр политики, и даёт ссылку на Microsoft Learn или MITRE.
- На обзоре каталога виден статус разделов оценки каталога. Списки учётных записей, dcdiag, условные пересылки DNS и полный разбор ADMX в эту версию не входят.

## 2.6.9

- Каталог показывает карточки контроллеров: процессор, занятую память и диск. Сбор железа больше не ждёт длинный журнал.
- DNS-зоны показывают DNSSEC, динамические обновления, передачу и очистку. Сравнение политик читает и шаблон безопасности, и часть Registry.pol. Секреты скрываются, имена DNS-записей не копируются.
- В Telegram добавлен HTTP-прокси адрес:порт и подсказка, как получить токен у BotFather и идентификатор канала.

## 2.6.8

- Из описания убраны снимки входа и справочника. Для Docker и WinRM добавлены команды ручной установки.
- Харденинг отмечает выключенный аудит изменений каталога и опасные права на корне домена, AdminSDHolder и подразделении контроллеров. Протоколы отмечают выключенное шифрование SMB и подпись клиента SMB.
- Сверка с AD-Audit: инвентарь пользователей, групп, доверий, политик, DNS, сертификатов и делегирования уже был. Облачные модули Exchange, SharePoint, Teams и Power Platform в эту сборку не входят.

## 2.6.7

- В шапке слева от имени стоит знак профиля. Параметры настроек открыты сразу и разложены в две колонки.
- Из карточки компании убран Chat ID Telegram, из подключения к каталогу — список дополнительных узлов. Скрипт сборщика убран.
- Ловушки объяснены по шагам: что создаётся, кто запускает и какие события смотреть.
- Каталог открывается обзором тех же областей, что в отчётах оценки каталога.

## 2.6.6

- В каталоге у группы видны первые участники. Состав зоны DNS показан полосой по типам записей, имена записей не копируются.
- Знак проекта заменён на киберкота. На странице входа он стоит по центру над названием.

## 2.6.5

- Правило ToDesk больше не совпадает с AutoDesk. В новой карточке сохраняется исходное имя программы.
- Справочник собран в один список проверок с письмом администраторам.
- Шестерёнка доставки стоит внутри колокольчика и не перекрывает закрытие.
- Таблица контроллеров показывает процессор, память, диск и счётчики за сутки.

## 2.6.4

- Имя в шапке открывает профиль и безопасность: персональные поля, проекты, смена пароля, код приложения и завершение других сеансов.
- Счётчик уязвимостей убран из шапки.

## 2.6.3

- Каталог рисует схему сайтов и линий репликации, граф доверий и матрицу расхождений политик.

## 2.6.2

- Матрица репликации и свойства зон DNS. Список записей зоны не выгружается.

## 2.6.1

- Схема каталога не уезжает за край. Разделы каталога открываются панелями, выбранный объект остаётся сбоку.

## 2.6.0

- Уведомления выбираются по событию: итог сканирования, сбой, опасное ПО, шаблон сертификатов, пароль в политике, доверие без фильтрации SID, остальные критичные находки. Почта и Telegram переключаются отдельно.
- В справочнике первая волна базы знаний: разбор, шаги передачи в ИТ и ссылки на документацию Microsoft и MITRE. Текст письма копируется.
- Каталог ищет по имени и открывает строку. Счётчики сайтов, контроллеров, доверий без фильтрации SID и расхождений политик переключают вкладку.

## 2.5.2

- Карточка объекта показывает описание и комментарий. Для компьютера по WinRM читается последний интерактивный вход, без текста сессии.
- На контроллере видны модель, память, диск и счётчики неудачных входов и блокировок за сутки.
- Параметры безопасности групповых политик сравниваются между собой. Похожие на пароль значения скрываются.
- Схема сайтов двигается и масштабируется. Чёрный список удалённого доступа и потребительских VPN расширен.

## 2.5.0

- Загрузка стороннего XML-отчёта убрана из меню, сборщика и API. Сравнение сканирований считает находки платформы.

## 2.4.0

- Ход сканирования остаётся на экране лентой модулей, полосой и журналом.
- Тема выбирается одной палитрой. Ассистент открывается из меню и шапки.
- Шаблоны AD CS читаются по LDAP.

## После 2.3.0

- Шаблоны AD CS читаются по LDAP из раздела конфигурации. Проверка больше не ходит в ADSI по WinRM, из-за которого `FindAll` возвращал «An operations error occurred».

## 2.3.0

- Расписание сканирования задается днями недели и временем, а не только «каждый день / неделю / месяц».
- Каталог читается шире: уровень домена, квота машинных учетных записей, длина и история паролей, блокировка, корзина, tombstone, подсети, SYSVOL на NTFRS, единственный контроллер, ограниченное делегирование, RBCD, обратимое шифрование, пароль не требуется, SID history, key credential, RC4 без AES, группа Pre-Windows 2000, чужие участники в привилегированных группах, Exchange Windows Permissions, слово «пароль» в описании, компьютеры без входа дольше 90 дней.
- Справочник показывает уровень риска. Правила PingCastle появляются только по проблемам, которые уже есть в загруженном отчете.
- Подпись Windows 10 больше не превращается в строку из вопросительных знаков: консоль WinRM читается в UTF-8, а уже сохраненные строки исправляются при показе.

## 2.2.0

- Консоль переписана на React и компоненты shadcn. Три темы: темная, светлая и кибер. Язык интерфейса русский и английский.
- Разделы: обзор, инциденты, учетные записи, пути атак, устройства, отчеты, сканирование, справочник, настройки.
- Приветствие показывается заново при новой версии. Внизу меню виден ответ каталога выбранной компании.
- История сканирований пишет, кто запустил проверку. Колокольчик хранит уведомления. Журнал настроек не содержит паролей.
- PingCastle сравнивает только два своих отчета. Индекс на обзоре считается по текущим находкам платформы.
- Сборщик для офицера отправляет файлы на сервер. Пароль домена в команду не входит.
- Чистая установка не создает демонстрационные компании и не записывает в код пароль администратора.
