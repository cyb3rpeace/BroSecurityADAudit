# Threat Hunting final delivery record

**Дата фиксации:** 2026-11-01
**Состояние:** production rollout завершён; модуль готов к ограниченной эксплуатации в заявленном объёме.

## Что завершено

- Tenant-scoped профили и зашифрованный импорт архивов с проверкой целостности SHA-256.
- Асинхронная обработка через отдельный pipeline worker с polling из консоли.
- Детерминированный анализ без обязательного AI: host, процессы, сеть, Windows services/tasks/startup, Linux services/timers, cron и SUID/SGID inventory.
- Evidence-first результаты: исходные строки, source/row citations, статус источника, missing/empty/truncated признаки, граф host → process/command → endpoint и timeline.
- Локализованные RU/EN отчёты Markdown и PDF с Unicode-шрифтом DejaVu.
- AI-отчёт с bounded context и обязательными ссылками `[evidence:source#row_number]`; неподтверждённые ссылки отклоняются, AI остаётся advisory.
- Acceptance-only внешние labels импортируются без опасной привязки к production campaign и помечаются предупреждением.
- Профили и каталоги не объявляют пустой или отсутствующий источник доказательством отсутствия компрометации.

## Проверка результата

- Полный набор проекта: **285 passed, 10 skipped**.
- Проверены login, создание hunting profile, импорт, analysis, worker polling и локализованные report endpoints.
- Production после cutover: HTTPS readiness `200`, SPA assets `200`, защищённые маршруты без авторизации возвращают `401`.
- До переключения сохранена полная резервная копия persistent volumes; SQLite WAL и существующие tenant/user данные проверены после rollout.
- Production data, tenant keys, reports и non-Threat-Hunting функциональность сохранены.

## Граница готовности

В executable packages включаются только проверенные bounded sources. Следующие источники остаются `candidate` и намеренно не упаковываются:

- Windows Security, PowerShell, Defender и RDP EVTX;
- WMI permanent subscriptions;
- Registry Run/RunOnce;
- Windows local accounts/groups и прочие источники, для которых нет signed-off real Windows acceptance.

Synthetic query/analyzer tests не являются Windows endpoint acceptance. Для перевода источника из `candidate` в `packaged` требуется отдельная проверка на поддерживаемых версиях Windows, positive/negative fixtures, privilege/error/empty/truncated states, archive import и regression tests. Полный disk image, memory acquisition, NTFS artefacts, journald/auditd и Linux account/SSH/PAM evidence в этот milestone не входят.

## Безопасная эксплуатация

1. Перед каждым обновлением сохранить `.env`, volumes `data`, `reports`, `certs` и tenant decryption keys.
2. Не использовать `docker compose down -v` при обновлении.
3. Сначала выполнить однохостовой pilot и проверить source status, missing/empty/truncated данные и точные citations.
4. Сохранять исходный encrypted archive, SHA-256, profile ID, host identity, collector logs и UTC collection window.
5. Рассматривать выводы как bounded triage, а не как автоматическое подтверждение компрометации.

Подробная матрица источников находится в [THREAT_HUNTING_COVERAGE.md](THREAT_HUNTING_COVERAGE.md), техническая модель и ограничения — в [THREAT_HUNTING.md](THREAT_HUNTING.md). Этот документ фиксирует итог milestone и не заменяет change approval или forensic chain-of-custody процедуру организации.
