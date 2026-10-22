"""Чтение каталога по LDAP или LDAPS. Пароли, билеты и хеши не запрашиваются."""

from __future__ import annotations

import os
import re
import ssl
from datetime import datetime, timedelta
from typing import Any

from ldap3 import BASE, LEVEL, NONE, NTLM, SIMPLE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

_DEDICATED = re.compile(r"(?i)(\.adm$|^adm_|_adm$|\.svc$|^svc_|_svc$)")
_PRIV_GROUPS = (
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Account Operators",
    "Backup Operators",
    "DnsAdmins",
)


def _filetime(value: Any) -> datetime | None:
    if value in (None, "", 0, "0"):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number <= 0 or number >= 0x7FFFFFFFFFFFFFFF:
        return None
    return datetime(1601, 1, 1) + timedelta(microseconds=number / 10)


def _first(entry: Any, name: str) -> Any:
    attr = entry[name]
    if attr is None:
        return None
    value = attr.value
    if isinstance(value, list):
        return value[0] if value else None
    return value


def connect(connection: dict[str, Any]) -> tuple[Connection, str]:
    host = connection["host"]
    user = connection["username"]
    password = connection["password"]
    use_ssl = bool(connection.get("ldap_ssl", True))
    port = int(connection.get("ldap_port") or (636 if use_ssl else 389))
    verify = (os.getenv("LDAP_TLS_VERIFY") or "false").lower() == "true"
    tls = Tls(validate=ssl.CERT_REQUIRED if verify else ssl.CERT_NONE)
    server = Server(host, port=port, use_ssl=use_ssl, get_info=NONE, tls=tls, connect_timeout=15)
    auth = NTLM if "\\" in user else SIMPLE
    conn = Connection(server, user=user, password=password, authentication=auth, auto_bind=True, receive_timeout=30)
    base = ""
    try:
        conn.search("", "(objectClass=*)", search_scope=BASE, attributes=["namingContexts"])
        if conn.entries:
            raw = conn.entries[0]["namingContexts"].value
            values = raw if isinstance(raw, list) else [raw]
            for item in values:
                text = str(item or "")
                if text.upper().startswith("DC="):
                    base = text
                    break
    except LDAPException:
        base = ""
    if not base:
        labels = [part for part in str(connection.get("domain") or "").split(".") if part]
        base = ",".join(f"DC={part}" for part in labels)
    if not base:
        raise RuntimeError("Контроллер не вернул корень каталога")
    return conn, base


def _search(conn: Connection, base: str, filt: str, attributes: list[str], limit: int = 200) -> list[Any]:
    conn.search(base, filt, search_scope=SUBTREE, attributes=attributes, size_limit=limit)
    description = (conn.result or {}).get("description")
    if description not in {"success", "sizeLimitExceeded"}:
        raise RuntimeError((conn.result or {}).get("message") or "Ошибка поиска LDAP")
    return list(conn.entries)


def scan_hygiene_ldap(connection: dict[str, Any]) -> dict[str, Any]:
    try:
        conn, base = connect(connection)
    except (LDAPException, OSError, RuntimeError) as exc:
        return {"ok": False, "findings": [], "score": None, "message": f"LDAPS/LDAP не открылся: {exc}"}
    findings: list[dict[str, Any]] = []
    try:
        computers = _search(
            conn,
            base,
            "(&(objectCategory=computer)(|(operatingSystem=*Windows 7*)(operatingSystem=*Windows 8*)(operatingSystem=*Windows 10*)(operatingSystem=*2003*)(operatingSystem=*2008*)(operatingSystem=*2012*)))",
            ["cn", "operatingSystem", "operatingSystemVersion"],
            40,
        )
        for entry in computers:
            os_name = str(_first(entry, "operatingSystem") or "")
            severity = "critical" if any(token in os_name for token in ("2003", "2008", "Windows 7", "Windows XP")) else "high"
            findings.append(
                {
                    "hostname": str(_first(entry, "cn") or ""),
                    "category": "Устаревшие ОС",
                    "title": "Устаревшая операционная система",
                    "severity": severity,
                    "detail": f"{os_name} {_first(entry, 'operatingSystemVersion') or ''}".strip(),
                    "tags": "baseline,hygiene,obsolete,module:baseline_hygiene",
                    "vuln_id": "obsolete_os",
                }
            )
        for group_name in _PRIV_GROUPS:
            groups = _search(conn, base, f"(&(objectClass=group)(sAMAccountName={group_name}))", ["distinguishedName"], 1)
            if not groups:
                continue
            group_dn = escape_filter_chars(str(_first(groups[0], "distinguishedName") or ""))
            members = _search(
                conn,
                base,
                f"(&(objectClass=user)(memberOf={group_dn}))",
                ["sAMAccountName"],
                30,
            )
            for member in members:
                sam = str(_first(member, "sAMAccountName") or "")
                if not sam or _DEDICATED.search(sam):
                    continue
                findings.append(
                    {
                        "hostname": sam,
                        "category": "Привилегии",
                        "title": "Обычная учетная запись в привилегированной группе",
                        "severity": "high",
                        "detail": group_name,
                        "tags": "baseline,hygiene,privileged,module:baseline_hygiene",
                        "vuln_id": "ordinary_privileged",
                    }
                )
        now = datetime.utcnow()
        users = _search(
            conn,
            base,
            "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "pwdLastSet", "lastLogonTimestamp"],
            400,
        )
        stale: list[tuple[int, dict[str, Any]]] = []
        for entry in users:
            changed = _filetime(_first(entry, "pwdLastSet"))
            if changed is None:
                continue
            age = (now - changed).days
            if age < 90:
                continue
            last = _filetime(_first(entry, "lastLogonTimestamp"))
            quiet = last is None or (now - last).days >= 90
            sam = str(_first(entry, "sAMAccountName") or "")
            if sam.lower() in {"krbtgt", "guest"}:
                continue
            stale.append(
                (
                    age,
                    {
                        "hostname": sam,
                        "category": "Неактивные учетные записи" if quiet else "Пароли",
                        "title": "Нет входа более 90 дней и пароль устарел" if quiet else "Пароль старше 90 дней при недавнем входе",
                        "severity": "high",
                        "detail": f"Пароль {age} дн., вход {last.date().isoformat() if last else 'нет'}",
                        "tags": "baseline,hygiene,password,module:baseline_hygiene",
                        "vuln_id": "inactive_stale" if quiet else "stale_password",
                    },
                )
            )
        for _age, item in sorted(stale, key=lambda pair: pair[0], reverse=True)[:25]:
            findings.append(item)
        try:
            findings.extend(scan_surface_ldap(conn, base))
        except (LDAPException, OSError, RuntimeError, ValueError):
            pass
        guests = _search(conn, base, "(&(objectClass=user)(sAMAccountName=Guest))", ["userAccountControl"], 1)
        if guests:
            uac = int(_first(guests[0], "userAccountControl") or 0)
            if uac & 2 == 0:
                findings.append(
                    {
                        "hostname": "Guest",
                        "category": "Гостевой доступ",
                        "title": "Включена учетная запись гостя",
                        "severity": "medium",
                        "detail": "Встроенная запись Guest включена.",
                        "tags": "baseline,hygiene,guest,module:baseline_hygiene",
                        "vuln_id": "guest_enabled",
                    }
                )
    finally:
        conn.unbind()
    return {
        "ok": True,
        "findings": findings,
        "score": None,
        "message": f"Каталог прочитан по {'LDAPS' if connection.get('ldap_ssl', True) else 'LDAP'}. Отклонений гигиены и покрытия: {len(findings)}.",
    }


_DISABLE = 0x2
_PASSWD_NOTREQD = 0x20
_REVERSIBLE = 0x80
_SERVER = 0x2000
_DELEGATION = 0x80000
_DES = 0x200000
_NO_PREAUTH = 0x400000
_PROTOCOL_TRANSITION = 0x1000000
_LEVELS = {0: "2000", 2: "2003", 3: "2008", 4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016", 10: "2025"}


def _uac(entry: Any) -> int:
    try:
        return int(_first(entry, "userAccountControl") or 0)
    except (TypeError, ValueError):
        return 0


def _keep(findings: list[dict[str, Any]], counts: dict[str, int], item: dict[str, Any], cap: int = 12) -> None:
    key = str(item.get("vuln_id") or "")
    counts[key] = counts.get(key, 0) + 1
    if counts[key] <= cap:
        findings.append(item)


def _config_base(conn: Connection) -> str:
    conn.search("", "(objectClass=*)", search_scope=BASE, attributes=["configurationNamingContext"])
    if not conn.entries:
        return ""
    return str(_first(conn.entries[0], "configurationNamingContext") or "")


def _safe_search(conn: Connection, base: str, filt: str, attributes: list[str], limit: int = 12) -> list[Any]:
    try:
        return _search(conn, base, filt, attributes, limit)
    except (LDAPException, OSError, RuntimeError, ValueError):
        return []


def scan_surface_ldap(conn: Connection, base: str) -> list[dict[str, Any]]:
    """Дополнительные проверки каталога. Только чтение атрибутов, без билетов и хешей."""
    findings: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    domain_rows = _safe_search(
        conn,
        base,
        "(objectClass=domain)",
        ["msDS-Behavior-Version", "ms-DS-MachineAccountQuota", "minPwdLength", "pwdHistoryLength", "lockoutThreshold", "msDS-EnabledFeature"],
        1,
    )
    if domain_rows:
        row = domain_rows[0]
        try:
            level = int(_first(row, "msDS-Behavior-Version") or 7)
        except (TypeError, ValueError):
            level = 7
        if level < 7:
            _keep(findings, counts, {
                "hostname": base,
                "category": "Режим домена",
                "title": f"Режим домена { _LEVELS.get(level, level) }",
                "severity": "high" if level < 6 else "medium",
                "detail": "Старый режим работы удерживает слабую криптографию. Поднимайте его после ухода старых контроллеров.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "functional_level",
            })
        try:
            quota = int(_first(row, "ms-DS-MachineAccountQuota") or 0)
        except (TypeError, ValueError):
            quota = 0
        if quota > 0:
            _keep(findings, counts, {
                "hostname": base,
                "category": "Регистрация компьютеров",
                "title": f"Пользователь может ввести в домен {quota} компьютеров",
                "severity": "high",
                "detail": "Квота ms-DS-MachineAccountQuota больше нуля. Поставьте 0 и выдайте ввод компьютеров отдельной группе поддержки.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "machine_quota",
            })
        try:
            length = int(_first(row, "minPwdLength") or 0)
        except (TypeError, ValueError):
            length = 0
        if 0 < length < 12:
            _keep(findings, counts, {
                "hostname": base,
                "category": "Политика паролей",
                "title": f"Минимальная длина пароля {length}",
                "severity": "critical" if length < 8 else "high",
                "detail": "Для людей лучше 14 символов и проверка по словарю. Сами пароли не читаются.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "password_length",
            })
        try:
            history = int(_first(row, "pwdHistoryLength") or 0)
        except (TypeError, ValueError):
            history = 0
        if history < 8:
            _keep(findings, counts, {
                "hostname": base,
                "category": "Политика паролей",
                "title": f"История паролей хранит {history}",
                "severity": "medium",
                "detail": "Поднимите историю хотя бы до 10, чтобы старый пароль нельзя было сразу вернуть.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "password_history",
            })
        try:
            lockout = int(_first(row, "lockoutThreshold") or 0)
        except (TypeError, ValueError):
            lockout = 0
        if lockout == 0:
            _keep(findings, counts, {
                "hostname": base,
                "category": "Политика паролей",
                "title": "Блокировка по неверному паролю выключена",
                "severity": "medium",
                "detail": "Задайте порог блокировки и окно наблюдения. Подбор в сеть платформа не запускает.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "no_lockout",
            })
        enabled = _first(row, "msDS-EnabledFeature")
        enabled_text = " ".join(str(part) for part in (enabled if isinstance(enabled, list) else [enabled]))
        if "Recycle Bin Feature" not in enabled_text:
            _keep(findings, counts, {
                "hostname": base,
                "category": "Каталог",
                "title": "Корзина Active Directory выключена",
                "severity": "low",
                "detail": "Включите Recycle Bin Feature один раз, когда режим леса это позволяет. Удаленный объект тогда можно вернуть штатно.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "recycle_bin",
            })
    try:
        config = _config_base(conn)
    except (LDAPException, OSError, RuntimeError, ValueError):
        config = ""
    if config:
        service = f"CN=Directory Service,CN=Windows NT,CN=Services,{config}"
        tomb = _safe_search(conn, service, "(objectClass=nTDSService)", ["tombstoneLifetime"], 1)
        if tomb:
            try:
                life = int(_first(tomb[0], "tombstoneLifetime") or 180)
            except (TypeError, ValueError):
                life = 180
            if life < 60:
                _keep(findings, counts, {
                    "hostname": base,
                    "category": "Каталог",
                    "title": f"Срок хранения удаленных объектов {life} дн.",
                    "severity": "medium",
                    "detail": "Короткий tombstoneLifetime мешает восстановить случайно удаленный объект. Обычно оставляют 180 дней.",
                    "tags": "baseline,surface,module:baseline_hygiene",
                    "vuln_id": "tombstone",
                })
        subnets = _safe_search(conn, f"CN=Subnets,CN=Sites,{config}", "(&(objectClass=subnet)(!(siteObject=*)))", ["cn"], 12)
        for entry in subnets:
            _keep(findings, counts, {
                "hostname": str(_first(entry, "cn") or ""),
                "category": "Сайты",
                "title": "Подсеть не привязана к сайту",
                "severity": "low",
                "detail": "Клиенты из этой сети могут ходить на случайный контроллер. Назначьте сайт в «Сайты и службы».",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "orphan_subnet",
            })
    dfsr = _safe_search(conn, f"CN=DFSR-GlobalSettings,CN=System,{base}", "(objectClass=msDFSR-GlobalSettings)", ["cn"], 1)
    frs = _safe_search(conn, f"CN=File Replication Service,CN=System,{base}", "(objectClass=nTFRSSettings)", ["cn"], 1)
    if frs and not dfsr:
        _keep(findings, counts, {
            "hostname": base,
            "category": "Репликация",
            "title": "SYSVOL еще на старой службе NTFRS",
            "severity": "high",
            "detail": "Запланируйте переход на DFSR отдельным проектом. Это не одна галка в момент сканирования.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "ntfrs_sysvol",
        })
    controllers = _safe_search(
        conn,
        base,
        f"(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:={_SERVER})(!(userAccountControl:1.2.840.113556.1.4.803:={_DISABLE})))",
        ["cn"],
        10,
    )
    if 0 < len(controllers) < 2:
        _keep(findings, counts, {
            "hostname": str(_first(controllers[0], "cn") or base),
            "category": "Контроллеры",
            "title": "В домене один контроллер",
            "severity": "high",
            "detail": "Отказ этого сервера останавливает вход. Добавьте второй контроллер.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "single_dc",
        })
    delegated = _safe_search(
        conn,
        base,
        f"(&(userAccountControl:1.2.840.113556.1.4.803:={_DELEGATION})(!(userAccountControl:1.2.840.113556.1.4.803:={_SERVER}))(!(userAccountControl:1.2.840.113556.1.4.803:={_DISABLE})))",
        ["sAMAccountName", "userAccountControl"],
        12,
    )
    for entry in delegated:
        _keep(findings, counts, {
            "hostname": str(_first(entry, "sAMAccountName") or ""),
            "category": "Делегирование",
            "title": "Неограниченное делегирование не на контроллере",
            "severity": "critical",
            "detail": "Снимите флаг TrustedForDelegation. Для контроллера домена такой флаг штатный и сюда не попадает.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "unconstrained_delegation",
        })
    constrained = _safe_search(
        conn,
        base,
        "(&(msDS-AllowedToDelegateTo=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "userAccountControl", "msDS-AllowedToDelegateTo"],
        12,
    )
    for entry in constrained:
        targets = _first(entry, "msDS-AllowedToDelegateTo")
        listed = targets if isinstance(targets, list) else [targets]
        names = ", ".join(str(part) for part in listed if part)[:180]
        transition = bool(_uac(entry) & _PROTOCOL_TRANSITION)
        _keep(findings, counts, {
            "hostname": str(_first(entry, "sAMAccountName") or ""),
            "category": "Делегирование",
            "title": "Ограниченное делегирование с переходом протокола" if transition else "Ограниченное делегирование",
            "severity": "critical" if transition else "high",
            "detail": f"Цели: {names or 'не прочитаны'}. Оставьте только одну нужную службу. Переход протокола включает только если без него служба не работает.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "constrained_delegation",
        })
    rbcd = _safe_search(
        conn,
        base,
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
        ["sAMAccountName"],
        12,
    )
    for entry in rbcd:
        _keep(findings, counts, {
            "hostname": str(_first(entry, "sAMAccountName") or ""),
            "category": "Делегирование",
            "title": "Кому-то разрешено действовать от имени этой записи",
            "severity": "high",
            "detail": "Проверьте список в msDS-AllowedToActOnBehalfOfOtherIdentity и уберите лишних. Содержимое бинарного списка в отчет не копируется.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "rbcd",
        })
    for flag, vuln_id, title, severity, detail in (
        (_NO_PREAUTH, "asrep_preauth", "Выключена предварительная проверка Kerberos", "high", "Верните предварительную проверку. Билет платформа не запрашивает."),
        (_REVERSIBLE, "reversible_encryption", "Включено обратимое шифрование пароля", "high", "Снимите флаг и смените пароль. Само значение пароля не читается."),
        (_PASSWD_NOTREQD, "password_not_required", "Для записи пароль не требуется", "high", "Снимите флаг и задайте пароль. Пустой пароль платформа не подбирает."),
        (_DES, "des_enabled", "Для записи разрешен DES", "high", "Оставьте AES. DES в отчет попадает как флаг, ключ не выгружается."),
    ):
        rows = _safe_search(
            conn,
            base,
            f"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={flag})(!(userAccountControl:1.2.840.113556.1.4.803:={_DISABLE})))",
            ["sAMAccountName"],
            12,
        )
        for entry in rows:
            sam = str(_first(entry, "sAMAccountName") or "")
            if sam.lower() in {"krbtgt", "guest"}:
                continue
            _keep(findings, counts, {
                "hostname": sam,
                "category": "Kerberos",
                "title": title,
                "severity": severity,
                "detail": detail,
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": vuln_id,
            })
    spn_rows = _safe_search(
        conn,
        base,
        f"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:={_DISABLE}))(!(sAMAccountName=krbtgt)))",
        ["sAMAccountName"],
        12,
    )
    for entry in spn_rows:
        _keep(findings, counts, {
            "hostname": str(_first(entry, "sAMAccountName") or ""),
            "category": "Kerberos",
            "title": "У пользовательской записи есть SPN",
            "severity": "high",
            "detail": "Переведите службу на gMSA. Имена служб в отчет не копируются, билет не запрашивается.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "kerberoasting",
        })
    history = _safe_search(conn, base, "(&(objectCategory=person)(sIDHistory=*))", ["sAMAccountName"], 12)
    for entry in history:
        _keep(findings, counts, {
            "hostname": str(_first(entry, "sAMAccountName") or ""),
            "category": "История SID",
            "title": "В истории SID остался чужой идентификатор",
            "severity": "high",
            "detail": "Очистите атрибут после проверки, что доступ уже перенесен. Новые значения туда не добавляйте.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "sid_history",
        })
    shadow = _safe_search(conn, base, "(msDS-KeyCredentialLink=*)", ["sAMAccountName"], 12)
    for entry in shadow:
        _keep(findings, counts, {
            "hostname": str(_first(entry, "sAMAccountName") or ""),
            "category": "Сертификаты",
            "title": "Есть альтернативный ключ входа",
            "severity": "medium",
            "detail": "Сверьте, что это Windows Hello или штатный ключ устройства. Постороннюю запись удалите. Сам ключ в отчет не копируется.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "shadow_credential",
        })
    rc4 = _safe_search(
        conn,
        base,
        "(&(objectCategory=person)(msDS-SupportedEncryptionTypes=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "msDS-SupportedEncryptionTypes"],
        40,
    )
    for entry in rc4:
        try:
            kinds = int(_first(entry, "msDS-SupportedEncryptionTypes") or 0)
        except (TypeError, ValueError):
            continue
        if kinds & 0x4 and not (kinds & 0x18):
            _keep(findings, counts, {
                "hostname": str(_first(entry, "sAMAccountName") or ""),
                "category": "Kerberos",
                "title": "Для записи разрешен только RC4",
                "severity": "high",
                "detail": "Включите AES128 и AES256, когда система это умеет. Ключ шифрования не выгружается.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "rc4_only",
            })
    prewin = _safe_search(conn, base, "(&(objectClass=group)(cn=Pre-Windows 2000 Compatible Access))", ["member"], 1)
    if prewin:
        members = _first(prewin[0], "member")
        listed = members if isinstance(members, list) else [members]
        weak = [str(part) for part in listed if part and any(token in str(part) for token in ("Anonymous", "Everyone", "Authenticated Users"))]
        if weak:
            _keep(findings, counts, {
                "hostname": "Pre-Windows 2000 Compatible Access",
                "category": "Анонимный доступ",
                "title": "Широкая группа совместимости со старыми клиентами",
                "severity": "critical" if any("Anonymous" in part or "Everyone" in part for part in weak) else "high",
                "detail": "Уберите Anonymous и Everyone. Authenticated Users оставляйте только если старое приложение без этого не читает каталог.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "pre_windows_2000",
            })
    for group_name in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Backup Operators"):
        groups = _safe_search(conn, base, f"(&(objectClass=group)(cn={group_name}))", ["distinguishedName"], 1)
        if not groups:
            continue
        group_dn = escape_filter_chars(str(_first(groups[0], "distinguishedName") or ""))
        foreign = _safe_search(conn, base, f"(&(objectClass=foreignSecurityPrincipal)(memberOf={group_dn}))", ["cn"], 8)
        for entry in foreign:
            _keep(findings, counts, {
                "hostname": str(_first(entry, "cn") or ""),
                "category": "Доверия",
                "title": f"Чужой принципал в группе {group_name}",
                "severity": "critical",
                "detail": "Уберите учетную запись другого домена из локальной привилегированной группы, если это не согласованный администратор леса.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "foreign_privileged",
            })
    exchange = _safe_search(conn, base, "(&(objectClass=group)(cn=Exchange Windows Permissions))", ["member"], 1)
    if exchange:
        members = _first(exchange[0], "member")
        listed = [str(part) for part in (members if isinstance(members, list) else [members]) if part]
        extra = [part for part in listed if "Exchange Trusted Subsystem" not in part]
        if extra:
            _keep(findings, counts, {
                "hostname": "Exchange Windows Permissions",
                "category": "Почта",
                "title": "В группе прав Exchange есть лишние участники",
                "severity": "high",
                "detail": f"Участников кроме подсистемы Exchange: {len(extra)}. Оставьте только то, что нужно серверам почты.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "exchange_permissions",
            })
    described = _safe_search(
        conn,
        base,
        "(&(objectCategory=person)(|(description=*password*)(description=*passwd*)(description=*пароль*)))",
        ["sAMAccountName"],
        12,
    )
    for entry in described:
        _keep(findings, counts, {
            "hostname": str(_first(entry, "sAMAccountName") or ""),
            "category": "Пароли",
            "title": "В описании записи похоже на пароль",
            "severity": "medium",
            "detail": "Откройте описание в карточке пользователя и уберите секрет. Текст описания в отчет не копируется.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "password_in_description",
        })
    cutoff = int((datetime.utcnow() - timedelta(days=90) - datetime(1601, 1, 1)).total_seconds() * 10_000_000)
    quiet = _safe_search(
        conn,
        base,
        f"(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:={_DISABLE}))(!(userAccountControl:1.2.840.113556.1.4.803:={_SERVER}))(lastLogonTimestamp<={cutoff}))",
        ["cn"],
        8,
    )
    for entry in quiet:
        _keep(findings, counts, {
            "hostname": str(_first(entry, "cn") or ""),
            "category": "Устаревшие компьютеры",
            "title": "Компьютер давно не отмечался в домене",
            "severity": "medium",
            "detail": "Сверьте с инвентаризацией и отключите учетную запись, если сервера уже нет.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "stale_computer",
        }, 8)
    cutoff = datetime.utcnow() - timedelta(days=90)
    old_pwd = str(int((cutoff - datetime(1601, 1, 1)).total_seconds() * 10_000_000))
    for entry in _safe_search(
        conn,
        base,
        f"(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(pwdLastSet<={old_pwd})(pwdLastSet>=1))",
        ["cn", "pwdLastSet"],
        8,
    ):
        age = _age_days(_first(entry, "pwdLastSet"))
        _keep(findings, counts, {
            "hostname": str(_first(entry, "cn") or ""),
            "category": "Учетные записи компьютеров",
            "title": "Пароль компьютера давно не менялся",
            "severity": "medium",
            "detail": f"pwdLastSet старше 90 дней{f' ({age} дн.)' if age is not None else ''}. Это не пароль человека: домен должен менять его сам.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "machine_password_old",
        }, 8)
    schema = ""
    try:
        conn.search("", "(objectClass=*)", search_scope=BASE, attributes=["schemaNamingContext"])
        if conn.entries:
            schema = str(_first(conn.entries[0], "schemaNamingContext") or "")
    except (LDAPException, OSError, RuntimeError, ValueError):
        schema = ""
    laps_in_schema = bool(schema) and bool(_safe_search(conn, schema, "(|(cn=ms-Mcs-AdmPwd)(cn=ms-LAPS-Password))", ["cn"], 2))
    if laps_in_schema:
        for entry in _safe_search(
            conn,
            base,
            "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(ms-Mcs-AdmPwdExpirationTime=*))(!(msLAPS-PasswordExpirationTime=*)))",
            ["cn", "operatingSystem"],
            8,
        ):
            _keep(findings, counts, {
                "hostname": str(_first(entry, "cn") or ""),
                "category": "LAPS",
                "title": "На компьютере нет управляемого пароля LAPS",
                "severity": "high",
                "detail": f"{_first(entry, 'operatingSystem') or 'ОС не указана'}. Срок пароля LAPS не задан. Сам пароль не читается.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "laps_gap",
            }, 8)
    for entry in _safe_search(
        conn,
        f"CN=Password Settings Container,CN=System,{base}",
        "(objectClass=msDS-PasswordSettings)",
        ["cn", "msDS-MinimumPasswordLength", "msDS-LockoutThreshold"],
        12,
    ):
        try:
            length = int(_first(entry, "msDS-MinimumPasswordLength") or 0)
            lockout = int(_first(entry, "msDS-LockoutThreshold") or 0)
        except (TypeError, ValueError):
            continue
        if length >= 12 and lockout > 0:
            continue
        _keep(findings, counts, {
            "hostname": str(_first(entry, "cn") or ""),
            "category": "Политика паролей",
            "title": "Точечная политика паролей слабее базовой",
            "severity": "high" if length < 8 or lockout == 0 else "medium",
            "detail": f"Минимальная длина {length}, порог блокировки {lockout}.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "weak_pso",
        }, 8)
    owners: set[str] = set()
    for scope, filt in (
        (base, "(objectClass=domain)"),
        (f"CN=System,{base}", "(cn=RID Manager$)"),
        (f"CN=System,{base}", "(cn=Infrastructure)"),
    ):
        for entry in _safe_search(conn, scope, filt, ["fSMORoleOwner"], 1):
            owner = str(_first(entry, "fSMORoleOwner") or "")
            parts = [part[3:] for part in owner.split(",") if part.upper().startswith("CN=") and "NTDS SETTINGS" not in part.upper()]
            if parts:
                owners.add(parts[0])
    dcs = _safe_search(conn, base, "(userAccountControl:1.2.840.113556.1.4.803:=8192)", ["cn"], 12)
    if len(dcs) > 1 and len(owners) == 1:
        _keep(findings, counts, {
            "hostname": next(iter(owners)),
            "category": "Топология",
            "title": "Роли FSMO собраны на одном контроллере",
            "severity": "medium",
            "detail": "PDC, RID и инфраструктура указывают на один узел при нескольких контроллерах. Это риск доступности, не атака.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "fsmo_single_host",
        }, 1)
    _structure_ldap(conn, base, findings, counts)
    return findings


def _structure_ldap(conn: Connection, base: str, findings: list[dict[str, Any]], counts: dict[str, int]) -> None:
    """Группы, подразделения и имена зон. Состав участников и двоичные записи DNS не сохраняются."""
    groups = _safe_search(conn, base, "(objectCategory=group)", ["cn", "distinguishedName", "member", "groupType"], 250)
    by_dn: dict[str, tuple[str, list[str]]] = {}
    for entry in groups:
        dn = str(_first(entry, "distinguishedName") or "").lower()
        name = str(_first(entry, "cn") or "")
        if not dn or not name:
            continue
        raw_members = entry["member"].value if "member" in entry else None
        members = raw_members if isinstance(raw_members, list) else ([raw_members] if raw_members else [])
        member_dns = [str(item).lower() for item in members if item]
        try:
            kind = int(_first(entry, "groupType") or 0)
        except (TypeError, ValueError):
            kind = 0
        by_dn[dn] = (name, member_dns)
        if kind & 0x80000000 and not member_dns:
            _keep(findings, counts, {
                "hostname": name,
                "category": "Группы",
                "title": "Пустая группа безопасности",
                "severity": "info",
                "detail": "У группы нет участников. Сверьте, нужна ли она ещё.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "empty_security_group",
            }, 8)
        if len(member_dns) >= 200:
            _keep(findings, counts, {
                "hostname": name,
                "category": "Группы",
                "title": "Очень большая группа",
                "severity": "medium",
                "detail": f"В группе не меньше {len(member_dns)} участников. Список участников в карточку не копируется.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "large_group",
            }, 5)
    children = {dn: [item for item in members if item in by_dn] for dn, (_, members) in by_dn.items()}

    def walk(start: str) -> tuple[int, bool]:
        seen: set[str] = set()
        trail: set[str] = set()
        deepest = 0
        cycle = False

        def visit(node: str, depth: int) -> None:
            nonlocal deepest, cycle
            if node in trail:
                cycle = True
                return
            if node in seen or depth > 6 or len(seen) > 80:
                return
            seen.add(node)
            trail.add(node)
            deepest = max(deepest, depth)
            for child in children.get(node, []):
                visit(child, depth + 1)
            trail.discard(node)

        visit(start, 0)
        return deepest, cycle

    for dn, (name, _) in list(by_dn.items())[:120]:
        depth, cycle = walk(dn)
        if cycle:
            _keep(findings, counts, {
                "hostname": name,
                "category": "Группы",
                "title": "Цикл во вложенности групп",
                "severity": "medium",
                "detail": "Группа прямо или через другие группы входит сама в себя. Цепочка участников в отчёт не копируется.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "circular_group_nesting",
            }, 3)
        elif depth >= 5:
            _keep(findings, counts, {
                "hostname": name,
                "category": "Группы",
                "title": "Слишком глубокая вложенность групп",
                "severity": "medium",
                "detail": "От этой группы до вложенной не меньше пяти шагов. Полный путь в отчёт не копируется.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "deep_group_nesting",
            }, 5)
    for entry in _safe_search(conn, base, "(objectClass=organizationalUnit)", ["ou", "distinguishedName"], 60):
        dn = str(_first(entry, "distinguishedName") or "")
        name = str(_first(entry, "ou") or "")
        if not dn:
            continue
        try:
            conn.search(dn, "(objectClass=*)", search_scope=LEVEL, attributes=["cn"], size_limit=1)
            occupied = bool(conn.entries)
        except (LDAPException, OSError, RuntimeError, ValueError):
            continue
        if not occupied:
            _keep(findings, counts, {
                "hostname": name or dn,
                "category": "Подразделения",
                "title": "Пустое подразделение",
                "severity": "info",
                "detail": "В подразделении нет дочерних объектов.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "empty_ou",
            }, 8)
    for suffix in (f"CN=MicrosoftDNS,DC=DomainDnsZones,{base}", f"CN=MicrosoftDNS,DC=ForestDnsZones,{base}"):
        for entry in _safe_search(conn, suffix, "(objectClass=dnsZone)", ["name"], 40):
            name = str(_first(entry, "name") or "")
            if "*" not in name:
                continue
            _keep(findings, counts, {
                "hostname": name,
                "category": "DNS",
                "title": "В имени зоны DNS есть подстановка",
                "severity": "high",
                "detail": "Зона с символом * отвечает на лишние имена. Двоичные записи зоны не читались.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "dns_wildcard",
            }, 5)


def scan_trusts_ldap(connection: dict[str, Any]) -> dict[str, Any]:
    try:
        conn, base = connect(connection)
    except (LDAPException, OSError, RuntimeError) as exc:
        return {"ok": False, "findings": [], "score": None, "message": f"LDAPS/LDAP не открылся: {exc}"}
    findings: list[dict[str, Any]] = []
    try:
        trusts = _search(conn, f"CN=System,{base}", "(objectClass=trustedDomain)", ["cn", "trustDirection", "trustAttributes"], 50)
        directions = {"1": "входящее", "2": "исходящее", "3": "двустороннее"}
        for entry in trusts:
            name = str(_first(entry, "cn") or "")
            try:
                flags = int(_first(entry, "trustAttributes") or 0)
            except (TypeError, ValueError):
                flags = 0
            kind = "Forest" if flags & 8 else "External"
            sid_on = bool(flags & 4)
            direction = directions.get(str(_first(entry, "trustDirection") or ""), "неизвестно")
            missing = not sid_on
            findings.append(
                {
                    "hostname": name,
                    "category": "Доверительные отношения",
                    "title": f"Фильтрация SID выключена: {name}" if missing else f"Доверие {name}: фильтрация SID включена",
                    "severity": "critical" if missing else "info",
                    "detail": f"{kind}, направление {direction}.",
                    "tags": "trust,sid-filter,module:trusts",
                    "vuln_id": "trust_sid_filter" if missing else "trust_ok",
                }
            )
    finally:
        conn.unbind()
    bad = sum(1 for item in findings if item["severity"] == "critical")
    return {"ok": True, "findings": findings, "score": None, "message": f"Доверий по LDAP: {len(findings)}, без фильтрации SID: {bad}."}


def directory_picture(connection: dict[str, Any]) -> dict[str, Any]:
    """Срез каталога для экранов кабинета. Без участников групп, записей DNS и паролей."""
    try:
        conn, base = connect(connection)
    except (LDAPException, OSError, RuntimeError) as exc:
        return {"ok": False, "message": f"Каталог не открылся: {exc}"}
    try:
        domain = _safe_search(conn, base, "(objectClass=domainDNS)", ["msDS-Behavior-Version", "minPwdLength", "pwdHistoryLength", "lockoutThreshold", "maxPwdAge", "fSMORoleOwner"], 1)
        level = ""
        policy = {"length": "", "history": "", "lockout": "", "max_age_days": ""}
        pdc = ""
        if domain:
            row = domain[0]
            try:
                level = _LEVELS.get(int(_first(row, "msDS-Behavior-Version") or 0), str(_first(row, "msDS-Behavior-Version") or ""))
            except (TypeError, ValueError):
                level = ""
            policy = {
                "length": str(_first(row, "minPwdLength") or ""),
                "history": str(_first(row, "pwdHistoryLength") or ""),
                "lockout": str(_first(row, "lockoutThreshold") or ""),
                "max_age_days": _interval_days(_first(row, "maxPwdAge")),
            }
            pdc = _role_cn(str(_first(row, "fSMORoleOwner") or ""))
        dcs = []
        for entry in _safe_search(conn, base, "(userAccountControl:1.2.840.113556.1.4.803:=8192)", ["cn", "dNSHostName", "operatingSystem"], 24):
            dcs.append({
                "name": str(_first(entry, "cn") or ""),
                "host": str(_first(entry, "dNSHostName") or ""),
                "os": str(_first(entry, "operatingSystem") or ""),
            })
        config = _config_base(conn)
        sites: list[dict[str, Any]] = []
        subnets: list[dict[str, str]] = []
        if config:
            site_base = f"CN=Sites,{config}"
            for entry in _safe_search(conn, site_base, "(objectClass=site)", ["cn"], 30):
                sites.append({"name": str(_first(entry, "cn") or ""), "servers": []})
            known = {item["name"].lower(): item for item in sites}
            for entry in _safe_search(conn, site_base, "(objectClass=server)", ["cn", "distinguishedName"], 40):
                site_name = _site_of(str(_first(entry, "distinguishedName") or ""))
                bucket = known.get(site_name.lower())
                if bucket is not None:
                    bucket["servers"].append(str(_first(entry, "cn") or ""))
            for entry in _safe_search(conn, f"CN=Subnets,{site_base}", "(objectClass=subnet)", ["cn", "siteObject"], 60):
                subnets.append({
                    "name": str(_first(entry, "cn") or ""),
                    "site": _site_of(str(_first(entry, "siteObject") or "")),
                })
        zones = []
        for suffix in (f"CN=MicrosoftDNS,DC=DomainDnsZones,{base}", f"CN=MicrosoftDNS,DC=ForestDnsZones,{base}"):
            for entry in _safe_search(conn, suffix, "(objectClass=dnsZone)", ["name"], 30):
                name = str(_first(entry, "name") or "")
                if name and name not in zones:
                    zones.append(name)
        wildcard = False
        for suffix in (f"CN=MicrosoftDNS,DC=DomainDnsZones,{base}", f"CN=MicrosoftDNS,DC=ForestDnsZones,{base}"):
            if _safe_search(conn, suffix, "(&(objectClass=dnsNode)(dc=\\2a))", ["dc"], 1):
                wildcard = True
                break
        ous = []
        ou_nodes = []
        for entry in _safe_search(conn, base, "(objectClass=organizationalUnit)", ["ou", "distinguishedName"], 80):
            dn = str(_first(entry, "distinguishedName") or "")
            chain = [part[3:] for part in dn.split(",") if part.upper().startswith("OU=")]
            name = chain[0] if chain else str(_first(entry, "ou") or "")
            if not name:
                continue
            ous.append(name)
            ou_nodes.append({"name": name[:80], "path": "/".join(reversed(chain))[:220]})
        domains = []
        if config:
            for entry in _safe_search(conn, f"CN=Partitions,{config}", "(objectClass=crossRef)", ["dnsRoot", "systemFlags"], 24):
                try:
                    flags = int(_first(entry, "systemFlags") or 0)
                except (TypeError, ValueError):
                    flags = 0
                if not flags & 2:
                    continue
                dns = str(_first(entry, "dnsRoot") or "")
                if dns and dns not in domains and len(domains) < 12:
                    domains.append(dns)
        groups = []
        for entry in _safe_search(conn, base, "(objectCategory=group)", ["cn", "groupType", "member"], 40):
            try:
                kind = int(_first(entry, "groupType") or 0)
            except (TypeError, ValueError):
                kind = 0
            raw = entry["member"].value if "member" in entry else None
            listed = raw if isinstance(raw, list) else ([raw] if raw else [])
            names = []
            for item in listed:
                if len(names) >= 24:
                    break
                cn = next((part[3:] for part in str(item).split(",") if part.upper().startswith("CN=")), "")
                if cn:
                    names.append(cn[:64])
            groups.append({
                "name": str(_first(entry, "cn") or ""),
                "security": bool(kind & 0x80000000),
                "members": names,
                "member_count": len([item for item in listed if item]),
            })
        gpos = []
        flag_text = {0: "включена", 1: "выключена часть пользователя", 2: "выключена часть компьютера", 3: "выключена"}
        for entry in _safe_search(conn, f"CN=Policies,CN=System,{base}", "(objectClass=groupPolicyContainer)", ["cn", "displayName", "flags"], 60):
            try:
                flags = int(_first(entry, "flags") or 0)
            except (TypeError, ValueError):
                flags = 0
            gpos.append({
                "id": str(_first(entry, "cn") or ""),
                "name": str(_first(entry, "displayName") or ""),
                "state": flag_text.get(flags, "состояние не прочитано"),
            })
        trusts = []
        directions = {"1": "входящее", "2": "исходящее", "3": "двустороннее"}
        for entry in _safe_search(conn, f"CN=System,{base}", "(objectClass=trustedDomain)", ["cn", "trustDirection", "trustAttributes"], 20):
            try:
                flags = int(_first(entry, "trustAttributes") or 0)
            except (TypeError, ValueError):
                flags = 0
            trusts.append({
                "name": str(_first(entry, "cn") or ""),
                "direction": directions.get(str(_first(entry, "trustDirection") or ""), "неизвестно"),
                "kind": "лес" if flags & 8 else "внешнее",
                "sid_filter": bool(flags & 4),
                "selective": bool(flags & 16) and not bool(flags & 32),
            })
        roles = [item for item in (pdc, _role_cn(_owner(conn, f"CN=RID Manager$,CN=System,{base}")), _role_cn(_owner(conn, f"CN=Infrastructure,CN=System,{base}"))) if item]
        return {
            "ok": True,
            "message": "Каталог прочитан. В группах показаны первые участники. Состав зон — это количество записей по типам, имена записей не копируются.",
            "domain": base,
            "level": level,
            "policy": policy,
            "roles": roles,
            "dcs": dcs,
            "sites": sites,
            "subnets": subnets,
            "zones": zones,
            "wildcard": wildcard,
            "ous": [name for name in ous if name],
            "ou_nodes": ou_nodes,
            "domains": domains,
            "groups": groups,
            "gpos": gpos,
            "trusts": trusts,
        }
    finally:
        conn.unbind()


def _interval_days(value: Any) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return ""
    if number in (0, -9223372036854775808):
        return "не ограничен"
    days = int(abs(number) / 10_000_000 / 86400)
    return str(days) if days else ""


def _role_cn(owner: str) -> str:
    parts = [part[3:] for part in owner.split(",") if part.upper().startswith("CN=") and "NTDS SETTINGS" not in part.upper()]
    return parts[0] if parts else ""


def _owner(conn: Connection, base: str) -> str:
    rows = _safe_search(conn, base, "(objectClass=*)", ["fSMORoleOwner"], 1)
    if not rows:
        return ""
    return str(_first(rows[0], "fSMORoleOwner") or "")


def _site_of(dn: str) -> str:
    parts = [part for part in dn.split(",") if part]
    for index, part in enumerate(parts):
        if part.upper() == "CN=SERVERS" and index + 1 < len(parts) and parts[index + 1].upper().startswith("CN="):
            return parts[index + 1][3:]
    for part in parts:
        if part.upper().startswith("CN=") and part.upper() not in {"CN=SITES", "CN=SUBNETS"}:
            return part[3:]
    return ""


def scan_hardening_ldap(connection: dict[str, Any]) -> dict[str, Any]:
    try:
        conn, base = connect(connection)
    except (LDAPException, OSError, RuntimeError) as exc:
        return {"ok": False, "findings": [], "score": None, "message": f"LDAPS/LDAP не открылся: {exc}"}
    findings: list[dict[str, Any]] = []
    try:
        krbtgt = _search(conn, base, "(&(objectClass=user)(sAMAccountName=krbtgt))", ["pwdLastSet"], 1)
        if krbtgt:
            changed = _filetime(_first(krbtgt[0], "pwdLastSet"))
            if changed and (datetime.utcnow() - changed).days > 180:
                age = (datetime.utcnow() - changed).days
                findings.append(
                    {
                        "hostname": connection["host"],
                        "category": "Харденинг",
                        "title": f"Пароль krbtgt не менялся {age} дн.",
                        "severity": "high",
                        "detail": "Нужна штатная двойная смена. Пароль в отчет не попадает.",
                        "tags": "compliance,hardening,module:dc_hardening",
                        "vuln_id": "krbtgt_old",
                    }
                )
        schema = ""
        conn.search("", "(objectClass=*)", search_scope="BASE", attributes=["schemaNamingContext"])
        if conn.entries:
            schema = str(_first(conn.entries[0], "schemaNamingContext") or "")
        if schema:
            laps = _search(conn, schema, "(|(cn=ms-Mcs-AdmPwd)(cn=ms-LAPS-Password))", ["cn"], 2)
            if not laps:
                findings.append(
                    {
                        "hostname": connection["host"],
                        "category": "Харденинг",
                        "title": "В схеме домена нет LAPS",
                        "severity": "high",
                        "detail": "Разверните Windows LAPS. Пароли локальных администраторов по LDAP не читаются.",
                        "tags": "compliance,hardening,module:dc_hardening",
                        "vuln_id": "laps_missing",
                    }
                )
    finally:
        conn.unbind()
    return {
        "ok": True,
        "findings": findings,
        "score": None,
        "message": f"По LDAP проверены krbtgt и схема LAPS. Отклонений: {len(findings)}. Служба печати и подпись LDAP видны только через WinRM.",
    }


_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
_SMART_CARD = "1.3.6.1.4.1.311.20.2.2"


def _as_int(entry: Any, name: str) -> int:
    try:
        return int(_first(entry, name) or 0)
    except (TypeError, ValueError):
        return 0


def _as_list(entry: Any, name: str) -> list[str]:
    attr = entry[name]
    if attr is None or attr.value is None:
        return []
    value = attr.value
    items = value if isinstance(value, list) else [value]
    return [str(item) for item in items if item is not None]


def scan_adcs_ldap(connection: dict[str, Any]) -> dict[str, Any]:
    """Шаблоны из раздела конфигурации. Только флаги и EKU, без прав выпуска и без запросов в центр сертификации."""
    secret = str(connection.get("password") or "")
    try:
        conn, _base = connect(connection)
    except (LDAPException, OSError, RuntimeError) as exc:
        text = str(exc).replace(secret, "") if secret else str(exc)
        return {"ok": False, "findings": [], "score": None, "message": f"LDAP не открылся: {text}"[:500]}
    findings: list[dict[str, Any]] = []
    try:
        config = _config_base(conn)
        if not config:
            return {"ok": False, "findings": [], "score": None, "message": "Контроллер не вернул раздел конфигурации."}
        templates = "CN=Certificate Templates,CN=Public Key Services,CN=Services," + config
        try:
            conn.search(
                templates,
                "(objectClass=pKICertificateTemplate)",
                search_scope=SUBTREE,
                attributes=["cn", "displayName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage"],
                size_limit=400,
            )
        except LDAPException as exc:
            text = str(exc).replace(secret, "") if secret else str(exc)
            return {"ok": False, "findings": [], "score": None, "message": f"Шаблоны AD CS не прочитаны: {text}"[:500]}
        description = str((conn.result or {}).get("description") or "")
        if description == "noSuchObject":
            return {
                "ok": True,
                "findings": [],
                "score": None,
                "message": "Контейнер шаблонов сертификатов не найден. В этом лесу служба AD CS не развернута либо контейнер недоступен для чтения.",
            }
        if description not in {"success", "sizeLimitExceeded"}:
            detail = str((conn.result or {}).get("message") or description or "поиск не выполнен")
            if secret:
                detail = detail.replace(secret, "")
            return {"ok": False, "findings": [], "score": None, "message": f"Шаблоны AD CS не прочитаны: {detail}"[:500]}
        rows = list(conn.entries)
        for entry in rows:
            name_flag = _as_int(entry, "msPKI-Certificate-Name-Flag")
            enroll_flag = _as_int(entry, "msPKI-Enrollment-Flag")
            eku = _as_list(entry, "pKIExtendedKeyUsage")
            enrollee_san = (name_flag & 1) == 1
            pending = (enroll_flag & 2) == 2
            auth = _CLIENT_AUTH in eku or _SMART_CARD in eku
            if not (enrollee_san and auth and not pending):
                continue
            cn = str(_first(entry, "cn") or "template")
            title = str(_first(entry, "displayName") or cn).replace("|", "/")
            findings.append(
                {
                    "hostname": str(connection.get("host") or ""),
                    "category": "AD CS",
                    "title": f"Шаблон {title}: заявитель задает альтернативное имя",
                    "severity": "high",
                    "detail": (
                        f"Шаблон {cn} одновременно разрешает имя субъекта от заявителя, "
                        "содержит EKU проверки подлинности клиента и не требует согласования выпуска. "
                        "Сузьте право Enroll и отключите поставку SAN заявителем."
                    ),
                    "tags": "compliance,adcs,module:ad_cs",
                    "vuln_id": "adcs_enrollee_san",
                }
            )
            if len(findings) >= 40:
                break
        if findings:
            message = f"Рискованных шаблонов AD CS: {len(findings)}. Прочитано шаблонов по LDAP: {len(rows)}."
        else:
            message = (
                "Шаблонов с комбинацией «SAN от заявителя + проверка подлинности клиента + автовыпуск» не найдено. "
                f"Прочитано шаблонов по LDAP: {len(rows)}."
            )
        return {"ok": True, "findings": findings, "score": None, "message": message}
    finally:
        try:
            conn.unbind()
        except LDAPException:
            pass


def list_computer_names(connection: dict[str, Any], limit: int = 2000) -> list[str]:
    """Имена включенных компьютеров домена. Пароли и хеши не читаются."""
    conn, base = connect(connection)
    names: list[str] = []
    try:
        pages = conn.extend.standard.paged_search(
            search_base=base,
            search_filter="(&(objectCategory=computer)(dNSHostName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            search_scope=SUBTREE,
            attributes=["dNSHostName"],
            paged_size=500,
            size_limit=limit,
            generator=True,
        )
        for item in pages:
            if not isinstance(item, dict) or item.get("type") != "searchResEntry":
                continue
            raw = (item.get("attributes") or {}).get("dNSHostName")
            host = raw[0] if isinstance(raw, list) else raw
            host = str(host or "").strip().rstrip(".")
            if host and host not in names:
                names.append(host)
            if len(names) >= limit:
                break
    finally:
        conn.unbind()
    return names


def probe_directory(connection: dict[str, Any]) -> dict[str, Any]:
    """Короткий bind к каталогу. Пароль в ответ не попадает."""
    secret = str(connection.get("password") or "")
    try:
        conn, _base = connect(connection)
        conn.unbind()
        return {"ok": True, "detail": "Каталог отвечает"}
    except Exception as exc:
        text = str(exc)
        if secret:
            text = text.replace(secret, "")
        text = " ".join(text.split())
        return {"ok": False, "detail": (text or "Каталог не ответил")[:180]}


_TIER = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
    "server operators",
    "dnsadmins",
    "group policy creator owners",
    "print operators",
    "cert publishers",
}
_UAC_FLAGS = (
    (0x20, "PASSWD_NOTREQD", "bad"),
    (0x10000, "DONT_EXPIRE_PASSWORD", "warn"),
    (0x80000, "TRUSTED_FOR_DELEGATION", "bad"),
    (0x1000000, "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION", "bad"),
    (0x2000, "SERVER_TRUST_ACCOUNT", "plain"),
    (0x200000, "USE_DES_KEY_ONLY", "bad"),
    (0x400000, "DONT_REQ_PREAUTH", "warn"),
)


def _cn(value: str) -> str:
    first = str(value or "").split(",", 1)[0]
    return first[3:] if first.upper().startswith("CN=") else first


def _age_days(value: Any) -> int | None:
    moment = _filetime(value)
    if moment is None:
        return None
    return max(0, (datetime.utcnow() - moment).days)


def _row(label: str, value: str, tone: str = "plain") -> dict[str, str]:
    return {"label": label, "value": value, "tone": tone}


def _public_note(value: Any) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    if not text:
        return ""
    text = re.sub(r"(?i)(пароль|password|pwd|cpassword)\s*[:=]\s*\S+", r"\1: [скрыто]", text)
    return text[:240]


def _sid_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value if value.startswith("S-") else ""
    try:
        raw = bytes(value)
    except TypeError:
        return ""
    if len(raw) < 8:
        return ""
    count = raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    parts = [f"S-{raw[0]}-{authority}"]
    offset = 8
    for _ in range(count):
        if offset + 4 > len(raw):
            return ""
        parts.append(str(int.from_bytes(raw[offset:offset + 4], "little")))
        offset += 4
    return "-".join(parts)


def lookup_asset(connection: dict[str, Any], name: str) -> dict[str, Any]:
    """Атрибуты одного объекта. Пароли, хеши и билеты не читаются."""
    secret = str(connection.get("password") or "")
    empty = {"found": False, "kind": "", "kind_label": "", "name": name, "rows": []}
    token = str(name or "").strip().rstrip(".")
    if not token or "\\" in token or len(token) > 180:
        return empty
    short = token.split(".", 1)[0]
    try:
        conn, base = connect(connection)
    except (LDAPException, OSError, RuntimeError):
        return empty
    try:
        clauses = []
        for item in {token, short, token + "$", short + "$"}:
            safe = escape_filter_chars(item)
            clauses.append(f"(sAMAccountName={safe})(cn={safe})(dNSHostName={safe})")
        filt = "(|" + "".join(clauses) + ")"
        try:
            conn.search(
                base,
                filt,
                search_scope=SUBTREE,
                attributes=[
                    "cn", "sAMAccountName", "objectClass", "userAccountControl", "pwdLastSet",
                    "memberOf", "servicePrincipalName", "msDS-SupportedEncryptionTypes",
                    "lastLogonTimestamp", "operatingSystem", "operatingSystemVersion",
                    "badPwdCount", "badPasswordTime", "distinguishedName", "msDS-GroupMSAMembership", "ms-DS-CreatorSID",
                    "description", "info", "comment", "displayName", "title", "department", "managedBy", "dNSHostName",
                ],
                size_limit=3,
            )
        except LDAPException as exc:
            text = str(exc).replace(secret, "") if secret else str(exc)
            return {**empty, "detail": text[:180]}
        if not conn.entries:
            return empty
        entry = conn.entries[0]
        classes = {item.lower() for item in _as_list(entry, "objectClass")}
        sam = str(_first(entry, "sAMAccountName") or _first(entry, "cn") or token)
        uac = _as_int(entry, "userAccountControl")
        spns = _as_list(entry, "servicePrincipalName")
        computer = "computer" in classes
        service = (not computer) and ("msds-groupmanagedserviceaccount" in classes or "msds-managedserviceaccount" in classes or bool(spns))
        if computer:
            kind, kind_label = "computer", "Машинная учетная запись"
        elif service:
            kind, kind_label = "service", "Служебная учетная запись"
        else:
            kind, kind_label = "user", "Пользовательская учетная запись"
        dns_host = str(_first(entry, "dNSHostName") or "")
        rows: list[dict[str, str]] = []
        for label, attr in (
            ("Отображаемое имя", "displayName"),
            ("Должность", "title"),
            ("Отдел", "department"),
            ("Описание", "description"),
            ("Заметка", "info"),
            ("Комментарий", "comment"),
        ):
            text = _public_note(_first(entry, attr))
            if text:
                rows.append(_row(label, text, "plain"))
        if computer:
            manager = _cn(str(_first(entry, "managedBy") or ""))
            if manager:
                rows.append(_row("Ответственный", manager, "plain"))
            os_name = str(_first(entry, "operatingSystem") or "не указана")
            version = str(_first(entry, "operatingSystemVersion") or "")
            old = any(token_os in os_name for token_os in ("2003", "2008", "2012", "Windows 7", "Windows XP", "Windows 8"))
            rows.append(_row("ОС", f"{os_name} {version}".strip(), "bad" if old else "plain"))
            creator = _sid_text(_first(entry, "ms-DS-CreatorSID"))
            if creator:
                rows.append(_row("Кто ввел в домен", creator, "plain"))
            seen = _age_days(_first(entry, "lastLogonTimestamp"))
            if seen is None:
                rows.append(_row("Активность", "lastLogon не задан", "warn"))
            else:
                rows.append(_row("Активность", f"последний вход {seen} дн. назад", "warn" if seen > 45 else "plain"))
        else:
            pwd_age = _age_days(_first(entry, "pwdLastSet"))
            if pwd_age is None:
                rows.append(_row("Возраст пароля", "pwdLastSet не задан", "warn"))
            else:
                tone = "bad" if pwd_age > 180 else "warn" if pwd_age > 90 else "plain"
                rows.append(_row("Возраст пароля", f"{pwd_age} дн.", tone))
        groups = [_cn(item) for item in _as_list(entry, "memberOf")]
        tier = [item for item in groups if item.lower() in _TIER]
        if kind == "user":
            rows.append(_row("Критичные группы", ", ".join(tier) if tier else "нет групп Tier 0/1", "bad" if tier else "plain"))
            try:
                bad = int(_first(entry, "badPwdCount") or 0)
            except (TypeError, ValueError):
                bad = 0
            when = _filetime(_first(entry, "badPasswordTime"))
            when_text = when.strftime("%d.%m.%Y %H:%M") if when and when.year > 1601 else "нет"
            rows.append(_row("Ошибки входа", f"badPwdCount {bad}, последняя {when_text}", "bad" if bad >= 5 else "warn" if bad else "plain"))
        if spns:
            shown = ", ".join(spns[:4])
            rows.append(_row("SPN", shown, "warn" if kind != "computer" else "plain"))
        flags = []
        flag_tone = "plain"
        dn = str(_first(entry, "distinguishedName") or "")
        for bit, label, tone in _UAC_FLAGS:
            if not uac & bit:
                continue
            if label == "SERVER_TRUST_ACCOUNT" and computer and "domain controllers" not in dn.lower():
                flags.append(label + " на рядовом компьютере")
                flag_tone = "bad"
                continue
            flags.append(label)
            if tone == "bad":
                flag_tone = "bad"
            elif tone == "warn" and flag_tone != "bad":
                flag_tone = "warn"
        if flags:
            rows.append(_row("Флаги UAC", ", ".join(flags), flag_tone))
        enc = _as_int(entry, "msDS-SupportedEncryptionTypes")
        if enc and kind != "user":
            names = []
            if enc & 0x3:
                names.append("DES")
            if enc & 0x4:
                names.append("RC4")
            if enc & 0x8:
                names.append("AES128")
            if enc & 0x10:
                names.append("AES256")
            weak = bool(names) and "AES128" not in names and "AES256" not in names
            rows.append(_row("Шифрование Kerberos", ", ".join(names) or str(enc), "bad" if weak else "plain"))
        if kind == "service" and "msds-groupmanagedserviceaccount" not in classes and "msds-managedserviceaccount" not in classes:
            rows.append(_row("Тип службы", "обычная учетная запись, не gMSA", "warn"))
        elif kind == "service":
            rows.append(_row("Тип службы", "gMSA или MSA", "plain"))
        return {"found": True, "kind": kind, "kind_label": kind_label, "name": sam, "dns": dns_host, "rows": rows[:16]}
    finally:
        try:
            conn.unbind()
        except LDAPException:
            pass
