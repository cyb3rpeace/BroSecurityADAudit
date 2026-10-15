"""Чтение каталога по LDAP или LDAPS. Пароли, билеты и хеши не запрашиваются."""

from __future__ import annotations

import os
import re
import ssl
from datetime import datetime, timedelta
from typing import Any

from ldap3 import BASE, NONE, NTLM, SIMPLE, SUBTREE, Connection, Server, Tls
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
    return findings


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
