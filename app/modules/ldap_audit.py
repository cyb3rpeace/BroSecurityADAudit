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


def _values(entry: Any, name: str) -> list[Any]:
    try:
        attr = entry[name]
    except Exception:
        return []
    if attr is None:
        return []
    value = attr.value
    if isinstance(value, list):
        return value
    return [value] if value else []


def _gplinks(raw: str) -> list[dict[str, Any]]:
    rows = []
    for match in re.finditer(r"\[LDAP://([^;\]]+);(\d+)\]", raw or "", re.I):
        guid = re.search(r"\{[0-9A-Fa-f-]+\}", match.group(1))
        try:
            flag = int(match.group(2))
        except ValueError:
            flag = 0
        rows.append({
            "guid": guid.group(0) if guid else "",
            "enabled": flag not in (1, 3),
            "enforced": flag in (2, 3),
        })
        if len(rows) >= 8:
            break
    return rows


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
_DONT_EXPIRE = 0x10000
_NOT_DELEGATED = 0x100000
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
    _coverage_ldap(conn, base, findings, counts)
    _depth_ldap(conn, base, findings, counts)
    return findings


def _coverage_ldap(conn: Connection, base: str, findings: list[dict[str, Any]], counts: dict[str, int]) -> None:
    """Проверки из каталога правил оценки, которых не было в гигиене. Только чтение LDAP."""
    hidden = _safe_search(
        conn,
        base,
        f"(&(objectCategory=person)(objectClass=user)(!(primaryGroupID=513))(!(userAccountControl:1.2.840.113556.1.4.803:={_DISABLE})))",
        ["sAMAccountName", "primaryGroupID"],
        12,
    )
    for entry in hidden:
        sam = str(_first(entry, "sAMAccountName") or "")
        if sam.lower() in {"guest", "krbtgt"}:
            continue
        _keep(findings, counts, {
            "hostname": sam,
            "category": "Учетные записи",
            "title": "Основная группа не Domain Users",
            "severity": "medium",
            "detail": f"primaryGroupID={_first(entry, 'primaryGroupID') or '?'}. Членство в основной группе не видно в списке member. Верните Domain Users, если скрывать группу не зачем.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "primary_group",
        })
    known = _safe_search(conn, base, "(objectClass=domainDNS)", ["wellKnownObjects"], 1)
    if known:
        raw = _values(known[0], "wellKnownObjects")
        stuck = []
        for item in raw:
            text = str(item)
            if "AA312825768811D1ADED00C04FD8D5CD" in text.upper() and text.upper().endswith("CN=COMPUTERS," + base.upper()):
                stuck.append("компьютеры")
            if "A9D1CA15768811D1ADED00C04FD8D5CD" in text.upper() and text.upper().endswith("CN=USERS," + base.upper()):
                stuck.append("пользователи")
        if stuck:
            _keep(findings, counts, {
                "hostname": base,
                "category": "Подразделения",
                "title": "Новые объекты всё ещё попадают в контейнер по умолчанию",
                "severity": "low",
                "detail": "Не перенаправлены: " + ", ".join(stuck) + ". Перенос делают redircmp и redirusr. Сами объекты контейнера не удаляются.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "default_container",
            })
    for group_name, vuln_id, title, severity in (
        ("Schema Admins", "schema_admins", "В группе Schema Admins есть участники", "high"),
        ("Account Operators", "operator_group", "Группа Account Operators не пуста", "high"),
        ("Server Operators", "operator_group", "Группа Server Operators не пуста", "high"),
        ("Print Operators", "operator_group", "Группа Print Operators не пуста", "medium"),
        ("DnsAdmins", "dns_admins", "В группе DnsAdmins есть участники", "medium"),
    ):
        groups = _safe_search(conn, base, f"(&(objectClass=group)(cn={group_name}))", ["member"], 1)
        if not groups:
            continue
        members = [part for part in _values(groups[0], "member") if part]
        if not members:
            continue
        names = ", ".join(_cn(str(part)) for part in members[:5])
        _keep(findings, counts, {
            "hostname": group_name,
            "category": "Привилегированные группы",
            "title": title,
            "severity": severity,
            "detail": f"Участников: {len(members)}. Первые: {names}. Список длиннее пяти в отчёт не копируется.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": vuln_id,
        })
    admins = _safe_search(conn, base, "(&(objectClass=group)(cn=Domain Admins))", ["distinguishedName", "member"], 1)
    if not admins:
        return
    members = [part for part in _values(admins[0], "member") if part]
    if len(members) > 5:
        _keep(findings, counts, {
            "hostname": "Domain Admins",
            "category": "Привилегированные группы",
            "title": f"Администраторов домена {len(members)}",
            "severity": "medium",
            "detail": "Оставьте в группе постоянных администраторов не больше пяти. Остальных выносите во временные группы.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "admin_count",
        })
    group_dn = escape_filter_chars(str(_first(admins[0], "distinguishedName") or ""))
    if not group_dn:
        return
    for flag, vuln_id, title, detail in (
        (0, "admin_delegatable", "Администратора домена можно делегировать", "Включите «учетная запись важна и не может быть делегирована». Билет платформа не запрашивает."),
        (_DONT_EXPIRE, "admin_password_never", "У администратора домена пароль не истекает", "Снимите флаг бессрочного пароля или уберите запись из Domain Admins. Пароль не читается."),
    ):
        extra = f"(userAccountControl:1.2.840.113556.1.4.803:={flag})" if flag else f"(!(userAccountControl:1.2.840.113556.1.4.803:={_NOT_DELEGATED}))"
        rows = _safe_search(
            conn,
            base,
            f"(&(objectCategory=person)(objectClass=user)(memberOf={group_dn}){extra}(!(userAccountControl:1.2.840.113556.1.4.803:={_DISABLE})))",
            ["sAMAccountName"],
            12,
        )
        for entry in rows:
            _keep(findings, counts, {
                "hostname": str(_first(entry, "sAMAccountName") or ""),
                "category": "Привилегированные учетные записи",
                "title": title,
                "severity": "high",
                "detail": detail,
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": vuln_id,
            })


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


_SD_CONTROL = ("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x05")
_OWNER_OK = {"S-1-5-18", "S-1-5-9", "S-1-5-32-544"}


def _sid_at(blob: bytes, off: int) -> tuple[str, int]:
    if off < 0 or off + 8 > len(blob):
        return "", 0
    count = blob[off + 1]
    end = off + 8 + 4 * count
    if count > 15 or end > len(blob):
        return "", 0
    auth = int.from_bytes(blob[off + 2:off + 8], "big")
    parts = [str(int.from_bytes(blob[off + 8 + 4 * i:off + 12 + 4 * i], "little")) for i in range(count)]
    sid = "S-1-" + str(auth) + ("-" + "-".join(parts) if parts else "")
    return sid, end - off


def _broad_label(sid: str) -> str:
    names = {"S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users", "S-1-5-32-545": "Users"}
    if sid in names:
        return names[sid]
    if sid.endswith("-513"):
        return "Domain Users"
    if sid.endswith("-515"):
        return "Domain Computers"
    return ""


def _broad_aces(raw: Any) -> list[str]:
    if isinstance(raw, list):
        raw = raw[0] if raw else b""
    try:
        blob = bytes(raw)
    except (TypeError, ValueError):
        return []
    if len(blob) < 20:
        return []
    start = int.from_bytes(blob[16:20], "little")
    if start <= 0 or start + 8 > len(blob):
        return []
    count = int.from_bytes(blob[start + 4:start + 6], "little")
    pos = start + 8
    found: list[str] = []
    for _ in range(min(count, 64)):
        if pos + 8 > len(blob):
            break
        ace_type = blob[pos]
        size = int.from_bytes(blob[pos + 2:pos + 4], "little")
        mask = int.from_bytes(blob[pos + 4:pos + 8], "little")
        if size < 8 or pos + size > len(blob):
            break
        if ace_type == 0:
            sid, _ = _sid_at(blob, pos + 8)
            label = _broad_label(sid)
            right = ""
            if mask & 0x10000000:
                right = "полный доступ"
            elif mask & 0x00040000:
                right = "смена списка прав"
            elif mask & 0x00080000:
                right = "смена владельца"
            elif mask & 0x40000000:
                right = "запись"
            if label and right:
                found.append(f"{label}: {right}")
        pos += size
        if len(found) >= 3:
            break
    return found


def _owner_sid(raw: Any) -> str:
    if isinstance(raw, list):
        raw = raw[0] if raw else b""
    try:
        blob = bytes(raw)
    except (TypeError, ValueError):
        return ""
    if len(blob) < 8:
        return ""
    sid, _ = _sid_at(blob, int.from_bytes(blob[4:8], "little"))
    return sid


def _owner_allowed(sid: str) -> bool:
    if not sid or sid in _OWNER_OK:
        return True
    return sid.endswith("-512") or sid.endswith("-516") or sid.endswith("-519") or sid.endswith("-544")


def _depth_ldap(conn: Connection, base: str, findings: list[dict[str, Any]], counts: dict[str, int]) -> None:
    """Глубокие признаки каталога. Анонимный вход только да или нет, данные через него не читаются."""
    try:
        probe = Connection(conn.server, user="", password="", authentication=SIMPLE, auto_bind=False, receive_timeout=8)
        opened = bool(probe.bind())
        probe.unbind()
    except (LDAPException, OSError):
        opened = False
    if opened:
        _keep(findings, counts, {
            "hostname": base,
            "category": "Харденинг",
            "title": "Каталог принимает вход без учетной записи",
            "severity": "high",
            "detail": "Анонимная привязка LDAP завершилась успехом. Объекты через неё не читались. Закройте анонимные операции на контроллере.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "anonymous_ldap",
        }, 1)
    config = _config_base(conn)
    if config:
        service = _safe_search(conn, f"CN=Directory Service,CN=Windows NT,CN=Services,{config}", "(objectClass=nTDSService)", ["dsHeuristics"], 1)
        if service:
            raw = str(_first(service[0], "dsHeuristics") or "")
            if len(raw) >= 7 and raw[6] == "2":
                _keep(findings, counts, {
                    "hostname": base,
                    "category": "Харденинг",
                    "title": "В dsHeuristics разрешены анонимные операции LDAP",
                    "severity": "high",
                    "detail": "Седьмой символ параметра равен 2. Это разрешение анонимных операций. Значение целиком в отчёт не копируется.",
                    "tags": "baseline,surface,module:baseline_hygiene",
                    "vuln_id": "ds_heuristics",
                }, 1)
        schema = ""
        try:
            conn.search("", "(objectClass=*)", search_scope=BASE, attributes=["schemaNamingContext"])
            if conn.entries:
                schema = str(_first(conn.entries[0], "schemaNamingContext") or "")
        except LDAPException:
            schema = ""
        if schema and _safe_search(conn, schema, "(|(cn=javaContainer)(cn=javaNamingReference))", ["cn"], 2):
            _keep(findings, counts, {
                "hostname": base,
                "category": "Харденинг",
                "title": "В схеме есть классы Java",
                "severity": "low",
                "detail": "Старые классы Java в схеме расширяют каталог. Удалите их, если служба, которая их создала, уже не используется.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "java_schema",
            }, 1)
        menus = _safe_search(conn, f"CN=DisplaySpecifiers,{config}", "(lDAPDisplayName=user)", ["adminContextMenu"], 2)
        if menus and _values(menus[0], "adminContextMenu"):
            _keep(findings, counts, {
                "hostname": base,
                "category": "Харденинг",
                "title": "У пользователя добавлен пункт контекстного меню",
                "severity": "medium",
                "detail": "В описании отображения пользователя есть дополнительная команда. Текст команды в отчёт не копируется. Оставьте только штатные пункты.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "display_menu",
            }, 1)
    for entry in _safe_search(conn, base, "(userAccountControl:1.2.840.113556.1.4.803:=33554432)", ["cn", "msDS-RevealOnDemandGroup", "msDS-NeverRevealGroup"], 8):
        name = str(_first(entry, "cn") or "RODC")
        _keep(findings, counts, {
            "hostname": name,
            "category": "Контроллеры",
            "title": f"Контроллер только для чтения: {name}",
            "severity": "low",
            "detail": "В каталоге есть RODC. Пароли на него не копируются этой проверкой. Сверьте группы раскрытия ниже.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "rodc_present",
        })
        reveal = [_cn(str(item)) for item in _values(entry, "msDS-RevealOnDemandGroup")]
        broad = [item for item in reveal if item.lower() in {"domain users", "everyone", "authenticated users", "domain computers", "users"}]
        if broad:
            _keep(findings, counts, {
                "hostname": name,
                "category": "Контроллеры",
                "title": f"На {name} пароли может раскрывать широкая группа",
                "severity": "high",
                "detail": "В группе раскрытия: " + ", ".join(broad[:4]) + ". Оставьте там только узлы, которым нужен кэш пароля. Сами пароли не читаются.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "rodc_reveal",
            })
        never = {_cn(str(item)).lower() for item in _values(entry, "msDS-NeverRevealGroup")}
        if "domain admins" not in never:
            _keep(findings, counts, {
                "hostname": name,
                "category": "Контроллеры",
                "title": f"На {name} нет запрета кэша Domain Admins",
                "severity": "high",
                "detail": "Группа Domain Admins не входит в список, который нельзя кэшировать на RODC. Добавьте её в этот список. Пароли не читаются.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "rodc_never",
            })
    for entry in _safe_search(conn, base, "(&(objectClass=computer)(sAMAccountName=AZUREADSSOACC$))", ["sAMAccountName", "pwdLastSet"], 2):
        changed = _filetime(_first(entry, "pwdLastSet"))
        age = (datetime.utcnow() - changed).days if changed else None
        _keep(findings, counts, {
            "hostname": "AZUREADSSOACC",
            "category": "Учетные записи",
            "title": "В домене есть учётная запись единого входа",
            "severity": "medium",
            "detail": "Компьютер AZUREADSSOACC отвечает за seamless SSO. Пароль не читается." + (f" Срок пароля {age} дн." if age is not None else ""),
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "azure_sso",
        }, 1)
    for entry in _safe_search(conn, base, "(unixUserPassword=*)", ["sAMAccountName"], 8):
        _keep(findings, counts, {
            "hostname": str(_first(entry, "sAMAccountName") or ""),
            "category": "Учетные записи",
            "title": "В каталоге заполнен пароль Unix",
            "severity": "high",
            "detail": "Атрибут unixUserPassword существует. Значение не читается и в отчёт не копируется. Очистите атрибут и храните секрет вне карточки.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "unix_password",
        })
    for entry in _safe_search(conn, base, "(objectClass=msDS-DelegatedManagedServiceAccount)", ["cn", "msDS-ManagedAccountPrecededByLink"], 8):
        link = str(_first(entry, "msDS-ManagedAccountPrecededByLink") or "")
        if not link:
            continue
        _keep(findings, counts, {
            "hostname": str(_first(entry, "cn") or ""),
            "category": "Учетные записи",
            "title": "Делегированная служебная запись указывает на предшественника",
            "severity": "high",
            "detail": "Связь с предшественником даёт новой записи действовать от его имени после включения в схеме. Уберите связь, если миграция не идёт. Пароль не читается.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "dmsa_link",
        })
    upn_seen: dict[str, int] = {}
    try:
        pages = conn.extend.standard.paged_search(
            search_base=base,
            search_filter="(&(objectCategory=person)(objectClass=user)(userPrincipalName=*))",
            search_scope=SUBTREE,
            attributes=["userPrincipalName"],
            paged_size=400,
            size_limit=800,
            generator=True,
        )
        for item in pages:
            if not isinstance(item, dict) or item.get("type") != "searchResEntry":
                continue
            raw = (item.get("attributes") or {}).get("userPrincipalName")
            upn = raw[0] if isinstance(raw, list) else raw
            key = str(upn or "").strip().lower()
            if key:
                upn_seen[key] = upn_seen.get(key, 0) + 1
    except (LDAPException, OSError, RuntimeError, ValueError):
        upn_seen = {}
    dupes = [(upn, count) for upn, count in upn_seen.items() if count >= 2][:8]
    for upn, count in dupes:
        _keep(findings, counts, {
            "hostname": upn.split("@", 1)[0][:40],
            "category": "Учетные записи",
            "title": "Один UPN записан у нескольких учётных записей",
            "severity": "medium",
            "detail": f"Такое имя входа встречается {count} раз. Оставьте его одной записи.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "duplicate_upn",
        })
    for entry in _safe_search(
        conn,
        base,
        f"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=262144)(userAccountControl:1.2.840.113556.1.4.803:={_DONT_EXPIRE}))",
        ["sAMAccountName"],
        8,
    ):
        _keep(findings, counts, {
            "hostname": str(_first(entry, "sAMAccountName") or ""),
            "category": "Учетные записи",
            "title": "Смарт-карта включена, а пароль не истекает",
            "severity": "medium",
            "detail": "Запись требует смарт-карту и одновременно не меняет пароль. Пароль не читается. Либо включите срок, либо уберите запись из привилегированного входа.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "smartcard_password",
        })
    krbtgt = _safe_search(conn, base, "(sAMAccountName=krbtgt)", ["msDS-SupportedEncryptionTypes"], 1)
    if krbtgt:
        try:
            kinds = int(_first(krbtgt[0], "msDS-SupportedEncryptionTypes") or 0)
        except (TypeError, ValueError):
            kinds = 0
        if kinds and not (kinds & 24):
            _keep(findings, counts, {
                "hostname": "krbtgt",
                "category": "Харденинг",
                "title": "У krbtgt не включены типы AES",
                "severity": "high",
                "detail": "В списке типов шифрования нет AES. Пароль и билеты не читаются. Включите AES128 и AES256.",
                "tags": "baseline,surface,module:baseline_hygiene",
                "vuln_id": "krbtgt_aes",
            }, 1)
    try:
        conn.search(
            base,
            "(objectClass=organizationalUnit)",
            search_scope=SUBTREE,
            attributes=["cn", "nTSecurityDescriptor"],
            size_limit=30,
            controls=[_SD_CONTROL],
        )
        entries = list(conn.entries) if (conn.result or {}).get("description") in {"success", "sizeLimitExceeded"} else []
    except (LDAPException, OSError, ValueError):
        entries = []
    for entry in entries:
        try:
            raw_sd = entry["nTSecurityDescriptor"].value
        except Exception:
            continue
        rights = _broad_aces(raw_sd)
        if not rights:
            continue
        _keep(findings, counts, {
            "hostname": str(_first(entry, "cn") or ""),
            "category": "Группы",
            "title": "На подразделении широкое право у обычной группы",
            "severity": "high",
            "detail": "Найдено: " + "; ".join(rights) + ". Снимите это право. Полный список доступа в отчёт не копируется.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "dangerous_ou_right",
        })
    owners_filter = "(|(distinguishedName=" + escape_filter_chars("OU=Domain Controllers," + base) + ")(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    try:
        conn.search(
            base,
            owners_filter,
            search_scope=SUBTREE,
            attributes=["cn", "nTSecurityDescriptor"],
            size_limit=8,
            controls=[_SD_CONTROL],
        )
        owned = list(conn.entries) if (conn.result or {}).get("description") in {"success", "sizeLimitExceeded"} else []
    except (LDAPException, OSError, ValueError):
        owned = []
    for entry in owned:
        try:
            sid = _owner_sid(entry["nTSecurityDescriptor"].value)
        except Exception:
            continue
        if _owner_allowed(sid):
            continue
        _keep(findings, counts, {
            "hostname": name,
            "category": "Контроллеры",
            "title": "Владелец объекта контроллера не входит в штатные группы",
            "severity": "medium",
            "detail": "Владелец не Domain Admins, Enterprise Admins и не встроенные администраторы. Верните владельца штатной группе. Дескриптор целиком не копируется.",
            "tags": "baseline,surface,module:baseline_hygiene",
            "vuln_id": "dc_owner",
        })


def _trust_assessment(attributes: Any, trust_type: Any, direction: Any, encryption: Any = None) -> dict[str, Any]:
    """Interpret public TDO metadata; never infer negotiated crypto or effective SID policy."""
    def number(value: Any) -> int | None:
        if value is None or value == "" or isinstance(value, bool):
            return None
        try:
            result = int(value)
            return result if 0 <= result <= 0xffffffff else None
        except (TypeError, ValueError, OverflowError):
            return None
    flags, kind, flow, enc = map(number, (attributes, trust_type, direction, encryption))
    issues: list[dict[str, str]] = []
    def add(code: str, severity: str, title: str, detail: str) -> None:
        issues.append({"code": code, "severity": severity, "title": title, "detail": detail})
    within = bool(flags & 0x20) if flags is not None else None
    forest = bool(flags & 0x8) if flags is not None else None
    quarantine = bool(flags & 0x4) if flags is not None else None
    selective = bool(flags & 0x10) if flags is not None else None
    contradictory = within is True and forest is True
    trust_kind = "неизвестно" if flags is None or kind is None or contradictory else "MIT Kerberos" if kind == 3 else "внутри леса" if within else "лес" if forest else "внешнее" if kind == 2 else "downlevel" if kind == 1 else "неизвестно"
    # Quarantine is NOT a generic on/off switch for SID filtering at forest boundaries.
    sid = "unknown" if flags is None or kind is None or contradictory else "quarantine" if quarantine else "within_forest" if within else "forest_boundary" if forest else "external_no_quarantine" if kind == 2 else "unknown"
    if flags is None or kind is None or flow not in (1, 2, 3) or contradictory:
        add("trust_metadata", "info", "Неполные или противоречивые атрибуты доверия", "Нельзя сделать заключение о безопасности без trustAttributes, trustType и trustDirection.")
    if sid == "external_no_quarantine":
        add("trust_sid_filter", "high", "Внешнее доверие без флага карантина SID", "trustType=2, WITHIN_FOREST и FOREST_TRANSITIVE не заданы, QUARANTINED_DOMAIN=0. Требуется проверка SIDHistory и направления доверия; это не доказательство эксплуатации.")
    if forest and flags is not None and flags & 0x40:
        add("trust_treat_external", "medium", "Доверие лесов помечено TREAT_AS_EXTERNAL", "Флаг 0x40 меняет обработку SID на границе лесов. Не означает полного отключения фильтрации; проверьте необходимость и SIDHistory.")
    if (forest or trust_kind == "внешнее") and selective is False:
        add("trust_selective_auth", "medium", "Не задан флаг selective authentication", "CROSS_ORGANIZATION=0. Проверьте допустимость широкой области аутентификации; доступ к ресурсам по одному флагу не определяется.")
    if enc is not None and enc & 0x7 and not enc & 0x18:
        add("trust_rc4", "high", "В атрибуте шифрования нет AES, задан DES/RC4", "msDS-SupportedEncryptionTypes содержит DES/RC4 без AES128/AES256. Это конфигурация TDO, а не наблюдение согласованного алгоритма.")
    if kind == 3 and flags is not None and flags & 0x80:
        add("trust_mit_rc4", "medium", "Для MIT-доверия задан USES_RC4_ENCRYPTION", "Флаг trustAttributes 0x80 применим к MIT-доверию; он не доказывает RC4-only для доверий AD.")
    if flags is not None and flags & 0x800:
        add("trust_tgt", "high", "Явно разрешено межорганизационное делегирование TGT", "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION=1. Проверьте необходимость; отсутствие DISABLE_TGT_DELEGATION само по себе не является доказательством разрешения.")
    return {"kind": trust_kind, "trust_attributes": flags, "trust_type": kind, "direction_value": flow,
            "supported_encryption_types": enc, "sid_filter": True if quarantine else False if sid == "external_no_quarantine" else None,
            "sid_filter_mode": sid, "selective": selective, "non_transitive_flag": bool(flags & 1) if flags is not None else None,
            "assessment": issues, "limitations": ["Только метаданные локального TDO; настройки партнёра и effective access не проверены.", "Нет проверки аутентификации, SIDHistory и фактически согласованного шифрования."]}


def scan_trusts_ldap(connection: dict[str, Any]) -> dict[str, Any]:
    try:
        conn, base = connect(connection)
    except (LDAPException, OSError, RuntimeError) as exc:
        return {"ok": False, "findings": [], "score": None, "message": f"LDAPS/LDAP не открылся: {exc}"}
    findings: list[dict[str, Any]] = []
    try:
        trusts = _search(conn, f"CN=System,{base}", "(objectClass=trustedDomain)", ["cn", "trustDirection", "trustAttributes", "trustType", "msDS-SupportedEncryptionTypes", "whenChanged"], 50)
        directions = {"1": "входящее", "2": "исходящее", "3": "двустороннее"}
        for entry in trusts:
            name = str(_first(entry, "cn") or "")
            assessment = _trust_assessment(_first(entry, "trustAttributes"), _first(entry, "trustType"), _first(entry, "trustDirection"), _first(entry, "msDS-SupportedEncryptionTypes"))
            direction = directions.get(str(_first(entry, "trustDirection") or ""), "неизвестно")
            issues = assessment["assessment"]
            for issue in issues:
                findings.append({"hostname": name, "category": "Доверительные отношения",
                    "title": issue["title"] + ": " + name, "severity": issue["severity"],
                    "detail": issue["detail"] + f" Направление: {direction}. trustAttributes={assessment['trust_attributes']}; trustType={assessment['trust_type']}; encryptionTypes={assessment['supported_encryption_types']}.",
                    "tags": "trust,module:trusts", "vuln_id": issue["code"]})
            if not issues:
                findings.append({"hostname": name, "category": "Доверительные отношения", "title": "Метаданные доверия: " + name,
                    "severity": "info", "detail": assessment["kind"] + ", " + direction + ". Явных отклонений по доступным атрибутам нет; безопасность доверия не подтверждена.",
                    "tags": "trust,module:trusts", "vuln_id": "trust_metadata"})
            changed = _first(entry, "whenChanged")
            if isinstance(changed, datetime):
                stamp = changed.replace(tzinfo=None) if changed.tzinfo else changed
                age = (datetime.utcnow() - stamp).days
                if age > 180:
                    findings.append({
                        "hostname": name,
                        "category": "Доверительные отношения",
                        "title": f"Доверие {name} не менялось {age} дн.",
                        "severity": "low",
                        "detail": "Давняя дата изменения сама по себе не рвёт доверие. Сверьте, что партнёр ещё нужен.",
                        "tags": "trust,sid-filter,module:trusts",
                        "vuln_id": "trust_inactive",
                    })
    finally:
        conn.unbind()
    bad = sum(1 for item in findings if item["vuln_id"] == "trust_sid_filter")
    return {"ok": True, "findings": findings, "score": None, "message": f"Доверий по LDAP: {len(trusts)}, отметок: {len(findings)}, внешних без карантина SID: {bad}."}


def directory_picture(connection: dict[str, Any]) -> dict[str, Any]:
    """Срез каталога для экранов кабинета. Без участников групп, записей DNS и паролей."""
    try:
        conn, base = connect(connection)
    except (LDAPException, OSError, RuntimeError) as exc:
        return {"ok": False, "message": f"Каталог не открылся: {exc}"}
    try:
        domain = _safe_search(conn, base, "(objectClass=domainDNS)", ["msDS-Behavior-Version", "minPwdLength", "pwdHistoryLength", "lockoutThreshold", "maxPwdAge", "fSMORoleOwner", "gPLink", "gPOptions"], 1)
        level = ""
        policy = {"length": "", "history": "", "lockout": "", "max_age_days": ""}
        domain_links: list[dict[str, Any]] = []
        domain_block = False
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
            domain_links = _gplinks(str(_first(row, "gPLink") or ""))
            try:
                domain_block = bool(int(_first(row, "gPOptions") or 0) & 1)
            except (TypeError, ValueError):
                domain_block = False
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
            for entry in _safe_search(conn, site_base, "(objectClass=nTDSDSA)", ["distinguishedName"], 80):
                server_name, site_name = _dc_site(str(_first(entry, "distinguishedName") or ""))
                bucket = known.get(site_name.lower())
                if bucket is not None and server_name and server_name not in bucket["servers"]:
                    bucket["servers"].append(server_name)
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
        for entry in _safe_search(conn, base, "(objectClass=organizationalUnit)", ["ou", "distinguishedName", "gPLink", "gPOptions"], 80):
            dn = str(_first(entry, "distinguishedName") or "")
            chain = [part[3:] for part in dn.split(",") if part.upper().startswith("OU=")]
            name = chain[0] if chain else str(_first(entry, "ou") or "")
            if not name:
                continue
            try:
                blocked = bool(int(_first(entry, "gPOptions") or 0) & 1)
            except (TypeError, ValueError):
                blocked = False
            ous.append(name)
            ou_nodes.append({
                "name": name[:80],
                "path": "/".join(reversed(chain))[:220],
                "blocked": blocked,
                "links": _gplinks(str(_first(entry, "gPLink") or "")),
            })
        domains = []
        if config:
            for entry in _safe_search(conn, f"CN=Partitions,{config}", "(objectClass=crossRef)", ["dnsRoot", "nCName", "systemFlags"], 24):
                try:
                    flags = int(_first(entry, "systemFlags") or 0)
                except (TypeError, ValueError):
                    flags = 0
                if not flags & 2:
                    continue
                context = str(_first(entry, "nCName") or "").upper()
                if any(token in context for token in ("CN=SCHEMA", "CN=CONFIGURATION", "DNSZONES")):
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
        for entry in _safe_search(conn, f"CN=Policies,CN=System,{base}", "(objectClass=groupPolicyContainer)", ["cn", "displayName", "flags", "gPCWQLFilter"], 60):
            try:
                flags = int(_first(entry, "flags") or 0)
            except (TypeError, ValueError):
                flags = 0
            wmi_match = re.search(r"\{[0-9A-Fa-f-]+\}", str(_first(entry, "gPCWQLFilter") or ""))
            gpos.append({
                "id": str(_first(entry, "cn") or ""),
                "name": str(_first(entry, "displayName") or ""),
                "state": flag_text.get(flags, "состояние не прочитано"),
                "wmi": wmi_match.group(0) if wmi_match else "",
            })
        wmi_filters = []
        for entry in _safe_search(conn, f"CN=SOM,CN=WMIPolicy,CN=System,{base}", "(objectClass=msWMI-Som)", ["msWMI-Name", "msWMI-Parm1", "msWMI-Parm2", "msWMI-ID"], 30):
            wmi_filters.append({
                "id": str(_first(entry, "msWMI-ID") or "")[:64],
                "name": str(_first(entry, "msWMI-Name") or "")[:80],
                "note": str(_first(entry, "msWMI-Parm1") or "")[:160],
                "query": str(_first(entry, "msWMI-Parm2") or "")[:180],
            })
        service_accounts = []
        for entry in _safe_search(conn, base, "(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))", ["cn", "sAMAccountName", "dNSHostName", "userAccountControl", "objectClass"], 40):
            classes = _values(entry, "objectClass")
            try:
                uac = int(_first(entry, "userAccountControl") or 0)
            except (TypeError, ValueError):
                uac = 0
            service_accounts.append({
                "name": str(_first(entry, "cn") or _first(entry, "sAMAccountName") or "")[:80],
                "host": str(_first(entry, "dNSHostName") or "")[:80],
                "kind": "gMSA" if any(str(item).lower() == "msds-groupmanagedserviceaccount" for item in classes) else "MSA",
                "disabled": bool(uac & 2),
            })
        trusts = []
        directions = {"1": "входящее", "2": "исходящее", "3": "двустороннее"}
        for entry in _safe_search(conn, f"CN=System,{base}", "(objectClass=trustedDomain)", ["cn", "trustDirection", "trustAttributes", "trustType", "msDS-SupportedEncryptionTypes"], 20):
            assessment = _trust_assessment(_first(entry, "trustAttributes"), _first(entry, "trustType"), _first(entry, "trustDirection"), _first(entry, "msDS-SupportedEncryptionTypes"))
            trusts.append({"name": str(_first(entry, "cn") or ""),
                "direction": directions.get(str(_first(entry, "trustDirection") or ""), "неизвестно"), **assessment})
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
            "wmi": wmi_filters,
            "service_accounts": service_accounts,
            "domain_links": domain_links,
            "domain_block": domain_block,
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


def _dc_site(dn: str) -> tuple[str, str]:
    """Имя контроллера и сайт из DN объекта NTDS Settings. Сервер без этой службы контроллером не считается."""
    parts = [part for part in dn.split(",") if part]
    server = ""
    site = ""
    for index, part in enumerate(parts):
        if part.upper().startswith("CN=NTDS SETTINGS") and index + 1 < len(parts) and parts[index + 1].upper().startswith("CN="):
            server = parts[index + 1][3:]
        if part.upper() == "CN=SERVERS" and index + 1 < len(parts) and parts[index + 1].upper().startswith("CN="):
            site = parts[index + 1][3:]
    return server, site


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
_ANY_PURPOSE = "2.5.29.37.0"
_ENROLL_AGENT = "1.3.6.1.4.1.311.20.2.1"


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
        conn, domain_base = connect(connection)
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
                attributes=["cn", "displayName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage", "msPKI-Minimal-Key-Size", "msPKI-Template-Schema-Version"],
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
        for entry in rows:
            if len(findings) >= 40:
                break
            cn = str(_first(entry, "cn") or "template")
            title = str(_first(entry, "displayName") or cn).replace("|", "/")
            key_size = _as_int(entry, "msPKI-Minimal-Key-Size")
            name_flag = _as_int(entry, "msPKI-Certificate-Name-Flag")
            enroll_flag = _as_int(entry, "msPKI-Enrollment-Flag")
            eku = _as_list(entry, "pKIExtendedKeyUsage")
            auth = _CLIENT_AUTH in eku or _SMART_CARD in eku
            if 0 < key_size < 2048:
                findings.append({
                    "hostname": str(connection.get("host") or ""),
                    "category": "AD CS",
                    "title": f"Шаблон {title}: короткий ключ",
                    "severity": "medium",
                    "detail": f"Минимальная длина ключа шаблона {cn} меньше 2048. Сертификат не выпускается и открытый ключ не копируется.",
                    "tags": "compliance,adcs,module:ad_cs",
                    "vuln_id": "adcs_weak_key",
                })
            if auth and (name_flag & 0x80000):
                findings.append({
                    "hostname": str(connection.get("host") or ""),
                    "category": "AD CS",
                    "title": f"Шаблон {title}: нет расширения безопасности",
                    "severity": "high",
                    "detail": f"Шаблон {cn} выдаёт сертификат входа и не добавляет расширение безопасности. Закрытый ключ не читается.",
                    "tags": "compliance,adcs,module:ad_cs",
                    "vuln_id": "adcs_no_sid_ext",
                })
            schema_version = _as_int(entry, "msPKI-Template-Schema-Version")
            if schema_version == 1 and (name_flag & 1):
                findings.append({
                    "hostname": str(connection.get("host") or ""),
                    "category": "AD CS",
                    "title": f"Шаблон {title}: старая схема и имя от заявителя",
                    "severity": "high",
                    "detail": f"Шаблон {cn} первой версии схемы разрешает имя субъекта от заявителя. Сертификат не выпускается.",
                    "tags": "compliance,adcs,module:ad_cs",
                    "vuln_id": "adcs_schema_v1",
                })
            if _ANY_PURPOSE in eku or cn.lower() in {"subca", "subordinateca"}:
                findings.append({
                    "hostname": str(connection.get("host") or ""),
                    "category": "AD CS",
                    "title": f"Шаблон {title}: слишком широкое назначение",
                    "severity": "high",
                    "detail": f"Шаблон {cn} разрешает любое назначение или выпуск подчиненного центра. Согласование и право выпуска сузьте. Сертификат не запрашивается.",
                    "tags": "compliance,adcs,module:ad_cs",
                    "vuln_id": "adcs_any_purpose",
                })
            if _ENROLL_AGENT in eku and (enroll_flag & 2) == 0:
                findings.append({
                    "hostname": str(connection.get("host") or ""),
                    "category": "AD CS",
                    "title": f"Шаблон {title}: агент подачи заявок без согласования",
                    "severity": "high",
                    "detail": f"Шаблон {cn} содержит назначение агента подачи и не требует ручного выпуска. Сертификат от имени другого человека не запрашивается.",
                    "tags": "compliance,adcs,module:ad_cs",
                    "vuln_id": "adcs_enroll_agent",
                })
        services = "CN=Enrollment Services,CN=Public Key Services,CN=Services," + config
        try:
            conn.search(services, "(objectClass=pKIEnrollmentService)", search_scope=SUBTREE, attributes=["cn", "msPKI-Enrollment-Servers"], size_limit=20)
            for entry in list(conn.entries):
                blob = " ".join(_as_list(entry, "msPKI-Enrollment-Servers")).lower()
                if "http://" not in blob:
                    continue
                findings.append({
                    "hostname": str(connection.get("host") or ""),
                    "category": "AD CS",
                    "title": "Выпуск сертификатов разрешён по HTTP",
                    "severity": "medium",
                    "detail": "У центра сертификации " + str(_first(entry, "cn") or "") + " в строке выпуска есть адрес без TLS. Сам адрес в отчёт не копируется. Сертификат не запрашивается.",
                    "tags": "compliance,adcs,module:ad_cs",
                    "vuln_id": "adcs_http",
                })
                if len(findings) >= 40:
                    break
        except LDAPException:
            pass
        oid_base = "CN=OID,CN=Public Key Services,CN=Services," + config
        for entry in _safe_search(conn, oid_base, "(msDS-OIDToGroupLink=*)", ["cn", "displayName"], 12):
            if len(findings) >= 40:
                break
            title = str(_first(entry, "displayName") or _first(entry, "cn") or "OID")
            findings.append({
                "hostname": str(connection.get("host") or ""),
                "category": "AD CS",
                "title": f"Политика выпуска {title} связана с группой",
                "severity": "high",
                "detail": "Идентификатор политики выпуска указывает на группу каталога. Членство в этой группе не копируется. Уберите связь, если группа не должна получать права от сертификата.",
                "tags": "compliance,adcs,module:ad_cs",
                "vuln_id": "adcs_oid_group",
            })
        if domain_base:
            for entry in _safe_search(conn, domain_base, "(&(objectCategory=person)(altSecurityIdentities=*))", ["sAMAccountName"], 12):
                if len(findings) >= 40:
                    break
                findings.append({
                    "hostname": str(_first(entry, "sAMAccountName") or ""),
                    "category": "AD CS",
                    "title": "У записи задано явное сопоставление сертификата",
                    "severity": "medium",
                    "detail": "Атрибут altSecurityIdentities заполнен. Само сопоставление в отчёт не копируется. Оставьте его только там, где сертификат сознательно привязан к человеку.",
                    "tags": "compliance,adcs,module:ad_cs",
                    "vuln_id": "adcs_explicit_map",
                })
        for base_dn, vuln_id, title in (
            (templates, "adcs_template_acl", "На шаблоне сертификата широкое право"),
            (services, "adcs_ca_acl", "На центре сертификации широкое право"),
        ):
            try:
                conn.search(base_dn, "(objectClass=*)", search_scope=LEVEL, attributes=["cn", "nTSecurityDescriptor"], size_limit=30, controls=[_SD_CONTROL])
                secured = list(conn.entries) if (conn.result or {}).get("description") in {"success", "sizeLimitExceeded"} else []
            except (LDAPException, OSError, ValueError):
                secured = []
            for entry in secured:
                if len(findings) >= 40:
                    break
                try:
                    rights = _broad_aces(entry["nTSecurityDescriptor"].value)
                except Exception:
                    continue
                if not rights:
                    continue
                findings.append({
                    "hostname": str(connection.get("host") or ""),
                    "category": "AD CS",
                    "title": title,
                    "severity": "high",
                    "detail": str(_first(entry, "cn") or "") + ": " + "; ".join(rights) + ". Полный список доступа не копируется. Сертификат не выпускается.",
                    "tags": "compliance,adcs,module:ad_cs",
                    "vuln_id": vuln_id,
                })
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
