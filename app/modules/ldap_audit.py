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
        "message": f"Каталог прочитан по {'LDAPS' if connection.get('ldap_ssl', True) else 'LDAP'}. Базовых отклонений: {len(findings)}.",
    }


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
