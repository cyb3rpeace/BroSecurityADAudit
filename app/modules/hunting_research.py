"""Public documentation research. Never send tenant evidence or free-form text."""
from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlparse

import requests

SEARCH_ENDPOINT = "https://html.duckduckgo.com/html/"
ALLOWLIST = frozenset({"attack.mitre.org", "learn.microsoft.com", "www.microsoft.com", "www.cisa.gov", "www.nist.gov", "docs.velociraptor.app", "unit42.paloaltonetworks.com", "www.welivesecurity.com", "www.bleepingcomputer.com"})
MAX_BYTES = 256 * 1024
MAX_RESULTS = 5
# Only these static public concepts may leave the application. No extracted names.
CONCEPTS = (
    (r"powershell|повершел", "PowerShell security detection"),
    (r"kerberoast|кербер", "Kerberoasting detection mitigation"),
    (r"credential|уч[её]тн|парол", "credential access detection"),
    (r"persist|закреп|автозапуск", "persistence detection"),
    (r"scheduled task|планиров|задан", "scheduled task security"),
    (r"systemd|linux|линукс", "Linux systemd threat hunting"),
    (r"dns|днс", "DNS threat hunting"),
    (r"ransomware|шифроваль", "ransomware detection response"),
    (r"lateral|латераль|боков", "lateral movement detection"),
    (r"command.{0,5}control|\bc2\b|управления", "command and control detection"),
    (r"process|процесс", "process behavior investigation"),
    (r"phish|фишинг", "phishing detection response"),
    (r"vulnerab|уязвим", "vulnerability mitigation"),
    (r"active directory|актив.{0,3}директор", "Active Directory security"),
    (r"threat hunt|форенз|компрометац|кибер|безопасност|инцидент", "threat hunting investigation methodology"),
)


def sanitized_question(question: str) -> str:
    """Project a question onto static concepts, dropping all arbitrary tokens."""
    text = question[:4000]
    text = re.sub(r"(?i)(?:password|passwd|pwd|token|secret|api[_-]?key|authorization|cpassword)\s*[=:]\s*\S+", " ", text)
    text = re.sub(r"https?://\S+|\S*[\\/@.]\S*|\b[\w-]*\d[\w-]*\b", " ", text)
    concepts = [label for pattern, label in CONCEPTS if re.search(pattern, text, re.I)]
    return "; ".join(concepts[:3])[:240]


def safe_url(value: str) -> str | None:
    try:
        parsed = urlparse(value)
        if parsed.hostname in {"duckduckgo.com", "html.duckduckgo.com"} or value.startswith("/l/?"):
            value = parse_qs(parsed.query).get("uddg", [""])[0]
            parsed = urlparse(value)
        if (parsed.scheme != "https" or parsed.hostname not in ALLOWLIST
                or parsed.username or parsed.password or parsed.port not in (None, 443)
                or len(value) > 1500 or any(ord(c) < 32 for c in value)):
            return None
        return value
    except ValueError:
        return None


class SearchParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.results = []
        self.url = None
        self.title = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "result__a" in attrs.get("class", "").split():
            self.url = safe_url(attrs.get("href", ""))
            self.title = []

    def handle_data(self, data):
        if self.url:
            self.title.append(data[:300])

    def handle_endtag(self, tag):
        if tag == "a" and self.url:
            if len(self.results) < MAX_RESULTS and self.url not in {r["url"] for r in self.results}:
                self.results.append({"title": "".join(self.title).strip()[:300], "url": self.url, "host": urlparse(self.url).hostname})
            self.url = None


def research_question(question: str, *, opt_in: bool = False, timeout: int = 8) -> dict:
    query = sanitized_question(question) if opt_in else ""
    result = {"status": "not_requested" if not opt_in else "not_supported", "enabled": opt_in,
              "sanitized_question": query, "results": [],
              "disclosure": "В поиск передаются только общие понятия из фиксированного словаря; evidence, имена, адреса и секреты не отправляются. Публичные источники не доказывают событие в tenant."}
    if not query:
        return result
    return _search(query, result, timeout)


def research_ioc(ioc: str, timeout: int = 8) -> dict:
    result = {"status": "not_supported", "ioc": "", "results": [],
              "disclosure": "Только публичный IPv4 или SHA-256; источники не доказывают компрометацию."}
    if re.fullmatch(r"[0-9a-fA-F]{64}", ioc):
        query = ioc.lower()
    else:
        try:
            address = ipaddress.ip_address(ioc)
            if address.version != 4 or not address.is_global:
                return result
            query = str(address)
        except ValueError:
            return result
    result["ioc"] = query
    return _search(query, result, timeout)


def _search(query: str, result: dict, timeout: int) -> dict:
    try:
        # No redirects, cookies, tenant headers or document fetching; bound response size.
        with requests.get(SEARCH_ENDPOINT, params={"q": query + " (" + " OR ".join("site:" + h for h in sorted(ALLOWLIST)) + ")"},
                          timeout=max(3, min(10, timeout)), allow_redirects=False, stream=True,
                          headers={"User-Agent": "AD-Identity-Guard-public-research/2.0"}) as response:
            if response.status_code != 200:
                result["status"] = "unavailable"
                return result
            body = bytearray()
            for chunk in response.iter_content(8192):
                if len(body) + len(chunk) > MAX_BYTES:
                    result["status"] = "response_too_large"
                    return result
                body.extend(chunk)
        parser = SearchParser()
        parser.feed(body.decode("utf-8", errors="replace"))
        result.update(status="completed" if parser.results else "no_results", results=parser.results)
    except (requests.RequestException, ValueError):
        result["status"] = "unavailable"
    return result
