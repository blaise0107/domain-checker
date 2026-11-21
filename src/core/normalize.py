"""Нормализация домена: ввод пользователя -> канонический хост и кандидаты для проверки."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Небольшой встроенный список многочастных суффиксов — без сетевых запросов.
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.mx", "com.ar", "com.co", "com.tr", "com.ua", "com.pl",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "ne.kr", "or.kr", "go.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.in", "net.in", "org.in", "gov.in", "edu.in",
    "com.sg", "com.hk", "com.tw", "com.my", "com.vn",
    "co.il", "net.il", "org.il", "gov.il",
    "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru",
    "co.id", "or.id", "web.id", "go.id",
    "co.za", "org.za", "net.za", "gov.za",
    "com.ph", "net.ph", "org.ph",
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app",
    "netlify.app", "herokuapp.com", "cloudfront.net", "azurewebsites.net",
    "s3.amazonaws.com", "hf.space", "replit.dev", "onrender.com",
}

COMMON_SUBDOMAINS = (
    "www", "api", "console", "app", "auth", "cdn", "static", "platform",
    "connect", "cdn-lfs", "oaiusercontent", "claudeusercontent",
)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_domain(raw: str) -> str | None:
    """Принимает 'https://API.Example.com:443/path?x=1' -> 'api.example.com'."""
    if not raw or not isinstance(raw, str):
        return None
    value = raw.strip().lower().strip('"\'<>')
    if not value:
        return None
    head = value.split("://")[-1].split("/")[0].split("?")[0]
    if is_ip(head.split(":")[0]):
        candidate = head.split(":")[0].strip("[]")
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    if "://" not in value:
        value = "//" + value
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    host = (parts.hostname or "").rstrip(".")
    if host.startswith("["):  # IPv6 в квадратных скобках
        host = host.strip("[]")
    if not host or len(host) > 253:
        return None
    if is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) < 2 or any(not LABEL.match(label) for label in labels):
        return None
    return host


def registrable_domain(host: str) -> str:
    """Возвращает registrable domain (eTLD+1) или IP как есть."""
    if is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    suffix2 = ".".join(labels[-2:])
    suffix3 = ".".join(labels[-3:])
    if suffix3 in MULTI_SUFFIXES:
        return ".".join(labels[-4:]) if len(labels) >= 4 else host
    if suffix2 in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return suffix2


def parent_domains(host: str) -> list[str]:
    """Все родительские домены от ближайшего до registrable."""
    if is_ip(host):
        return []
    labels = host.split(".")
    limit = registrable_domain(host).count(".") + 1
    result = []
    for i in range(1, len(labels)):
        candidate = ".".join(labels[i:])
        if candidate == host:
            continue
        if len(candidate.split(".")) < limit:
            break
        result.append(candidate)
    return result


def candidate_hosts(host: str, redirect_target: str | None = None) -> list[str]:
    """Список доменов для BlockCheck: введённый, родители, корень, частые поддомены, редирект."""
    result: list[str] = []

    def add(value: str | None) -> None:
        if not value:
            return
        value = normalize_domain(value)
        if value and value not in result:
            result.append(value)

    add(host)
    for parent in parent_domains(host):
        add(parent)
    base = registrable_domain(host)
    add(base)
    if not is_ip(base):
        for prefix in COMMON_SUBDOMAINS:
            add(f"{prefix}.{base}")
    if redirect_target:
        add(redirect_target)
        for parent in parent_domains(redirect_target):
            add(parent)
    return result[:16]


def domain_matches(pattern: str, host: str) -> bool:
    """Совпадение записи списка с хостом: голой домен покрывает поддомены, '^' — только DoH."""
    raw = pattern.strip().lower()
    doh_only = raw.startswith("^")
    pattern = raw.lstrip("^")
    if not pattern:
        return False
    if doh_only:
        return host == pattern
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern or host.endswith("." + pattern)
