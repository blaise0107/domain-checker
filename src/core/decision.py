"""Движок решений: превращает собранные доказательства в вердикт и конкретные действия."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from .knowledge import DomainEntry, Knowledge, Pitfall
from .normalize import domain_matches, registrable_domain
from .router import RouterClient

LEVEL_TITLES = {
    "SNI": "DPI / подмена SNI",
    "DNS": "Подмена DNS / резолвинг",
    "IP": "Блокировка по IP/порту",
    "REGION": "Регион/аккаунт на стороне сервиса",
    "OK": "Блокировки нет",
    "NXDOMAIN": "Домен не существует (NXDOMAIN)",
    "UNKNOWN": "Недостаточно данных",
}


@dataclass
class Action:
    kind: str
    title: str
    path: str = ""
    line: str = ""
    commands: str = ""
    note: str = ""
    url: str = ""


@dataclass
class Verdict:
    domain: str
    candidates: list[str]
    level: str
    title: str
    summary: str
    confidence: str
    evidence: list[tuple[str, str, str]] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    pitfalls: list[Pitfall] = field(default_factory=list)
    knowledge: list[DomainEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def level_title(self) -> str:
        return LEVEL_TITLES.get(self.level, self.level)


def _suspicious_ip(value: str | None) -> bool:
    if not value:
        return True
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (addr.is_private or addr.is_loopback or addr.is_unspecified
            or addr.is_link_local or addr.is_multicast)


def _fmt_bc(target: dict[str, Any] | None) -> str:
    if not target:
        return "нет данных"
    parts = []
    if target.get("blocked") is not None:
        parts.append("blocked=" + str(target["blocked"]).lower())
    if target.get("verdict"):
        parts.append("verdict=" + str(target["verdict"]))
    if target.get("code") not in (None, ""):
        parts.append("code=" + str(target["code"]))
    if target.get("ttfb_ms") is not None:
        parts.append(f"ttfb={target['ttfb_ms']} мс")
    if target.get("connect_ms") not in (None, ""):
        parts.append(f"connect={target['connect_ms']} мс")
    return ", ".join(parts) if parts else "пустой ответ"


def _known_level(entries: list[DomainEntry], host: str) -> str | None:
    """Только точное совпадение домена. Наследовать вердикт другого кандидата нельзя."""
    for entry in entries:
        if entry.domain == host:
            return entry.level
    return None


def analyze(
    domain: str,
    data: dict[str, Any],
    knowledge: Knowledge,
    cfg: Config,
) -> Verdict:
    hosts: list[str] = data.get("hosts", [domain])
    host = hosts[0] if hosts else domain
    base = registrable_domain(host)
    redirect = data.get("redirect_target")

    bc = data.get("blockcheck", {})
    # DNS и IP строго целевого хоста: подстановка данных www/редиректов даёт
    # ложные DNS/IP-вердикты и лишние маршруты VPN-туннель.
    dns_info: dict[str, Any] = data.get("dns", {}).get(host) or {}
    ips: list[str] = list(dns_info.get("ips", []))
    connections = data.get("connections", {})
    ip_proof = RouterClient.ip_block_evidence(connections.get("items", []), ips) if ips else []
    known = knowledge.lookup(hosts)
    known_level = _known_level(known, host)

    list_status = str(data.get("lists", {}).get("status", "none"))
    list_message = str(data.get("lists", {}).get("message", "Домен ни в одном списке nfqws2 не найден."))
    list_matches = [m for m in data.get("lists", {}).get("matches", []) if m.get("host") == host]
    general_match = [m for m in list_matches
                     if m.get("short") == "list_general" and not m.get("doh_only")]
    dns_matches = [m for m in data.get("dnsserver", {}).get("matches", []) if m.get("host") == host]
    # Маршрут считаем "уже добавленным" только если он относится к целевому
    # хосту или к его IP; совпадение у другого кандидата не считается.
    avo_matches = [
        m for m in data.get("tunnel", {}).get("matches", [])
        if m.get("target") == host or m.get("target") in ips
        or domain_matches(str(m.get("line", "")).split(":")[0], host)
    ]

    # НЕ подменять результат основного хоста первым попавшимся: чужой результат
    # (www, редирект, другой кандидат) привёл бы к неверному вердикту.
    bc_target = next((v for k, v in bc.get("targets", {}).items() if k == host), None)
    blocked = bool(bc_target and bc_target.get("blocked") is True)
    verdict_word = str(bc_target.get("verdict", "")).lower() if bc_target else ""
    bc_err = str(bc_target.get("err", "") or "").lower() if bc_target else ""
    # NXDOMAIN — только когда НЕ смог резолвить и сам роутерный DNS-тест.
    # BlockCheck часто не может резолвить через 1.1.1.1/8.8.8.8 (изоляция,
    # перехват или недоступность публичного резолвера у провайдера) и выдаёт
    # «no such host» для вполне существующего домена — это НЕ NXDOMAIN.
    # NXDOMAIN требует УСПЕШНОГО, но пустого DNS-замера: если тест роутера
    # просто упал (ok=False), «no such host» от BlockCheck не доказывает NXDOMAIN.
    nxdomain = (
        verdict_word == "dns" and dns_info.get("ok", False) and not ips and (
            "no such host" in bc_err or "nxdomain" in bc_err
            or "name error" in bc_err or "nodata" in bc_err
        )
    )
    blockcheck_dns_issue = (
        verdict_word == "dns" and bool(ips) and (
            "no such host" in bc_err or "lookup" in bc_err or "nxdomain" in bc_err
        )
    )
    # Циклический редирект сайта (?__rr=1 у Ozon и т.п.) — BlockCheck ошибочно
    # помечает blocked=true/verdict=error, но это НЕ блокировка провайдера.
    redirect_loop = (
        verdict_word == "error" and (
            "redirect" in bc_err or "stopped after" in bc_err
        )
    )
    # Провал DNS-замера (ok=False, сетевая ошибка) НЕ подмена: подозрительным
    # считаем только успешный пустой/мусорный ответ.
    suspicious_dns = (dns_info.get("ok", False) and not ips) or any(_suspicious_ip(ip) for ip in ips)

    # ---------- выбор уровня ----------
    confidence = "высокая"
    if nxdomain:
        level = "NXDOMAIN"
        confidence = "высокая"
        warnings = ["Проверьте написание домена и расширение зоны: "
                    "возможно, адрес введён с опечаткой (например, 1tvrrr.ru вместо 1tv.ru)."]
    elif redirect_loop:
        # Сайт отвечает (у Ozon —Loop ?__rr=1), BlockCheck просто не смог
        # проследить редиректы. Провайдер здесь ни при чём.
        level = "OK"
        confidence = "средняя"
        warnings = ["BlockCheck завершился ошибкой из-за циклического редиректа сайта "
                    "(«stopped after … redirects»), а не из-за блокировки. "
                    "Сайт доступен — списки nfqws2 и DNS-правила не нужны."]
    elif blockcheck_dns_issue:
        # Роутерный DNS знает IP, а BlockCheck — нет: публичный резолвер
        # (1.1.1.1/8.8.8.8) в изоляции недоступен/перехвачен. Домен существует.
        level = "DNS"
        confidence = "средняя"
        warnings = ["BlockCheck не смог резолвить домен через публичный резолвер "
                    "(1.1.1.1/8.8.8.8), но DNS роутера вернул реальный IP — "
                    "домен существует. Это особенность изоляции BlockCheck или подмена DNS, "
                    "а не NXDOMAIN. Для самого сайта достаточно DNS-правила/релея; "
                    "если TLS висит — дополнительно list-general.list."]
    elif not bc.get("ok", False) or not data.get("panel_ok", False):
        level = known_level or "UNKNOWN"
        confidence = "низкая"
        warnings = []
        if not data.get("panel_ok", False):
            warnings.append("Панель роутера недоступна — выбран вердикт по базе знаний. "
                            "Повторите проверку при включённом роутере.")
        else:
            warnings.append("BlockCheck завершился ошибкой — вердикт построен по базе знаний "
                            "и косвенным признакам. Повторите проверку в спокойные моменты: "
                            "сбой изоляции часто вызван переподключением PPPoE или рестартом nfqws2.")
    elif not blocked and bc.get("ok", False):
        # Провайдер НЕ блокирует (BlockCheck получил ответ 200/301/302/403).
        # conntrack здесь НЕ доказательство блокировки: SYN_SENT на один из IP
        # релея/балансировки — норма. Опираемся на BlockCheck, DNS и базу знаний.
        if suspicious_dns:
            level = "DNS"
            confidence = "средняя"
            warnings = ["BlockCheck блокировки не показал, но DNS-ответ подозрительный. "
                        "Проверьте запись А в панели вручную."]
        elif known_level == "REGION":
            level = "REGION"
            warnings = []
        elif known_level in {"SNI", "DNS", "IP", "OK"}:
            level = known_level
            confidence = "средняя" if known_level != "OK" else "высокая"
            if known_level == "IP":
                warnings = ["База знаний: для этого домена подтверждён блок по IP (провайдер роняет SYN). "
                            "Сейчас BlockCheck не показал блок — проверьте conntrack в момент сбоя. "
                            "Если сервис не открывается — VPN-туннель/туннель остаётся крайней мерой."]
            elif known_level in {"SNI", "DNS"}:
                if dns_matches:
                    warnings = ["DNS-правило для этого домена уже настроено в панели, "
                                "BlockCheck блокировки не показывает — дополнительных действий не требуется. "
                                "VPN-туннель не нужен."]
                else:
                    warnings = ["База знаний: для этого домена требуется DNS-правило/релей. "
                                "Сейчас BlockCheck блокировки не показывает, но правило в панели не найдено — "
                                "настройте DNS Server."]
            else:
                warnings = []
        else:
            level = "OK"
            warnings = []
    elif blocked and verdict_word == "dns":
        # BlockCheck — эталон: вердикт DNS важнее conntrack. SYN_SENT на
        # подставной DNS-адрес — следствие подмены DNS, а не IP-блока.
        level = "DNS"
        warnings = []
    elif ip_proof:
        level = "IP"
        warnings = []
    elif blocked and (verdict_word == "timeout" or verdict_word == "error"):
        if known_level == "IP" or _zero_connect(bc_target):
            level = "IP"
            confidence = "средняя" if not ip_proof else "высокая"
            warnings = ([] if ip_proof else
                        ["Прямых доказательств в conntrack нет. Подтвердите уровень IP: "
                         "откройте сервис и проверьте SYN_SENT / unreplied / 0 байт."])
        else:
            level = "SNI"
            warnings = []
    elif blocked:
        level = "SNI"
        warnings = []
    else:
        level = "OK"
        warnings = []

    if not data.get("panel_ok", False):
        warnings.append("Панель NFQWS2 (:8090) не отвечает — живые замеры отсутствуют.")
    if not data.get("lists", {}).get("ok", False):
        list_errors = data.get("lists", {}).get("errors") or []
        if list_errors:
            warnings.append("Не все списки nfqws2 прочитаны (" + "; ".join(list_errors[:3]) +
                            ") — проверка «уже в списке» может быть неполной.")
        else:
            warnings.append("SSH к Entware недоступен — нельзя проверить, есть ли домен уже в списках.")
    if data.get("panel_ok") and dns_info and not dns_info.get("ok", False):
        warnings.append("DNS-тест роутера не удался — DNS-слой не проверен; вердикт опирается на BlockCheck.")
    if (list_status in {"conflict", "wrong_exclude", "wrong_google", "wrong_doh"}
            and level in {"SNI", "DNS"}):
        warnings.append(list_message)
    for entry in known:
        if entry.level != level:
            warnings.append(f"В базе знаний для {entry.domain}: {entry.level} — {entry.action}. "
                            "Учтите исторический вердикт.")

    # ---------- доказательства ----------
    evidence: list[tuple[str, str, str]] = []
    evidence.append(("Панель :8090", data.get("panel_message", "нет данных"),
                     "ok" if data.get("panel_ok") else "bad"))
    evidence.append(("SSH Entware (222/22)", "доступен" if data.get("lists", {}).get("ok") else "недоступен",
                     "ok" if data.get("lists", {}).get("ok") else "warn"))
    bc_value = _fmt_bc(bc_target) if bc.get("ok") else (bc.get("error") or "нет данных")
    if bc_err:
        bc_value += f" · {bc_err[:200]}"
    evidence.append((f"BlockCheck: {host}", bc_value,
                     "bad" if (nxdomain or blocked) else ("ok" if bc.get("ok") else "bad")))
    dns_value = ", ".join(ips) if ips else (dns_info.get("error") or "нет ответа")
    if dns_info.get("route"):
        dns_value += f" · маршрут: {dns_info['route']}"
    if dns_info.get("upstream"):
        dns_value += f" · апстрим: {dns_info['upstream']}"
    evidence.append((f"DNS A: {host}", dns_value, "ok" if ips and not suspicious_dns else "warn"))
    if ip_proof:
        proof = ip_proof[0]
        evidence.append(("Conntrack", f"{proof['dst']}:{proof['dport']} {proof['state']}, "
                                      f"unreplied={proof['unreplied']}, reply_bytes={proof['reply_bytes']}", "bad"))
    else:
        evidence.append(("Conntrack", "признаков IP-блока нет"
                         if connections.get("ok") else "нет данных", "ok" if connections.get("ok") else "warn"))
    status_color = {"ok": "ok", "none": "ok", "conflict": "bad",
                    "wrong_exclude": "bad", "wrong_google": "warn", "wrong_doh": "warn"}.get(list_status, "warn")
    evidence.append(("Списки nfqws2", list_message, status_color))
    evidence.append(("DNS Server rules",
                     f"совпадений: {len(dns_matches)} (всего {data.get('dnsserver', {}).get('rules_count', 0)})",
                     "ok" if dns_matches else "warn"))
    evidence.append(("VPN-туннель routes",
                     "; ".join(m["line"] for m in avo_matches) or "адрес не найден",
                     "warn" if avo_matches else "ok"))
    if redirect:
        evidence.append(("Редирект", redirect, "warn"))
    evidence.append(("База знаний", f"совпадений: {len(known)}", "ok" if known else "warn"))

    # ---------- действия ----------
    actions: list[Action] = []
    note_known = "; ".join(f"{e.domain}: {e.action}" for e in known[:3])

    if level == "NXDOMAIN":
        actions.append(Action(
            kind="info",
            title="Домен не существует — проверьте написание",
            note="BlockCheck не смог резолвить имя даже через публичный резолвер 8.8.8.8 "
                 "(`no such host` / NXDOMAIN). Это не блокировка и не подмена DNS: "
                 "такого домена нет в DNS. Добавление в списки nfqws2, DNS-правила или VPN-туннель "
                 "ничего не изменят. Проверьте опечатку, зону (.ru/.com) и существует ли сайт вообще.",
        ))

    if level == "SNI":
        already = bool(general_match or [
            m for m in list_matches
            if m.get("short") == "list_general_user" and not m.get("doh_only")
        ])
        # Если проверяемый домен уже в списке — показываем именно его, а не
        # родительский registrable domain (forum.ru-board.com != ru-board.com).
        line = host if already or _is_doh(host) else base
        commands = (
            "L=/opt/etc/nfqws2/lists/list-general.list\n"
            f'cp -a "$L" "/opt/var/backup-$(date +%Y%m%d-%H%M%S).list"\n'
            f'grep -qx "{line}" "$L" || echo "{line}" >> "$L"\n'
            "/opt/etc/init.d/S51nfqws2 restart"
        )
        actions.append(Action(
            kind="nfqws2",
            title="Список nfqws2 — основной SNI-список",
            path="/opt/etc/nfqws2/lists/list-general.list",
            line=line,
            commands=commands,
            note=("Домен уже присутствует — повторное добавление no-op. "
                  if already else "")
            + ("Запись без префикса покрывает поддомены. " if line == base else "")
            + "Не путать с list-exclude*.list (там обход выключается), auto.list и list-google.list. "
              "После рестарта проверить функционально: curl -s -o NUL -w \"HTTP=%{http_code} connect=%{time_connect}s\" "
              f"https://{host}/",
            url=cfg.panel_url,
        ))
        if note_known:
            actions[0].note += f" Эталон: {note_known}."
        if suspicious_dns or (known and any(e.level == "DNS" for e in known)):
            actions.append(Action(
                kind="dns",
                title="Дополнительно: DNS-правило (оба слоя)",
                path="/opt/etc/nfqws2-strategy/dnsserver.json",
                line=f"{base} + «включая поддомены»",
                note="В истории сети были случаи, когда требовались оба слоя (mistral.ai): "
                     "сначала DNS-правило, затем список. Если после списка не заработает — вернитесь к правилу.",
                url=cfg.panel_url,
            ))

    elif level == "DNS":
        relay = "sync.bezmezhau.com" if any(
            k in host for k in ("openai", "chatgpt", "grok", "x.ai", "openrouter")
        ) else None
        note = ("Галочка «включая поддомены» — один домен покрывает www./api. "
                "Апстрим: https://1.1.1.1/dns-query или https://1.0.0.1/dns-query; "
                "ветку comss.one добавлять как резерв можно, но dns.dns-ai.ru у этого провайдера недоступен.")
        if relay:
            note += (f" Для обхода геоблока OpenAI используйте зарубежный relay {relay} "
                     "в правиле DNS Server — VPN для этого не нужен.")
        if dns_matches:
            upstreams = []
            for m in dns_matches[:3]:
                up = (m.get("rule") or {}).get("upstream") or {}
                address = up.get("address") if isinstance(up, dict) else None
                if address and address not in upstreams:
                    upstreams.append(address)
            note += (" Для этого домена правило уже настроено" +
                     (f" (апстрим: {', '.join(upstreams)})" if upstreams else "") +
                     ". Если сайт открывается — ничего менять не нужно; VPN-туннель здесь не нужен.")
        actions.append(Action(
            kind="dns",
            title=("DNS-правило уже настроено — проверьте, что всё работает"
                   if dns_matches else "DNS Server → доменное правило"),
            path="/opt/etc/nfqws2-strategy/dnsserver.json",
            line=host,
            note=note,
            url=cfg.panel_url,
        ))
        if known and any(e.level == "SNI" for e in known):
            actions.append(Action(
                kind="nfqws2",
                title="Если DNS-правило не поможет — добавить в список",
                path="/opt/etc/nfqws2/lists/list-general.list",
                line=base,
                commands=("L=/opt/etc/nfqws2/lists/list-general.list\n"
                          f'grep -qx "{base}" "$L" || echo "{base}" >> "$L"\n'
                          "/opt/etc/init.d/S51nfqws2 restart"),
                note="По эталонным замерам для этого домена требовался и второй слой.",
                url=cfg.panel_url,
            ))

    elif level == "IP":
        target = base
        if ips:
            target = ips[0]
        ip_lines = [f"{ip}:443" for ip in ips[:5]] or [f"{base}:443"]
        line = "; ".join(ip_lines)
        already = bool(avo_matches)
        commands = "\n".join(f"/opt/bin/nfqws2 add {entry}" for entry in ip_lines)
        commands += "\n# либо через панель: «Быстрое добавление / удаление»"
        actions.append(Action(
            kind="tunnel",
            title="VPN-туннель — маршрут через туннель",
            path="/opt/etc/vpn/list-general.list",
            line=line,
            commands=commands,
            note=("Адрес уже есть в списке — повторное добавление ничего не изменит. " if already else "")
                 + "Формат: адрес или адрес:порт (порт по умолчанию 443); домены резолвятся при применении; "
                   "маски *.example.com не поддерживаются. Учтите реальный порт сервиса "
                   "(например 5005/7708 у AdwertApp). Для домен с несколькими A-записями добавляйте все адреса.",
            url=cfg.tunnel_url,
        ))
        actions.append(Action(
            kind="client",
            title="Либо VPN/WARP на клиенте",
            note="Списки nfqws2 и DNS-правила при блоке по IP не помогают. "
                 "Для Bot API локальные MTProto-прокси роутера (1433/1443/1080) не подходят — "
                 "нужен WARP/VPN на машине с ботом. WARPUDP/2408 на самом Keenetic не работает "
                 "(DPI режет WireGuard после handshake).",
        ))

    elif level == "REGION":
        actions.append(Action(
            kind="client",
            title="На роутере ничего не поможет",
            note="Сайт отвечает 200/302 и сам пишет «unsupported region». "
                 "Нужен аккаунт поддерживаемой страны или VPN/релей через неё. "
                 "Списки nfqws2 и DNS-правила здесь бессильны.",
        ))

    elif level == "OK":
        actions.append(Action(
            kind="none",
            title="Роутер трогать не нужно",
            note="Сеть доступна. Если сайт не открывается — это браузер, аккаунт, "
                 "антибот-челлендж Cloudflare (403) или геоблок сервиса. "
                 "Не добавляйте домен «на всякий случай».",
        ))

    else:  # UNKNOWN
        actions.append(Action(
            kind="info",
            title="Проверьте доступность роутера",
            note="Подключитесь к сети Keenetic и повторите проверку. "
                 "Панель: http://192.168.1.1:8090, SSH Entware (доступ задаётся в Настройках), порт 222 (фолбэк 22).",
            url=cfg.panel_url,
        ))

    # Все подводные камни уровня показываем всегда: WARP-предупреждение
    # особенно важно именно при недоступной панели (тесты с ПК недействительны).
    pitfalls = knowledge.pitfalls_for(level)
    sources = [
        "02_Keenetic_Router/domain-lists.md",
        "02_Keenetic_Router/dns-server-rules.md",
        "02_Keenetic_Router/diagnostics.md",
        "diagnosing-blocked-domains-keenetic/SKILL.md",
        "03_Bypass_RKN/warp-and-tunnels.md",
    ]

    if level == "SNI":
        headline = f"Добавить {base} в list-general.list"
    elif level == "DNS":
        headline = f"Добавить DNS-правило для {host}"
    elif level == "IP":
        headline = f"Завернуть {target} через VPN-туннель / VPN на клиенте"
    elif level == "REGION":
        headline = "Геоблок сервиса — на роутере не лечится"
    elif level == "OK":
        headline = "Блокировки нет — ничего не добавлять"
    elif level == "NXDOMAIN":
        headline = f"Домен {host} не существует"
    else:
        headline = "Нет данных — проверьте доступность роутера"

    summary = {
        "SNI": "IP резолвится верно, но TLS-соединение рвётся или висит — это DPI по SNI. "
               "Лечится списком nfqws2 с маскировкой.",
        "DNS": "Резолвер отдаёт подставной/пустой ответ либо используется гео-подмена. "
               "Нужно доменное правило DNS Server с нужным апстримом.",
        "IP": "Провайдер роняет SYN до IP/порта. Ни списки, ни DNS-правила не помогут — "
              "нужен туннель для конкретного адреса.",
        "REGION": "Сеть в порядке, доступ ограничен самой площадкой по стране или аккаунту.",
        "OK": "BlockCheck подтверждает: провайдер не режет этот домен. "
              "Любая правка конфига будет лишней.",
        "NXDOMAIN": "Имя не разрешается ни одним резолвером — NXDOMAIN. "
                    "Это не блокировка и не подмена DNS: такого имени нет. "
                    "Проверьте опечатку (например, 1tvrrr.ru вместо 1tv.ru).",
        "UNKNOWN": "Не удалось собрать доказательства. Вердикт основан только на базе знаний.",
    }[level]

    return Verdict(
        domain=host,
        candidates=hosts,
        level=level,
        title=headline,
        summary=summary,
        confidence=confidence,
        evidence=evidence,
        actions=actions,
        pitfalls=pitfalls,
        knowledge=known,
        warnings=warnings,
        sources=sources,
        raw=data,
    )


def _zero_connect(target: dict[str, Any] | None) -> bool:
    if not target:
        return False
    value = target.get("connect_ms", target.get("connect"))
    if value in (None, ""):
        return False
    text = str(value).strip().lower()
    if text.endswith("ms"):
        text = text[:-2]
    elif text.endswith("s"):
        text = text[:-1]
    try:
        return float(text) == 0.0
    except ValueError:
        return False


def _is_doh(host: str) -> bool:
    if any(token in host for token in ("dns.google", "cloudflare-dns", "dns.comss")):
        return True
    # «doh» как отдельный label, а не подстрока (иначе playdoh.com — DoH).
    return "doh" in host.split(".")
