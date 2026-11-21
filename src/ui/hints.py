"""Подсказки для трёх уровней пользователя: новичок / средний / профи.

Все тексты — на «человеческом» языке, без жаргона в режиме новичка.
Режим «профи» даёт максимум сырых данных и готовый промпт для ИИ.
"""

from __future__ import annotations

from ..config import Config
from ..core.decision import Verdict

MODE_LABELS = {
    "novice": "Новичок",
    "intermediate": "Средний",
    "pro": "Профи",
}

# Простыми словами: что означает каждый вердикт и что делать.
LEVEL_PLAIN: dict[str, dict[str, str]] = {
    "SNI": {
        "name": "Сайт заблокирован Роскомнадзором",
        "what": "Интернет-провайдер видит название сайта (например, mistral.ai) и сбрасывает соединение. "
                "При этом сам адрес сайта определён правильно — проблема именно в «заголовке» запроса.",
        "fix": "Нужно добавить адрес в список обхода nfqws2. Ниже дана готовая команда — "
               "нажмите «Открыть терминал роутера», вставьте её и нажмите Enter.",
    },
    "DNS": {
        "name": "Сайту подсовывают неправильный адрес",
        "what": "Когда компьютер спрашивает «где находится этот сайт», ему отвечают неверным адресом "
                "или не отвечают совсем. Из-за этого сайт не открывается, хотя сам он работает.",
        "fix": "Нужно добавить правило в DNS-сервер роутера, чтобы адрес сайта определялся правильно. "
               "Откройте панель DNS по кнопке ниже и добавьте домен.",
    },
    "IP": {
        "name": "Доступ закрыт по IP-адресу",
        "what": "Провайдер блокирует соединение напрямую с адресом сайта — просто не пропускает пакеты. "
                "Ни список обхода, ни настройки DNS здесь не помогут.",
        "fix": "Это самый крайний случай. Нужен VPN-туннель или VPN/WARP на компьютере. "
               "Если сайт и так открывается — ничего делать не надо.",
    },
    "REGION": {
        "name": "Сервис не пускает пользователей из России",
        "what": "Сайт отвечает нормально, но сам сообщает, что доступ из нашей страны ограничен. "
                "Это решение самого сервиса, а не блокировка провайдера.",
        "fix": "Настройки роутера здесь не помогут. Нужен аккаунт другой страны или VPN, "
               "выходящий в разрешённую страну.",
    },
    "OK": {
        "name": "С сайтом всё в порядке",
        "what": "Проверка показала, что провайдер не блокирует этот адрес. Сайт отвечает нормально.",
        "fix": "Ничего добавлять не нужно. Если сайт не открывается — проблема в браузере, "
               "аккаунте или защите самого сайта от роботов.",
    },
    "NXDOMAIN": {
        "name": "Такого адреса не существует",
        "what": "Такого названия сайта нет в интернете. Скорее всего, в адресе опечатка.",
        "fix": "Проверьте написание и расширение (.ru, .com и т.д.). "
               "Например, правильный адрес телеканала — 1tv.ru, а не 1tvrrr.ru.",
    },
    "UNKNOWN": {
        "name": "Не удалось проверить сайт",
        "what": "Роутер не ответил на запросы, поэтому приложение не смогло собрать доказательства.",
        "fix": "Убедитесь, что вы в сети Keenetic и роутер включён, затем повторите проверку.",
    },
}

TOOLTIPS: dict[str, dict[str, str]] = {
    "domain": {
        "novice": "Впишите адрес сайта, который не открывается. Можно просто «mistral.ai» "
                  "или целую ссылку — приложение само разберётся.",
        "intermediate": "Домен или URL. Пример: api.telegram.org, https://mistral.ai/chat",
        "pro": "Host / URL → normalize_domain() → candidate_hosts()",
    },
    "check": {
        "novice": "Нажмите, чтобы приложение проверило сайт и подсказало, что делать.",
        "intermediate": "Запустить BlockCheck + DNS + conntrack и построить вердикт (Ctrl+Enter).",
        "pro": "Run CheckWorker: probe_redirect → collect() → analyze()",
    },
    "settings": {
        "novice": "Здесь задаются адрес роутера и данные для входа. Обычно менять ничего не надо.",
        "intermediate": "Настройки подключения: хост, порты, SSH, таймауты, режим подсказок.",
        "pro": "Config → config.local.json (пароль не сохраняется по умолчанию)",
    },
    "history": {
        "novice": "Список всех проверенных сайтов. Можно открыть сохранённый отчёт.",
        "intermediate": "История проверок (последние 200), экспорт отчёта.",
        "pro": "history.json → load_history()",
    },
    "terminal": {
        "novice": "Открывает окно входа на роутер — пароль уже подставлен. "
                  "Можно вставлять команды из подсказок прямо туда.",
        "intermediate": "Подключиться к SSH Entware с сохранёнными учётными данными.",
        "pro": "paramiko SSHClient → invoke_shell()",
    },
    "evidence": {
        "novice": "Здесь собраны все проверки, которые сделало приложение. "
                  "Зелёный — всё хорошо, оранжевый — стоит внимания, красный — проблема.",
        "intermediate": "Результаты BlockCheck, DNS, conntrack, списков nfqws2 и правил DNS.",
        "pro": "Verdict.evidence[] — (label, value, status)",
    },
    "warnings": {
        "novice": "Важные замечания. Например: проверки с компьютера под VPN могут быть неверными.",
        "intermediate": "Предупреждения и подводные камни для текущего уровня блокировки.",
        "pro": "Verdict.warnings[] + knowledge.pitfalls_for(level)",
    },
    "known": {
        "novice": "Приложения уже проверяло эти сайты раньше — здесь записано, что с ними делали.",
        "intermediate": "Эталонные вердикты из базы знаний data/domains.json.",
        "pro": "Knowledge.lookup(hosts) → DomainEntry[]",
    },
    "actions": {
        "novice": "Пошаговые действия: куда нажать или какую команду скопировать.",
        "intermediate": "Точные пути, строки и готовые команды для копирования.",
        "pro": "Verdict.actions[] — kind/path/line/commands/note",
    },
    "copy_commands": {
        "novice": "Копирует команду. Затем откройте терминал роутера и вставьте её правой кнопкой мыши.",
        "intermediate": "Скопировать команды в буфер обмена.",
        "pro": "QApplication.clipboard().setText(action.commands)",
    },
    "save_report": {
        "novice": "Сохраняет подробный отчёт в файл — можно отправить его специалисту или ИИ.",
        "intermediate": "Экспорт карточки в Markdown.",
        "pro": "build_markdown(verdict) → *.md",
    },
    "ai_copy": {
        "novice": "Копирует всё, что приложение узнало, в виде готового сообщения для ИИ-помощника.",
        "intermediate": "Скопировать полный диагностический отчёт для ИИ.",
        "pro": "Copy structured prompt with raw evidence + config paths",
    },
    "panel": {
        "novice": "Открывает веб-страницу настроек обхода блокировок на роутере.",
        "intermediate": "Открыть панель NFQWS2 Strategy Selector (:8090).",
        "pro": "http://<host>:8090",
    },
    "panel_alt": {
        "novice": "Открывает другую панель обхода для РКН и YouTube.",
        "intermediate": "Открыть nfqws-keenetic-web (:90).",
        "pro": "http://<host>:90",
    },
    "hint_mode": {
        "novice": "Выберите, насколько подробные подсказки вам нужны: "
                  "«Новичок» — простыми словами, «Средний» — как раньше, "
                  "«Профи» — сырые данные и копирование для ИИ.",
        "intermediate": "Уровень детализации подсказок.",
        "pro": "hint_mode: novice | intermediate | pro",
    },
    "level_label": {
        "novice": "Как приложение поняло проблему и насколько оно уверено.",
        "intermediate": "Уровень блокировки и уверенность вердикта.",
        "pro": "Verdict.level / Verdict.confidence",
    },
    "open_evidence": {
        "novice": "Открыть большое окно со всеми проверками — там удобно читать длинные строки и копировать данные.",
        "intermediate": "Открыть полную таблицу доказательств в отдельном окне.",
        "pro": "Open EvidenceDialog (full table, copy)",
    },
    "open_pitfalls": {
        "novice": "Открыть большое окно со всеми предупреждениями и подсказками про VPN, 403 и другие ловушки.",
        "intermediate": "Открыть полный список предупреждений и подводных камней.",
        "pro": "Open PitfallsDialog (full text, copy)",
    },
    "open_known": {
        "novice": "Открыть окно с тем, что приложение уже знает об этом сайте из своей базы проверенных доменов.",
        "intermediate": "Открыть полный список эталонных записей из data/domains.json.",
        "pro": "Open KnowledgeDialog (DomainEntry[] with notes)",
    },
}


def normalize_mode(mode: str | None) -> str:
    return mode if mode in MODE_LABELS else "novice"


def mode_of(cfg: Config) -> str:
    return normalize_mode(getattr(cfg, "hint_mode", "novice"))


def tooltip(key: str, mode: str) -> str:
    entry = TOOLTIPS.get(key, {})
    return entry.get(normalize_mode(mode), entry.get("novice", ""))


def verdict_text(verdict: Verdict, mode: str) -> tuple[str, str, str]:
    """Возвращает (строка уровня, заголовок, пояснение) под выбранный режим."""
    mode = normalize_mode(mode)
    plain = LEVEL_PLAIN.get(verdict.level, LEVEL_PLAIN["UNKNOWN"])
    if mode == "novice":
        level = plain["name"].upper()
        title = verdict.title
        summary = (f"ПРОСТЫМИ СЛОВАМИ. {plain['what']}\n\n"
                   f"ЧТО ДЕЛАТЬ. {plain['fix']}")
        raw = verdict.raw or {}
        list_message = str((raw.get("lists") or {}).get("message", ""))
        list_status = str((raw.get("lists") or {}).get("status", "none"))
        if list_message:
            if verdict.level == "OK" and list_status == "wrong_exclude":
                list_message = ("Домен в списке исключений nfqws2 — обход для него выключен, "
                                "и это правильно: сайт и так работает.")
            summary += f"\n\nПРОВЕРКА СПИСКОВ НА РОУТЕРЕ. {list_message}"
        return level, title, summary
    if mode == "pro":
        level = f"{verdict.level} · {verdict.confidence} · {verdict.domain}"
        title = verdict.title
        raw = verdict.raw or {}
        bits = [
            f"level={verdict.level} confidence={verdict.confidence}",
            f"bc={raw.get('blockcheck', {}).get('targets', {})}",
            f"dns={raw.get('dns', {})}",
            f"ips={raw.get('ip_addresses', [])}",
            f"lists_ok={raw.get('lists', {}).get('ok')} matches={(raw.get('lists', {}).get('matches') or [])[:5]}",
            f"dns_rules={(raw.get('dnsserver', {}).get('matches') or [])[:3]}",
        ]
        return level, title, "\n".join(str(b) for b in bits)
    return f"{verdict.level_title.upper()}  ·  уверенность: {verdict.confidence}", verdict.title, verdict.summary


def action_note(action_note_text: str, verdict: Verdict, mode: str, has_commands: bool) -> str:
    """Дополняет описание действия подсказками для новичка."""
    mode = normalize_mode(mode)
    if mode == "novice":
        plain = LEVEL_PLAIN.get(verdict.level, LEVEL_PLAIN["UNKNOWN"])
        steps = []
        if has_commands:
            steps.append("1. Нажмите «Копировать команды».")
            steps.append("2. Нажмите «Открыть терминал роутера» — пароль подставится сам.")
            steps.append("3. Вставьте команду правой кнопкой мыши и нажмите Enter.")
            steps.append("4. Проверьте, открылся ли сайт.")
        if action_note_text:
            steps.append(action_note_text)
        steps.append(plain["fix"])
        return "\n".join(s for s in steps if s)
    if mode == "pro":
        return action_note_text
    return action_note_text


def ai_prompt(verdict: Verdict, cfg: Config) -> str:
    """Готовый компактный промпт для ИИ со всеми собранными данными."""
    lines = [
        "Проанализируй диагностику домена. Приложение — Domain Checker (Keenetic + NFQWS2).",
        "",
        f"Домен: {verdict.domain}",
        f"Кандидаты: {', '.join(verdict.candidates)}",
        f"Вердикт приложения: {verdict.level} ({verdict.level_title}), уверенность {verdict.confidence}.",
        f"Заголовок: {verdict.title}",
        f"Пояснение: {verdict.summary}",
        "",
        "ДОКАЗАТЕЛЬСТВА:",
    ]
    for label, value, status in verdict.evidence:
        lines.append(f"- [{status}] {label}: {value}")
    if verdict.warnings:
        lines.append("\nПРЕДУПРЕЖДЕНИЯ:")
        lines.extend(f"- {w}" for w in verdict.warnings)
    if verdict.actions:
        lines.append("\nПРЕДЛОЖЕННЫЕ ДЕЙСТВИЯ:")
        for a in verdict.actions:
            lines.append(f"- {a.title}: путь={a.path or '-'} строка={a.line or '-'}")
            if a.commands:
                lines.append("  Команды:")
                lines.extend("    " + x for x in a.commands.splitlines())
    lines += [
        "",
        "КОНФИГУРАЦИЯ ПОДКЛЮЧЕНИЯ:",
        f"panel={cfg.panel_url} alt={cfg.alt_panel_url} "
        f"ssh={cfg.ssh_user}@{cfg.router_host}:{cfg.ssh_ports}",
        "",
        "Скажи, согласен ли ты с вердиктом и если нет — на каком уровне проблема "
        "и куда именно нужно добавить домен.",
    ]
    return "\n".join(lines)
