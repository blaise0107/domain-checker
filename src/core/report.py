"""Экспорт вердикта в Markdown и ведение локальной истории проверок."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ..config import app_dir
from .decision import Verdict


def build_markdown(verdict: Verdict, timestamp: datetime | None = None) -> str:
    ts = (timestamp or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# Проверка домена: {verdict.domain}",
        "",
        f"*Дата: {ts}*",
        "",
        f"## Вердикт: {verdict.level_title}",
        "",
        f"**{verdict.title}**",
        "",
        verdict.summary,
        "",
        f"Уверенность: {verdict.confidence}.",
        "",
        "## Доказательства",
        "",
        "| Проверка | Результат |",
        "|---|---|",
    ]
    for label, value, status in verdict.evidence:
        safe = str(value).replace("|", "\\|").replace("\n", " ")
        mark = {"ok": "✅", "warn": "⚠️", "bad": "❌"}.get(status, "•")
        lines.append(f"| {mark} {label} | {safe} |")

    lines += ["", "## Куда прописывать", ""]
    for idx, action in enumerate(verdict.actions, 1):
        lines.append(f"### {idx}. {action.title}")
        lines.append("")
        if action.path:
            lines.append(f"**Путь:** `{action.path}`")
            lines.append("")
        if action.line:
            lines.append(f"**Что добавить:** `{action.line}`")
            lines.append("")
        if action.url:
            lines.append(f"**Панель:** {action.url}")
            lines.append("")
        if action.commands:
            lines.append("```sh")
            lines.append(action.commands)
            lines.append("```")
            lines.append("")
        if action.note:
            lines.append(action.note)
            lines.append("")

    if verdict.warnings:
        lines += ["## Предупреждения", ""]
        lines += [f"- {w}" for w in verdict.warnings]
        lines.append("")

    if verdict.pitfalls:
        lines += ["## Подводные камни", ""]
        for p in verdict.pitfalls:
            lines += [f"### {p.title}", "", p.text, ""]

    if verdict.knowledge:
        lines += ["## Эталонные записи из базы знаний", ""]
        for e in verdict.knowledge:
            lines += [f"- `{e.domain}` — **{e.level}**: {e.action}. {e.note}"]
        lines.append("")

    lines += ["## Источники", ""]
    lines += [f"- {s}" for s in verdict.sources]
    lines.append("")
    return "\n".join(lines)


def history_path() -> Path:
    return app_dir() / "history.json"


def load_history() -> list[dict]:
    path = history_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def add_history(verdict: Verdict, markdown: str) -> dict:
    """Добавляет запись и возвращает её (historic limit — 200 записей)."""
    now = datetime.now()
    record = {
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        "domain": verdict.domain,
        "level": verdict.level,
        "title": verdict.title,
        "confidence": verdict.confidence,
        "report": markdown,
    }
    items = [x for x in load_history() if x.get("domain") != verdict.domain]
    items.insert(0, record)
    path = history_path()
    try:
        path.write_text(json.dumps(items[:200], ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass
    return record
