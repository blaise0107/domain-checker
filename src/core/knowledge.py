"""Загрузка и поиск по встроенной базе знаний (эталонные домены и подводные камни)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..config import resource_dir
from .normalize import domain_matches


@dataclass(frozen=True)
class DomainEntry:
    domain: str
    level: str
    action: str
    note: str

    @classmethod
    def from_dict(cls, data: dict) -> "DomainEntry":
        return cls(
            domain=str(data.get("domain", "")).lower(),
            level=str(data.get("level", "OK")).upper(),
            action=str(data.get("action", "")),
            note=str(data.get("note", "")),
        )


@dataclass(frozen=True)
class Pitfall:
    id: str
    levels: tuple[str, ...]
    title: str
    text: str

    @classmethod
    def from_dict(cls, data: dict) -> "Pitfall":
        levels = data.get("levels", ["*"])
        if isinstance(levels, str):
            levels = [levels]
        return cls(
            id=str(data.get("id", "")),
            levels=tuple(str(x).upper() for x in levels),
            title=str(data.get("title", "")),
            text=str(data.get("text", "")),
        )

    def applies_to(self, level: str) -> bool:
        return "*" in self.levels or level.upper() in self.levels


class Knowledge:
    def __init__(self, data_dir: Path | None = None) -> None:
        base = data_dir or (resource_dir() / "data")
        self.entries: list[DomainEntry] = []
        self.pitfalls: list[Pitfall] = []
        self.source = ""
        self._load(base)

    def _load(self, base: Path) -> None:
        domains_file = base / "domains.json"
        pitfalls_file = base / "pitfalls.json"
        try:
            raw = json.loads(domains_file.read_text(encoding="utf-8"))
            self.entries = [DomainEntry.from_dict(x) for x in raw.get("entries", [])]
            self.source = str(raw.get("source", ""))
        except (OSError, ValueError):
            self.entries = []
        try:
            raw = json.loads(pitfalls_file.read_text(encoding="utf-8"))
            self.pitfalls = [Pitfall.from_dict(x) for x in raw.get("items", [])]
        except (OSError, ValueError):
            self.pitfalls = []

    def lookup(self, hosts: list[str]) -> list[DomainEntry]:
        """Возвращает все эталонные записи, подходящие под проверяемые хосты."""
        found: list[DomainEntry] = []
        for host in hosts:
            for entry in self.entries:
                if domain_matches(entry.domain, host) and entry not in found:
                    found.append(entry)
        return found

    def pitfalls_for(self, level: str) -> list[Pitfall]:
        return [p for p in self.pitfalls if p.applies_to(level)]
