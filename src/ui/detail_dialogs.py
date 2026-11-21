"""Отдельные просторные окна для «Доказательств» и «Подводных камней»."""

from __future__ import annotations

import html

from PySide6.QtCore import QSettings, Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QDialog, QHBoxLayout, QHeaderView, QLabel,
    QPlainTextEdit, QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QTextBrowser, QVBoxLayout, QWidget,
)

from ..core.decision import Verdict
from .hints import mode_of, normalize_mode

STATUS_COLOR = {"ok": "#1b5e20", "warn": "#e65100", "bad": "#b71c1c"}
STATUS_LABEL = {"ok": "✅ хорошо", "warn": "⚠️ внимание", "bad": "❌ проблема"}

STYLE = """
QDialog { background: #f5f7f9; }
QTableWidget, QTextBrowser, QPlainTextEdit { background: #ffffff; border: 1px solid #cfd8dc;
    border-radius: 5px; font-family: 'Segoe UI', sans-serif; font-size: 13px; }
QHeaderView::section { background: #eceff1; padding: 8px; font-weight: 700; border: 0; }
QPushButton { background: #607d8b; color: white; border: 0; border-radius: 5px; padding: 8px 14px; }
QPushButton:hover { background: #546e7a; }
"""


def evidence_as_text(verdict: Verdict) -> str:
    lines = [f"Доказательства для {verdict.domain} (вердикт: {verdict.level})", "=" * 60]
    for label, value, status in verdict.evidence:
        mark = STATUS_LABEL.get(status, "•")
        lines.append(f"[{mark}] {label}: {value}")
    return "\n".join(lines)


def pitfalls_as_text(verdict: Verdict) -> str:
    lines = [f"Предупреждения и подводные камни для {verdict.domain}", "=" * 60]
    if verdict.warnings:
        lines.append("\nПРЕДУПРЕЖДЕНИЯ:")
        lines.extend(f"⚠️ {w}" for w in verdict.warnings)
    if verdict.pitfalls:
        lines.append("\nПОДВОДНЫЕ КАМНИ:")
        for p in verdict.pitfalls:
            lines.append(f"\n📌 {p.title}\n{p.text}")
    if not verdict.warnings and not verdict.pitfalls:
        lines.append("Нет специальных предупреждений.")
    return "\n".join(lines)


class _BaseDetailDialog(QDialog):
    def __init__(self, title: str, settings_key: str, cfg) -> None:
        super().__init__()
        self.setWindowTitle(title)
        self.resize(1100, 720)
        self.setStyleSheet(STYLE)
        self.settings = QSettings("VPN_Router", "DomainChecker")
        self.settings_key = settings_key
        self.mode = mode_of(cfg)
        raw = self.settings.value(settings_key)
        if raw is not None:
            self.restoreGeometry(raw)

    def closeEvent(self, event) -> None:  # noqa: N802
        self.settings.setValue(self.settings_key, self.saveGeometry())
        self.settings.sync()
        super().closeEvent(event)

    def _button_row(self, text: str, getter) -> QHBoxLayout:
        row = QHBoxLayout()
        hint = QLabel("Данные можно выделить и скопировать.")
        hint.setStyleSheet("color:#546e7a;")
        row.addWidget(hint)
        row.addStretch()
        copy = QPushButton("Копировать всё")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(getter()))
        row.addWidget(copy)
        close = QPushButton("Закрыть")
        close.clicked.connect(self.close)
        row.addWidget(close)
        return row


class EvidenceDialog(_BaseDetailDialog):
    def __init__(self, verdict: Verdict, cfg) -> None:
        super().__init__(f"Доказательства — {verdict.domain}", "evidenceDialog/geometry", cfg)
        layout = QVBoxLayout(self)
        header = QLabel(
            "Все проверки, которые сделало приложение. Нажмите на строку, чтобы увидеть детали. "
            "Длинные значения прокручиваются по горизонтали."
        )
        header.setWordWrap(True)
        header.setStyleSheet("color:#37474f; padding: 4px 0;")
        layout.addWidget(header)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Проверка", "Результат", "Статус"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setWordWrap(False)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setColumnWidth(1, 800)
        for label, value, status in verdict.evidence:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(str(label)))
            item = QTableWidgetItem(str(value))
            color = STATUS_COLOR.get(status)
            if color:
                item.setForeground(QColor(color))
            self.table.setItem(r, 1, item)
            status_item = QTableWidgetItem(STATUS_LABEL.get(status, "•"))
            if color:
                status_item.setForeground(QColor(color))
            self.table.setItem(r, 2, status_item)
        self.table.itemSelectionChanged.connect(self._on_select)
        splitter.addWidget(self.table)

        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(False)
        self.detail.setMinimumWidth(340)
        self.detail.setHtml("<p>Выберите строку, чтобы увидеть подробности.</p>")
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, stretch=1)
        layout.addLayout(self._button_row("evidence", lambda: evidence_as_text(verdict)))

    def _on_select(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        label = self.table.item(row, 0).text() if self.table.item(row, 0) else ""
        value = self.table.item(row, 1).text() if self.table.item(row, 1) else ""
        status = self.table.item(row, 2).text() if self.table.item(row, 2) else ""
        self.detail.setHtml(
            f"<h3>{html.escape(label)}</h3>"
            f"<p><b>Статус:</b> {html.escape(status)}</p>"
            f"<pre style='white-space:pre-wrap;'>{html.escape(value)}</pre>"
        )


class PitfallsDialog(_BaseDetailDialog):
    def __init__(self, verdict: Verdict, cfg) -> None:
        super().__init__(f"Подводные камни — {verdict.domain}", "pitfallsDialog/geometry", cfg)
        layout = QVBoxLayout(self)
        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(False)
        parts: list[str] = []
        if verdict.warnings:
            parts.append("<h3>⚠️ Предупреждения</h3>")
            for w in verdict.warnings:
                parts.append(f"<p>{html.escape(w)}</p>")
        if verdict.pitfalls:
            parts.append("<h3>📌 Подводные камни</h3>")
            for p in verdict.pitfalls:
                parts.append(
                    f"<p><b>{html.escape(p.title)}.</b><br>"
                    f"<span style='color:#546e7a'>{html.escape(p.text)}</span></p>"
                )
        if not parts:
            parts.append("<p>Нет специальных предупреждений.</p>")
        self.browser.setHtml("".join(parts))
        layout.addWidget(self.browser, stretch=1)
        layout.addLayout(self._button_row("pitfalls", lambda: pitfalls_as_text(verdict)))
