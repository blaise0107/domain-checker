"""Главное окно приложения Domain Checker."""

from __future__ import annotations

import html
import traceback
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QByteArray, QSettings, Qt, QThread, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont, QIcon
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QFrame, QGroupBox, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea,
    QSpinBox, QSplitter, QTableWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget,
)

from ..config import Config, load_config, resource_dir, save_config
from ..core.decision import Verdict, analyze
from ..core.knowledge import Knowledge
from ..core.normalize import candidate_hosts, normalize_domain
from ..core.report import add_history, build_markdown, load_history
from ..core.router import RouterClient
from .hints import (
    MODE_LABELS, action_note, ai_prompt, mode_of, normalize_mode, tooltip, verdict_text,
)
from .terminal import TerminalDialog

LEVEL_COLORS = {
    "SNI": ("#fff3e0", "#e65100", "#ffb74d"),
    "DNS": ("#e3f2fd", "#0d47a1", "#64b5f6"),
    "IP": ("#ffebee", "#b71c1c", "#ef5350"),
    "REGION": ("#f3e5f5", "#6a1b9a", "#ba68c8"),
    "OK": ("#e8f5e9", "#1b5e20", "#81c784"),
    "NXDOMAIN": ("#fff8e1", "#e65100", "#ffca28"),
    "UNKNOWN": ("#eceff1", "#37474f", "#90a4ae"),
}

STYLE = """
QWidget { font-family: 'Segoe UI', 'Inter', sans-serif; font-size: 13px; color: #263238; }
QMainWindow, QDialog { background: #f5f7f9; }
QLineEdit, QPlainTextEdit, QTextBrowser { background: #ffffff; border: 1px solid #cfd8dc;
    border-radius: 5px; padding: 6px 8px; selection-background-color: #90caf9; }
QLineEdit:focus, QPlainTextEdit:focus { border-color: #1976d2; }
QPushButton { background: #1976d2; color: white; border: 0; border-radius: 5px;
    padding: 8px 14px; font-weight: 600; }
QPushButton:hover { background: #1565c0; }
QPushButton:disabled { background: #b0bec5; }
QPushButton.secondary { background: #607d8b; }
QPushButton.secondary:hover { background: #546e7a; }
QGroupBox { font-weight: 600; border: 1px solid #cfd8dc; border-radius: 6px;
    margin-top: 12px; padding: 10px 10px 10px 10px; background: #ffffff; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: #37474f; }
QTableWidget { background: #ffffff; gridline-color: #eceff1; border: 1px solid #cfd8dc;
    border-radius: 5px; }
QHeaderView::section { background: #eceff1; padding: 6px; font-weight: 600; border: 0; }
QScrollArea { border: 0; }
"""


class CheckWorker(QThread):
    progress = Signal(str)
    result_ready = Signal(object, object)

    def __init__(self, raw_domain: str, cfg: Config, knowledge: Knowledge) -> None:
        super().__init__()
        self.raw_domain = raw_domain
        self.cfg = cfg
        self.knowledge = knowledge

    def run(self) -> None:
        client: RouterClient | None = None
        try:
            host = normalize_domain(self.raw_domain)
            if not host:
                self.result_ready.emit(None, "Некорректный домен. Пример: api.telegram.org или https://example.com/path")
                return
            self.progress.emit("Проверка редиректа…")
            client = RouterClient(self.cfg)
            redirect = client.probe_redirect(host)
            candidates = candidate_hosts(host, redirect)
            self.progress.emit("Опрос роутера: BlockCheck, DNS, conntrack…")
            data = client.collect(candidates, redirect)
            self.progress.emit("Анализ и формирование вердикта…")
            verdict = analyze(host, data, self.knowledge, self.cfg)
            self.result_ready.emit(verdict, None)
        except Exception:  # noqa: BLE001 — показываем пользователю полный traceback
            self.result_ready.emit(None, traceback.format_exc())
        finally:
            if client is not None:
                client.close()


class SettingsDialog(QDialog):
    def __init__(self, cfg: Config, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Настройки подключения")
        self.setMinimumWidth(440)
        form = QFormLayout(self)

        self.host = QLineEdit(cfg.router_host)
        self.panel_port = QSpinBox(); self.panel_port.setRange(1, 65535); self.panel_port.setValue(cfg.panel_port)
        self.alt_panel_port = QSpinBox(); self.alt_panel_port.setRange(1, 65535); self.alt_panel_port.setValue(cfg.alt_panel_port)
        self.avo_port = QSpinBox(); self.avo_port.setRange(1, 65535); self.avo_port.setValue(cfg.tunnel_port)
        self.ssh_user = QLineEdit(cfg.ssh_user)
        self.ssh_password = QLineEdit(cfg.ssh_password); self.ssh_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.ssh_ports = QLineEdit(", ".join(str(p) for p in cfg.ssh_ports))
        self.http_timeout = QSpinBox(); self.http_timeout.setRange(1, 60); self.http_timeout.setValue(int(cfg.http_timeout))
        self.bc_timeout = QSpinBox(); self.bc_timeout.setRange(10, 600); self.bc_timeout.setValue(int(cfg.blockcheck_timeout))
        self.save_password = QCheckBox("Сохранить пароль в config.local.json")
        self.save_password.setChecked(cfg.save_password)
        self.hint_mode = QComboBox()
        self.hint_mode.addItems([MODE_LABELS[k] for k in ("novice", "intermediate", "pro")])
        self.hint_mode.setCurrentIndex(["novice", "intermediate", "pro"].index(normalize_mode(cfg.hint_mode)))
        self.hint_mode.setToolTip(tooltip("hint_mode", cfg.hint_mode))
        # Не редактируется в UI, но не должен теряться при сохранении настроек.
        self._ssh_timeout = cfg.ssh_timeout

        form.addRow("Адрес роутера:", self.host)
        form.addRow("Порт панели NFQWS2:", self.panel_port)
        form.addRow("Порт альт. панели обхода (:90):", self.alt_panel_port)
        form.addRow("Порт панели VPN-туннель:", self.avo_port)
        form.addRow("SSH пользователь:", self.ssh_user)
        form.addRow("SSH пароль:", self.ssh_password)
        form.addRow("SSH порты (через запятую):", self.ssh_ports)
        form.addRow("Таймаут HTTP, с:", self.http_timeout)
        form.addRow("Таймаут BlockCheck, с:", self.bc_timeout)
        form.addRow("Режим подсказок:", self.hint_mode)
        form.addRow("", self.save_password)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def values(self) -> Config:
        try:
            ports = tuple(int(p.strip()) for p in self.ssh_ports.text().split(",") if p.strip())
        except ValueError:
            ports = (222, 22)
        return Config(
            router_host=self.host.text().strip() or "192.168.1.1",
            panel_port=self.panel_port.value(),
            alt_panel_port=self.alt_panel_port.value(),
            tunnel_port=self.avo_port.value(),
            ssh_user=self.ssh_user.text().strip() or "root",
            ssh_password=self.ssh_password.text(),
            ssh_ports=ports or (222, 22),
            http_timeout=float(self.http_timeout.value()),
            blockcheck_timeout=float(self.bc_timeout.value()),
            ssh_timeout=self._ssh_timeout,
            save_password=self.save_password.isChecked(),
            hint_mode=["novice", "intermediate", "pro"][self.hint_mode.currentIndex()],
        )


class HistoryDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("История проверок")
        self.resize(820, 480)
        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Дата", "Домен", "Уровень", "Вердикт"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)
        row = QHBoxLayout()
        open_btn = QPushButton("Открыть отчёт")
        open_btn.clicked.connect(self._open_report)
        close_btn = QPushButton("Закрыть")
        close_btn.setProperty("class", "secondary")
        close_btn.clicked.connect(self.reject)
        row.addWidget(open_btn)
        row.addStretch()
        row.addWidget(close_btn)
        layout.addLayout(row)

        # Держим снимок истории: воркер может дописать запись, пока диалог открыт,
        # и повторная загрузка съехала бы с индексом строки.
        self._items = load_history()
        for item in self._items:
            r = self.table.rowCount()
            self.table.insertRow(r)
            for col, key in enumerate(("timestamp", "domain", "level", "title")):
                self.table.setItem(r, col, QTableWidgetItem(str(item.get(key, ""))))
        self.table.resizeColumnsToContents()

    def _open_report(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        items = self._items
        if row >= len(items):
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Отчёт: {items[row].get('domain', '')}")
        dialog.resize(760, 620)
        layout = QVBoxLayout(dialog)
        browser = QTextBrowser()
        browser.setMarkdown(items[row].get("report", ""))
        layout.addWidget(browser)
        dialog.exec()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.cfg = load_config()
        self.knowledge = Knowledge()
        self.verdict: Verdict | None = None
        self.markdown: str = ""
        self.worker: CheckWorker | None = None
        self.setWindowTitle("Domain Checker — Keenetic / NFQWS2 / VPN-туннель")
        self.settings = QSettings("VPN_Router", "DomainChecker")
        self.resize(1280, 820)
        self._restore_geometry()
        icon_path = resource_dir() / "app.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        self.setStyleSheet(STYLE)
        self._build_ui()
        self.statusBar().showMessage("Готово. Введите домен и нажмите Enter.")

    def _restore_geometry(self) -> None:
        raw = self.settings.value("geometry")
        if isinstance(raw, QByteArray) and not raw.isEmpty():
            self.restoreGeometry(raw)

    def _save_geometry(self) -> None:
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.sync()

    # ---------- построение интерфейса ----------

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(14, 12, 14, 10)
        root.setSpacing(10)

        mode = mode_of(self.cfg)
        top = QHBoxLayout()
        self.domain_lbl = QLabel("Домен:")
        self.domain_lbl.setToolTip(tooltip("domain", mode))
        top.addWidget(self.domain_lbl)
        self.input = QLineEdit()
        self.input.setPlaceholderText("например: api.telegram.org  или  https://mistral.ai/chat")
        self.input.returnPressed.connect(self._on_check)
        self.input.setFont(QFont("Consolas", 12))
        self.input.setToolTip(tooltip("domain", mode))
        top.addWidget(self.input, stretch=1)

        self.check_btn = QPushButton("Проверить")
        self.check_btn.setShortcut("Ctrl+Return")
        self.check_btn.clicked.connect(self._on_check)
        self.check_btn.setToolTip(tooltip("check", mode))
        top.addWidget(self.check_btn)

        self.mode_lbl = QLabel("Подсказки:")
        self.mode_lbl.setToolTip(tooltip("hint_mode", mode))
        top.addWidget(self.mode_lbl)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems([MODE_LABELS[k] for k in ("novice", "intermediate", "pro")])
        self.mode_combo.setCurrentIndex(["novice", "intermediate", "pro"].index(mode))
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        self.mode_combo.setToolTip(tooltip("hint_mode", mode))
        top.addWidget(self.mode_combo)

        self.term_btn = QPushButton("Терминал роутера")
        self.term_btn.setProperty("class", "secondary")
        self.term_btn.clicked.connect(self._on_terminal)
        self.term_btn.setToolTip(tooltip("terminal", mode))
        top.addWidget(self.term_btn)

        self.settings_btn = QPushButton("Настройки")
        self.settings_btn.setProperty("class", "secondary")
        self.settings_btn.clicked.connect(self._on_settings)
        self.settings_btn.setToolTip(tooltip("settings", mode))
        top.addWidget(self.settings_btn)
        self.history_btn = QPushButton("История")
        self.history_btn.setProperty("class", "secondary")
        self.history_btn.clicked.connect(self._on_history)
        self.history_btn.setToolTip(tooltip("history", mode))
        top.addWidget(self.history_btn)
        root.addLayout(top)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._left_pane())
        splitter.addWidget(self._right_pane())
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 5)
        root.addWidget(splitter, stretch=1)

    def _left_pane(self) -> QWidget:
        pane = QWidget()
        layout = QVBoxLayout(pane)
        layout.setContentsMargins(0, 0, 8, 0)

        mode = mode_of(self.cfg)
        self.verdict_frame = QFrame()
        self.verdict_frame.setFrameShape(QFrame.Shape.StyledPanel)
        self.verdict_frame.setStyleSheet(self._verdict_style("UNKNOWN"))
        vf = QVBoxLayout(self.verdict_frame)
        self.level_label = QLabel("ОЖИДАНИЕ ПРОВЕРКИ")
        self.level_label.setStyleSheet("font-size: 11px; font-weight: 700; letter-spacing: 1px;")
        self.level_label.setToolTip(tooltip("level_label", mode))
        self.title_label = QLabel("Введите домен выше и нажмите «Проверить»")
        self.title_label.setWordWrap(True)
        self.title_label.setStyleSheet("font-size: 18px; font-weight: 700; padding: 4px 0;")
        self.summary_label = QLabel("")
        self.summary_label.setWordWrap(True)
        self.summary_label.setTextFormat(Qt.TextFormat.PlainText)
        vf.addWidget(self.level_label)
        vf.addWidget(self.title_label)
        vf.addWidget(self.summary_label)
        layout.addWidget(self.verdict_frame)

        self.evidence_box = QGroupBox("Доказательства")
        self.evidence_box.setToolTip(tooltip("evidence", mode))
        ev_layout = QVBoxLayout(self.evidence_box)
        self.evidence_table = QTableWidget(0, 2)
        self.evidence_table.setHorizontalHeaderLabels(["Проверка", "Результат"])
        self.evidence_table.verticalHeader().setVisible(False)
        self.evidence_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        # Длинные значения не переносятся, а прокручиваются по горизонтали.
        self.evidence_table.setWordWrap(False)
        self.evidence_table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.evidence_table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.evidence_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.evidence_table.horizontalHeader().setStretchLastSection(False)
        self.evidence_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.evidence_table.setColumnWidth(1, 620)
        self.evidence_table.setToolTip(tooltip("evidence", mode))
        ev_layout.addWidget(self.evidence_table)
        layout.addWidget(self.evidence_box, stretch=2)

        self.warnings_box = QGroupBox("Предупреждения и подводные камни")
        self.warnings_box.setToolTip(tooltip("warnings", mode))
        warn_layout = QVBoxLayout(self.warnings_box)
        self.warnings_browser = QTextBrowser()
        self.warnings_browser.setOpenExternalLinks(False)
        self.warnings_browser.setToolTip(tooltip("warnings", mode))
        warn_layout.addWidget(self.warnings_browser)
        layout.addWidget(self.warnings_box, stretch=1)

        self.known_box = QGroupBox("Эталонные записи из базы знаний")
        self.known_box.setToolTip(tooltip("known", mode))
        known_layout = QVBoxLayout(self.known_box)
        self.known_browser = QTextBrowser()
        self.known_browser.setToolTip(tooltip("known", mode))
        known_layout.addWidget(self.known_browser)
        layout.addWidget(self.known_box, stretch=1)
        return pane

    def _right_pane(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        widget = QWidget()
        self.actions_layout = QVBoxLayout(widget)
        self.actions_layout.setContentsMargins(2, 0, 8, 0)
        self.actions_layout.addWidget(QLabel("Куда именно прописывать:"))

        self.report_box = QGroupBox("Отчёт")
        report_layout = QHBoxLayout(self.report_box)
        mode = mode_of(self.cfg)
        save_btn = QPushButton("Сохранить Markdown")
        save_btn.clicked.connect(self._save_report)
        save_btn.setToolTip(tooltip("save_report", mode))
        ai_btn = QPushButton("Скопировать для ИИ")
        ai_btn.setProperty("class", "secondary")
        ai_btn.clicked.connect(self._copy_ai_prompt)
        ai_btn.setToolTip(tooltip("ai_copy", mode))
        panel_btn = QPushButton("Панель NFQWS2")
        panel_btn.setProperty("class", "secondary")
        panel_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.cfg.panel_url)))
        panel_btn.setToolTip(tooltip("panel", mode))
        alt_btn = QPushButton("Панель :90 (обход РКН)")
        alt_btn.setProperty("class", "secondary")
        alt_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.cfg.alt_panel_url)))
        alt_btn.setToolTip(tooltip("panel_alt", mode))
        avo_btn = QPushButton("VPN-туннель")
        avo_btn.setProperty("class", "secondary")
        avo_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.cfg.tunnel_url)))
        avo_btn.setToolTip(tooltip("tunnel", mode))
        report_layout.addWidget(save_btn)
        report_layout.addWidget(ai_btn)
        report_layout.addWidget(panel_btn)
        report_layout.addWidget(alt_btn)
        report_layout.addWidget(avo_btn)
        self.actions_layout.addWidget(self.report_box)
        self.actions_layout.addStretch()
        scroll.setWidget(widget)
        return scroll

    @staticmethod
    def _verdict_style(level: str) -> str:
        bg, fg, border = LEVEL_COLORS.get(level, LEVEL_COLORS["UNKNOWN"])
        return (f"background: {bg}; border: 1px solid {border}; border-left: 5px solid {border}; "
                f"border-radius: 6px; padding: 12px; color: {fg};")

    # ---------- проверка ----------

    def closeEvent(self, event) -> None:  # noqa: N802 — Qt API
        self._save_geometry()
        # Не завершать QApplication, пока CheckWorker ещё работает: иначе поток
        # обратится к Destroyed-виджетам. Закроемся сами, когда он завершится.
        if self.worker and self.worker.isRunning():
            self.statusBar().showMessage("Идёт проверка — окно закроется после её завершения…")
            self.worker.finished.connect(self._close_after_worker, Qt.ConnectionType.UniqueConnection)
            event.ignore()
            return
        super().closeEvent(event)

    def _close_after_worker(self) -> None:
        self.worker = None
        self.close()

    def _on_check(self) -> None:
        raw = self.input.text().strip()
        if not raw:
            QMessageBox.information(self, "Пустой ввод", "Введите домен, например api.telegram.org")
            return
        if self.worker and self.worker.isRunning():
            return
        self.check_btn.setEnabled(False)
        self.statusBar().showMessage("Запуск проверки…")
        self.worker = CheckWorker(raw, self.cfg, self.knowledge)
        self.worker.progress.connect(lambda text: self.statusBar().showMessage(text))
        self.worker.result_ready.connect(self._on_result)
        self.worker.start()

    def _on_result(self, verdict: Verdict | None, error: object) -> None:
        self.check_btn.setEnabled(True)
        if error is not None:
            QMessageBox.critical(self, "Ошибка проверки", str(error)[:2000])
            self.statusBar().showMessage("Ошибка")
            return
        if verdict is None:
            return
        self.verdict = verdict
        self.markdown = build_markdown(verdict)
        add_history(verdict, self.markdown)
        self._render_verdict(verdict)
        self.statusBar().showMessage(f"Проверено: {verdict.domain} · {datetime.now():%H:%M:%S}")

    def _render_verdict(self, v: Verdict) -> None:
        mode = mode_of(self.cfg)
        level_text, title_text, summary_text = verdict_text(v, mode)
        self.verdict_frame.setStyleSheet(self._verdict_style(v.level))
        self.level_label.setText(level_text)
        self.title_label.setText(title_text)
        self.summary_label.setText(summary_text)

        self.evidence_table.setRowCount(0)
        for label, value, status in v.evidence:
            row = self.evidence_table.rowCount()
            self.evidence_table.insertRow(row)
            self.evidence_table.setItem(row, 0, QTableWidgetItem(label))
            item = QTableWidgetItem(str(value))
            color = {"ok": "#1b5e20", "warn": "#e65100", "bad": "#b71c1c"}.get(status)
            if color:
                item.setForeground(QColor(color))
            self.evidence_table.setItem(row, 1, item)
        # Ширина колонки фиксированная (см. _left_pane), иначе длинные значения
        # растягивают таблицу и горизонтальная прокрутка не появляется.

        esc = html.escape
        warn_html = []
        for w in v.warnings:
            warn_html.append(f"<p>⚠️ <b>{esc(w)}</b></p>")
        for p in v.pitfalls:
            warn_html.append(f"<p>📌 <b>{esc(p.title)}.</b> {esc(p.text)}</p>")
        self.warnings_browser.setHtml("".join(warn_html) or "<p>Нет специальных предупреждений.</p>")

        known_html = []
        for e in v.knowledge:
            known_html.append(
                f"<p><code>{esc(e.domain)}</code> → <b>{esc(e.level)}</b>: {esc(e.action)}<br>"
                f"<span style='color:#546e7a'>{esc(e.note)}</span></p>"
            )
        self.known_browser.setHtml("".join(known_html) or "<p>Домен в эталонной базе не найден.</p>")
        self._render_actions(v)

    def _render_actions(self, v: Verdict) -> None:
        while self.actions_layout.count():
            item = self.actions_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        mode = mode_of(self.cfg)
        header = QLabel("Куда именно прописывать:")
        header.setToolTip(tooltip("actions", mode))
        self.actions_layout.addWidget(header)
        for idx, action in enumerate(v.actions, 1):
            box = QGroupBox(f"{idx}. {action.title}")
            box.setToolTip(tooltip("actions", mode))
            layout = QVBoxLayout(box)
            if action.path:
                path_label = QLabel(f"Путь: <code>{html.escape(action.path)}</code>")
                path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                layout.addWidget(path_label)
            if action.line:
                line_label = QLabel(f"Добавить: <code>{html.escape(action.line)}</code>")
                line_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                layout.addWidget(line_label)
            if action.commands:
                commands = QPlainTextEdit()
                commands.setPlainText(action.commands)
                commands.setReadOnly(True)
                commands.setMaximumHeight(130)
                layout.addWidget(commands)
                copy = QPushButton("Копировать команды")
                copy.setProperty("class", "secondary")
                copy.clicked.connect(lambda checked=False, text=action.commands: QApplication.clipboard().setText(text))
                copy.setToolTip(tooltip("copy_commands", mode))
                layout.addWidget(copy)
            if action.url:
                open_btn = QPushButton(f"Открыть {action.url}")
                open_btn.setProperty("class", "secondary")
                open_btn.clicked.connect(lambda checked=False, url=action.url: QDesktopServices.openUrl(QUrl(url)))
                layout.addWidget(open_btn)
            if action.note or mode == "novice":
                note_text = action_note(action.note, v, mode, bool(action.commands))
                note = QLabel(note_text)
                note.setTextFormat(Qt.TextFormat.PlainText)
                note.setWordWrap(True)
                note.setStyleSheet("color: #546e7a; line-height: 140%;" if mode == "novice" else "color: #546e7a;")
                layout.addWidget(note)
            self.actions_layout.addWidget(box)

        self.report_box = QGroupBox("Отчёт")
        report_layout = QHBoxLayout(self.report_box)
        mode = mode_of(self.cfg)
        save_btn = QPushButton("Сохранить Markdown")
        save_btn.clicked.connect(self._save_report)
        save_btn.setToolTip(tooltip("save_report", mode))
        ai_btn = QPushButton("Скопировать для ИИ")
        ai_btn.setProperty("class", "secondary")
        ai_btn.clicked.connect(self._copy_ai_prompt)
        ai_btn.setToolTip(tooltip("ai_copy", mode))
        panel_btn = QPushButton("Панель NFQWS2")
        panel_btn.setProperty("class", "secondary")
        panel_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.cfg.panel_url)))
        panel_btn.setToolTip(tooltip("panel", mode))
        alt_btn = QPushButton("Панель :90 (обход РКН)")
        alt_btn.setProperty("class", "secondary")
        alt_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.cfg.alt_panel_url)))
        alt_btn.setToolTip(tooltip("panel_alt", mode))
        avo_btn = QPushButton("VPN-туннель")
        avo_btn.setProperty("class", "secondary")
        avo_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(self.cfg.tunnel_url)))
        avo_btn.setToolTip(tooltip("tunnel", mode))
        report_layout.addWidget(save_btn)
        report_layout.addWidget(ai_btn)
        report_layout.addWidget(panel_btn)
        report_layout.addWidget(alt_btn)
        report_layout.addWidget(avo_btn)
        self.actions_layout.addWidget(self.report_box)
        self.actions_layout.addStretch()

    # ---------- меню/сервис ----------

    def _on_mode_changed(self, index: int) -> None:
        keys = ["novice", "intermediate", "pro"]
        self.cfg.hint_mode = keys[index] if 0 <= index < len(keys) else "novice"
        save_config(self.cfg)
        # Обновляем подсказки у инструментов без перезапуска.
        mode = self.cfg.hint_mode
        for widget, key in (
            (self.input, "domain"), (self.domain_lbl, "domain"), (self.check_btn, "check"),
            (self.mode_combo, "hint_mode"), (self.mode_lbl, "hint_mode"),
            (self.term_btn, "terminal"), (self.settings_btn, "settings"), (self.history_btn, "history"),
            (self.evidence_table, "evidence"), (self.evidence_box, "evidence"),
            (self.warnings_browser, "warnings"), (self.warnings_box, "warnings"),
            (self.known_browser, "known"), (self.known_box, "known"), (self.level_label, "level_label"),
        ):
            widget.setToolTip(tooltip(key, mode))
        if self.verdict is not None:
            self._render_verdict(self.verdict)
        self.statusBar().showMessage(f"Режим подсказок: {MODE_LABELS[mode]}")

    def _on_terminal(self) -> None:
        if not self.cfg.ssh_password:
            QMessageBox.information(
                self, "Пароль не задан",
                "Откройте «Настройки» и введите пароль SSH роутера, чтобы подключиться к терминалу.",
            )
            return
        dialog = TerminalDialog(self.cfg, self)
        dialog.exec()

    def _copy_ai_prompt(self) -> None:
        if self.verdict is None:
            QMessageBox.information(self, "Нет данных", "Сначала проверьте домен.")
            return
        QApplication.clipboard().setText(ai_prompt(self.verdict, self.cfg))
        self.statusBar().showMessage("Отчёт для ИИ скопирован в буфер обмена.")

    def _save_report(self) -> None:
        if not self.markdown:
            QMessageBox.information(self, "Нет отчёта", "Сначала проверьте домен.")
            return
        name = self.verdict.domain if self.verdict else "domain"
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить отчёт", f"{name}-check.md", "Markdown (*.md);;Все файлы (*.*)"
        )
        if not path:
            return
        try:
            Path(path).write_text(self.markdown, encoding="utf-8")
            self.statusBar().showMessage(f"Отчёт сохранён: {path}")
        except OSError as exc:
            QMessageBox.critical(self, "Ошибка сохранения", str(exc))

    def _on_settings(self) -> None:
        dialog = SettingsDialog(self.cfg, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self.cfg = dialog.values()
        idx = ["novice", "intermediate", "pro"].index(self.cfg.hint_mode)
        self.mode_combo.blockSignals(True)
        self.mode_combo.setCurrentIndex(idx)
        self.mode_combo.blockSignals(False)
        ok, info = save_config(self.cfg)
        if ok:
            self.statusBar().showMessage(f"Настройки сохранены: {info}")
        else:
            QMessageBox.warning(self, "Не удалось сохранить", info)
        if self.verdict is not None:
            self._render_verdict(self.verdict)

    def _on_history(self) -> None:
        HistoryDialog(self).exec()
