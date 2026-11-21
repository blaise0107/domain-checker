"""Окно терминала роутера: подключается к SSH Entware с данными из настроек."""

from __future__ import annotations

import time

import paramiko
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QCloseEvent, QFont, QTextCursor
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QVBoxLayout,
)

from ..config import Config, app_dir
from ..core.router import _TrustOnFirstUsePolicy


class ShellWorker(QThread):
    output = Signal(str)
    error = Signal(str)

    def __init__(self, cfg: Config) -> None:
        super().__init__()
        self.cfg = cfg
        self._stop = False
        self._channel: paramiko.Channel | None = None
        self._client: paramiko.SSHClient | None = None

    def send(self, line: str) -> None:
        if self._channel and not self._channel.closed:
            self._channel.send(line + "\r")

    def stop(self) -> None:
        self._stop = True
        if self._channel is not None:
            try:
                self._channel.close()
            except Exception:  # noqa: BLE001
                pass
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass

    def run(self) -> None:
        client = paramiko.SSHClient()
        known_hosts = app_dir() / "known_hosts.txt"
        try:
            if known_hosts.exists():
                client.load_host_keys(str(known_hosts))
            client.set_missing_host_key_policy(_TrustOnFirstUsePolicy(known_hosts))
            self._client = client
            last_error = ""
            for port in self.cfg.ssh_ports:
                try:
                    client.connect(
                        hostname=self.cfg.router_host,
                        port=port,
                        username=self.cfg.ssh_user,
                        password=self.cfg.ssh_password,
                        timeout=self.cfg.ssh_timeout,
                        look_for_keys=False,
                        allow_agent=False,
                        banner_timeout=self.cfg.ssh_timeout,
                        auth_timeout=self.cfg.ssh_timeout,
                    )
                    break
                except paramiko.BadHostKeyException as exc:
                    self.error.emit(
                        f"Ключ хоста {self.cfg.router_host}:{port} НЕ совпадает — возможна MITM-атака. "
                        f"Если роутер перепрошивали, удалите known_hosts.txt. ({exc})"
                    )
                    return
                except (paramiko.SSHException, OSError) as exc:
                    last_error = f"порт {port}: {exc}"
            else:
                self.error.emit(f"Не удалось подключиться к SSH ({last_error})")
                return

            self.output.emit(
                f"=== Подключено к {self.cfg.ssh_user}@{self.cfg.router_host} "
                f"(порт {client.get_transport().sock.getpeername()[1]}) ===\r\n"
            )
            channel = client.invoke_shell(term="xterm", width=120, height=32)
            self._channel = channel
            channel.settimeout(0.5)
            while not self._stop:
                try:
                    if channel.recv_ready():
                        data = channel.recv(65535)
                        if not data:
                            break
                        self.output.emit(data.decode("utf-8", "replace"))
                    elif channel.closed:
                        break
                except Exception:  # noqa: BLE001 — таймаут recv ожидаем
                    pass
                time.sleep(0.05)
            self.output.emit("\r\n=== Соединение закрыто ===")
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass


class TerminalDialog(QDialog):
    def __init__(self, cfg: Config, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Терминал роутера — {cfg.ssh_user}@{cfg.router_host}")
        self.resize(900, 560)
        self.cfg = cfg

        layout = QVBoxLayout(self)
        info = QLabel(
            "Команды выполняются прямо на роутере. Вставьте команду из подсказки и нажмите Enter. "
            "Для выхода из терминала введите exit."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color:#546e7a; padding: 4px 0;")
        layout.addWidget(info)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 11))
        self.output.setStyleSheet("background:#101820; color:#d7e2ea; border-radius:5px;")
        layout.addWidget(self.output, stretch=1)

        row = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText("команда, например: cat /opt/etc/nfqws2/lists/list-general.list")
        self.input.setFont(QFont("Consolas", 11))
        self.input.returnPressed.connect(self._send)
        row.addWidget(self.input, stretch=1)
        send_btn = QPushButton("Отправить")
        send_btn.clicked.connect(self._send)
        row.addWidget(send_btn)
        copy_btn = QPushButton("Копировать вывод")
        copy_btn.setProperty("class", "secondary")
        copy_btn.clicked.connect(self._copy_output)
        row.addWidget(copy_btn)
        close_btn = QPushButton("Закрыть")
        close_btn.setProperty("class", "secondary")
        close_btn.clicked.connect(self.close)
        row.addWidget(close_btn)
        layout.addLayout(row)

        self.worker = ShellWorker(cfg)
        self.worker.output.connect(self._append)
        self.worker.error.connect(self._on_error)
        self.worker.start()
        self.input.setFocus()

    def _append(self, text: str) -> None:
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        self.output.setTextCursor(cursor)
        self.output.ensureCursorVisible()

    def _on_error(self, message: str) -> None:
        self._append(f"\n[ОШИБКА] {message}\n")

    def _send(self) -> None:
        line = self.input.text().strip()
        if not line:
            return
        self._append(f"{self.cfg.ssh_user}@router:~$ {line}\r\n")
        self.worker.send(line)
        self.input.clear()

    def _copy_output(self) -> None:
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.output.toPlainText())

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        self.worker.stop()
        self.worker.wait(3000)
        super().closeEvent(event)
