"""Точка входа Domain Checker."""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox


def _show_fatal(message: str) -> None:
    try:
        log = Path(sys.executable).resolve().parent / "domain_checker_error.log"
        log.write_text(message, encoding="utf-8")
    except OSError:
        pass
    try:
        app = QApplication.instance() or QApplication(sys.argv)
        QMessageBox.critical(None, "Domain Checker — ошибка запуска", message[:2000])
    except Exception:  # noqa: BLE001
        print(message, file=sys.stderr)


def main() -> int:
    try:
        app = QApplication(sys.argv)
        app.setApplicationName("Domain Checker")
        app.setOrganizationName("VPN_Router")
        from .ui.main_window import MainWindow
        window = MainWindow()
        window.show()
        return app.exec()
    except Exception:  # noqa: BLE001
        _show_fatal(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())
