"""Стартовая точка для PyInstaller: импортирует приложение как пакет src."""

from src.main import main

if __name__ == "__main__":
    raise SystemExit(main())
