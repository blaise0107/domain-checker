"""Конфигурация приложения: значения по умолчанию и локальный config.local.json."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, replace
from pathlib import Path


@dataclass
class Config:
    router_host: str = "192.168.1.1"
    panel_port: int = 8090
    alt_panel_port: int = 90
    ssh_user: str = "root"
    ssh_password: str = "keenetic"  # заводской пароль Keenetic; в config.local.json не пишется (save_password=False)
    ssh_ports: tuple[int, ...] = (222, 22)
    http_timeout: float = 8.0
    blockcheck_timeout: float = 90.0
    ssh_timeout: float = 20.0
    save_password: bool = False  # по умолчанию пароль НЕ пишется в config.local.json (plaintext)
    hint_mode: str = "novice"  # novice / intermediate / pro — режим подсказок

    @property
    def panel_url(self) -> str:
        return f"http://{self.router_host}:{self.panel_port}"

    @property
    def alt_panel_url(self) -> str:
        return f"http://{self.router_host}:{self.alt_panel_port}/"


def app_dir() -> Path:
    """Каталог приложения: рядом с exe либо корень проекта при запуске из исходников."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def resource_dir() -> Path:
    """Каталог ресурсов (data/). В PyInstaller — распакованный _MEIPASS."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return app_dir()


def config_path() -> Path:
    return app_dir() / "config.local.json"


def load_config() -> Config:
    path = config_path()
    cfg = Config()
    if not path.exists():
        return cfg
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw.pop("_comment", None)
        # save_password=False пишет ssh_password:"" — пустая строка не должна
        # затирать заводской пароль по умолчанию, иначе SSH ломается после
        # первого же сохранения настроек и перезапуска.
        if not raw.get("ssh_password"):
            raw.pop("ssh_password", None)
        if "ssh_ports" in raw and isinstance(raw["ssh_ports"], list):
            raw["ssh_ports"] = tuple(int(p) for p in raw["ssh_ports"])
        known = {f for f in Config.__dataclass_fields__}
        cfg = replace(cfg, **{k: v for k, v in raw.items() if k in known})
    except (OSError, ValueError, TypeError):
        pass
    return cfg


def save_config(cfg: Config) -> tuple[bool, str]:
    path = config_path()
    data = asdict(cfg)
    data["ssh_ports"] = list(cfg.ssh_ports)
    data["_comment"] = "Локальные настройки. Пароль хранится только здесь, в исходниках его нет."
    if not cfg.save_password:
        data["ssh_password"] = ""
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return True, str(path)
    except OSError as exc:
        return False, str(exc)


# Пути на роутере (только чтение)
ROUTER_PATHS = {
    "list_general": "/opt/etc/nfqws2/lists/list-general.list",
    "list_general_user": "/opt/etc/nfqws2/lists/list-general-user.list",
    "list_exclude": "/opt/etc/nfqws2/lists/list-exclude.list",
    "list_exclude_user": "/opt/etc/nfqws2/lists/list-exclude-user.list",
    "list_google": "/opt/etc/nfqws2/lists/list-google.list",
    "dnsserver": "/opt/etc/nfqws2-strategy/dnsserver.json",
}
