"""Опрос роутера: HTTP API панели NFQWS2 (:8090) и read-only SSH (Entware)."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
import os
import threading
import time
import warnings
from pathlib import Path
from typing import Any

import paramiko
import requests
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

from ..config import ROUTER_PATHS, Config, app_dir
from .normalize import domain_matches, normalize_domain

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Роль каждого списка nfqws2: включает обход, выключает его, только Google.
LIST_ROLES = {
    "list_general": "include",
    "list_general_user": "include",
    "list_exclude": "exclude",
    "list_exclude_user": "exclude",
    "list_google": "google",
}

# Человеческие названия файлов для подсказок.
LIST_NAMES = {
    "list_general": "list-general.list",
    "list_general_user": "list-general-user.list",
    "list_exclude": "list-exclude.list",
    "list_exclude_user": "list-exclude-user.list",
    "list_google": "list-google.list",
}


def classify_list_status(placements: list[dict[str, Any]]) -> dict[str, Any]:
    """Классифицирует наличие домена в списках nfqws2.

    placements — записи вида {short, line, host, doh_only}.
    Возвращает {status, message, conflicts} где status:
      none | ok | wrong_exclude | wrong_google | wrong_doh | conflict
    """
    roles = {p.get("short") for p in placements}
    includes = [p for p in placements if LIST_ROLES.get(p.get("short", "")) == "include" and not p.get("doh_only")]
    excludes = [p for p in placements if LIST_ROLES.get(p.get("short", "")) == "exclude"]
    googles = [p for p in placements if LIST_ROLES.get(p.get("short", "")) == "google"]
    doh_only = [p for p in placements if p.get("doh_only")]

    def describe(items: list[dict[str, Any]]) -> str:
        seen: list[str] = []
        for p in items:
            label = f"{LIST_NAMES.get(p.get('short', ''), p.get('short', '?'))}: {p.get('line', '')}"
            if label not in seen:
                seen.append(label)
        return "; ".join(seen)

    if includes and excludes:
        return {
            "status": "conflict",
            "message": (f"КОНФЛИКТ: домен есть и в списке обхода ({describe(includes)}), "
                        f"и в списке исключений ({describe(excludes)}). "
                        "В списке исключений обход ВЫКЛЮЧАЕТСЯ — удалите оттуда эту запись."),
            "conflicts": includes + excludes,
        }
    if excludes:
        return {
            "status": "wrong_exclude",
            "message": (f"Домен находится в списке исключений ({describe(excludes)}), "
                        "где обход nfqws2 ВЫКЛЮЧАЕТСЯ. Если сайт не открывается — уберите его оттуда "
                        "и добавьте в list-general.list."),
            "conflicts": list(excludes),
        }
    if googles and not includes:
        return {
            "status": "wrong_google",
            "message": (f"Домен лежит в list-google.list ({describe(googles)}) — этот список только для "
                        "доменов Google. Для обхода нужна запись в list-general.list."),
            "conflicts": list(googles),
        }
    if doh_only and not includes:
        return {
            "status": "wrong_doh",
            "message": (f"Запись с префиксом ^ ({describe(doh_only)}) — это только DoH-резолверы. "
                        "Для обычного сайта нужна запись без ^ в list-general.list."),
            "conflicts": list(doh_only),
        }
    if includes:
        return {
            "status": "ok",
            "message": (f"Домен уже в правильном списке ({describe(includes)}) — обход применён, "
                        "добавлять больше нечего. Запись без префикса покрывает поддомены."),
            "conflicts": [],
        }
    return {"status": "none", "message": "Домен ни в одном списке nfqws2 не найден.", "conflicts": []}


_KNOWN_HOSTS_LOCK = threading.Lock()


class _TrustOnFirstUsePolicy(paramiko.MissingHostKeyPolicy):
    """При первом подключении сохраняет ключ хоста, дальше проверяет его (защита от MITM)."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key) -> None:
        client.get_host_keys().add(hostname, key.get_name(), key)
        with _KNOWN_HOSTS_LOCK:
            try:
                # Атомарная запись: router.py и терминал могут писать из разных потоков.
                tmp = self.path.with_suffix(self.path.suffix + ".tmp")
                client.get_host_keys().save(str(tmp))
                os.replace(tmp, self.path)
            except OSError:
                pass


def _first_ip(value: Any) -> str | None:
    if isinstance(value, str):
        match = IP_RE.search(value)
        return match.group(0) if match else None
    if isinstance(value, (list, tuple)):
        for item in value:
            found = _first_ip(item)
            if found:
                return found
    if isinstance(value, dict):
        for item in value.values():
            found = _first_ip(item)
            if found:
                return found
    return None


def _all_ips(value: Any) -> list[str]:
    if isinstance(value, str):
        return IP_RE.findall(value)
    if isinstance(value, (list, tuple)):
        result: list[str] = []
        for item in value:
            result.extend(_all_ips(item))
        return result
    if isinstance(value, dict):
        result: list[str] = []
        for item in value.values():
            result.extend(_all_ips(item))
        return result
    return []


class RouterClient:
    """Все запросы только на чтение — конфиг роутера не изменяется."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "DomainChecker/1.0"})
        self._ssh_cache: dict[str, dict[str, Any]] = {}
        self._ssh_failure: str | None = None
        self._ssh_mitm: bool = False
        self._ssh_client: paramiko.SSHClient | None = None

    # ---------- HTTP панель ----------

    def panel_status(self) -> tuple[bool, str]:
        try:
            resp = self.session.get(self.cfg.panel_url, timeout=min(4.0, self.cfg.http_timeout))
            return True, f"панель {self.cfg.panel_url} отвечает (HTTP {resp.status_code})"
        except RequestException as exc:
            return False, f"панель {self.cfg.panel_url} недоступна: {exc}"

    def blockcheck(self, targets: list[str]) -> dict[str, Any]:
        """Запускает BlockCheck и ждёт результата. Возвращает targets по хостам."""
        if not targets:
            return {"ok": False, "error": "нет целей для проверки", "targets": {}}
        try:
            response = self.session.post(
                f"{self.cfg.panel_url}/api/blockcheck",
                json={"targets": targets, "threads": 2},
                timeout=self.cfg.http_timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except (RequestException, ValueError) as exc:
            return {"ok": False, "error": f"запуск BlockCheck: {exc}", "targets": {}}

        check_id = payload.get("id") or payload.get("check_id")
        if not check_id:
            if "targets" in payload:
                return self._parse_blockcheck(payload)
            return {"ok": False, "error": "панель не вернула id BlockCheck", "targets": {}}

        deadline = time.monotonic() + self.cfg.blockcheck_timeout
        data: dict[str, Any] = {}
        poll_errors = 0
        while time.monotonic() < deadline:
            try:
                resp = self.session.get(
                    f"{self.cfg.panel_url}/api/blockcheck/{check_id}",
                    timeout=self.cfg.http_timeout,
                )
                resp.raise_for_status()
                data = resp.json()
            except (RequestException, ValueError) as exc:
                # Одна transient-ошибка GET не должна обнулять всю проверку.
                poll_errors += 1
                if poll_errors >= 3:
                    return {"ok": False, "error": f"опрос BlockCheck: {exc}", "targets": {}}
                time.sleep(1.5)
                continue
            poll_errors = 0
            if self._blockcheck_done(data):
                return self._parse_blockcheck(data)
            time.sleep(1.5)
        return {"ok": False, "error": "BlockCheck не завершился за отведённое время", "targets": {}}

    @staticmethod
    def _blockcheck_done(data: dict[str, Any]) -> bool:
        if data.get("error"):
            return True
        status = str(data.get("status", "")).lower()
        if status in {"done", "complete", "completed", "finished", "ok"}:
            return True
        if any(key in data for key in ("running", "in_progress", "is_running")):
            return not any(bool(data.get(k)) for k in ("running", "in_progress", "is_running"))
        done = data.get("done")
        total = data.get("total")
        if done is not None and total is not None:
            try:
                if int(done) < int(total):
                    return False
                # done == total, но targets пуст (все цели отвалились или панель
                # вернула неполный ответ) — не ждать до таймаута, а вернуть
                # то, что есть. Иначе проверка висит ~90 секунд зря.
                return True
            except (TypeError, ValueError):
                pass
        targets = data.get("targets")
        # Панель может вернуть targets как dict {host: {...}} — _parse_blockcheck
        # это поддерживает, а здесь раньше не учитывалось → вечный timeout.
        if isinstance(targets, dict) and targets:
            return all(isinstance(t, dict) and "blocked" in t for t in targets.values())
        if isinstance(targets, list) and targets:
            return all(isinstance(t, dict) and "blocked" in t for t in targets)
        return False

    @staticmethod
    def _parse_blockcheck(data: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {"ok": True, "error": None, "targets": {}, "raw": data}
        if data.get("error"):
            result["ok"] = False
            result["error"] = str(data["error"])
            return result
        targets = data.get("targets", [])
        if isinstance(targets, dict):
            targets = [
                {"host": host, **value} if isinstance(value, dict) else {"host": host}
                for host, value in targets.items()
            ]
        if not isinstance(targets, list):
            return result
        for item in targets:
            if not isinstance(item, dict):
                continue
            host = str(item.get("host") or item.get("target") or item.get("domain") or "").lower()
            if not host:
                continue
            result["targets"][host] = {
                "blocked": item.get("blocked"),
                "verdict": str(item.get("verdict", "")),
                "code": item.get("code"),
                "ttfb_ms": item.get("ttfb_ms", item.get("ttfb")),
                "connect_ms": item.get("connect_ms", item.get("connect")),
                "err": str(item.get("err", "") or ""),
            }
        return result

    def dns_test(self, domain: str, rtype: str = "A") -> dict[str, Any]:
        try:
            resp = self.session.post(
                f"{self.cfg.panel_url}/api/dnsserver/test",
                json={"domain": domain, "type": rtype},
                timeout=self.cfg.http_timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except (RequestException, ValueError) as exc:
            return {"ok": False, "error": str(exc), "ips": [], "raw": None}

        error = data.get("error") if isinstance(data, dict) else None
        # Только A/AAAA-записи из answers: _all_ips(data) тащил бы IP из
        # upstream (https://1.1.1.1/dns-query) и bootstrap_ips — ложные адреса
        # попадали в conntrack и создавали ложные IP-вердикты.
        wanted = "AAAA" if rtype.upper() == "AAAA" else "A"
        ips: list[str] = []
        answers = data.get("answers", []) if isinstance(data, dict) else []
        for answer in answers if isinstance(answers, list) else []:
            if not isinstance(answer, str):
                continue
            parts = answer.split()
            if wanted not in parts:
                continue
            candidate = parts[-1]
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if candidate not in ips:
                ips.append(candidate)
        unique = [ip for ip in ips if ip != self.cfg.router_host]
        return {
            "ok": not error,
            "error": str(error) if error else None,
            "ips": unique,
            "ip": unique[0] if unique else None,
            "route": data.get("route") if isinstance(data, dict) else None,
            "upstream": data.get("upstream") if isinstance(data, dict) else None,
            "raw": data,
        }

    def connections(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                f"{self.cfg.panel_url}/api/connections", timeout=self.cfg.http_timeout
            )
            resp.raise_for_status()
            data = resp.json()
        except (RequestException, ValueError) as exc:
            return {"ok": False, "error": str(exc), "items": []}
        items = data.get("items", []) if isinstance(data, dict) else []
        return {"ok": True, "error": None, "items": items if isinstance(items, list) else []}

    def probe_redirect(self, host: str) -> str | None:
        """Информационная проверка редиректа. На ПК под WARP результат может быть неполным."""
        try:
            resp = self.session.get(
                f"https://{host}/",
                allow_redirects=False,
                timeout=min(6.0, self.cfg.http_timeout),
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            location = resp.headers.get("Location")
            target = normalize_domain(location) if location else None
            # Редирект на самого себя (например ozon.ru -> ozon.ru/?__rr=1)
            # не является настоящим редиректом на другой домен.
            if target == host:
                return None
            return target
        except RequestException:
            return None

    # ---------- SSH (Entware), только cat ----------

    def ssh_read(self, command: str) -> dict[str, Any]:
        if command in self._ssh_cache:
            return self._ssh_cache[command]
        if self._ssh_failure:
            return {"ok": False, "error": self._ssh_failure, "stdout": "", "stderr": ""}
        if not self._connect_ssh():
            # _ssh_failure уже содержит явное MITM-сообщение при смене ключа.
            return {"ok": False, "error": self._ssh_failure or "SSH недоступен",
                    "stdout": "", "stderr": "", "mitm": self._ssh_mitm}

        try:
            _, stdout, stderr = self._ssh_client.exec_command(command, timeout=self.cfg.ssh_timeout)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            exit_code = stdout.channel.recv_exit_status()
            if exit_code == 0:
                result = {"ok": True, "error": None, "stdout": out, "stderr": err}
            else:
                detail = err.strip() or f"exit code {exit_code}"
                result = {"ok": False, "error": detail, "stdout": out, "stderr": err,
                          "exit_code": exit_code}
        except (paramiko.SSHException, OSError) as exc:
            result = {"ok": False, "error": str(exc), "stdout": "", "stderr": ""}
        self._ssh_cache[command] = result
        return result

    def _connect_ssh(self) -> bool:
        if self._ssh_client is not None:
            transport = self._ssh_client.get_transport()
            if transport is not None and transport.is_active():
                return True
            self._ssh_client.close()
            self._ssh_client = None
        known_hosts = app_dir() / "known_hosts.txt"
        client = paramiko.SSHClient()
        if known_hosts.exists():
            client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(_TrustOnFirstUsePolicy(known_hosts))
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
                self._ssh_client = client
                self._ssh_failure = None
                self._ssh_mitm = False
                return True
            except paramiko.BadHostKeyException as exc:
                # Ключ хоста сменился — возможная MITM-атака. Не пробуем другие
                # порты и не маскируем под «SSH недоступен».
                self._ssh_mitm = True
                client.close()
                self._ssh_failure = (
                    f"ВНИМАНИЕ: SSH-ключ {self.cfg.router_host}:{port} НЕ совпадает с сохранённым "
                    f"в known_hosts.txt — возможна MITM-атака ({exc}). "
                    "Если роутер перепрошивали — удалите known_hosts.txt и подключитесь заново."
                )
                return False
            except (paramiko.SSHException, OSError) as exc:
                last_error = f"порт {port}: {exc}"
        client.close()
        self._ssh_failure = f"SSH недоступен ({last_error})"
        return False

    def close(self) -> None:
        if self._ssh_client is not None:
            self._ssh_client.close()
            self._ssh_client = None
        self.session.close()

    def cat(self, path: str) -> dict[str, Any]:
        # Не подавляем stderr: при отсутствии файла он даёт понятную причину,
        # а exit-код всё равно проверяется в ssh_read().
        return self.ssh_read(f"cat {shlex.quote(path)}")

    # ---------- Сводный сбор данных ----------

    def collect(self, hosts: list[str], redirect_target: str | None = None) -> dict[str, Any]:
        panel_ok, panel_message = self.panel_status()
        check_hosts = list(dict.fromkeys([h for h in hosts if h][:6]))
        if redirect_target and redirect_target not in check_hosts:
            check_hosts.append(redirect_target)

        result: dict[str, Any] = {
            "panel_ok": panel_ok,
            "panel_message": panel_message,
            "hosts": check_hosts,
            "redirect_target": redirect_target,
            "blockcheck": {"ok": False, "error": "панель недоступна", "targets": {}},
            "dns": {},
            "connections": {"ok": False, "error": "панель недоступна", "items": []},
            "lists": {},
            "dnsserver": {"ok": False, "error": "панель недоступна", "rules": [], "matches": []},
        }

        if panel_ok:
            result["blockcheck"] = self.blockcheck(check_hosts)
            for host in check_hosts[:4]:
                result["dns"][host] = self.dns_test(host, "A")
            result["connections"] = self.connections()

        # Списки nfqws2
        list_matches: list[dict[str, str]] = []
        placements: list[dict[str, Any]] = []  # вхождения проверяемого (первого) хоста
        list_contents: dict[str, list[str]] = {}
        ssh_ok = True
        list_errors: list[str] = []
        for key in ("list_general", "list_general_user", "list_exclude", "list_exclude_user", "list_google"):
            path = ROUTER_PATHS[key]
            data = self.cat(path)
            if not data.get("ok"):
                ssh_ok = False
                list_errors.append(f"{key}: {data.get('error')}")
            lines = [line.strip() for line in data.get("stdout", "").splitlines() if line.strip()]
            list_contents[key] = lines
            for host in check_hosts:
                for line in lines:
                    if line.startswith("#"):
                        continue
                    doh_only = line.startswith("^")
                    if domain_matches(line, host):
                        item = {"file": path, "line": line, "host": host, "short": key,
                                "doh_only": doh_only}
                        list_matches.append(item)
                        if host == check_hosts[0]:
                            placements.append(item)
        list_status = classify_list_status(placements)
        result["lists"] = {"ok": ssh_ok, "contents": list_contents, "matches": list_matches,
                           "errors": list_errors, "placements": placements,
                           "status": list_status["status"], "message": list_status["message"],
                           "conflicts": list_status["conflicts"]}

        # dnsserver.json
        dns_data = self.cat(ROUTER_PATHS["dnsserver"])
        rules: list[dict[str, Any]] = []
        matches: list[dict[str, Any]] = []
        if dns_data.get("ok") and dns_data.get("stdout", "").strip():
            try:
                parsed = json.loads(dns_data["stdout"])
                config = parsed.get("config", parsed)
                raw_rules = config.get("rules", []) if isinstance(config, dict) else []
                for rule in raw_rules if isinstance(raw_rules, list) else []:
                    if not isinstance(rule, dict):
                        continue
                    rules.append(rule)
                    domain = str(rule.get("domain") or rule.get("name") or rule.get("host") or "")
                    for host in check_hosts:
                        if domain and domain_matches(domain, host):
                            matches.append({"host": host, "rule": rule})
            except ValueError:
                dns_data = {"ok": False, "error": "не удалось разобрать dnsserver.json", "stdout": ""}
        result["dnsserver"] = {
            "ok": dns_data.get("ok", False),
            "error": dns_data.get("error"),
            "rules_count": len(rules),
            "matches": matches,
        }

        result["ip_addresses"] = sorted({ip for info in result["dns"].values() for ip in info.get("ips", [])})
        return result

    def _ssh_ok(self) -> bool:
        return not self._ssh_failure

    @staticmethod
    def ip_block_evidence(items: list[dict[str, Any]], ips: list[str]) -> list[dict[str, Any]]:
        """Ищет в conntrack признаки роняемого SYN по IP."""
        proof: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            dst = str(item.get("dst", ""))
            if ips and not any(dst == ip or dst.startswith(ip + ":") for ip in ips):
                continue
            state = str(item.get("state", "")).upper()
            unreplied = item.get("unreplied")
            reply_raw = item.get("reply_bytes")
            has_reply = reply_raw is not None
            try:
                reply_bytes = int(reply_raw) if has_reply else 0
            except (TypeError, ValueError):
                reply_bytes, has_reply = 0, False
            # Отсутствие поля reply_bytes ≠ «0 байт»: у обычного
            # устанавливающегося соединения поле может просто отсутствовать.
            zero_reply = has_reply and reply_bytes == 0
            if state == "SYN_SENT" and (unreplied is True or str(unreplied).lower() in {"1", "true"} or zero_reply):
                proof.append({
                    "dst": dst, "dport": item.get("dport"), "state": state,
                    "unreplied": unreplied, "reply_bytes": reply_bytes,
                })
        return proof
