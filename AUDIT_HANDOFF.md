# AUDIT_HANDOFF — краткий брифинг для следующего audited-агента

Этот файл существует, чтобы новая модель могла сразу взяться за аудит, не перечитывая весь чат.

## Что это за проект

`Domain Checker` — десктопное приложение (Windows 11) для диагностики доменов на роутере Keenetic с NFQWS2 Strategy Selector и VPN-туннель.

- Репозиторий: `https://github.com/blaise0107/domain-checker` (ветка `main`).
- Стек: Python 3.14, PySide6 6.12, requests, paramiko 5.0, PyInstaller 6.22; exe ~54 МБ.
- Локально: папка `07_Domain_Checker` рядом с остальными разделами проекта.
- Тесты: `python -m unittest discover -s tests -v` — сейчас **22/22**.
- Сборка: `python -m PyInstaller build.spec --noconfirm` → `dist/DomainChecker.exe`.

Приложение **только читает** роутер и советует; конфиг не меняет. Ввод домена → вердикт об уровне блокировки + точное место правки + готовые команды + отчёт Markdown + история.

## Источники данных

| Источник | Что даёт |
|---|---|
| `:8090/api/blockcheck` (POST + polling `GET /api/blockcheck/{id}` по `done/total`) | `blocked`, `verdict`, `code`, `err`, `ttfb_ms` — эталон, выполняется на роутере |
| `:8090/api/dnsserver/test` | A/AAAA, `route`, `upstream`, `answers` (обязательно поле `type`) |
| `:8090/api/connections` | conntrack: `SYN_SENT` + `unreplied` + `reply_bytes=0` → доказательство IP-блока |
| SSH Entware `:222` (фолбэк `:22`), `root` / заводской `keenetic` | чтение `list-general.list`, `list-general-user.list`, `list-exclude*`, `list-google.list`, `dnsserver.json`, `/opt/etc/vpn/list-general.list` |
| Панель VPN-туннель `:8090` | состояние туннеля, формат `адрес[:порт]`, домены без масок |
| Панель `:90` | `nfqws-keenetic-web` (nfqws v1, обход РКН/YouTube) — только ссылка в GUI |

Безопасность SSH: `save_password=False` по умолчанию (пароль не пишется в `config.local.json`), ключ хоста сохраняется в `known_hosts.txt` по имени `[host]:port` и проверяется при следующих подключениях (TOFU-политика `_TrustOnFirstUsePolicy`).

## Уровни вердикта

`SNI` → `list-general.list` + рестарт nfqws2; `DNS` → правило DNS Server (для геоблока OpenAI — релей `sync.bezmezhau.com`); `IP` → VPN-туннель/туннель (крайняя мера); `REGION` и `OK` → роутер не трогать; `NXDOMAIN` → домена не существует; `UNKNOWN` → нет данных.

Ключевые файлы: `src/core/decision.py` (движок), `src/core/router.py` (опрос), `src/config.py`, `src/core/normalize.py`, `src/core/knowledge.py` (`data/*.json`), `src/ui/main_window.py`, `src/core/report.py`.

## Уже исправлено (16 проблем, два круга аудита с ChatGPT)

1. IP-доказательства и IP для VPN-туннель — только адреса **целевого** хоста, без кандидатов/www/редиректов.
2. Убран fallback к первому попавшемуся результату BlockCheck чужого домена.
3. При успешном BlockCheck conntrack не влияет на вердикт.
4. `_known_level()` — только точное совпадение домена, без наследования чужой записи.
5. `dns_info` и `ips` строго целевого хоста, без подстановки других кандидатов.
6. `avo_matches` фильтруется по целевому хосту/IP (`already` не от чужих маршрутов).
7. NXDOMAIN только при двойном подтверждении: BlockCheck «no such host» **и** пустой DNS роутера.
8. `no such host` через `1.1.1.1/8.8.8.8` при живом IP роутера → DNS/подмена резолвера, не NXDOMAIN.
9. `stopped after N redirects` (Ozon `?__rr=1`) → OK, а не блок.
10. `SYN_SENT` на IP DNS-релея (chatgpt.com) → не IP-блок.
11. SSH: exit-код и stderr учитываются, отсутствие файла ≠ успешное чтение.
12. SSH: host-key TOFU вместо `AutoAddPolicy`; `known_hosts.txt` в `.gitignore`.
13. `lists.ok` честный — только если прочитаны все обязательные списки + список ошибок.
14. `html.escape()` для всех данных, вставляемых в `QTextBrowser`.
15. `save_password=False` по умолчанию.
16. SNI-команда показывает проверяемый домен, если он уже в списке (не родительский).

### Третий круг (находки Qwen из `chat.qwen.ai`, применены)

17. `dns_test()` берёт IP **только из `answers` нужного типа** (A/AAAA): раньше `_all_ips(data)` тащил адреса из `upstream` (`https://1.1.1.1/dns-query`) и `bootstrap_ips` в conntrack/VPN-туннель.
18. `cat()` больше не подавляет stderr — при отсутствии файла видна причина; exit-код проверяется.
19. SSH: сброс «липкого» `_ssh_failure` после успешного подключения; `BadHostKeyException` отделяется от ordinary ошибок порта и помечается как возможный MITM.
20. GUI: `closeEvent` блокирует закрытие окна, пока работает `CheckWorker` (иначе краш из-за Destroyed-виджетов).
21. Удалён инвертированный фильтр, который **убирал** WARP-предупреждение при недоступной панели.
22. BlockCheck: завершение при `done >= total` даже если `targets` пуст (раньше висело до таймаута).

⚠️ Qwen в `chat.qwen.ai` уперся в stateless-песочницу: между вызовами интерпретатора файлы исчезают (`/tmp/dc` → `exists: False`), он циклился на повторной генерации полных файлов (~208k символов) и не выдал финальный структурированный ответ. Если будете просить модель что-то проверить кодом — сразу говорите, что песочница stateless, и просите только точечные diff-блоки текстом.

## Известные ложные срабатывания (не «исправлять» обратно)

| Домен | Почему чекер должен быть осторожен |
|---|---|
| `api.telegram.org` | реальный IP-блок: `SYN_SENT/unreplied/0 байт` + BlockCheck timeout → VPN-туннель — крайняя мера |
| `chatgpt.com` | работает через DNS-релей; `SYN_SENT` на соседний IP релея — норма, не блок |
| `forum.ru-board.com` | BlockCheck не резолвит через `1.1.1.1`, но DNS роутера даёт IP; домен уже в `list-general.list` |
| `ozon.ru` | циклический редирект `?__rr=1` — не блок |
| `1tvrrr.ru` | настоящий NXDOMAIN (не путать с предыдущим) |

## Что стоит проверить следующему аудитору

- Гонки/таймауты: один недоступный источник не должен ломать всю проверку; корректность polling BlockCheck.
- GUI: потоки (`CheckWorker`), состояние кнопок, большие данные в таблицах.
- Тесты: насколько они реально изолируют логику, а не просто зелёные.
- PyInstaller: запуск на чистой системе, путь к `data/`, `known_hosts.txt`, `history.json`.
- Любые новые расхождения вердикта на живом роутере (приоритет — корректность решения).

Проверять лучше по шагам и сразу давать конкретный патч с файлом и строкой;общие рассуждения без подтверждения кодом не нужны.
