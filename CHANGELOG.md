# Журнал изменений VPSWall

## 0.5.0 — 2026-11-26

- Show native firewall rules and listening TCP/UDP ports on the main web page,
  including rules added from the console before VPSWall was installed or configured.
- Render numbered UFW rules as a readable table preserving IPv6, interfaces,
  source restrictions, direction and comments. Keep administrator rules read-only.
- Inspect every installed firewall: UFW active/saved rules and policies, firewalld
  runtime/permanent zones and direct rules, full nftables ruleset, all IPv4/IPv6
  iptables tables including NAT. Keep native output for complex conditions.
- Add `vpswall ports`; expand CLI/TUI system overview without requiring backend selection.
- Distinguish listening sockets, firewall permissions and external reachability;
  show collection errors, timestamps and truncation instead of misleading empty results.
- Cache authenticated web observations for 10 seconds outside the firewall mutation lock.
- Fix forwarding on Linux by allowing the sysctl executable, reject forwarding when
  socket inspection fails, and restore the previous forwarding configuration/rules
  when an apply fails. Log successful changes only after applying them.
- Build with patched Go 1.26.11 to address known standard-library vulnerabilities;
  update golang.org/x/sys to v0.50.0 and golang.org/x/text to v0.44.0.
- Include vendored Go dependencies and licenses for offline module builds.
- Add regression tests and isolated Linux checks for console rules and native forwarding,
  plus an offline smoke test running the extracted release outside the source tree.

## 0.4.0 — 2026-11-17

### Безопасность доступа по SSH
- Источник SSH-разрешения выбирается в мастерах «Оставить SSH-порт открытым»
  и «Новый SSH-порт» в TUI и вебе: **со всех адресов** (по умолчанию), из подсети
  (/24, IPv6 /64) или только с текущего IP. Раньше разрешался только текущий IP,
  и при его смене доступ терялся.
- Предупреждение в TUI и вебе (`warnings` в `/api/state`), если правила VPSWall
  пускают на SSH-порт только с фиксированных адресов при запрещающей политике.
- Веб-API: необязательное поле `ssh_source` (`any` | `subnet` | `ip`)
  в операциях `toggle` и `ssh-new`. Если поле не передано, используется `any`.
  Остальной формат не изменился.
- `vpswall confirm` принимает только SSH-сеанс, начатый после изменения
  (по времени запуска родительского процесса sshd). Сеанс, открытый до изменения,
  и запуск из tmux/screen отклоняются. В `change.json` добавлено поле `created`.

### Надёжность правил
- Планировщик проверяет фактическое наличие правил VPSWall (UFW, firewalld,
  nftables, iptables), а не только fingerprint последнего применения. После reload,
  `nft flush ruleset` или `ufw reset` правила применяются заново (`DRIFT` в истории).
- Изменения, которые только убирают разрешения (например, закрытие истёкшего окна),
  применяются даже при конфликте с появившимся чужим firewall: Docker, fail2ban,
  активный UFW или firewalld. Открытие портов при конфликте по-прежнему запрещено.
- Тревога: если применение не удалось (например, окно порта не закрылось), в историю
  один раз пишется `ALERT`, а TUI и веб (`alert` в `/api/state`) показывают её
  до успешного применения.
- UFW: открытие и закрытие окон и удаление правил меняют только затронутые правила,
  без пересоздания всех.
- TUI передаёт ревизию конфигурации: изменение поверх правок из другого сеанса
  отклоняется, как в веб-панели.

### Установка
- `install.sh` сверяет SHA-256 бинарника с `dist/SHA256SUMS`, который `build.ps1`
  теперь кладёт в архив.
- `vpswall-web.service`: `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectHome=yes`.
  Чтобы обновить юнит на сервере, выполните `sudo vpswall web enable` повторно.
- README: токен веб-панели не привязан к SSH-сеансу (исправлено описание).

### Прочее
- Пересылка портов (relay): раздел в CLI, TUI и веб-панели.
