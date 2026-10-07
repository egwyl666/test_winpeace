<#
  winpeas-lite.ps1 — БЕЗПЕЧНИЙ аналог WinPEAS для лабораторного тесту детекту.
  ТІЛЬКИ ЧИТАЄ систему і друкує звіт. Нічого не змінює, не містить експлойтів.
  Мета: згенерувати телеметрію «невідомий скрипт із Temp перебирає систему» для перевірки SOC.
  Запуск:  powershell -ExecutionPolicy Bypass -File winpeas-lite.ps1 -Marker RECON01_...
#>
param([string]$Marker = "RECON01_adhoc")

$ErrorActionPreference = 'SilentlyContinue'
function Sec($t) { Write-Host "`n===== $t =====" -ForegroundColor Cyan }
Write-Host "winpeas-lite | marker $Marker | $(Get-Date -Format 'u') | host $env:COMPUTERNAME" -ForegroundColor Green
Write-Host "READ-ONLY privilege-escalation recon (lab). No changes are made.`n"

Sec "User and privileges"
whoami /all
whoami /priv

Sec "Local users and admins"
Get-LocalUser | Select Name, Enabled, LastLogon | Format-Table -Auto
Get-LocalGroupMember Administrators | Select Name, PrincipalSource | Format-Table -Auto

Sec "System info"
Get-CimInstance Win32_OperatingSystem | Select Caption, Version, OSArchitecture, LastBootUpTime | Format-List
Get-HotFix | Select -Last 10 HotFixID, InstalledOn | Format-Table -Auto

Sec "Unquoted service paths (classic privesc vector)"
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and $_.PathName -notmatch '^C:\\Windows' } |
  Select Name, StartMode, PathName | Format-Table -Auto -Wrap

Sec "Services with weak-looking binary location (Users/Temp/ProgramData)"
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -match '(?i)\\(users|temp|appdata|programdata)\\' } |
  Select Name, StartName, PathName | Format-Table -Auto -Wrap

Sec "Autoruns (Run keys)"
foreach ($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run') {
  "[$k]"; (Get-Item $k).Property | ForEach-Object { "  $_ = $((Get-ItemProperty $k).$_)" }
}

Sec "Scheduled tasks (non-Microsoft)"
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled' } |
  Select TaskName, TaskPath | Format-Table -Auto

Sec "Stored credentials / interesting env"
cmdkey /list
"PATH dirs writable check (read-only):"
$env:PATH -split ';' | Select-Object -First 15

Sec "Network"
ipconfig /all | Select-String 'IPv4|Gateway|DNS'
Get-NetTCPConnection -State Listen | Select LocalAddress, LocalPort, OwningProcess | Sort LocalPort | Format-Table -Auto

Write-Host "`n===== winpeas-lite done ($Marker) =====" -ForegroundColor Green
