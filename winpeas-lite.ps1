<#
  winpeas-lite.ps1 — БЕЗПЕЧНИЙ аналог WinPEAS для лабораторного тесту детекту.
  ТІЛЬКИ ЧИТАЄ систему і друкує звіт. Нічого не змінює, не містить експлойтів.
  Мета: згенерувати телеметрію «невідомий скрипт із Temp перебирає систему» для перевірки SOC.

  Фокус саме на privesc-векторах (крок 4b, після Ingress Tool Transfer) — без дублювання
  ручної розвідки фаз 1-2 (whoami, systeminfo, net user/localgroup, ipconfig, netstat-listen
  уже зроблено оператором вручну; тут їх немає, щоб не змазувати таймлайн повторним сплеском).

  Запуск:  powershell -ExecutionPolicy Bypass -File winpeas-lite.ps1 -Marker RECON01_...
#>
param([string]$Marker = "RECON01_adhoc")

$ErrorActionPreference = 'SilentlyContinue'
function Sec($t) { Write-Host "`n===== $t =====" -ForegroundColor Cyan }
Write-Host "winpeas-lite | marker $Marker | $(Get-Date -Format 'u') | host $env:COMPUTERNAME" -ForegroundColor Green
Write-Host "READ-ONLY privilege-escalation recon (lab). No changes are made.`n"

Sec "Unquoted service paths (classic privesc vector)"
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and $_.PathName -notmatch '^C:\\Windows' } |
  Select Name, StartMode, PathName | Format-Table -Auto -Wrap

Sec "Services with weak-looking binary location (Users/Temp/ProgramData)"
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -match '(?i)\\(users|temp|appdata|programdata)\\' } |
  Select Name, StartName, PathName | Format-Table -Auto -Wrap

Sec "Writable permissions on service binaries/folders (read-only ACL check)"
Get-CimInstance Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
  $exe = ($_.PathName -replace '^"?([^"]+\.exe).*$', '$1')
  if (Test-Path $exe) {
    $acl = Get-Acl $exe -ErrorAction SilentlyContinue
    $writable = $acl.Access | Where-Object {
      $_.FileSystemRights -match 'FullControl|Write|Modify' -and
      $_.IdentityReference -match 'Users|Everyone|Authenticated Users'
    }
    if ($writable) {
      "  [!] $($_.Name) -> $exe writable by: $($writable.IdentityReference -join ', ')"
    }
  }
}

Sec "AlwaysInstallElevated (MSI privesc vector)"
foreach ($k in 'HKLM:\Software\Policies\Microsoft\Windows\Installer', 'HKCU:\Software\Policies\Microsoft\Windows\Installer') {
  $v = (Get-ItemProperty -Path $k -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
  "  [$k] AlwaysInstallElevated = $v"
}

Sec "Autoruns (Run keys)"
foreach ($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run') {
  "[$k]"; (Get-Item $k).Property | ForEach-Object { "  $_ = $((Get-ItemProperty $k).$_)" }
}

Sec "Scheduled tasks (non-Microsoft)"
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled' } |
  Select TaskName, TaskPath | Format-Table -Auto

Sec "Stored credentials"
cmdkey /list

Sec "Credentials in config files (read-only search, common lab locations)"
$searchRoots = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "C:\inetpub", "C:\ProgramData")
foreach ($root in $searchRoots) {
  if (Test-Path $root) {
    Get-ChildItem -Path $root -Recurse -Include '*.config','*.xml','*.ini','unattend.xml' -ErrorAction SilentlyContinue |
      Select-String -Pattern 'password\s*=|passwd\s*=' -ErrorAction SilentlyContinue |
      Select-Object -First 5 Path, LineNumber
  }
}

Sec "PATH dirs writable check (read-only)"
$env:PATH -split ';' | Select-Object -First 15

Sec "Installed AV/EDR services (visibility check)"
Get-Service | Where-Object { $_.DisplayName -match '(?i)defender|sense|edr|wazuh|crowdstrike|sentinel|carbon' } |
  Select Name, DisplayName, Status | Format-Table -Auto

Sec "Defender exclusion paths (where a dropped tool could hide)"
try { (Get-MpPreference).ExclusionPath } catch {}

Sec "WDigest (plaintext creds cached in LSASS memory if enabled)"
$v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
"  UseLogonCredential = $v (1 = plaintext creds cached)"

Sec "LSA Protection (RunAsPPL)"
$v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
"  RunAsPPL = $v (empty/0 = LSASS not protected)"

Sec "Credential Guard"
$v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name LsaCfgFlags -ErrorAction SilentlyContinue).LsaCfgFlags
"  LsaCfgFlags = $v (empty/0 = Credential Guard off)"

Sec "Cached logon count policy"
$v = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -ErrorAction SilentlyContinue).CachedLogonsCount
"  CachedLogonsCount = $v"

Sec "UAC settings"
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue |
  Select EnableLUA, ConsentPromptBehaviorAdmin, LocalAccountTokenFilterPolicy | Format-List

Sec "PowerShell audit logging status (are we even visible right now?)"
$sb = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
$tr = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -Name EnableTranscripting -ErrorAction SilentlyContinue).EnableTranscripting
$ml = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging
"  ScriptBlockLogging=$sb  Transcription=$tr  ModuleLogging=$ml"

Sec "WSUS over plain HTTP (classic MITM/privesc vector)"
$wu = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
$waserver = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer
"  WUServer = $($wu.WUServer)  UseWUServer = $waserver"

Write-Host "`n===== winpeas-lite done ($Marker) =====" -ForegroundColor Green
