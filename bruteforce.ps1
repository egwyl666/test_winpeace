<#
  bruteforce.ps1 — Фаза 0 емуляції (ENERGY / testPC_2, лабораторний тест).
  Створює ТЕСТОВИЙ локальний обліковий запис <Marker>_user, робить серію НЕВДАЛИХ входів,
  потім один успішний — для генерації 4625/4776 -> 4624. Нічого бойового не чіпає.
  Обліковий запис видаляється у фазі прибирання (recon-lab.ps1 / Invoke-Cleanup).
  Запуск:  powershell -ExecutionPolicy Bypass -File bruteforce.ps1 -Marker RECON01_... [-Attempts 6]
#>
param([string]$Marker = "RECON01_adhoc", [int]$Attempts = 6)

$ErrorActionPreference = 'SilentlyContinue'
$user = "${Marker}_user"
$realPass = 'Wrong_Pass_1'
Write-Host "bruteforce | marker $Marker | target LOCAL test account $user | host $env:COMPUTERNAME" -ForegroundColor Green

# create the throwaway target account (disabled from interactive use is fine; net use failures still log 4625/4776)
net user $user $realPass /add | Out-Null
Write-Host "Created test account $user"

Write-Host "Failed attempts (expect 4625 series + 4776):"
for ($i = 1; $i -le $Attempts; $i++) {
  cmd /c "net use \\127.0.0.1\IPC$ /user:$env:COMPUTERNAME\$user WrongPwd_$i" 2>$null | Out-Null
  net use \\127.0.0.1\IPC$ /delete /y 2>$null | Out-Null
  Start-Sleep -Milliseconds 400
  Write-Host "  attempt $i : bad password"
}

Write-Host "Successful logon (expect 4624):"
cmd /c "net use \\127.0.0.1\IPC$ /user:$env:COMPUTERNAME\$user $realPass" 2>$null | Out-Null
net use \\127.0.0.1\IPC$ /delete /y 2>$null | Out-Null

Write-Host "bruteforce done ($Marker). Account $user will be removed in cleanup." -ForegroundColor Green
