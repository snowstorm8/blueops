# Prints a JSON snapshot of host state the Windows audit must never change (used by
# tests/shared/test_windows_live_audit.py). Read-only.
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') {
    $p = Get-ItemProperty -LiteralPath $k
    $o[$k] = if ($p) { ($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ';' } else { '' }
}
$o.services = (Get-CimInstance Win32_Service | Sort-Object Name | ForEach-Object { "$($_.Name)|$($_.StartMode)|$($_.PathName)" }) -join "`n"
$o.users = (Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Sort-Object Name | ForEach-Object { "$($_.Name)|$($_.Disabled)|$($_.PasswordRequired)" }) -join "`n"
$o.tasks = (schtasks.exe /query /fo csv /nh 2>$null | ForEach-Object { ($_ -split '","')[0] } | Sort-Object) -join "`n"
$o.startup = (Get-ChildItem -LiteralPath "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force | ForEach-Object { "$($_.Name)|$($_.Length)" }) -join "`n"
$o.hosts = (Get-FileHash -LiteralPath "$env:SystemRoot\System32\drivers\etc\hosts" -Algorithm SHA256).Hash
$o.fwrules = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules').Count
$o.wmisubs = @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter).Count
$o | ConvertTo-Json -Depth 3
