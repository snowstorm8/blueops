# Prints a JSON snapshot of host state the Windows audit must never change (used by
# tests/shared/test_windows_live_audit.py). Read-only.
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') {
    $p = Get-ItemProperty -LiteralPath $k
    $names = @()
    $text = ''
    if ($p) {
        $props = @($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Sort-Object Name)
        $names = @($props | ForEach-Object { $_.Name })
        $text = ($props | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ';'
    }
    # Names plus a digest only: values (for example Winlogon's) can be sensitive and must not reach test output.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $digest = [BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)))
    $o[$k] = "$($names -join ',') sha256=$digest"
}
$o.services = @(Get-CimInstance Win32_Service | Sort-Object Name | ForEach-Object { "$($_.Name)|$($_.StartMode)|$($_.PathName)" })
$o.users = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Sort-Object Name | ForEach-Object { "$($_.Name)|$($_.Disabled)|$($_.PasswordRequired)" })
$o.tasks = (schtasks.exe /query /fo csv /nh 2>$null | ForEach-Object { ($_ -split '","')[0] } | Sort-Object) -join "`n"
$o.startup = (Get-ChildItem -LiteralPath "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force | ForEach-Object { "$($_.Name)|$($_.Length)" }) -join "`n"
$o.hosts = (Get-FileHash -LiteralPath "$env:SystemRoot\System32\drivers\etc\hosts" -Algorithm SHA256).Hash
$o.fwrules = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules').Count
$o.wmisubs = @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter).Count
# Diagnostics only (the test never compares this key): when the snapshot was taken and the
# System-log start-type changes (event 7040) of the last 30 minutes, so a service difference can be
# attributed to the host instead of guessed at.
$changes = @()
try {
    $changes = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7040; StartTime = (Get-Date).AddMinutes(-30) } -ErrorAction Stop |
        ForEach-Object { [ordered]@{ at = $_.TimeCreated.ToUniversalTime().ToString('o'); message = ($_.Message -replace '\s+', ' ') } })
} catch { Write-Verbose "no 7040 events: $($_.Exception.Message)" }
$o.diag = [ordered]@{ at = (Get-Date).ToUniversalTime().ToString('o'); start_type_changes = $changes }
$o | ConvertTo-Json -Depth 4
