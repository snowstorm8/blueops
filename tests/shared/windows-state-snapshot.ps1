# Prints a JSON snapshot of host state the Windows audit must never change (used by
# tests/shared/test_windows_live_audit.py). Read-only.
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

# Diagnostics for a registry key difference (kept under diag, which the test never compares). Per value:
# type, length, a short digest and, only for the Lsa key and only when the name does not look like a
# credential, the data itself. Binary data is never printed. Keys are opened read-only.
$sensitiveName = '(?i)pass|secret|credential|token|key|pwd'
$dataKeys = @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa')
$regTimeOk = $false
try {
    Add-Type -Namespace BoDiag -Name RegTime -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern int RegQueryInfoKey(System.IntPtr hKey, System.Text.StringBuilder lpClass, System.IntPtr lpcbClass, System.IntPtr lpReserved, System.IntPtr lpcSubKeys, System.IntPtr lpcbMaxSubKeyLen, System.IntPtr lpcbMaxClassLen, System.IntPtr lpcValues, System.IntPtr lpcbMaxValueNameLen, System.IntPtr lpcbMaxValueLen, System.IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);
'@
    $regTimeOk = $true
} catch { Write-Verbose "no last-write support: $($_.Exception.Message)" }

function Get-RegDetail {
    param([string]$Key, [bool]$ShowData)
    $detail = [ordered]@{ last_write = $null; values = [ordered]@{} }
    $rk = $null
    try {
        $hive = if ($Key -like 'HKLM:*') { [Microsoft.Win32.Registry]::LocalMachine } else { [Microsoft.Win32.Registry]::CurrentUser }
        $rk = $hive.OpenSubKey(($Key -replace '^HK(LM|CU):\\', ''))
        if ($null -eq $rk) { return $detail }
        if ($regTimeOk) {
            $ft = [long]0
            $rc = [BoDiag.RegTime]::RegQueryInfoKey($rk.Handle.DangerousGetHandle(), $null, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [System.IntPtr]::Zero, [ref]$ft)
            if ($rc -eq 0) { $detail.last_write = [DateTime]::FromFileTimeUtc($ft).ToString('o') }
        }
        foreach ($n in @($rk.GetValueNames() | Sort-Object)) {
            $kind = [string]$rk.GetValueKind($n)
            $v = $rk.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($v -is [byte[]]) { $text = [BitConverter]::ToString($v) }
            elseif ($v -is [string[]]) { $text = $v -join '|' }
            else { $text = [string]$v }
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $hex = [BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))).Replace('-', '').Substring(0, 16).ToLowerInvariant()
            $entry = [ordered]@{ type = $kind; length = $text.Length; sha256 = $hex; data = $null }
            if ($ShowData -and $kind -ne 'Binary' -and $kind -ne 'Unknown' -and $n -notmatch $sensitiveName) {
                $entry.data = if ($text.Length -gt 120) { $text.Substring(0, 120) + '...' } else { $text }
            }
            $detail.values[$n] = $entry
        }
    } catch { $detail.error = $_.Exception.GetType().Name } finally { if ($rk) { $rk.Dispose() } }
    return $detail
}
$regDetail = [ordered]@{}
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
    $regDetail[$k] = Get-RegDetail -Key $k -ShowData ($dataKeys -contains $k)
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
$bitsSvc = Get-Service -Name BITS -ErrorAction SilentlyContinue
$o.diag = [ordered]@{ at = (Get-Date).ToUniversalTime().ToString('o'); bits_status = [string]$bitsSvc.Status; start_type_changes = $changes; registry = $regDetail }
$o | ConvertTo-Json -Depth 8
