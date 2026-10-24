# Module: system (category: audit, read-only). Dot-sourced by the audit entry points.
# Inventory of OS, hardware, boot time and patch level; flags unsupported OS releases.

function ConvertTo-BoDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime() }
    $d = [DateTime]::MinValue
    if ([DateTime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
    return $null
}

function Invoke-BoSystemModule {
    [CmdletBinding()]
    param()
    $cat = 'system'
    Register-BoCheck -Id 'SYS-INFO-001' -Title 'System inventory' -Severity 'info' -Category $cat -Cap 20
    Register-BoCheck -Id 'SYS-OS-001' -Title 'Operating system is out of support' -Severity 'medium' -Category $cat `
        -Description 'The OS release no longer receives security updates (unless covered by extended support).' `
        -Remediation 'Plan an upgrade; until then isolate the host and restrict exposed services.'
    Register-BoCheck -Id 'SYS-UPTIME-001' -Title 'Host has not rebooted for over a year' -Severity 'low' -Category $cat `
        -Description 'Long uptime usually means pending updates and kernel/driver patches are not applied.'
    Register-BoCheck -Id 'SYS-HOTFIX-001' -Title 'No recent security updates installed' -Severity 'low' -Category $cat `
        -Description 'The newest installed hotfix is older than 90 days (or none is reported).' `
        -Remediation 'Check Windows Update / WSUS connectivity and apply pending updates.'

    $os = $null; $cs = $null
    $r = Invoke-BoProvider -Name 'cim.Win32_OperatingSystem' -ErrorCode 'OS_UNREADABLE' -Message 'cannot read Win32_OperatingSystem' -CheckId 'SYS-INFO-001' -Live { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
    if ($r.Ok -and $r.Data.Count -gt 0) { $os = $r.Data[0] }
    $r = Invoke-BoProvider -Name 'cim.Win32_ComputerSystem' -ErrorCode 'CS_UNREADABLE' -Message 'cannot read Win32_ComputerSystem' -CheckId 'SYS-INFO-001' -NonMaterial -Live { Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
    if ($r.Ok -and $r.Data.Count -gt 0) { $cs = $r.Data[0] }

    $caption = [string](Get-BoProp $os 'Caption' 'unknown Windows')
    $version = [string](Get-BoProp $os 'Version' 'unknown')
    $build = [string](Get-BoProp $os 'BuildNumber' '')
    $arch = [string](Get-BoProp $os 'OSArchitecture' 'unknown')
    $boot = ConvertTo-BoDate (Get-BoProp $os 'LastBootUpTime' $null)
    $up = ''
    $uptimeDays = -1
    if ($null -ne $boot) {
        $uptimeDays = [int][Math]::Floor(([DateTime]::UtcNow - $boot).TotalDays)
        $up = "up $($uptimeDays)d, booted $($boot.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    }
    $mem = ''
    $ram = Get-BoProp $cs 'TotalPhysicalMemory' $null
    if ($null -ne $ram) { $mem = ', RAM {0} MiB' -f [int]([double]$ram / 1MB) }
    $domain = 'unknown'
    if ($null -ne $cs) { $domain = "$([string](Get-BoProp $cs 'Domain' 'unknown')) (domain-joined: $([string](Get-BoProp $cs 'PartOfDomain' $false)))" }
    $hw = ([string](Get-BoProp $cs 'Manufacturer' '') + ' ' + [string](Get-BoProp $cs 'Model' '')).Trim()
    $cpus = [string](Get-BoProp $cs 'NumberOfLogicalProcessors' '?')
    $desc = "$caption $version build $build $arch; host $([string](Get-BoProp $os 'CSName' (Get-BoProp $cs 'Name' 'unknown'))); domain $domain; hardware '$hw', CPUs $cpus$mem; $up; PowerShell $($PSVersionTable.PSVersion)"
    $script:BoChecks['SYS-INFO-001'].Description = $desc
    Add-BoHit -Id 'SYS-INFO-001' -Type 'other' -Ref 'cim:Win32_OperatingSystem' -Excerpt "$caption $version"

    # End-of-support releases.
    $eol = @(
        @{ Pattern = 'Windows (XP|Vista)|Server 2003'; Name = 'Windows XP/Vista/Server 2003' },
        @{ Pattern = 'Windows 7|Server 2008'; Name = 'Windows 7 / Server 2008 (R2)' },
        @{ Pattern = 'Windows 8(\.1)?\b|Server 2012'; Name = 'Windows 8/8.1 / Server 2012 (R2)' }
    )
    foreach ($e in $eol) {
        if ($caption -match $e.Pattern) { Add-BoHit -Id 'SYS-OS-001' -Type 'other' -Ref 'cim:Win32_OperatingSystem' -Excerpt "$caption ($($e.Name))" }
    }
    if ($caption -match 'Windows 10') {
        Add-BoHit -Id 'SYS-OS-001' -Type 'other' -Ref 'cim:Win32_OperatingSystem' -Excerpt "$caption (support ended 2025-10-14 unless ESU)" -Severity 'low'
    }
    if ($uptimeDays -gt 365) { Add-BoHit -Id 'SYS-UPTIME-001' -Type 'other' -Ref 'cim:Win32_OperatingSystem' -Excerpt "uptime $uptimeDays days" }

    $r = Invoke-BoProvider -Name 'cim.Win32_QuickFixEngineering' -ErrorCode 'HOTFIX_UNREADABLE' -Message 'cannot enumerate installed hotfixes' -CheckId 'SYS-HOTFIX-001' -NonMaterial -Live { Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop }
    if ($r.Ok) {
        $newest = $null
        foreach ($h in $r.Data) {
            $d = ConvertTo-BoDate (Get-BoProp $h 'InstalledOn' $null)
            if ($null -ne $d -and ($null -eq $newest -or $d -gt $newest)) { $newest = $d }
        }
        if ($r.Data.Count -eq 0) { Add-BoHit -Id 'SYS-HOTFIX-001' -Type 'other' -Ref 'cim:Win32_QuickFixEngineering' -Excerpt 'no hotfixes reported' }
        elseif ($null -ne $newest -and ([DateTime]::UtcNow - $newest).TotalDays -gt 90) {
            Add-BoHit -Id 'SYS-HOTFIX-001' -Type 'other' -Ref 'cim:Win32_QuickFixEngineering' -Excerpt "newest hotfix installed $($newest.ToString('yyyy-MM-dd')) ($($r.Data.Count) total)"
        }
    }
    Publish-BoCheck
}
