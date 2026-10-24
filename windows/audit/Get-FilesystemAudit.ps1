# Module: filesystem (category: audit, read-only). Dot-sourced by the audit entry points.
# Executables and scripts in user-writable locations, recent changes to system binaries, writable PATH
# directories and drive inventory. Files are never opened for execution; scripts are read (<=16 KiB).

function Invoke-BoFilesystemModule {
    [CmdletBinding()]
    param()
    $cat = 'filesystem'
    Register-BoCheck -Id 'FS-INFO-001' -Title 'Fixed volume inventory' -Severity 'info' -Category $cat -Cap 30
    Register-BoCheck -Id 'FS-EXE-001' -Title 'Unsigned or unverified executable in a user-writable location' -Severity 'medium' -Category $cat `
        -Description 'Binaries in public, temp, download, ProgramData and per-user locations without a valid Authenticode signature.' `
        -Remediation 'Hash and submit the file for analysis; remove it if it is not expected.' -Mitre @('T1204.002', 'T1036')
    Register-BoCheck -Id 'FS-SCRIPT-001' -Title 'Script in a user-writable location' -Severity 'medium' -Category $cat `
        -Description 'Script files in public, temp, download and ProgramData locations; high severity when content matches attacker tradecraft.' `
        -Remediation 'Review the content and its creator; remove if unexpected.' -Mitre @('T1059')
    Register-BoCheck -Id 'FS-ROOT-001' -Title 'Executable or script at the root of the system drive' -Severity 'medium' -Category $cat `
        -Description 'The root of C:\ is writable by authenticated users on many hosts and is not a normal location for programs.' -Mitre @('T1036')
    Register-BoCheck -Id 'FS-RECENT-001' -Title 'Recently modified system binary without a valid signature' -Severity 'medium' -Category $cat `
        -Description 'Executables and libraries in System32/SysWOW64 changed inside the recent window and not Authenticode-valid.' `
        -Remediation 'Compare against a known-good copy (sfc /verifyonly, DISM) and investigate the change.' -Mitre @('T1036.005', 'T1574')
    Register-BoCheck -Id 'FS-RECENT-002' -Title 'Recently modified signed system binaries' -Severity 'info' -Category $cat -Cap 20 `
        -Description 'Count of validly signed system binaries changed in the recent window (normally Windows Update).'
    Register-BoCheck -Id 'FS-ACL-001' -Title 'Directory in the system PATH is writable by non-administrators' -Severity 'high' -Category $cat `
        -Description 'Writable PATH directories enable binary planting and DLL/command hijacking by any user.' `
        -Remediation 'Remove write access for Users/Authenticated Users/Everyone or drop the directory from PATH.' -Mitre @('T1574.007')

    $disks = Invoke-BoProvider -Name 'cim.Win32_LogicalDisk' -ErrorCode 'DISKS_UNREADABLE' -Message 'cannot enumerate logical disks' -CheckId 'FS-INFO-001' -NonMaterial -Live {
        Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop
    }
    if ($disks.Ok) {
        foreach ($d in $disks.Data) {
            $size = [double](Get-BoProp $d 'Size' 0); $free = [double](Get-BoProp $d 'FreeSpace' 0)
            Add-BoHit -Id 'FS-INFO-001' -Type 'other' -Ref "volume:$([string](Get-BoProp $d 'DeviceID' '?'))" -Excerpt ("{0} {1:N1} GiB, {2:N1} GiB free" -f [string](Get-BoProp $d 'FileSystem' '?'), ($size / 1GB), ($free / 1GB))
        }
    }

    $binExt = @('.exe', '.dll', '.scr', '.sys', '.com', '.cpl', '.ocx')
    $scriptExt = @('.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta')
    $roots = New-Object System.Collections.Generic.List[object]
    if ($script:Bo.FsPath.Count -gt 0) {
        foreach ($p in $script:Bo.FsPath) { $roots.Add(@($p, 3)) }
    }
    else {
        foreach ($r in @('C:\Users\Public', 'C:\Windows\Temp', 'C:\Windows\Tasks', 'C:\PerfLogs')) { $roots.Add(@($r, 3)) }
        $roots.Add(@('C:\ProgramData', 3))
        foreach ($u in (Get-BoChildDirectory 'C:\Users')) {
            if ($u -match '(?i)\\Public$') { continue }
            $roots.Add(@("$u\Downloads", 2)); $roots.Add(@("$u\AppData\Local\Temp", 2)); $roots.Add(@("$u\AppData\Roaming", 2)); $roots.Add(@("$u\Desktop", 1))
        }
    }
    $sigChecks = 0
    $sigCap = 300
    $skipDir = '(?i)\\ProgramData\\(Microsoft|Package Cache)\\'
    foreach ($r in $roots) {
        foreach ($f in (Get-BoChildFile -Path $r[0] -MaxDepth $r[1] -Extension ($binExt + $scriptExt))) {
            if ($f.FullPath -match $skipDir) { continue }
            if ($f.FullPath -match '(?i)\\AppData\\Roaming\\' -and (Get-BoPathZone $f.FullPath) -eq 'appdata-known') { continue }
            if ($binExt -contains $f.Extension) {
                if ($sigChecks -ge $sigCap) { continue }
                $sigChecks++
                $sig = Get-BoSignature -Path $f.FullPath
                if ($sig.Status -eq 'Valid') { continue }
                $zone = Get-BoPathZone $f.FullPath
                $sev = 'medium'
                if ($zone -eq 'temp' -and $sig.Status -ne 'Unknown') { $sev = 'high' }
                if ($f.FullPath -match '(?i)\\(downloads|desktop)\\' -and $sev -eq 'high') { $sev = 'medium' }
                if ($sig.Status -eq 'Unknown') { $sev = 'low'; if ($zone -eq 'temp') { $sev = 'medium' } }
                Add-BoHit -Id 'FS-EXE-001' -Type 'file' -Ref $f.FullPath -Excerpt "signature=$($sig.Status) size=$($f.Length) modified=$($f.LastWriteUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))" -Severity $sev
            }
            else {
                $zone = Get-BoPathZone $f.FullPath
                if ($zone -eq 'appdata' -or $zone -eq 'appdata-known') { continue }
                $text = ''
                try {
                    $fs = [System.IO.File]::OpenRead((Resolve-BoFsPath $f.FullPath))
                    try {
                        $buf = New-Object byte[] ([Math]::Min(16384, [int]$f.Length))
                        $n = $fs.Read($buf, 0, $buf.Length)
                        $text = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
                    }
                    finally { $fs.Dispose() }
                }
                catch { Add-BoPermError -Message "cannot read script $($f.FullPath)" -CheckId 'FS-SCRIPT-001' }
                $reasons = Get-BoCommandReason ($text -replace '\r?\n', ' ')
                if ($reasons.Strong.Count -gt 0) { Add-BoHit -Id 'FS-SCRIPT-001' -Type 'file' -Ref $f.FullPath -Excerpt ($reasons.Strong -join '; ') -Severity 'high' }
                else { Add-BoHit -Id 'FS-SCRIPT-001' -Type 'file' -Ref $f.FullPath -Excerpt "size=$($f.Length) modified=$($f.LastWriteUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))" }
            }
        }
    }
    if ($sigChecks -ge $sigCap) { Add-BoError -Code 'SIG_CAP' -Message "signature checks capped at $sigCap files in user-writable locations" -CheckId 'FS-EXE-001' -Material $false }

    if ($script:Bo.FsPath.Count -eq 0) {
        foreach ($f in (Get-BoChildFile -Path 'C:\' -MaxDepth 0 -Extension ($binExt + $scriptExt))) {
            Add-BoHit -Id 'FS-ROOT-001' -Type 'file' -Ref $f.FullPath -Excerpt "size=$($f.Length)"
        }
        $cutoff = [DateTime]::UtcNow.AddDays(-[int]$script:Bo.RecentDays)
        $recentSigned = 0
        $checked = 0
        foreach ($dir in @('C:\Windows\System32', 'C:\Windows\SysWOW64')) {
            $recent = @(Get-BoChildFile -Path $dir -MaxDepth 0 -Extension $binExt -Limit 60000 | Where-Object { $_.LastWriteUtc -gt $cutoff } | Sort-Object -Property LastWriteUtc -Descending)
            foreach ($f in $recent) {
                if ($checked -ge 200) { break }
                $checked++
                $sig = Get-BoSignature -Path $f.FullPath
                if ($sig.Status -eq 'Valid') { $recentSigned++; continue }
                Add-BoHit -Id 'FS-RECENT-001' -Type 'file' -Ref $f.FullPath -Excerpt "signature=$($sig.Status) modified=$($f.LastWriteUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
            }
        }
        if ($recentSigned -gt 0) { Add-BoHit -Id 'FS-RECENT-002' -Type 'other' -Ref 'C:\Windows\System32' -Excerpt "$recentSigned signed binaries changed in the last $($script:Bo.RecentDays) day(s)" }

        $envKey = Get-BoRegKeyChecked -Path ($script:HKLM + '\SYSTEM\CurrentControlSet\Control\Session Manager\Environment') -CheckId 'FS-ACL-001'
        if ($null -ne $envKey) {
            $seen = @{}
            foreach ($entry in ([string](Get-BoProp $envKey.Values 'Path' '') -split ';')) {
                $dir = (Expand-BoEnvPath $entry).Trim().TrimEnd('\')
                if (-not $dir -or $seen.ContainsKey($dir.ToLowerInvariant())) { continue }
                $seen[$dir.ToLowerInvariant()] = $true
                $w = @(Get-BoBroadWriter -Path $dir)
                if ($w.Count -gt 0) { Add-BoHit -Id 'FS-ACL-001' -Type 'file' -Ref $dir -Excerpt "writable by $($w -join ', ')" }
            }
        }
    }
    Publish-BoCheck
}
