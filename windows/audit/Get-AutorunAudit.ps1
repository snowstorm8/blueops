# Module: autoruns (category: audit, read-only). Dot-sourced by the audit entry points.
# Registry Run keys (machine and loaded user hives), Winlogon shell values and Startup folders.

function Invoke-BoAutorunsModule {
    [CmdletBinding()]
    param()
    $cat = 'autoruns'
    Register-BoCheck -Id 'AUT-RUN-001' -Title 'Autorun registry entries' -Severity 'info' -Category $cat -Cap 300 `
        -Description 'Programs started at logon or boot from Run, RunOnce and related keys.'
    Register-BoCheck -Id 'AUT-CMD-001' -Title 'Autorun command matches attacker tradecraft' -Severity 'high' -Category $cat `
        -Description 'Autorun commands using encoded PowerShell, downloaders or LOLBin abuse.' `
        -Remediation 'Export the value, collect the payload, then remove the autorun entry.' -Mitre @('T1547.001', 'T1059')
    Register-BoCheck -Id 'AUT-PATH-001' -Title 'Autorun target is in a user-writable or unsigned location' -Severity 'medium' -Category $cat `
        -Description 'Autorun programs in temp, public, download or unsigned per-user locations.' `
        -Remediation 'Verify the binary and its signature; remove the entry if unexpected.' -Mitre @('T1547.001')
    Register-BoCheck -Id 'AUT-WINLOGON-001' -Title 'Winlogon Shell or Userinit has been modified' -Severity 'high' -Category $cat `
        -Description 'Shell must be explorer.exe and Userinit must be userinit.exe; extra values run at every logon.' `
        -Remediation 'Restore the default value after collecting the referenced binary.' -Mitre @('T1547.004')
    Register-BoCheck -Id 'AUT-STARTUP-001' -Title 'Executable or script in a Startup folder' -Severity 'medium' -Category $cat `
        -Description 'Programs and scripts placed directly in a Startup folder run at logon.' `
        -Remediation 'Verify each file; remove those that are not expected.' -Mitre @('T1547.001')
    Register-BoCheck -Id 'AUT-STARTUP-002' -Title 'Startup folder shortcuts' -Severity 'info' -Category $cat -Cap 100 `
        -Description 'Shortcuts in Startup folders (targets are not resolved by this read-only audit).'

    $runRel = @(
        '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
        '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        '\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        '\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $scopes = @(, @($script:HKLM, 'machine'))
    foreach ($h in (Get-BoUserHive)) {
        $scopes += , @(($script:HKU + '\' + $h.Sid), $h.Name)
    }
    foreach ($scope in $scopes) {
        foreach ($rel in $runRel) {
            $keyPath = $scope[0] + $rel
            if ($scope[0] -like '*HKEY_USERS*') { $keyPath = $scope[0] + $rel }
            $key = Get-BoRegKeyChecked -Path $keyPath -CheckId 'AUT-RUN-001'
            if ($null -eq $key) { continue }
            foreach ($n in @($key.Values.Keys | Sort-Object)) {
                $data = [string]$key.Values[$n]
                $ref = "$keyPath :: $n"
                Add-BoHit -Id 'AUT-RUN-001' -Type 'registry' -Ref $ref -Excerpt "scope=$($scope[1]) data=$data"
                $reasons = Get-BoCommandReason $data
                if ($reasons.Strong.Count -gt 0) { Add-BoHit -Id 'AUT-CMD-001' -Type 'registry' -Ref $ref -Excerpt "$($reasons.Strong -join '; '): $data" }
                $risk = Get-BoTargetRisk $data
                if ($risk.Severity) { Add-BoHit -Id 'AUT-PATH-001' -Type 'registry' -Ref $ref -Excerpt "$($risk.Path) ($($risk.Zone), signature: $($risk.Status))" -Severity $risk.Severity }
            }
        }
    }
    # Active Setup StubPath commands run once per user at logon.
    $asRoot = $script:HKLM + '\SOFTWARE\Microsoft\Active Setup\Installed Components'
    $as = Get-BoRegKeyChecked -Path $asRoot -CheckId 'AUT-RUN-001'
    if ($null -ne $as) {
        foreach ($sub in $as.SubKeys) {
            $k = Get-BoRegKeyChecked -Path ($asRoot + '\' + $sub) -CheckId 'AUT-RUN-001'
            if ($null -eq $k -or -not $k.Values.ContainsKey('StubPath')) { continue }
            $data = [string]$k.Values['StubPath']
            $ref = "$asRoot\$sub :: StubPath"
            $reasons = Get-BoCommandReason $data
            if ($reasons.Strong.Count -gt 0) { Add-BoHit -Id 'AUT-CMD-001' -Type 'registry' -Ref $ref -Excerpt "$($reasons.Strong -join '; '): $data" }
            $risk = Get-BoTargetRisk $data
            if ($risk.Severity) { Add-BoHit -Id 'AUT-PATH-001' -Type 'registry' -Ref $ref -Excerpt "$($risk.Path) ($($risk.Zone), signature: $($risk.Status))" -Severity $risk.Severity }
        }
    }

    # Winlogon
    $wl = $script:HKLM + '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $w = Get-BoRegKeyChecked -Path $wl -CheckId 'AUT-WINLOGON-001'
    if ($null -ne $w) {
        $shell = [string](Get-BoProp $w.Values 'Shell' 'explorer.exe')
        $userinit = [string](Get-BoProp $w.Values 'Userinit' 'C:\Windows\system32\userinit.exe,')
        if ($shell.Trim() -ne '' -and $shell.Trim() -notmatch '(?i)^explorer\.exe$') { Add-BoHit -Id 'AUT-WINLOGON-001' -Type 'registry' -Ref "$wl :: Shell" -Excerpt $shell }
        if ($userinit.Trim() -notmatch '(?i)^(c:\\windows\\system32\\|%systemroot%\\system32\\)userinit\.exe,?$') { Add-BoHit -Id 'AUT-WINLOGON-001' -Type 'registry' -Ref "$wl :: Userinit" -Excerpt $userinit }
        foreach ($extra in @('Taskman', 'AppSetup', 'VmApplet', 'System', 'UIHost')) {
            $v = [string](Get-BoProp $w.Values $extra '')
            if ($extra -eq 'VmApplet' -and $v.Trim() -match '(?i)^((%systemroot%|c:\\windows)\\system32\\)?SystemPropertiesPerformance\.exe /pagefile$') { continue }
            if ($v.Trim() -ne '') { Add-BoHit -Id 'AUT-WINLOGON-001' -Type 'registry' -Ref "$wl :: $extra" -Excerpt $v }
        }
    }

    # Startup folders
    $folders = New-Object System.Collections.Generic.List[string]
    $folders.Add('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp')
    foreach ($u in (Get-BoChildDirectory 'C:\Users')) { $folders.Add($u + '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') }
    $execExt = @('.exe', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.ps1', '.hta', '.scr', '.dll', '.com', '.jar')
    foreach ($f in $folders) {
        foreach ($file in (Get-BoChildFile -Path $f -MaxDepth 0)) {
            if ($file.Name -ieq 'desktop.ini') { continue }
            if ($file.Extension -eq '.lnk') { Add-BoHit -Id 'AUT-STARTUP-002' -Type 'file' -Ref $file.FullPath -Excerpt "size=$($file.Length)" }
            elseif ($execExt -contains $file.Extension) { Add-BoHit -Id 'AUT-STARTUP-001' -Type 'file' -Ref $file.FullPath -Excerpt "size=$($file.Length) modified=$($file.LastWriteUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))" }
        }
    }
    Publish-BoCheck
}
