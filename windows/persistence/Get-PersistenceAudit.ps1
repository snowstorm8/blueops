# Module: persistence (category: persistence, read-only detection). Dot-sourced by entry points.
# Mechanisms beyond Run keys/services/tasks: WMI subscriptions, IFEO, AppInit/AppCert, LSA packages,
# COM hijacks, time providers, port monitors, accessibility binaries, PowerShell profiles, BITS.

function Get-BoRegStringList {
    param($Value)
    $out = @()
    foreach ($v in @($Value)) { if ($null -ne $v -and ([string]$v).Trim() -ne '') { $out += [string]$v } }
    return $out
}

function Invoke-BoPersistenceModule {
    [CmdletBinding()]
    param()
    $cat = 'persistence'
    Register-BoCheck -Id 'PER-WMI-001' -Title 'WMI event consumer executes commands or scripts' -Severity 'high' -Category $cat `
        -Description 'CommandLine and ActiveScript event consumers run attacker code when their filter fires.' `
        -Remediation 'Export the filter, consumer and binding, then remove them from root\subscription.' -Mitre @('T1546.003')
    Register-BoCheck -Id 'PER-WMI-002' -Title 'WMI event subscription inventory' -Severity 'info' -Category $cat -Cap 100 `
        -Description 'Permanent event consumers in root\subscription (the default SCM Event Log Consumer is expected).'
    Register-BoCheck -Id 'PER-IFEO-001' -Title 'Image File Execution Options debugger is set' -Severity 'high' -Category $cat `
        -Description 'A Debugger value makes Windows launch another program whenever the named image starts.' `
        -Remediation 'Delete the Debugger value after collecting the referenced binary.' -Mitre @('T1546.012')
    Register-BoCheck -Id 'PER-SILENT-001' -Title 'SilentProcessExit monitor is configured' -Severity 'high' -Category $cat `
        -Description 'MonitorProcess launches a program when the named process exits.' -Mitre @('T1546.012')
    Register-BoCheck -Id 'PER-APPINIT-001' -Title 'AppInit_DLLs is populated' -Severity 'medium' -Category $cat `
        -Description 'AppInit DLLs are injected into every process that loads user32.dll when LoadAppInit_DLLs is 1.' `
        -Remediation 'Clear the value and set LoadAppInit_DLLs to 0.' -Mitre @('T1546.010')
    Register-BoCheck -Id 'PER-APPCERT-001' -Title 'AppCertDLLs entries exist' -Severity 'high' -Category $cat `
        -Description 'AppCert DLLs are loaded into processes calling CreateProcess*; there is no legitimate default.' -Mitre @('T1546.009')
    Register-BoCheck -Id 'PER-LSA-001' -Title 'Non-default LSA authentication, security or notification package' -Severity 'high' -Category $cat `
        -Description 'Extra LSA packages load into lsass.exe and can capture credentials.' `
        -Remediation 'Verify the package file and signature; remove it from the Lsa key.' -Mitre @('T1547.002', 'T1547.005')
    Register-BoCheck -Id 'PER-NETSH-001' -Title 'Non-default netsh helper DLL' -Severity 'medium' -Category $cat -Confidence 'low' `
        -Description 'netsh loads registered helper DLLs when run; unknown helpers can hide persistence.' -Mitre @('T1546.007')
    Register-BoCheck -Id 'PER-TIMEPROV-001' -Title 'Non-default W32Time time provider DLL' -Severity 'high' -Category $cat `
        -Description 'Time provider DLLs are loaded by the Windows Time service at boot.' -Mitre @('T1547.003')
    Register-BoCheck -Id 'PER-PORTMON-001' -Title 'Non-default print port monitor DLL' -Severity 'medium' -Category $cat -Confidence 'low' `
        -Description 'Print monitors load into the spooler as SYSTEM at boot.' -Mitre @('T1547.010')
    Register-BoCheck -Id 'PER-COM-001' -Title 'Per-user COM registration points to a risky or unsigned DLL' -Severity 'medium' -Category $cat `
        -Description 'HKCU COM class registrations override machine-wide ones and are used for hijacking.' `
        -Remediation 'Verify the DLL; delete the HKCU CLSID key if it is not expected.' -Mitre @('T1546.015')
    Register-BoCheck -Id 'PER-SCRSAVE-001' -Title 'Screensaver outside the Windows directory' -Severity 'medium' -Category $cat `
        -Description 'The configured screensaver is an executable outside %SystemRoot%.' -Mitre @('T1546.002')
    Register-BoCheck -Id 'PER-CMDAUTORUN-001' -Title 'Command Processor AutoRun is set' -Severity 'high' -Category $cat `
        -Description 'The AutoRun value runs a command whenever cmd.exe starts.' -Mitre @('T1546')
    Register-BoCheck -Id 'PER-LOGON-001' -Title 'User logon script is configured in the registry' -Severity 'high' -Category $cat `
        -Description 'UserInitMprLogonScript runs at every logon of the user.' -Mitre @('T1037.001')
    Register-BoCheck -Id 'PER-BOOT-001' -Title 'Session Manager boot-time execution list was modified' -Severity 'high' -Category $cat `
        -Description 'BootExecute/SetupExecute/PlatformExecute should only contain autocheck autochk *.' -Mitre @('T1547')
    Register-BoCheck -Id 'PER-PROFILE-001' -Title 'PowerShell profile scripts exist' -Severity 'low' -Category $cat -Cap 50 `
        -Description 'Profile scripts run at every PowerShell start; review their content.'
    Register-BoCheck -Id 'PER-PROFILE-002' -Title 'PowerShell profile contains attacker tradecraft' -Severity 'high' -Category $cat `
        -Description 'Profile content matches download-and-execute, encoded commands or similar patterns.' -Mitre @('T1546.013')
    Register-BoCheck -Id 'PER-BITS-001' -Title 'BITS job with a notification command' -Severity 'high' -Category $cat `
        -Description 'BITS jobs can run a command when a transfer completes and survive reboots.' -Mitre @('T1197')
    Register-BoCheck -Id 'PER-BITS-002' -Title 'BITS transfer jobs present' -Severity 'low' -Category $cat -Cap 50 `
        -Description 'Background transfer jobs (Windows Update creates some); review the URLs.'
    Register-BoCheck -Id 'PER-ACCESS-001' -Title 'Accessibility binary replaced by a command shell' -Severity 'high' -Category $cat `
        -Description 'sethc/utilman/osk/narrator/magnify binaries whose hash equals cmd.exe or powershell.exe give SYSTEM access at the logon screen.' `
        -Remediation 'Restore the file with sfc /scannow from trusted media after collecting evidence.' -Mitre @('T1546.008')

    # WMI permanent event subscriptions
    $wmi = Invoke-BoProvider -Name 'wmi.subscriptions' -ErrorCode 'WMI_UNREADABLE' -Message 'cannot read root\subscription event consumers' -CheckId 'PER-WMI-001' -NonMaterial -Live {
        foreach ($c in @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop)) {
            $cls = [string]$c.CimClass.CimClassName
            $cmd = ''
            if ($cls -eq 'CommandLineEventConsumer') { $cmd = [string]$c.CommandLineTemplate + ' ' + [string]$c.ExecutablePath }
            elseif ($cls -eq 'ActiveScriptEventConsumer') { $cmd = [string]$c.ScriptFileName + ' ' + [string]$c.ScriptText }
            [pscustomobject]@{ Class = $cls; Name = [string]$c.Name; Command = $cmd.Trim() }
        }
    }
    if ($wmi.Ok) {
        foreach ($c in $wmi.Data) {
            $cls = [string](Get-BoProp $c 'Class' '')
            $nm = [string](Get-BoProp $c 'Name' '')
            $cmd = [string](Get-BoProp $c 'Command' '')
            Add-BoHit -Id 'PER-WMI-002' -Type 'other' -Ref "wmi:$cls/$nm" -Excerpt $cmd
            if ($cls -eq 'CommandLineEventConsumer' -or $cls -eq 'ActiveScriptEventConsumer') {
                Add-BoHit -Id 'PER-WMI-001' -Type 'other' -Ref "wmi:$cls/$nm" -Excerpt $cmd
            }
        }
    }

    # IFEO, SilentProcessExit
    $nt = $script:HKLM + '\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    foreach ($base in @($nt, ($script:HKLM + '\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion'))) {
        $ifeo = Get-BoRegKeyChecked -Path ($base + '\Image File Execution Options') -CheckId 'PER-IFEO-001'
        if ($null -ne $ifeo) {
            foreach ($img in $ifeo.SubKeys) {
                $k = Get-BoRegKeyChecked -Path ($base + '\Image File Execution Options\' + $img) -CheckId 'PER-IFEO-001'
                if ($null -eq $k) { continue }
                $dbg = [string](Get-BoProp $k.Values 'Debugger' '')
                if ($dbg.Trim() -ne '' -and $dbg -notmatch '(?i)vsjitdebugger\.exe') {
                    Add-BoHit -Id 'PER-IFEO-001' -Type 'registry' -Ref "$base\Image File Execution Options\$img :: Debugger" -Excerpt $dbg
                }
            }
        }
    }
    $spe = Get-BoRegKeyChecked -Path ($nt + '\SilentProcessExit') -CheckId 'PER-SILENT-001'
    if ($null -ne $spe) {
        foreach ($img in $spe.SubKeys) {
            $k = Get-BoRegKeyChecked -Path ($nt + '\SilentProcessExit\' + $img) -CheckId 'PER-SILENT-001'
            if ($null -ne $k -and ([string](Get-BoProp $k.Values 'MonitorProcess' '')).Trim() -ne '') {
                Add-BoHit -Id 'PER-SILENT-001' -Type 'registry' -Ref "$nt\SilentProcessExit\$img :: MonitorProcess" -Excerpt ([string]$k.Values['MonitorProcess'])
            }
        }
    }
    foreach ($base in @(($nt + '\Windows'), ($script:HKLM + '\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'))) {
        $w = Get-BoRegKeyChecked -Path $base -CheckId 'PER-APPINIT-001'
        if ($null -eq $w) { continue }
        $dlls = [string](Get-BoProp $w.Values 'AppInit_DLLs' '')
        if ($dlls.Trim() -ne '') {
            $sev = 'medium'
            if ([int](Get-BoProp $w.Values 'LoadAppInit_DLLs' 0) -eq 1) { $sev = 'high' }
            Add-BoHit -Id 'PER-APPINIT-001' -Type 'registry' -Ref "$base :: AppInit_DLLs" -Excerpt "LoadAppInit_DLLs=$([string](Get-BoProp $w.Values 'LoadAppInit_DLLs' 0)) $dlls" -Severity $sev
        }
    }
    $sm = $script:HKLM + '\SYSTEM\CurrentControlSet\Control\Session Manager'
    $ac = Get-BoRegKeyChecked -Path ($sm + '\AppCertDLLs') -CheckId 'PER-APPCERT-001'
    if ($null -ne $ac) { foreach ($n in $ac.Values.Keys) { Add-BoHit -Id 'PER-APPCERT-001' -Type 'registry' -Ref "$sm\AppCertDLLs :: $n" -Excerpt ([string]$ac.Values[$n]) } }
    $smk = Get-BoRegKeyChecked -Path $sm -CheckId 'PER-BOOT-001'
    if ($null -ne $smk) {
        $be = Get-BoRegStringList (Get-BoProp $smk.Values 'BootExecute' @())
        foreach ($b in $be) { if ($b.Trim() -notmatch '(?i)^autocheck autochk \*$') { Add-BoHit -Id 'PER-BOOT-001' -Type 'registry' -Ref "$sm :: BootExecute" -Excerpt $b } }
        foreach ($nme in @('SetupExecute', 'PlatformExecute')) {
            foreach ($b in (Get-BoRegStringList (Get-BoProp $smk.Values $nme @()))) { Add-BoHit -Id 'PER-BOOT-001' -Type 'registry' -Ref "$sm :: $nme" -Excerpt $b }
        }
    }

    # LSA packages
    $lsaPath = $script:HKLM + '\SYSTEM\CurrentControlSet\Control\Lsa'
    $lsa = Get-BoRegKeyChecked -Path $lsaPath -CheckId 'PER-LSA-001'
    if ($null -ne $lsa) {
        $allowed = @{
            'Authentication Packages' = @('msv1_0')
            'Security Packages'       = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoextender', '""')
            'Notification Packages'   = @('scecli', 'rassfm')
        }
        foreach ($name in $allowed.Keys) {
            foreach ($pkg in (Get-BoRegStringList (Get-BoProp $lsa.Values $name @()))) {
                foreach ($piece in ($pkg -split '[,\s]+')) {
                    if ($piece -and ($allowed[$name] -notcontains $piece.ToLowerInvariant())) { Add-BoHit -Id 'PER-LSA-001' -Type 'registry' -Ref "$lsaPath :: $name" -Excerpt $piece }
                }
            }
        }
    }

    # netsh helpers, time providers, port monitors
    $netsh = Get-BoRegKeyChecked -Path ($script:HKLM + '\SOFTWARE\Microsoft\NetSh') -CheckId 'PER-NETSH-001'
    if ($null -ne $netsh) {
        $okNetsh = 'ifmon|rasmontr|authfwcfg|dhcpcmonitor|dot3cfg|fwcfg|hnetmon|netiohlp|nettrace|nshhttp|nshipsec|nshwfp|p2pnetsh|rpc|wcnnetsh|wshelper|wwancfg|whhelper|wlancfg|peerdistsh|nlmnetsh|netprofm|nfsnetsh|mbnmontr|wfpnetsh|rasmbn|hostednetworkmgr|netsh'
        foreach ($n in $netsh.Values.Keys) {
            $dll = [string]$netsh.Values[$n]
            $leaf = ($dll -split '\\')[-1] -replace '(?i)\.dll$', ''
            $outside = ($dll -match '\\' -and $dll -notmatch '(?i)^(%systemroot%|c:\\windows)\\system32\\')
            if ($outside -or $leaf -notmatch "(?i)^($okNetsh)$") { Add-BoHit -Id 'PER-NETSH-001' -Type 'registry' -Ref "$($script:HKLM)\SOFTWARE\Microsoft\NetSh :: $n" -Excerpt $dll }
        }
    }
    $tp = $script:HKLM + '\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'
    $tpk = Get-BoRegKeyChecked -Path $tp -CheckId 'PER-TIMEPROV-001'
    if ($null -ne $tpk) {
        foreach ($sub in $tpk.SubKeys) {
            $k = Get-BoRegKeyChecked -Path ($tp + '\' + $sub) -CheckId 'PER-TIMEPROV-001'
            $dll = [string](Get-BoProp $k.Values 'DllName' '')
            if ($dll -and $dll -notmatch '(?i)^(%systemroot%|c:\\windows)\\system32\\(w32time|vmictimeprovider)\.dll$') { Add-BoHit -Id 'PER-TIMEPROV-001' -Type 'registry' -Ref "$tp\$sub :: DllName" -Excerpt $dll }
        }
    }
    $pm = $script:HKLM + '\SYSTEM\CurrentControlSet\Control\Print\Monitors'
    $pmk = Get-BoRegKeyChecked -Path $pm -CheckId 'PER-PORTMON-001'
    if ($null -ne $pmk) {
        foreach ($sub in $pmk.SubKeys) {
            $k = Get-BoRegKeyChecked -Path ($pm + '\' + $sub) -CheckId 'PER-PORTMON-001'
            $dll = [string](Get-BoProp $k.Values 'Driver' '')
            if ($dll -and ($dll -notmatch '(?i)^(localspl|tcpmon|usbmon|wsdmon|appmon|mfmon|pjlmon|lprmon|fxsmon|hpmon)\.dll$')) { Add-BoHit -Id 'PER-PORTMON-001' -Type 'registry' -Ref "$pm\$sub :: Driver" -Excerpt $dll }
        }
    }

    # Per-user hives: COM hijacks, screensaver, Command Processor AutoRun, logon script
    $cp = '\Software\Microsoft\Command Processor'
    $cpm = Get-BoRegKeyChecked -Path ($script:HKLM + '\SOFTWARE\Microsoft\Command Processor') -CheckId 'PER-CMDAUTORUN-001'
    if ($null -ne $cpm -and ([string](Get-BoProp $cpm.Values 'AutoRun' '')).Trim() -ne '') {
        Add-BoHit -Id 'PER-CMDAUTORUN-001' -Type 'registry' -Ref "$($script:HKLM)\SOFTWARE\Microsoft\Command Processor :: AutoRun" -Excerpt ([string]$cpm.Values['AutoRun'])
    }
    foreach ($h in (Get-BoUserHive)) {
        $root = $script:HKU + '\' + $h.Sid
        $ck = Get-BoRegKeyChecked -Path ($root + $cp) -CheckId 'PER-CMDAUTORUN-001'
        if ($null -ne $ck -and ([string](Get-BoProp $ck.Values 'AutoRun' '')).Trim() -ne '') { Add-BoHit -Id 'PER-CMDAUTORUN-001' -Type 'registry' -Ref "$root$cp :: AutoRun" -Excerpt ([string]$ck.Values['AutoRun']) }
        $env1 = Get-BoRegKeyChecked -Path ($root + '\Environment') -CheckId 'PER-LOGON-001'
        if ($null -ne $env1 -and ([string](Get-BoProp $env1.Values 'UserInitMprLogonScript' '')).Trim() -ne '') {
            Add-BoHit -Id 'PER-LOGON-001' -Type 'registry' -Ref "$root\Environment :: UserInitMprLogonScript" -Excerpt ([string]$env1.Values['UserInitMprLogonScript'])
        }
        $dsk = Get-BoRegKeyChecked -Path ($root + '\Control Panel\Desktop') -CheckId 'PER-SCRSAVE-001'
        if ($null -ne $dsk) {
            $scr = [string](Get-BoProp $dsk.Values 'SCRNSAVE.EXE' '')
            if ($scr -and (Get-BoPathZone (Get-BoExecutablePath $scr)) -ne 'system') { Add-BoHit -Id 'PER-SCRSAVE-001' -Type 'registry' -Ref "$root\Control Panel\Desktop :: SCRNSAVE.EXE" -Excerpt $scr }
        }
        $clsRoot = $root + '\Software\Classes\CLSID'
        $cls = Get-BoRegKeyChecked -Path $clsRoot -CheckId 'PER-COM-001'
        if ($null -ne $cls) {
            foreach ($guid in $cls.SubKeys) {
                foreach ($srv in @('InprocServer32', 'LocalServer32')) {
                    $sk = Get-BoRegKeyChecked -Path ("$clsRoot\$guid\$srv") -CheckId 'PER-COM-001'
                    if ($null -eq $sk) { continue }
                    $dll = [string](Get-BoProp $sk.Values '(default)' '')
                    if (-not $dll) { continue }
                    $risk = Get-BoTargetRisk $dll
                    if ($risk.Severity) { Add-BoHit -Id 'PER-COM-001' -Type 'registry' -Ref "$clsRoot\$guid\$srv" -Excerpt "$($risk.Path) ($($risk.Zone), signature: $($risk.Status)) user=$($h.Name)" -Severity $risk.Severity }
                }
            }
        }
    }

    # PowerShell profiles
    $profiles = New-Object System.Collections.Generic.List[string]
    foreach ($p in @('C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1', 'C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1', 'C:\Program Files\PowerShell\7\profile.ps1')) { $profiles.Add($p) }
    foreach ($u in (Get-BoChildDirectory 'C:\Users')) {
        foreach ($d in @('Documents\WindowsPowerShell', 'Documents\PowerShell')) {
            foreach ($f in @('profile.ps1', 'Microsoft.PowerShell_profile.ps1')) { $profiles.Add("$u\$d\$f") }
        }
    }
    foreach ($p in $profiles) {
        if (-not (Test-BoPath $p)) { continue }
        $content = ''
        try {
            $content = [System.IO.File]::ReadAllText((Resolve-BoFsPath $p))
            if ($content.Length -gt 65536) { $content = $content.Substring(0, 65536) }
        }
        catch { Add-BoPermError -Message "cannot read profile $p" -CheckId 'PER-PROFILE-001' }
        $trim = ($content -replace '(?m)^\s*#.*$', '').Trim()
        if ($trim -eq '') { continue }
        Add-BoHit -Id 'PER-PROFILE-001' -Type 'file' -Ref $p -Excerpt "$($trim.Length) bytes of script"
        $reasons = Get-BoCommandReason ($trim -replace '\r?\n', ' ')
        if ($reasons.Strong.Count -gt 0) { Add-BoHit -Id 'PER-PROFILE-002' -Type 'file' -Ref $p -Excerpt ($reasons.Strong -join '; ') }
    }

    # BITS jobs
    $bits = Invoke-BoProvider -Name 'bits.jobs' -ErrorCode 'BITS_UNREADABLE' -Message 'cannot enumerate BITS jobs (needs administrator)' -CheckId 'PER-BITS-001' -NonMaterial -Live {
        # Starting BITS (which any Get-BitsTransfer/bitsadmin call does) flips its startup type from
        # Manual to Automatic, so a stopped service is never queried.
        $svc = Get-Service -Name 'BITS' -ErrorAction Stop
        if ($svc.Status -ne 'Running') { throw 'BITS service is not running; not started because starting it changes its startup type' }
        Get-BitsTransfer -AllUsers -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ DisplayName = [string]$_.DisplayName; JobState = [string]$_.JobState; OwnerAccount = [string]$_.OwnerAccount; NotifyCmdLine = [string]$_.NotifyCmdLine; Url = (@($_.FileList | ForEach-Object { [string]$_.RemoteName }) -join ',') }
        }
    }
    if ($bits.Ok) {
        foreach ($j in $bits.Data) {
            $dn = [string](Get-BoProp $j 'DisplayName' '')
            $ncl = [string](Get-BoProp $j 'NotifyCmdLine' '')
            Add-BoHit -Id 'PER-BITS-002' -Type 'other' -Ref "bits:$dn" -Excerpt "owner=$([string](Get-BoProp $j 'OwnerAccount' '')) state=$([string](Get-BoProp $j 'JobState' '')) url=$([string](Get-BoProp $j 'Url' ''))"
            if ($ncl.Trim() -ne '') { Add-BoHit -Id 'PER-BITS-001' -Type 'other' -Ref "bits:$dn" -Excerpt $ncl }
        }
    }

    # Accessibility binaries replaced by a shell
    $shellHashes = @{}
    foreach ($sh in @('C:\Windows\System32\cmd.exe', 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe')) {
        $hh = Get-BoFileSha256 $sh
        if ($hh) { $shellHashes[$hh] = $sh }
    }
    foreach ($bin in @('sethc', 'utilman', 'osk', 'narrator', 'magnify', 'displayswitch', 'atbroker')) {
        $p = "C:\Windows\System32\$bin.exe"
        $hh = Get-BoFileSha256 $p
        if ($hh -and $shellHashes.ContainsKey($hh)) { Add-BoHit -Id 'PER-ACCESS-001' -Type 'file' -Ref $p -Excerpt "sha256 equals $($shellHashes[$hh])" }
    }
    Publish-BoCheck
}
