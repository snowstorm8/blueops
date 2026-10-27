# Module: processes (category: audit, read-only). Dot-sourced by the audit entry points.
# Running-process inventory with masquerading, parentage, command-line and location checks.

function Invoke-BoProcessesModule {
    [CmdletBinding()]
    param()
    $cat = 'processes'
    Register-BoCheck -Id 'PRC-INFO-001' -Title 'Process inventory' -Severity 'info' -Category $cat -Cap 500 `
        -Description 'Running processes: pid, parent, name, image path.'
    Register-BoCheck -Id 'PRC-MASQ-001' -Title 'System process name running from an unexpected path' -Severity 'high' -Category $cat `
        -Description 'Core Windows process names are only legitimate when run from the Windows system directory.' `
        -Remediation 'Capture the process and image for analysis, then terminate it as part of incident response.' -Mitre @('T1036.005')
    Register-BoCheck -Id 'PRC-PARENT-001' -Title 'System process with an unexpected parent' -Severity 'high' -Category $cat `
        -Description 'svchost.exe must be started by services.exe; lsass.exe and services.exe by wininit.exe.' -Mitre @('T1036.009')
    Register-BoCheck -Id 'PRC-PARENT-002' -Title 'Script interpreter spawned by an Office or script-host parent' -Severity 'high' -Category $cat `
        -Description 'Office applications and WMI/script hosts launching shells are a common initial-execution pattern.' -Mitre @('T1204.002', 'T1059')
    Register-BoCheck -Id 'PRC-CMD-001' -Title 'Process command line matches attacker tradecraft' -Severity 'high' -Category $cat `
        -Description 'Command lines with encoded commands, download-and-execute, LOLBin abuse or credential tooling.' `
        -Remediation 'Review the process tree and parent; collect the script or payload.' -Mitre @('T1059.001', 'T1218')
    Register-BoCheck -Id 'PRC-PATH-001' -Title 'Process image runs from a user-writable location' -Severity 'medium' -Category $cat `
        -Description 'Image path is in a temp, public, download or unsigned per-user directory.' `
        -Remediation 'Verify the binary; legitimate software rarely runs from these locations.' -Mitre @('T1204.002')

    $res = Invoke-BoProvider -Name 'cim.Win32_Process' -ErrorCode 'PROCESS_UNREADABLE' -Message 'cannot enumerate processes via CIM' -CheckId 'PRC-INFO-001' -Live {
        Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
    }
    $procs = @()
    if ($res.Ok) { $procs = @($res.Data) }
    else {
        $fb = Invoke-BoProvider -Name 'process.fallback' -ErrorCode 'PROCESS_UNAVAILABLE' -Message 'Get-Process fallback also failed' -CheckId 'PRC-INFO-001' -Live {
            Get-Process -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ ProcessId = $_.Id; ParentProcessId = 0; Name = ($_.ProcessName + '.exe'); ExecutablePath = $_.Path; CommandLine = '' } }
        }
        if ($fb.Ok) {
            $procs = @($fb.Data)
            Add-BoError -Code 'PARENT_UNKNOWN' -Message 'parent pids and command lines unavailable (Get-Process fallback); parentage checks skipped' -CheckId 'PRC-PARENT-001' -Material $false
        }
    }
    $procFull = $res.Ok
    if (-not $procFull -and $procs.Count -gt 0) {
        Add-BoCoverage -Domain 'processes' -Status 'degraded' -Reason 'Get-Process fallback: command lines unknown'
    }
    $byPid = @{}
    foreach ($p in $procs) { $byPid[[int](Get-BoProp $p 'ProcessId' 0)] = $p }

    $core = @('smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'spoolsv.exe', 'taskhostw.exe', 'dwm.exe', 'sihost.exe', 'fontdrvhost.exe', 'runtimebroker.exe', 'conhost.exe', 'lsm.exe')
    $officeParents = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe', 'wmiprvse.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe')
    $shells = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe')
    $unreadable = 0
    foreach ($p in $procs) {
        $procId = [int](Get-BoProp $p 'ProcessId' 0)
        $ppid = [int](Get-BoProp $p 'ParentProcessId' 0)
        $name = [string](Get-BoProp $p 'Name' '')
        $lname = $name.ToLowerInvariant()
        $path = [string](Get-BoProp $p 'ExecutablePath' '')
        $cmd = [string](Get-BoProp $p 'CommandLine' '')
        $ref = "pid=$procId"
        Add-BoHit -Id 'PRC-INFO-001' -Type 'process' -Ref $ref -Excerpt "ppid=$ppid name=$name path=$path cmd=$cmd"
        if ($name -and $procId -gt 4) {
            # Identity is the image name; pid and parent are transient and never compared.
            $invExe = $null
            if ($path) { $invExe = $path }
            Add-BoInventory -Domain 'processes' -Key "process:$lname" -Attrs @{ name = $name; exe = $invExe } -Volatile @{ pid = [string]$procId; ppid = [string]$ppid }
        }
        if ([string]::IsNullOrEmpty($path) -and $procId -gt 4) { $unreadable++ }

        if ($core -contains $lname -and -not [string]::IsNullOrEmpty($path)) {
            $lp = $path.ToLowerInvariant()
            if ($lp -notmatch '^c:\\windows\\(system32|syswow64)\\' -and $lp -notmatch '^c:\\windows\\system32\\') {
                Add-BoHit -Id 'PRC-MASQ-001' -Type 'process' -Ref $ref -Excerpt "$name running from $path"
            }
        }
        if ($byPid.ContainsKey($ppid) -and $ppid -ne $procId) {
            $parent = [string](Get-BoProp $byPid[$ppid] 'Name' '')
            $lparent = $parent.ToLowerInvariant()
            $expected = ''
            if ($lname -eq 'svchost.exe') { $expected = 'services.exe' }
            elseif ($lname -eq 'lsass.exe' -or $lname -eq 'services.exe') { $expected = 'wininit.exe' }
            if ($expected -and $lparent -ne $expected) {
                Add-BoHit -Id 'PRC-PARENT-001' -Type 'process' -Ref $ref -Excerpt "$name (ppid=$ppid $parent), expected parent $expected"
            }
            if ($shells -contains $lname -and $officeParents -contains $lparent) {
                Add-BoHit -Id 'PRC-PARENT-002' -Type 'process' -Ref $ref -Excerpt "$name started by $parent (ppid=$ppid): $cmd"
            }
        }
        if ($cmd) {
            $reasons = Get-BoCommandReason $cmd
            if ($reasons.Strong.Count -gt 0) {
                Add-BoHit -Id 'PRC-CMD-001' -Type 'process' -Ref $ref -Excerpt "$($reasons.Strong -join '; '): $cmd"
            }
        }
        if ($path) {
            $risk = Get-BoTargetRisk $path
            if ($risk.Severity) {
                Add-BoHit -Id 'PRC-PATH-001' -Type 'process' -Ref $ref -Excerpt "$name from $path (signature: $($risk.Status))" -Severity $risk.Severity
            }
        }
    }
    if ($unreadable -gt 0) {
        $msg = "$unreadable process(es) had no readable image path (protected or not elevated)"
        if ($script:Bo.Elevated) { Add-BoError -Code 'PROC_PATH_UNREADABLE' -Message $msg -CheckId 'PRC-PATH-001' -Material $false }
        else { Add-BoPermError -Message $msg -CheckId 'PRC-PATH-001' }
    }
    Publish-BoCheck
}
