# Module: services (category: audit, read-only). Dot-sourced by the audit entry points.
# Windows service and kernel-driver inventory with path, command-line and configuration checks.

function Invoke-BoServicesModule {
    [CmdletBinding()]
    param()
    $cat = 'services'
    Register-BoCheck -Id 'SVC-INFO-001' -Title 'Service inventory' -Severity 'info' -Category $cat -Cap 500 `
        -Description 'Windows services: name, state, start mode, account and image path.'
    Register-BoCheck -Id 'SVC-ACCOUNT-001' -Title 'Services running under a named user or domain account' -Severity 'info' -Category $cat -Cap 100 `
        -Description 'These services run with a specific account; stored credentials and privileges deserve review.'
    Register-BoCheck -Id 'SVC-UNQUOTED-001' -Title 'Unquoted service path containing spaces' -Severity 'medium' -Category $cat `
        -Description 'An unquoted path with spaces lets a user who can write to a parent directory run code as the service account.' `
        -Remediation 'Quote the ImagePath and verify directory permissions.' -Mitre @('T1574.009')
    Register-BoCheck -Id 'SVC-PATH-001' -Title 'Service binary in a user-writable or unsigned location' -Severity 'medium' -Category $cat `
        -Description 'Service images in temp, public, download or unsigned per-user locations are a persistence and privilege-escalation indicator.' `
        -Remediation 'Verify the binary and its signature; remove the service if it is not expected.' -Mitre @('T1543.003')
    Register-BoCheck -Id 'SVC-CMD-001' -Title 'Service command line matches attacker tradecraft' -Severity 'high' -Category $cat `
        -Description 'Service image paths that launch encoded PowerShell, downloaders or LOLBins.' `
        -Remediation 'Capture the service definition and referenced payload, then disable the service.' -Mitre @('T1543.003', 'T1059')
    Register-BoCheck -Id 'SVC-LEGACY-001' -Title 'Legacy or high-risk service is enabled' -Severity 'low' -Category $cat `
        -Description 'Telnet, FTP, TFTP, SNMP, UPnP and Remote Registry services increase attack surface.' `
        -Remediation 'Disable services that are not required.'
    Register-BoCheck -Id 'SVC-SECURITY-001' -Title 'Security-relevant service is stopped or disabled' -Severity 'low' -Category $cat `
        -Description 'Firewall, event logging and antivirus services should be running unless intentionally replaced.' `
        -Remediation 'Start the service and investigate why it stopped; stopping these is a common defense-evasion step.' -Mitre @('T1562.001')
    Register-BoCheck -Id 'SVC-DRIVER-001' -Title 'Kernel driver loaded from a user-writable location' -Severity 'high' -Category $cat `
        -Description 'Kernel drivers outside the system driver directories, especially in temp locations, are used for rootkits and BYOVD attacks.' `
        -Remediation 'Treat as a likely compromise; collect the driver and isolate the host.' -Mitre @('T1543.003', 'T1014')

    $res = Invoke-BoProvider -Name 'cim.Win32_Service' -ErrorCode 'SERVICES_UNREADABLE' -Message 'cannot enumerate services via CIM' -CheckId 'SVC-INFO-001' -Live {
        Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
    }
    $svcs = @()
    $svcFull = $true
    if ($res.Ok) { $svcs = @($res.Data) }
    else {
        $fb = Invoke-BoProvider -Name 'services.fallback' -ErrorCode 'SERVICES_UNAVAILABLE' -Message 'Get-Service fallback also failed; no service inventory' -CheckId 'SVC-INFO-001' -Live {
            Get-Service -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; State = [string]$_.Status; StartMode = [string]$_.StartType; PathName = ''; StartName = '' } }
        }
        if ($fb.Ok) {
            $svcs = @($fb.Data)
            $svcFull = $false
            Add-BoCoverage -Domain 'services' -Status 'degraded' -Reason 'Get-Service fallback: image paths and accounts unknown'
            Add-BoError -Code 'SERVICE_PATHS_UNKNOWN' -Message 'image paths and accounts unavailable (Get-Service fallback); path checks skipped' -CheckId 'SVC-PATH-001' -Material $false
        }
    }
    $legacy = @{
        tlntsvr = @('Telnet server', 'medium'); ftpsvc = @('IIS FTP server', 'medium'); tftpd = @('TFTP server', 'medium')
        snmp = @('SNMP service', 'medium'); ssdpsrv = @('SSDP discovery', 'low'); upnphost = @('UPnP device host', 'low')
        remoteregistry = @('Remote Registry', 'low'); mrxsmb10 = @('SMBv1 client driver', 'medium')
    }
    $security = @{
        mpssvc = @('Windows Defender Firewall', 'high'); bfe = @('Base Filtering Engine', 'high'); eventlog = @('Windows Event Log', 'high')
        windefend = @('Microsoft Defender Antivirus (ignore if a third-party AV is in use)', 'medium'); wscsvc = @('Security Center', 'low')
    }
    foreach ($s in $svcs) {
        $name = [string](Get-BoProp $s 'Name' '')
        $lname = $name.ToLowerInvariant()
        $state = [string](Get-BoProp $s 'State' '')
        $mode = [string](Get-BoProp $s 'StartMode' '')
        $path = [string](Get-BoProp $s 'PathName' '')
        $acct = [string](Get-BoProp $s 'StartName' '')
        $ref = "service:$name"
        Add-BoHit -Id 'SVC-INFO-001' -Type 'other' -Ref $ref -Excerpt "state=$state start=$mode account=$acct path=$path"
        if ($name) {
            # The fallback cannot see the image path or account: unknown, not empty.
            $invPath = $null; $invAcct = $null
            if ($svcFull) { $invPath = Protect-BoText $path 500; $invAcct = $acct }
            Add-BoInventory -Domain 'services' -Key "service:$lname" -Attrs @{ name = $name; state = $state; start_mode = $mode; account = $invAcct; image_path = $invPath }
        }
        if ($acct -and $acct -notmatch '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\)') {
            Add-BoHit -Id 'SVC-ACCOUNT-001' -Type 'other' -Ref $ref -Excerpt "account=$acct state=$state"
        }
        if ($path) {
            $exe = Get-BoExecutablePath $path
            $expanded = (Expand-BoEnvPath $path).Trim()
            if (-not $expanded.StartsWith('"') -and $exe -match '^[A-Za-z]:\\.* .*' -and $exe -match '(?i)\.(exe|sys)$') {
                Add-BoHit -Id 'SVC-UNQUOTED-001' -Type 'other' -Ref $ref -Excerpt $path
            }
            $risk = Get-BoTargetRisk $path
            if ($risk.Severity) { Add-BoHit -Id 'SVC-PATH-001' -Type 'file' -Ref $risk.Path -Excerpt "service $name ($($risk.Zone), signature: $($risk.Status))" -Severity $risk.Severity }
            $reasons = Get-BoCommandReason $path
            if ($reasons.Strong.Count -gt 0) { Add-BoHit -Id 'SVC-CMD-001' -Type 'command' -Ref $ref -Excerpt "$($reasons.Strong -join '; '): $path" }
        }
        $enabled = ($mode -ne 'Disabled')
        if ($legacy.ContainsKey($lname) -and ($state -eq 'Running' -or $mode -eq 'Auto')) {
            Add-BoHit -Id 'SVC-LEGACY-001' -Type 'other' -Ref $ref -Excerpt "$($legacy[$lname][0]) state=$state start=$mode" -Severity $legacy[$lname][1]
        }
        if ($security.ContainsKey($lname)) {
            $bad = ($state -ne 'Running')
            if ($lname -eq 'wscsvc' -or $lname -eq 'bfe') { $bad = ($state -ne 'Running') }
            if ($bad -or -not $enabled) {
                Add-BoHit -Id 'SVC-SECURITY-001' -Type 'other' -Ref $ref -Excerpt "$($security[$lname][0]): state=$state start=$mode" -Severity $security[$lname][1]
            }
        }
    }
    $drv = Invoke-BoProvider -Name 'cim.Win32_SystemDriver' -ErrorCode 'DRIVERS_UNREADABLE' -Message 'cannot enumerate kernel drivers' -CheckId 'SVC-DRIVER-001' -NonMaterial -Live {
        Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop
    }
    if ($drv.Ok) {
        foreach ($d in $drv.Data) {
            $dpath = [string](Get-BoProp $d 'PathName' '')
            if (-not $dpath) { continue }
            $zone = Get-BoPathZone (Get-BoExecutablePath $dpath)
            if ($zone -eq 'temp') {
                Add-BoHit -Id 'SVC-DRIVER-001' -Type 'file' -Ref (Get-BoExecutablePath $dpath) -Excerpt "driver $([string](Get-BoProp $d 'Name' '')) state=$([string](Get-BoProp $d 'State' ''))"
            }
        }
    }
    Publish-BoCheck
}
