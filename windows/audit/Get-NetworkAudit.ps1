# Module: network (category: audit, read-only). Dot-sourced by the audit entry points.
# Listeners and connections with owning processes, exposure, DNS/hosts/proxy, shares and routing.

function ConvertFrom-BoNetstat {
    # Parses 'netstat -ano' (state words are localized, so a remote port of 0 marks a listener).
    param([string]$Text)
    $tcp = New-Object System.Collections.Generic.List[object]
    $udp = New-Object System.Collections.Generic.List[object]
    foreach ($line in ($Text -split "`r?`n")) {
        $t = $line.Trim()
        if ($t -match '^TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)$') {
            $state = 'Established'
            if ([int]$Matches[4] -eq 0) { $state = 'Listen' }
            $tcp.Add([pscustomobject]@{ LocalAddress = $Matches[1]; LocalPort = [int]$Matches[2]; RemoteAddress = $Matches[3]; RemotePort = [int]$Matches[4]; State = $state; OwningProcess = [int]$Matches[6] })
        }
        elseif ($t -match '^UDP\s+(\S+):(\d+)\s+\S+\s+(\d+)$') {
            $udp.Add([pscustomobject]@{ LocalAddress = $Matches[1]; LocalPort = [int]$Matches[2]; OwningProcess = [int]$Matches[3] })
        }
    }
    return [pscustomobject]@{ Tcp = $tcp.ToArray(); Udp = $udp.ToArray() }
}

function Invoke-BoNetworkModule {
    [CmdletBinding()]
    param()
    $cat = 'network'
    Register-BoCheck -Id 'NET-LISTEN-001' -Title 'Listening TCP/UDP endpoints' -Severity 'info' -Category $cat -Cap 300 -Description 'Listening sockets with the owning process.'
    Register-BoCheck -Id 'NET-LISTEN-002' -Title 'Listener owned by a shell, script host or user-writable binary' -Severity 'high' -Category $cat `
        -Description 'Command shells, script hosts and binaries from temp/download locations should not accept connections.' `
        -Remediation 'Identify the process and parent, collect the binary, then contain the host.' -Mitre @('T1571', 'T1059')
    Register-BoCheck -Id 'NET-EXPOSE-001' -Title 'Insecure or remote-control service exposed on a non-loopback address' -Severity 'high' -Category $cat `
        -Description 'Cleartext or unauthenticated remote-access services (Telnet, VNC, Docker API) are listening beyond localhost.' `
        -Remediation 'Disable the service or restrict it with the host firewall.' -Mitre @('T1021')
    Register-BoCheck -Id 'NET-EXPOSE-002' -Title 'Database, cache or legacy file service exposed on a non-loopback address' -Severity 'medium' -Category $cat `
        -Description 'Data stores and legacy protocols listening beyond localhost are frequently unauthenticated or weakly protected.' `
        -Remediation 'Bind to localhost or restrict to required hosts with firewall rules.'
    Register-BoCheck -Id 'NET-EXPOSE-003' -Title 'Remote administration or file-sharing service reachable' -Severity 'low' -Category $cat `
        -Description 'RDP, WinRM and SMB are normal on managed hosts, but should be limited to management networks.' `
        -Remediation 'Restrict by source address; require NLA for RDP and SMB signing.'
    Register-BoCheck -Id 'NET-ESTAB-001' -Title 'Established connections to non-local addresses' -Severity 'info' -Category $cat -Cap 300
    Register-BoCheck -Id 'NET-ESTAB-002' -Title 'Shell or LOLBin with an outbound connection to a public address' -Severity 'high' -Category $cat `
        -Description 'Command shells and living-off-the-land binaries holding external connections may indicate a reverse shell or staged download.' `
        -Remediation 'Inspect the process tree and command line; block the remote address and contain if unexpected.' -Mitre @('T1059', 'T1105')
    Register-BoCheck -Id 'NET-ESTAB-003' -Title 'Connection to a port commonly used by reverse shells or C2' -Severity 'medium' -Category $cat -Confidence 'low' `
        -Description 'Remote ports such as 4444, 1337 and 31337 are rarely used by legitimate services.' -Mitre @('T1571')
    Register-BoCheck -Id 'NET-IFACE-001' -Title 'Network adapter configuration' -Severity 'info' -Category $cat -Cap 50
    Register-BoCheck -Id 'NET-DNS-001' -Title 'Configured DNS servers' -Severity 'info' -Category $cat -Cap 50
    Register-BoCheck -Id 'NET-HOSTS-001' -Title 'Custom hosts file entries' -Severity 'low' -Category $cat `
        -Description 'Entries in the hosts file override DNS; verify each is expected.'
    Register-BoCheck -Id 'NET-HOSTS-002' -Title 'Hosts file overrides security or update vendor domains' -Severity 'medium' -Category $cat `
        -Description 'Redirecting update or security-vendor names is used to block patching and AV telemetry.' `
        -Remediation 'Remove the entries after verifying they were not intentionally added.' -Mitre @('T1562.001')
    Register-BoCheck -Id 'NET-PROXY-001' -Title 'System or user proxy is configured' -Severity 'low' -Category $cat `
        -Description 'Proxy settings can redirect traffic through an attacker-controlled host; benign in managed networks.' -Mitre @('T1090')
    Register-BoCheck -Id 'NET-SHARE-001' -Title 'Non-default SMB shares' -Severity 'low' -Category $cat `
        -Description 'Shares other than the administrative defaults (C$, ADMIN$, IPC$).'
    Register-BoCheck -Id 'NET-SHARE-002' -Title 'Custom hidden SMB share' -Severity 'medium' -Category $cat `
        -Description 'Hidden shares (name ends with $) other than the defaults are a common data-staging or persistence trick.' -Mitre @('T1021.002')
    Register-BoCheck -Id 'NET-FWD-001' -Title 'IP forwarding is enabled' -Severity 'low' -Category $cat `
        -Description 'The host routes packets between interfaces (IPEnableRouter=1).'

    $procs = Get-BoProcessTable
    $tcp = @(); $udp = @()
    $r = Invoke-BoProvider -Name 'net.tcp' -ErrorCode 'TCP_UNAVAILABLE' -Message 'Get-NetTCPConnection unavailable' -CheckId 'NET-LISTEN-001' -NonMaterial -Live { Get-NetTCPConnection -ErrorAction Stop }
    $r2 = Invoke-BoProvider -Name 'net.udp' -ErrorCode 'UDP_UNAVAILABLE' -Message 'Get-NetUDPEndpoint unavailable' -CheckId 'NET-LISTEN-001' -NonMaterial -Live { Get-NetUDPEndpoint -ErrorAction Stop }
    if ($r.Ok -and $r2.Ok) { $tcp = @($r.Data); $udp = @($r2.Data) }
    else {
        $ns = Invoke-BoProvider -Name 'net.netstat' -ErrorCode 'SOCKETS_UNAVAILABLE' -Message 'netstat fallback failed; no socket inventory' -CheckId 'NET-LISTEN-001' -Text -Live {
            (& netstat.exe -ano 2>&1 | Out-String)
        }
        if ($ns.Ok) {
            $parsed = ConvertFrom-BoNetstat -Text $ns.Data
            if (-not $r.Ok) { $tcp = $parsed.Tcp } else { $tcp = @($r.Data) }
            if (-not $r2.Ok) { $udp = $parsed.Udp } else { $udp = @($r2.Data) }
            Add-BoError -Code 'NETSTAT_FALLBACK' -Message 'socket data came from netstat -ano (cmdlets unavailable); connection states are approximated' -CheckId 'NET-LISTEN-001' -Material $false
        }
        else {
            Add-BoError -Code 'SOCKETS_MISSING' -Message 'no socket inventory could be produced' -CheckId 'NET-LISTEN-001' -Material $true
            Add-BoCoverage -Domain 'listeners' -Status 'unavailable' -Reason 'no socket inventory could be produced'
        }
    }

    $high = @{ 23 = 'Telnet'; 5900 = 'VNC'; 5901 = 'VNC'; 5902 = 'VNC'; 2375 = 'Docker API (unauthenticated)'; 512 = 'rexec'; 513 = 'rlogin'; 514 = 'rsh' }
    $medium = @{ 21 = 'FTP'; 69 = 'TFTP'; 161 = 'SNMP'; 1433 = 'SQL Server'; 3306 = 'MySQL'; 5432 = 'PostgreSQL'; 6379 = 'Redis'; 27017 = 'MongoDB'; 9200 = 'Elasticsearch'; 11211 = 'memcached'; 1521 = 'Oracle' }
    $low = @{ 3389 = 'RDP'; 5985 = 'WinRM (HTTP)'; 5986 = 'WinRM (HTTPS)'; 445 = 'SMB'; 139 = 'NetBIOS session' }
    $shellNames = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'nc.exe', 'ncat.exe', 'netcat.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe')
    $softShells = @('powershell.exe', 'pwsh.exe')
    $c2Ports = @(4444, 4443, 1337, 31337, 5555, 6667, 6697, 9001)

    $listeners = @()
    foreach ($c in $tcp) {
        if ([string](Get-BoProp $c 'State' '') -match '^(Listen|2)$') { $listeners += , @('tcp', $c) }
    }
    foreach ($u in $udp) { $listeners += , @('udp', $u) }
    foreach ($l in $listeners) {
        $proto = $l[0]; $c = $l[1]
        $addr = [string](Get-BoProp $c 'LocalAddress' '')
        $port = [int](Get-BoProp $c 'LocalPort' 0)
        $procId = [int](Get-BoProp $c 'OwningProcess' 0)
        $pn = ''; $pp = ''
        if ($procs.ContainsKey($procId)) { $pn = [string](Get-BoProp $procs[$procId] 'Name' ''); $pp = [string](Get-BoProp $procs[$procId] 'ExecutablePath' '') }
        $ref = "$proto $($addr):$port"
        Add-BoHit -Id 'NET-LISTEN-001' -Type 'network' -Ref $ref -Excerpt "pid=$procId $pn $pp"
        # Ephemeral ports are re-keyed by the comparison engine; the owning pid is volatile.
        $invProc = $null
        if ($pn) { $invProc = $pn.ToLowerInvariant() }
        elseif ($procId -eq 0) { $invProc = '' }
        Add-BoInventory -Domain 'listeners' -Key "listener:$proto/$($addr.ToLowerInvariant())/$port" -Attrs @{ proto = $proto; bind = $addr; port = [string]$port; process = $invProc } -Volatile @{ pid = [string]$procId } -EvidenceType 'network' -EvidenceRef $ref
        $loop = Test-BoLoopbackAddress $addr
        if (-not $loop) {
            if ($high.ContainsKey($port)) { Add-BoHit -Id 'NET-EXPOSE-001' -Type 'network' -Ref $ref -Excerpt "$($high[$port]) pid=$procId $pn" }
            elseif ($medium.ContainsKey($port)) { Add-BoHit -Id 'NET-EXPOSE-002' -Type 'network' -Ref $ref -Excerpt "$($medium[$port]) pid=$procId $pn" }
            elseif ($low.ContainsKey($port) -and $proto -eq 'tcp') { Add-BoHit -Id 'NET-EXPOSE-003' -Type 'network' -Ref $ref -Excerpt "$($low[$port]) pid=$procId $pn" }
        }
        if ($pn -and -not $loop) {
            $risk = Get-BoTargetRisk $pp
            if ($shellNames -contains $pn.ToLowerInvariant() -and $softShells -notcontains $pn.ToLowerInvariant()) {
                Add-BoHit -Id 'NET-LISTEN-002' -Type 'network' -Ref $ref -Excerpt "$pn (pid=$procId) is listening"
            }
            elseif ($risk.Severity -eq 'high' -or $risk.Severity -eq 'medium') {
                Add-BoHit -Id 'NET-LISTEN-002' -Type 'network' -Ref $ref -Excerpt "$pn from $pp (signature: $($risk.Status))"
            }
        }
    }
    foreach ($c in $tcp) {
        if ([string](Get-BoProp $c 'State' '') -notmatch '^(Established|5)$') { continue }
        $remote = [string](Get-BoProp $c 'RemoteAddress' '')
        if (Test-BoLoopbackAddress $remote) { continue }
        $rport = [int](Get-BoProp $c 'RemotePort' 0)
        $procId = [int](Get-BoProp $c 'OwningProcess' 0)
        $pn = ''; $pp = ''
        if ($procs.ContainsKey($procId)) { $pn = [string](Get-BoProp $procs[$procId] 'Name' ''); $pp = [string](Get-BoProp $procs[$procId] 'ExecutablePath' '') }
        $ref = "tcp $([string](Get-BoProp $c 'LocalAddress' '')):$([int](Get-BoProp $c 'LocalPort' 0)) -> $($remote):$rport"
        Add-BoHit -Id 'NET-ESTAB-001' -Type 'network' -Ref $ref -Excerpt "pid=$procId $pn"
        $public = -not (Test-BoPrivateAddress $remote)
        if ($public -and $pn -and $procId -ne $PID -and ($shellNames -contains $pn.ToLowerInvariant())) {
            $sev = 'high'
            if ($softShells -contains $pn.ToLowerInvariant()) { $sev = 'medium' }
            Add-BoHit -Id 'NET-ESTAB-002' -Type 'network' -Ref $ref -Excerpt "$pn (pid=$procId) -> $($remote):$rport" -Severity $sev
        }
        if ($public -and ($c2Ports -contains $rport)) {
            Add-BoHit -Id 'NET-ESTAB-003' -Type 'network' -Ref $ref -Excerpt "pid=$procId $pn remote port $rport"
        }
    }
    $nic = Invoke-BoProvider -Name 'cim.Win32_NetworkAdapterConfiguration' -ErrorCode 'NIC_UNREADABLE' -Message 'cannot read adapter configuration' -CheckId 'NET-IFACE-001' -NonMaterial -Live {
        Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop
    }
    if ($nic.Ok) {
        foreach ($n in $nic.Data) {
            $d = [string](Get-BoProp $n 'Description' 'adapter')
            $ips = @(Get-BoProp $n 'IPAddress' @()) -join ','
            $gw = @(Get-BoProp $n 'DefaultIPGateway' @()) -join ','
            $dns = @(Get-BoProp $n 'DNSServerSearchOrder' @()) -join ','
            Add-BoHit -Id 'NET-IFACE-001' -Type 'other' -Ref "adapter:$d" -Excerpt "ip=$ips gw=$gw dhcp=$([string](Get-BoProp $n 'DHCPEnabled' ''))"
            if ($dns) { Add-BoHit -Id 'NET-DNS-001' -Type 'other' -Ref "adapter:$d" -Excerpt "dns=$dns" }
            Add-BoInventory -Domain 'config' -Scope 'network' -Key "config:dns:$($d.ToLowerInvariant())" -Attrs @{ adapter = $d; servers = @(Get-BoProp $n 'DNSServerSearchOrder' @()) } -EvidenceType 'other' -EvidenceRef "adapter:$d"
        }
    }

    # hosts file
    $hostsPath = 'C:\Windows\System32\drivers\etc\hosts'
    $real = Resolve-BoFsPath $hostsPath
    if (Test-Path -LiteralPath $real) {
        $selfName = ''
        try { if (Test-BoFixtureMode) { $selfName = [string](Get-BoProp (Get-BoFixtureJson 'host') 'hostname' '') } else { $selfName = [Environment]::MachineName } } catch { $selfName = '' }
        $vendors = 'microsoft|windowsupdate|windows\.com|live\.com|defender|kaspersky|symantec|norton|mcafee|eset|sophos|crowdstrike|sentinelone|malwarebytes|avast|avg\.|bitdefender|trendmicro|virustotal|carbonblack'
        foreach ($line in [System.IO.File]::ReadAllLines($real)) {
            $t = ($line -replace '#.*$', '').Trim()
            if (-not $t) { continue }
            $parts = $t -split '\s+'
            if ($parts.Count -lt 2) { continue }
            $names = @($parts[1..($parts.Count - 1)])
            $keep = @()
            foreach ($n in $names) { if ($n -ne 'localhost' -and $n -ne 'localhost.localdomain' -and $n -ne 'broadcasthost' -and ($selfName -eq '' -or $n -ne $selfName.ToLowerInvariant())) { $keep += $n } }
            if ($keep.Count -eq 0) { continue }
            Add-BoHit -Id 'NET-HOSTS-001' -Type 'file' -Ref $hostsPath -Excerpt "$($parts[0]) $($keep -join ' ')"
            foreach ($hn in $keep) { Add-BoInventory -Domain 'config' -Scope 'network' -Key "config:hosts:$($parts[0].ToLowerInvariant())/$($hn.ToLowerInvariant())" -Attrs @{ address = $parts[0]; name = $hn } -EvidenceType 'file' -EvidenceRef $hostsPath }
            if (($keep -join ' ') -match $vendors) { Add-BoHit -Id 'NET-HOSTS-002' -Type 'file' -Ref $hostsPath -Excerpt "$($parts[0]) $($keep -join ' ')" }
        }
        if (-not $script:Bo.Elevated) { Write-BoLog 'DEBUG' 'hosts file read as non-admin' }
    }
    else { Add-BoError -Code 'HOSTS_UNREADABLE' -Message "cannot read $hostsPath" -CheckId 'NET-HOSTS-001' -Material $false }

    # proxy settings (machine and every loaded user hive)
    $proxyKeys = @(, @(($script:HKLM + '\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'), 'machine'))
    foreach ($h in (Get-BoUserHive)) { $proxyKeys += , @(($script:HKU + '\' + $h.Sid + '\Software\Microsoft\Windows\CurrentVersion\Internet Settings'), $h.Name) }
    foreach ($k in $proxyKeys) {
        $key = Get-BoRegKeyChecked -Path $k[0] -CheckId 'NET-PROXY-001'
        if ($null -eq $key) { continue }
        $enable = Get-BoProp $key.Values 'ProxyEnable' 0
        $server = [string](Get-BoProp $key.Values 'ProxyServer' '')
        $pac = [string](Get-BoProp $key.Values 'AutoConfigURL' '')
        $proxyId = 'machine'
        if ($k[0] -match '(S-1-5-21-[\d-]+)') { $proxyId = $Matches[1] }
        Add-BoInventory -Domain 'config' -Scope 'network' -Key "config:proxy:$($proxyId.ToLowerInvariant())" -Attrs @{ enabled = ([int]$enable -eq 1); server = ([regex]::Replace($server, '//[^/@\s]*@', '//<redacted>@')); pac = ([regex]::Replace($pac, '//[^/@\s]*@', '//<redacted>@')) } -EvidenceType 'registry' -EvidenceRef $k[0]
        if (([int]$enable -eq 1 -and $server) -or $pac) {
            Add-BoHit -Id 'NET-PROXY-001' -Type 'registry' -Ref $k[0] -Excerpt "scope=$($k[1]) proxy=$server pac=$pac"
        }
    }

    $sh = Invoke-BoProvider -Name 'cim.Win32_Share' -ErrorCode 'SHARES_UNREADABLE' -Message 'cannot enumerate SMB shares' -CheckId 'NET-SHARE-001' -NonMaterial -Live { Get-CimInstance -ClassName Win32_Share -ErrorAction Stop }
    if ($sh.Ok) {
        foreach ($s in $sh.Data) {
            $n = [string](Get-BoProp $s 'Name' '')
            if ($n -match '^([A-Za-z]\$|ADMIN\$|IPC\$)$') { continue }
            $path = [string](Get-BoProp $s 'Path' '')
            Add-BoHit -Id 'NET-SHARE-001' -Type 'other' -Ref "share:$n" -Excerpt "path=$path"
            Add-BoInventory -Domain 'config' -Scope 'network' -Key "config:share:$($n.ToLowerInvariant())" -Attrs @{ name = $n; path = $path } -EvidenceType 'other' -EvidenceRef "share:$n"
            if ($n.EndsWith('$')) { Add-BoHit -Id 'NET-SHARE-002' -Type 'other' -Ref "share:$n" -Excerpt "path=$path" }
        }
    }
    $fwd = Get-BoRegValue -Path ($script:HKLM + '\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') -Name 'IPEnableRouter' -Default 0
    Add-BoInventory -Domain 'config' -Scope 'network' -Key 'config:ip_forward' -Attrs @{ enabled = ([int]$fwd -eq 1) } -EvidenceType 'registry' -EvidenceRef ($script:HKLM + '\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters :: IPEnableRouter')
    if ([int]$fwd -eq 1) { Add-BoHit -Id 'NET-FWD-001' -Type 'registry' -Ref ($script:HKLM + '\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') -Excerpt 'IPEnableRouter=1' }
    Publish-BoCheck
}
