<#
.SYNOPSIS
    Collects normalized endpoint telemetry as a JSON Lines stream (read-only).

.DESCRIPTION
    Category: audit (read-only). Reads CIM/WMI, the registry, scheduled tasks, network tables and
    Windows event logs, and writes only to standard output (the stream) and standard error
    (diagnostics). It never changes the host, never contacts a network and never collects
    passwords, keys or tokens (command lines and registry values are redacted).

    For authorized systems only. The output can contain sensitive data (user names, command
    lines, addresses): store it with restrictive permissions.

    Stream format (docs/telemetry.md): one JSON object per line - header, coverage / record /
    error lines, then an end marker. A stream without the end marker is treated as incomplete.
    Run elevated for full coverage: the Security event log and some process owners require it, and
    each unreadable source is reported as a coverage gap.

.PARAMETER SinceHours
    Event window for log sources (default 24).

.PARAMETER MaxEvents
    Cap per event log (default 5000).

.PARAMETER Categories
    Comma-separated subset of categories (default: all).

.PARAMETER ShowVersion
    Print the collector version and exit.

.NOTES
    Exit codes: 0 ok, 2 usage error, 6 collected with gaps.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1, 2160)][int]$SinceHours = 24,
    [ValidateRange(1, 1000000)][int]$MaxEvents = 5000,
    [string]$Categories = '',
    [switch]$ShowVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Script-scope copies: the collection functions below read these (parameters are not visible to
# the analyzer through function bodies).
$script:SinceHours = $SinceHours
$script:MaxEvents = $MaxEvents

. (Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'lib/Telemetry.ps1')

$script:AllCategories = @('process', 'user', 'group', 'session', 'service', 'scheduled_task',
    'network_connection', 'listener', 'auth_event', 'security_event', 'config_change',
    'system_config', 'integrity', 'persistence')

function Test-TelWanted {
    param([string[]]$Category)
    if ([string]::IsNullOrEmpty($Categories)) { return $true }
    $wanted = $Categories.Split(',')
    foreach ($c in $Category) { if ($wanted -contains $c) { return $true } }
    return $false
}

function Test-TelElevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

function Get-TelRegValue {
    # Returns @{ Found = $bool; Value = ... } for a registry value; unreadable keys raise.
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return @{ Found = $false; Value = $null } }
    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    $p = $item.PSObject.Properties[$Name]
    if ($null -eq $p) { return @{ Found = $false; Value = $null } }
    return @{ Found = $true; Value = $p.Value }
}

# ----------------------------------------------------------------------------- processes

function Get-TelProcessData {
    $procs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    # Process owners come from Get-Process -IncludeUserName, which needs elevation; without it all
    # owners are unknown (declared in the coverage), not guessed.
    $owners = @{}
    $ownersKnown = $true
    try {
        foreach ($gp in @(Get-Process -IncludeUserName -ErrorAction Stop)) { $owners[[int]$gp.Id] = [string]$gp.UserName }
    }
    catch { $ownersKnown = $false }
    $ownerFailures = 0
    foreach ($p in $procs) {
        $procId = [int](Get-TelProp $p 'ProcessId' 0)
        $ppid = [int](Get-TelProp $p 'ParentProcessId' 0)
        $name = ([string](Get-TelProp $p 'Name' '')).ToLowerInvariant()
        $exe = Get-TelProp $p 'ExecutablePath' $null
        $cmd = Get-TelProp $p 'CommandLine' $null
        $created = ConvertTo-TelIso (Get-TelProp $p 'CreationDate' $null)
        $user = $null
        if ($ownersKnown -and $owners.ContainsKey($procId) -and $owners[$procId]) { $user = $owners[$procId] }
        if ($null -eq $user) { $ownerFailures = $ownerFailures + 1 }
        $attrs = @{
            pid = $procId
            ppid = $ppid
            name = $name
            exe = $exe
            user = $user
            cmdline = $(if ($null -ne $cmd) { Limit-TelText (Hide-TelSecret ([string]$cmd)) 500 } else { $null })
        }
        $key = 'pid:{0}:{1}' -f $procId, $created
        Write-TelRecord -Category 'process' -Key $key -SourceType 'api' -SourceRef 'Win32_Process' -Method 'cim' -Attributes $attrs
    }
    if ($ownerFailures -gt 0) {
        Write-TelCoverage -Category 'process' -Status 'partial' -Reason ('owner unknown for {0} process(es); Get-Process -IncludeUserName needs elevation' -f $ownerFailures)
    }
    else { Write-TelCoverage -Category 'process' -Status 'complete' }
}

# ----------------------------------------------------------------------------- accounts

function Get-TelUserData {
    $users = $null
    if (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue) {
        $users = @(Get-LocalUser -ErrorAction Stop)
        foreach ($u in $users) {
            $attrs = @{
                name = [string]$u.Name
                sid = [string]$u.SID.Value
                enabled = [bool]$u.Enabled
                password_required = [bool](Get-TelProp $u 'PasswordRequired' $true)
                last_logon = ConvertTo-TelIso (Get-TelProp $u 'LastLogon' $null)
                password_last_set = ConvertTo-TelIso (Get-TelProp $u 'PasswordLastSet' $null)
            }
            if (-not $attrs['last_logon']) { $attrs['last_logon'] = $null }
            Write-TelRecord -Category 'user' -Key ('user:{0}' -f $u.SID.Value) -SourceType 'api' -SourceRef 'Get-LocalUser' -Method 'localaccounts' -Attributes $attrs
        }
    }
    else {
        $users = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
        foreach ($u in $users) {
            $attrs = @{
                name = [string]$u.Name
                sid = [string]$u.SID
                enabled = (-not [bool]$u.Disabled)
                password_required = [bool]$u.PasswordRequired
            }
            Write-TelRecord -Category 'user' -Key ('user:{0}' -f $u.SID) -SourceType 'api' -SourceRef 'Win32_UserAccount' -Method 'cim' -Attributes $attrs
        }
    }
    Write-TelCoverage -Category 'user' -Status 'complete' -Reason 'local accounts only; domain accounts are not enumerated'
}

function Get-TelGroupData {
    $failed = 0
    if (Get-Command -Name Get-LocalGroup -ErrorAction SilentlyContinue) {
        foreach ($g in @(Get-LocalGroup -ErrorAction Stop)) {
            $members = $null
            try {
                $members = @(Get-LocalGroupMember -Group $g.Name -ErrorAction Stop | ForEach-Object { [string]$_.Name })
            }
            catch { $failed = $failed + 1 }
            $attrs = @{ name = [string]$g.Name; sid = [string]$g.SID.Value; members = $members }
            Write-TelRecord -Category 'group' -Key ('group:{0}' -f $g.SID.Value) -SourceType 'api' -SourceRef 'Get-LocalGroup' -Method 'localaccounts' -Attributes $attrs
        }
    }
    else {
        foreach ($g in @(Get-CimInstance -ClassName Win32_Group -Filter 'LocalAccount=True' -ErrorAction Stop)) {
            $attrs = @{ name = [string]$g.Name; sid = [string]$g.SID; members = $null }
            $failed = $failed + 1
            Write-TelRecord -Category 'group' -Key ('group:{0}' -f $g.SID) -SourceType 'api' -SourceRef 'Win32_Group' -Method 'cim' -Attributes $attrs
        }
    }
    if ($failed -gt 0) {
        Write-TelCoverage -Category 'group' -Status 'partial' -Reason ('members of {0} group(s) could not be read (orphaned SIDs or missing cmdlets)' -f $failed)
    }
    else { Write-TelCoverage -Category 'group' -Status 'complete' }
}

function Get-TelSessionData {
    $sessions = @(Get-CimInstance -ClassName Win32_LogonSession -ErrorAction Stop | Where-Object { @(2, 10, 11) -contains [int]$_.LogonType })
    $n = 0
    foreach ($s in $sessions) {
        $n = $n + 1
        if ($n -gt 200) { break }
        $user = $null
        $dom = $null
        try {
            $acct = Get-CimAssociatedInstance -InputObject $s -Association Win32_LoggedOnUser -ErrorAction Stop | Select-Object -First 1
            if ($null -ne $acct) { $user = [string]$acct.Name; $dom = [string]$acct.Domain }
        }
        catch { $user = $null }
        $attrs = @{ user = $user; logon_type = [int]$s.LogonType; domain = $dom; started = ConvertTo-TelIso (Get-TelProp $s 'StartTime' $null) }
        if (-not $attrs['started']) { $attrs['started'] = $null }
        Write-TelRecord -Category 'session' -Key ('session:{0}' -f $s.LogonId) -SourceType 'api' -SourceRef 'Win32_LogonSession' -Method 'cim' -Attributes $attrs
    }
    Write-TelCoverage -Category 'session' -Status 'complete' -Reason 'interactive, remote-interactive and cached-interactive sessions only'
}

# ----------------------------------------------------------------------------- services and tasks

function Get-TelServiceData {
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        $path = Get-TelProp $s 'PathName' $null
        $attrs = @{
            name = [string]$s.Name
            display_name = [string](Get-TelProp $s 'DisplayName' '')
            state = [string](Get-TelProp $s 'State' '')
            start_mode = [string](Get-TelProp $s 'StartMode' '')
            path = $(if ($null -ne $path) { Limit-TelText (Hide-TelSecret ([string]$path)) 400 } else { $null })
            account = Get-TelProp $s 'StartName' $null
            pid = [int](Get-TelProp $s 'ProcessId' 0)
        }
        Write-TelRecord -Category 'service' -Key ('service:{0}' -f $s.Name) -SourceType 'api' -SourceRef 'Win32_Service' -Method 'cim' -Attributes $attrs
    }
    Write-TelCoverage -Category 'service' -Status 'complete'
}

function Get-TelScheduledTaskData {
    if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        Write-TelCoverage -Category 'scheduled_task' -Status 'unavailable' -Reason 'the ScheduledTasks module (Get-ScheduledTask) is not available'
        return
    }
    foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
        $cmds = @()
        foreach ($a in @(Get-TelProp $t 'Actions' @())) {
            $exe = [string](Get-TelProp $a 'Execute' '')
            $arg = [string](Get-TelProp $a 'Arguments' '')
            if ($exe) { $cmds += (Hide-TelSecret (($exe + ' ' + $arg).Trim())) }
        }
        $trig = @()
        foreach ($g in @(Get-TelProp $t 'Triggers' @())) { $trig += ($g.CimClass.CimClassName -replace '^MSFT_TaskTrigger|^MSFT_Task|Trigger$', '') }
        $princ = Get-TelProp $t 'Principal' $null
        $user = $null
        if ($null -ne $princ) { $user = Get-TelProp $princ 'UserId' $null }
        $full = ([string]$t.TaskPath) + ([string]$t.TaskName)
        $attrs = @{
            name = $full
            command = $(if ($cmds.Count -gt 0) { Limit-TelText ($cmds -join ' ; ') 500 } else { $null })
            user = $user
            enabled = ([string]$t.State -ne 'Disabled')
            state = [string]$t.State
            schedule = $(if ($trig.Count -gt 0) { $trig -join ',' } else { $null })
            kind = 'scheduled-task'
        }
        Write-TelRecord -Category 'scheduled_task' -Key ('task:{0}' -f $full) -SourceType 'api' -SourceRef 'Get-ScheduledTask' -Method 'scheduledtasks' -Attributes $attrs
    }
    Write-TelCoverage -Category 'scheduled_task' -Status 'complete'
}

# ----------------------------------------------------------------------------- network

function Get-TelNetworkData {
    $names = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { $names[[int]$p.Id] = ([string]$p.ProcessName).ToLowerInvariant() + '.exe' }
    $haveCmdlets = [bool](Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue)
    if ($haveCmdlets) {
        foreach ($c in @(Get-NetTCPConnection -ErrorAction Stop)) {
            $owner = [int]$c.OwningProcess
            $pname = $null
            if ($names.ContainsKey($owner)) { $pname = $names[$owner] }
            $state = ([string]$c.State).ToLowerInvariant()
            if ($state -eq 'listen') {
                $attrs = @{ protocol = 'tcp'; local_address = [string]$c.LocalAddress; local_port = [int]$c.LocalPort; pid = $owner; process = $pname }
                Write-TelRecord -Category 'listener' -Key ('listener:tcp:{0}:{1}' -f $c.LocalAddress, $c.LocalPort) -SourceType 'api' -SourceRef 'Get-NetTCPConnection' -Method 'nettcpip' -Attributes $attrs
            }
            else {
                $attrs = @{ protocol = 'tcp'; state = $state; local_address = [string]$c.LocalAddress; local_port = [int]$c.LocalPort; remote_address = [string]$c.RemoteAddress; remote_port = [int]$c.RemotePort; pid = $owner; process = $pname }
                $key = 'conn:tcp:{0}:{1}:{2}:{3}:{4}' -f $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $owner
                Write-TelRecord -Category 'network_connection' -Key $key -SourceType 'api' -SourceRef 'Get-NetTCPConnection' -Method 'nettcpip' -Attributes $attrs
            }
        }
        if (Get-Command -Name Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
            foreach ($u in @(Get-NetUDPEndpoint -ErrorAction Stop)) {
                $owner = [int]$u.OwningProcess
                $pname = $null
                if ($names.ContainsKey($owner)) { $pname = $names[$owner] }
                $attrs = @{ protocol = 'udp'; local_address = [string]$u.LocalAddress; local_port = [int]$u.LocalPort; pid = $owner; process = $pname }
                Write-TelRecord -Category 'listener' -Key ('listener:udp:{0}:{1}:{2}' -f $u.LocalAddress, $u.LocalPort, $owner) -SourceType 'api' -SourceRef 'Get-NetUDPEndpoint' -Method 'nettcpip' -Attributes $attrs
            }
        }
        Write-TelCoverage -Category 'network_connection' -Status 'complete'
        Write-TelCoverage -Category 'listener' -Status 'complete'
        return
    }
    # Fallback: netstat. Its state names are localized, so listening sockets are recognised by an
    # all-zero foreign address instead of the state text.
    $netstat = Get-TelSystemToolPath -Name 'netstat.exe'
    if ($null -eq $netstat) {
        Write-TelCoverage -Category 'network_connection' -Status 'unavailable' -Reason 'Get-NetTCPConnection and netstat.exe are both unavailable'
        Write-TelCoverage -Category 'listener' -Status 'unavailable' -Reason 'Get-NetTCPConnection and netstat.exe are both unavailable'
        return
    }
    $lines = @(& $netstat -ano -p tcp 2>$null)
    foreach ($line in $lines) {
        $parts = ($line.Trim() -split '\s+')
        if ($parts.Count -ge 5 -and $parts[0] -eq 'TCP') {
            $l = $parts[1]; $r = $parts[2]; $owner = 0
            [void][int]::TryParse($parts[4], [ref]$owner)
            $li = $l.LastIndexOf(':'); $ri = $r.LastIndexOf(':')
            if ($li -lt 1 -or $ri -lt 1) { continue }
            $pname = $null
            if ($names.ContainsKey($owner)) { $pname = $names[$owner] }
            $lp = 0; $rp = 0
            [void][int]::TryParse($l.Substring($li + 1), [ref]$lp)
            [void][int]::TryParse($r.Substring($ri + 1), [ref]$rp)
            $la = $l.Substring(0, $li).Trim('[', ']'); $ra = $r.Substring(0, $ri).Trim('[', ']')
            if ($rp -eq 0 -and ($ra -eq '0.0.0.0' -or $ra -eq '::' -or $ra -eq '*')) {
                Write-TelRecord -Category 'listener' -Key ('listener:tcp:{0}:{1}' -f $la, $lp) -SourceType 'command' -SourceRef 'netstat -ano' -Method 'netstat' -Attributes @{ protocol = 'tcp'; local_address = $la; local_port = $lp; pid = $owner; process = $pname }
            }
            else {
                Write-TelRecord -Category 'network_connection' -Key ('conn:tcp:{0}:{1}:{2}:{3}:{4}' -f $la, $lp, $ra, $rp, $owner) -SourceType 'command' -SourceRef 'netstat -ano' -Method 'netstat' -Attributes @{ protocol = 'tcp'; state = 'established'; local_address = $la; local_port = $lp; remote_address = $ra; remote_port = $rp; pid = $owner; process = $pname }
            }
        }
    }
    Write-TelCoverage -Category 'network_connection' -Status 'partial' -Reason 'netstat fallback: TCP only, connection state names are not interpreted (all non-listening rows are recorded as established)'
    Write-TelCoverage -Category 'listener' -Status 'partial' -Reason 'netstat fallback: TCP only'
}

# ----------------------------------------------------------------------------- event logs

function Read-TelLog {
    # Streams parsed events of one log; returns the number read. Errors are reported by the caller.
    param([string]$LogName, [string[]]$Ids, [scriptblock]$OnEvent)
    $start = (Get-Date).AddHours(-1 * $script:SinceHours)
    $filter = @{ LogName = $LogName; Id = [int[]]$Ids; StartTime = $start }
    $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $script:MaxEvents -ErrorAction Stop)
    foreach ($e in $events) {
        $parsed = Convert-TelEventXml -Xml $e.ToXml()
        if ($null -eq $parsed) { continue }
        & $OnEvent $parsed
    }
    return $events.Count
}

function Get-TelEventData {
    $wantAuth = Test-TelWanted @('auth_event')
    $wantSec = Test-TelWanted @('security_event', 'config_change')
    $authDone = $false
    $emit = {
        param($parsed)
        foreach ($r in @(ConvertTo-TelRecord -EventInfo $parsed)) {
            $wanted = Test-TelWanted @($r.Category)
            if ($wanted) {
                Write-TelRecord -Category $r.Category -Key $r.Key -SourceType 'eventlog' -SourceRef $r.Source -Method 'winevent' -EventTime $r.Time -Attributes $r.Attributes
            }
        }
    }
    $securityIds = @('4624', '4625', '4648', '4720', '4722', '4724', '4725', '4726', '4738', '4740', '4728', '4732', '4756', '4729', '4733', '4757', '1102', '4719', '4697', '4698', '4699', '4702')
    try {
        $n = Read-TelLog -LogName 'Security' -Ids $securityIds -OnEvent $emit
        $note = 'Security log, last {0}h, at most {1}; service/batch logons and machine accounts are not recorded' -f $script:SinceHours, $script:MaxEvents
        if ($n -ge $script:MaxEvents) { Write-TelError -Code 'EVENT_LIMIT' -Message ('the Security log reached the {0}-event cap; older events were not read' -f $script:MaxEvents) -Category 'auth_event' }
        if ($wantAuth) { Write-TelCoverage -Category 'auth_event' -Status $(if ($n -ge $script:MaxEvents) { 'partial' } else { 'complete' }) -Reason $note }
        if ($wantSec) {
            Write-TelCoverage -Category 'security_event' -Status 'complete' -Reason 'log clears, audit policy changes and service installs only'
            Write-TelCoverage -Category 'config_change' -Status 'complete' -Reason 'derived from service-install, scheduled-task and audit-policy events only'
        }
        $authDone = $true
    }
    catch {
        $msg = $_.Exception.Message
        $reason = 'the Security event log could not be read: ' + $msg
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            if ($wantAuth) { Write-TelCoverage -Category 'auth_event' -Status 'complete' -Reason 'no matching events in the window' }
            if ($wantSec) {
                Write-TelCoverage -Category 'security_event' -Status 'complete' -Reason 'no matching events in the window'
                Write-TelCoverage -Category 'config_change' -Status 'complete' -Reason 'no matching events in the window'
            }
            $authDone = $true
        }
        else {
            if ($wantAuth) { Write-TelCoverage -Category 'auth_event' -Status 'unavailable' -Reason $reason }
            if ($wantSec) { Write-TelCoverage -Category 'security_event' -Status 'unavailable' -Reason $reason }
            if ($wantSec) { Write-TelCoverage -Category 'config_change' -Status 'unavailable' -Reason $reason }
        }
    }
    # System log: service installs (7045) and log clears (104). Merged into the same coverage as
    # the Security log; a failure here is a gap of its own.
    if ($wantSec -and $authDone) {
        try {
            [void](Read-TelLog -LogName 'System' -Ids @('7045', '104') -OnEvent $emit)
        }
        catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
                Write-TelCoverage -Category 'security_event' -Status 'partial' -Reason ('the System event log could not be read: ' + $_.Exception.Message)
            }
        }
    }
}

# ----------------------------------------------------------------------------- configuration

function Write-TelSettingRecord {
    param([string]$Setting, [string]$Path, [string]$Name, [string]$Scope)
    $r = Get-TelRegValue -Path $Path -Name $Name
    $value = 'not_set'
    if ($r.Found) { $value = [string]$r.Value }
    Write-TelRecord -Category 'system_config' -Key ('setting:{0}' -f $Setting) -Scope $Scope -SourceType 'registry' -SourceRef ('{0}\{1}' -f $Path, $Name) -Method 'registry' -Attributes @{ setting = $Setting; value = $value; source = ('{0}\{1}' -f $Path, $Name) }
}

function Get-TelSystemConfigData {
    $h = 'Registry::HKEY_LOCAL_MACHINE'
    Write-TelSettingRecord -Setting 'uac.enablelua' -Path "$h\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'EnableLUA' -Scope 'uac'
    Write-TelSettingRecord -Setting 'uac.consentprompt_admin' -Path "$h\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'ConsentPromptBehaviorAdmin' -Scope 'uac'
    Write-TelSettingRecord -Setting 'uac.local_account_token_filter' -Path "$h\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'LocalAccountTokenFilterPolicy' -Scope 'uac'
    Write-TelSettingRecord -Setting 'lsa.runasppl' -Path "$h\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'RunAsPPL' -Scope 'lsa'
    Write-TelSettingRecord -Setting 'lsa.lmcompatibilitylevel' -Path "$h\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'LmCompatibilityLevel' -Scope 'lsa'
    Write-TelSettingRecord -Setting 'lsa.nolmhash' -Path "$h\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'NoLMHash' -Scope 'lsa'
    Write-TelSettingRecord -Setting 'lsa.restrictanonymous' -Path "$h\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'RestrictAnonymous' -Scope 'lsa'
    Write-TelSettingRecord -Setting 'wdigest.uselogoncredential' -Path "$h\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name 'UseLogonCredential' -Scope 'lsa'
    Write-TelSettingRecord -Setting 'smb1.server' -Path "$h\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name 'SMB1' -Scope 'smb'
    Write-TelSettingRecord -Setting 'rdp.deny_connections' -Path "$h\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name 'fDenyTSConnections' -Scope 'rdp'
    Write-TelSettingRecord -Setting 'rdp.nla' -Path "$h\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name 'UserAuthentication' -Scope 'rdp'
    Write-TelSettingRecord -Setting 'powershell.scriptblock_logging' -Path "$h\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Scope 'powershell'
    Write-TelSettingRecord -Setting 'autorun.nodrivetypeautorun' -Path "$h\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -Scope 'autorun'
    if (Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        try {
            foreach ($fp in @(Get-NetFirewallProfile -ErrorAction Stop)) {
                $en = [string]$fp.Enabled
                Write-TelRecord -Category 'system_config' -Key ('setting:firewall.{0}' -f $fp.Name) -Scope 'firewall' -SourceType 'api' -SourceRef 'Get-NetFirewallProfile' -Method 'netsecurity' -Attributes @{ setting = ('firewall.{0}.enabled' -f ([string]$fp.Name).ToLowerInvariant()); value = $en.ToLowerInvariant(); source = 'Get-NetFirewallProfile' }
            }
        }
        catch { Write-TelError -Code 'FIREWALL_UNREADABLE' -Message ('firewall profiles could not be read: ' + $_.Exception.Message) -Category 'system_config' }
    }
    if (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            Write-TelRecord -Category 'system_config' -Key 'setting:defender.realtime' -Scope 'defender' -SourceType 'api' -SourceRef 'Get-MpComputerStatus' -Method 'defender' -Attributes @{ setting = 'defender.realtime_protection'; value = ([string]$mp.RealTimeProtectionEnabled).ToLowerInvariant(); source = 'Get-MpComputerStatus' }
        }
        catch { Write-TelError -Code 'DEFENDER_UNREADABLE' -Message ('Defender status could not be read: ' + $_.Exception.Message) -Category 'system_config' }
    }
    Write-TelCoverage -Category 'system_config' -Status 'complete' -Reason 'selected settings only (UAC, LSA, SMB1, RDP, firewall, PowerShell logging, Defender); a value of not_set means the registry value is absent'
}

# ----------------------------------------------------------------------------- integrity, persistence

function Write-TelIntegrityRecord {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    $sha = $null
    try { $sha = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { $sha = $null; $script:TelIntegrityUnread = $script:TelIntegrityUnread + 1 }
    $attrs = @{ path = $Path; sha256 = $sha; size = [long]$item.Length; mtime = ConvertTo-TelIso $item.LastWriteTimeUtc }
    Write-TelRecord -Category 'integrity' -Key ('integrity:{0}' -f $Path) -SourceType 'file' -SourceRef $Path -Method 'sha256' -Attributes $attrs
}

function Get-TelIntegrityData {
    $script:TelIntegrityUnread = 0
    $sysroot = $env:SystemRoot
    $paths = @("$sysroot\System32\drivers\etc\hosts", "$sysroot\System32\drivers\etc\networks")
    if ($env:ProgramFiles) { $paths += "$env:ProgramFiles\PowerShell\7\profile.ps1" }
    $paths += "$sysroot\System32\WindowsPowerShell\v1.0\profile.ps1"
    $paths += "$sysroot\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1"
    $startup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    if (Test-Path -LiteralPath $startup) {
        foreach ($f in @(Get-ChildItem -LiteralPath $startup -File -ErrorAction SilentlyContinue)) { $paths += $f.FullName }
    }
    foreach ($p in $paths) { Write-TelIntegrityRecord -Path $p }
    if ($script:TelIntegrityUnread -gt 0) {
        Write-TelCoverage -Category 'integrity' -Status 'partial' -Reason ('{0} file(s) exist but could not be hashed' -f $script:TelIntegrityUnread)
    }
    else { Write-TelCoverage -Category 'integrity' -Status 'complete' -Reason 'fixed list of sensitive files (hosts, PowerShell profiles, all-users startup folder); absent files are not listed' }
}

function Write-TelRunKeyRecord {
    param([string]$Root, [string]$Label)
    foreach ($sub in @('Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce', 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')) {
        $path = "$Root\$sub"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $item = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
        foreach ($prop in $item.PSObject.Properties) {
            if ($prop.Name -like 'PS*') { continue }
            $val = Limit-TelText (Hide-TelSecret ([string]$prop.Value)) 400
            Write-TelRecord -Category 'persistence' -Key ('runkey:{0}:{1}:{2}' -f $Label, $sub, $prop.Name) -SourceType 'registry' -SourceRef ('{0}\{1}' -f $path, $prop.Name) -Method 'registry' -Attributes @{ mechanism = 'run_key'; location = ('{0}\{1}\{2}' -f $Label, $sub, $prop.Name); value = $val }
        }
    }
}

function Get-TelPersistenceData {
    Write-TelRunKeyRecord -Root 'Registry::HKEY_LOCAL_MACHINE' -Label 'HKLM'
    foreach ($hive in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        if ($hive.PSChildName -match '^S-1-5-21-[0-9-]+$') { Write-TelRunKeyRecord -Root $hive.PSPath -Label ('HKU\' + $hive.PSChildName) }
    }
    $wl = Get-TelRegValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Userinit'
    if ($wl.Found) {
        Write-TelRecord -Category 'persistence' -Key 'winlogon:userinit' -SourceType 'registry' -SourceRef 'HKLM\...\Winlogon\Userinit' -Method 'registry' -Attributes @{ mechanism = 'winlogon'; location = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit'; value = (Limit-TelText (Hide-TelSecret ([string]$wl.Value)) 300) }
    }
    $sh = Get-TelRegValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Shell'
    if ($sh.Found) {
        Write-TelRecord -Category 'persistence' -Key 'winlogon:shell' -SourceType 'registry' -SourceRef 'HKLM\...\Winlogon\Shell' -Method 'registry' -Attributes @{ mechanism = 'winlogon'; location = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell'; value = (Limit-TelText (Hide-TelSecret ([string]$sh.Value)) 300) }
    }
    $ai = Get-TelRegValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'AppInit_DLLs'
    if ($ai.Found -and [string]$ai.Value) {
        Write-TelRecord -Category 'persistence' -Key 'appinit_dlls' -SourceType 'registry' -SourceRef 'HKLM\...\Windows\AppInit_DLLs' -Method 'registry' -Attributes @{ mechanism = 'appinit'; location = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs'; value = (Limit-TelText ([string]$ai.Value) 300) }
    }
    $ifeo = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path -LiteralPath $ifeo) {
        foreach ($k in @(Get-ChildItem -LiteralPath $ifeo -ErrorAction SilentlyContinue)) {
            $dbg = Get-TelRegValue -Path $k.PSPath -Name 'Debugger'
            if ($dbg.Found) {
                Write-TelRecord -Category 'persistence' -Key ('ifeo:{0}' -f $k.PSChildName) -SourceType 'registry' -SourceRef ('IFEO\{0}\Debugger' -f $k.PSChildName) -Method 'registry' -Attributes @{ mechanism = 'ifeo'; location = ('IFEO\{0}' -f $k.PSChildName); value = (Limit-TelText (Hide-TelSecret ([string]$dbg.Value)) 300) }
            }
        }
    }
    $startup = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    if (Test-Path -LiteralPath $startup) {
        foreach ($f in @(Get-ChildItem -LiteralPath $startup -File -ErrorAction SilentlyContinue)) {
            Write-TelRecord -Category 'persistence' -Key ('startup:{0}' -f $f.FullName) -SourceType 'file' -SourceRef $f.FullName -Method 'directory-listing' -Attributes @{ mechanism = 'startup_folder'; location = $f.FullName; value = $f.FullName }
        }
    }
    $wmiOk = $true
    try {
        foreach ($cls in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) {
            foreach ($c in @(Get-CimInstance -Namespace 'root/subscription' -ClassName $cls -ErrorAction Stop)) {
                $v = $(if ($cls -eq 'CommandLineEventConsumer') { [string](Get-TelProp $c 'CommandLineTemplate' '') } else { 'script consumer' })
                Write-TelRecord -Category 'persistence' -Key ('wmi:{0}:{1}' -f $cls, $c.Name) -SourceType 'api' -SourceRef ('root/subscription:{0}' -f $cls) -Method 'cim' -Attributes @{ mechanism = 'wmi_subscription'; location = ('root/subscription/{0}/{1}' -f $cls, $c.Name); value = (Limit-TelText (Hide-TelSecret $v) 300) }
            }
        }
    }
    catch { $wmiOk = $false; Write-TelError -Code 'WMI_SUBSCRIPTION_UNREADABLE' -Message ('WMI event subscriptions could not be read: ' + $_.Exception.Message) -Category 'persistence' }
    if ($wmiOk) { Write-TelCoverage -Category 'persistence' -Status 'complete' -Reason 'selected locations only: Run/RunOnce keys, Winlogon, AppInit_DLLs, IFEO debuggers, all-users startup folder, WMI event consumers; per-user startup folders and services/tasks (separate categories) are not included' }
    else { Write-TelCoverage -Category 'persistence' -Status 'partial' -Reason 'WMI event subscriptions could not be read' }
}

# ----------------------------------------------------------------------------- main

function Invoke-TelSection {
    param([string]$Name, [scriptblock]$Body, [string[]]$Category)
    if (-not (Test-TelWanted $Category)) { return }
    try { & $Body }
    catch {
        Write-TelError -Code 'SECTION_FAILED' -Message ('{0} failed: {1}' -f $Name, $_.Exception.Message) -Category $Category[0]
        foreach ($c in $Category) {
            if (-not $script:TelCovState.ContainsKey($c)) { Write-TelCoverage -Category $c -Status 'unavailable' -Reason ('{0} failed: {1}' -f $Name, (Limit-TelText $_.Exception.Message 200)) }
        }
    }
}

if ($ShowVersion) {
    Write-Output ('Invoke-TelemetryCollection.ps1 {0}' -f $script:TelVersion)
    exit 0
}
if (-not [string]::IsNullOrEmpty($Categories)) {
    foreach ($c in $Categories.Split(',')) {
        if ($script:AllCategories -notcontains $c) {
            [Console]::Error.WriteLine("unknown category: $c")
            exit 2
        }
    }
}
if (-not (Test-TelWindows)) {
    [Console]::Error.WriteLine('this collector inspects Windows hosts only')
    exit 3
}

$script:TelNow = ConvertTo-TelIso (Get-Date)
$os = $null
try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { $os = $null }
$elevated = Test-TelElevated
$hostName = $env:COMPUTERNAME
$collectionId = 'tel-{0}-{1}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMdd"T"HHmmss"Z"', [System.Globalization.CultureInfo]::InvariantCulture), $PID
Write-TelLine ([ordered]@{
        type = 'header'
        schema_version = '1.0.0'
        collector = [ordered]@{ name = 'blueops-windows-telemetry'; version = $script:TelVersion }
        host = [ordered]@{
            hostname = $hostName
            os = [ordered]@{ family = 'windows'; name = [string](Get-TelProp $os 'Caption' 'Windows'); version = [string](Get-TelProp $os 'Version' 'unknown') }
            arch = [string]$env:PROCESSOR_ARCHITECTURE
        }
        collection = [ordered]@{ id = $collectionId; started_at = $script:TelNow; elevated = $elevated }
    })
if (-not $elevated) {
    Write-TelError -Code 'NOT_PRIVILEGED' -Message 'running without elevation: the Security event log and some process owners are unreadable; each is reported as a gap in the coverage lines'
}
Invoke-TelSection 'processes' { Get-TelProcessData } @('process')
Invoke-TelSection 'users' { Get-TelUserData } @('user')
Invoke-TelSection 'groups' { Get-TelGroupData } @('group')
Invoke-TelSection 'sessions' { Get-TelSessionData } @('session')
Invoke-TelSection 'services' { Get-TelServiceData } @('service')
Invoke-TelSection 'scheduled tasks' { Get-TelScheduledTaskData } @('scheduled_task')
Invoke-TelSection 'network' { Get-TelNetworkData } @('network_connection', 'listener')
Invoke-TelSection 'event logs' { Get-TelEventData } @('auth_event', 'security_event', 'config_change')
Invoke-TelSection 'configuration' { Get-TelSystemConfigData } @('system_config')
Invoke-TelSection 'integrity' { Get-TelIntegrityData } @('integrity')
Invoke-TelSection 'persistence' { Get-TelPersistenceData } @('persistence')

$gaps = 0
foreach ($k in $script:TelCovState.Keys) { if ($script:TelCovState[$k] -ne 'complete') { $gaps = 1 } }
Write-TelLine ([ordered]@{ type = 'end'; ended_at = (ConvertTo-TelIso (Get-Date)); records = $script:TelCount })
if ($gaps -eq 1) { exit 6 }
exit 0
