# Module: eventlog (category: audit, read-only). Dot-sourced by the audit entry points.
# Event log service and channel configuration, read from the registry only (no event is read):
# service start type, configured sizes and retention, and explicitly disabled diagnostic channels.
#
# Thresholds (kilobytes) are BlueOps defaults in line with common hardening baselines: a small
# Security log is overwritten within hours on a busy host, which destroys the evidence a defender
# needs. A log whose size is not configured is judged unknown, never "too small".

function ConvertTo-BoRetentionValue {
    # Classic Retention is a DWORD: 0 = overwrite as needed, 0xFFFFFFFF = never overwrite, any
    # other value = overwrite events older than that many seconds. PowerShell reads 0xFFFFFFFF as
    # -1, JSON fixtures may hold 4294967295: both mean "never overwrite".
    param($Value)
    if ($null -eq $Value) { return $null }
    $n = 0L
    if (-not [long]::TryParse([string]$Value, [ref]$n)) { return $null }
    if ($n -lt 0) { $n += 4294967296L }
    if ($n -eq 4294967295L) { return 'never-overwrite' }
    if ($n -eq 0) { return 'overwrite-as-needed' }
    return "overwrite-older-than-${n}s"
}

function Get-BoEventLogSetting {
    # Effective size (KB) and retention of one classic log. Group Policy beats the local service
    # key. Returns MaxKb = $null when no size is configured and Known = $false on a read problem.
    param([Parameter(Mandatory)][string]$Name)
    $svc = $script:HKLM + '\SYSTEM\CurrentControlSet\Services\EventLog\' + $Name
    $pol = $script:HKLM + '\SOFTWARE\Policies\Microsoft\Windows\EventLog\' + $Name
    $errBefore = $script:Bo.Errors.Count
    $sk = Get-BoRegKeyChecked -Path $svc -CheckId 'EVT-SIZE-001'
    $pk = Get-BoRegKeyChecked -Path $pol -CheckId 'EVT-SIZE-001'
    $known = ($script:Bo.Errors.Count -eq $errBefore)
    $maxKb = $null; $source = 'unset'; $retention = $null; $ref = $svc
    if ($null -ne $sk) {
        if ($sk.Values.ContainsKey('MaxSize')) {
            $bytes = 0L
            if ([long]::TryParse([string]$sk.Values['MaxSize'], [ref]$bytes)) { $maxKb = [long][math]::Floor($bytes / 1024); $source = 'service' }
        }
        # Retention is independent of MaxSize: a log can set one without the other.
        $retention = ConvertTo-BoRetentionValue (Get-BoProp $sk.Values 'Retention' $null)
    }
    if ($null -ne $pk -and $pk.Values.ContainsKey('MaxSize')) {
        $kb = 0L
        if ([long]::TryParse([string]$pk.Values['MaxSize'], [ref]$kb)) { $maxKb = $kb; $source = 'policy'; $ref = $pol }
    }
    return [pscustomobject]@{ Name = $Name; MaxKb = $maxKb; Source = $source; Retention = $retention; Ref = $ref; Known = $known }
}

function Invoke-BoEventlogModule {
    [CmdletBinding()]
    param()
    $cat = 'eventlog'
    Register-BoCheck -Id 'EVT-INFO-001' -Title 'Event log configuration summary' -Severity 'info' -Category $cat -Cap 20
    Register-BoCheck -Id 'EVT-SVC-001' -Title 'Windows Event Log service is not set to start automatically' -Severity 'high' -Category $cat `
        -Description 'The Event Log service records every security-relevant event. A disabled or manual-start service means events are lost, a common step in covering tracks.' `
        -Remediation 'Set the EventLog service start type to Automatic and start it, then review what happened while it was off.' -Mitre @('T1562.002')
    Register-BoCheck -Id 'EVT-SIZE-001' -Title 'Event log maximum size is small' -Severity 'low' -Category $cat -Confidence 'high' `
        -Description 'A small log wraps quickly on a busy host and overwrites the history needed for an investigation. Thresholds: Security 196608 KB, System and Application 32768 KB.' `
        -Remediation 'Raise the maximum size (Group Policy: Computer Configuration > Administrative Templates > Windows Components > Event Log Service) and forward events off the host.' -Mitre @('T1070.001')
    Register-BoCheck -Id 'EVT-RET-001' -Title 'Event log never overwrites old events' -Severity 'low' -Category $cat `
        -Description 'With retention set to "do not overwrite", a full log stops recording new events (and, with CrashOnAuditFail, can halt the system). Old evidence is kept but new activity is lost.' `
        -Remediation 'Use overwrite-as-needed with a large size and archive or forward logs on a schedule.' -Mitre @('T1562.002')
    Register-BoCheck -Id 'EVT-CHAN-001' -Title 'Diagnostic event log channel is disabled' -Severity 'medium' -Category $cat `
        -Description 'These channels are enabled by default and feed detection of script, remote-management and antivirus activity. Disabling one is a known defense-evasion step.' `
        -Remediation 'Re-enable the channel (wevtutil sl CHANNEL /e:true) once you have confirmed who disabled it and why.' -Mitre @('T1562.002')

    $summary = New-Object System.Collections.Generic.List[string]

    # Service start type: 2 = automatic. Missing key/value = unknown (not judged).
    $evSvc = $script:HKLM + '\SYSTEM\CurrentControlSet\Services\EventLog'
    $svcKey = Get-BoRegKeyChecked -Path $evSvc -CheckId 'EVT-SVC-001'
    $start = $null
    $parsedStart = 0
    if ($null -ne $svcKey -and $svcKey.Values.ContainsKey('Start') -and [int]::TryParse([string]$svcKey.Values['Start'], [ref]$parsedStart)) {
        $start = $parsedStart
        if ($start -ne 2) {
            $label = 'start type ' + [string]$start
            if ($start -eq 4) { $label = 'disabled' } elseif ($start -eq 3) { $label = 'manual start' }
            Add-BoHit -Id 'EVT-SVC-001' -Type 'registry' -Ref "$evSvc :: Start" -Excerpt $label
        }
    }
    Add-BoInventory -Domain 'config' -Scope 'eventlog' -Key 'config:eventlog:service' -Attrs @{ start = $start } -EvidenceType 'registry' -EvidenceRef "$evSvc :: Start"
    $summary.Add("EventLog service Start=$start")

    # Sizes and retention of the three classic logs.
    $limits = [ordered]@{ Security = 196608; System = 32768; Application = 32768 }
    foreach ($name in $limits.Keys) {
        $s = Get-BoEventLogSetting -Name $name
        $maxKb = $null; $source = $null; $retention = $null
        if ($s.Known) { $maxKb = $s.MaxKb; $source = $s.Source; $retention = $s.Retention }
        Add-BoInventory -Domain 'config' -Scope 'eventlog' -Key ('config:eventlog:log:' + $name.ToLowerInvariant()) `
            -Attrs @{ max_kb = $maxKb; source = $source; retention = $retention } -EvidenceType 'registry' -EvidenceRef $s.Ref
        $summary.Add("$name max=$maxKb KB ($source) retention=$retention")
        if ($s.Known -and $null -ne $s.MaxKb -and $s.MaxKb -lt $limits[$name]) {
            Add-BoHit -Id 'EVT-SIZE-001' -Type 'registry' -Ref "$($s.Ref) :: MaxSize" -Excerpt "$name log maximum $($s.MaxKb) KB (below $($limits[$name]) KB)"
        }
        if ($s.Known -and $s.Retention -eq 'never-overwrite') {
            Add-BoHit -Id 'EVT-RET-001' -Type 'registry' -Ref "$($s.Ref) :: Retention" -Excerpt "$name log does not overwrite old events"
        }
    }

    # Channels that are on by default; only an explicit Enabled=0 is a finding.
    $chanRoot = $script:HKLM + '\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels'
    $channels = @('Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-WinRM/Operational', 'Microsoft-Windows-Windows Defender/Operational')
    foreach ($ch in $channels) {
        $path = $chanRoot + '\' + $ch
        $errBefore = $script:Bo.Errors.Count
        $ck = Get-BoRegKeyChecked -Path $path -CheckId 'EVT-CHAN-001'
        $enabled = '<unset>'
        if ($script:Bo.Errors.Count -gt $errBefore) { $enabled = $null }
        elseif ($null -ne $ck -and $ck.Values.ContainsKey('Enabled')) {
            $enabled = [string]$ck.Values['Enabled']
            if ($enabled -eq '0') { Add-BoHit -Id 'EVT-CHAN-001' -Type 'registry' -Ref "$path :: Enabled" -Excerpt "channel $ch is disabled" }
        }
        Add-BoInventory -Domain 'config' -Scope 'eventlog' -Key ('config:eventlog:channel:' + $ch.ToLowerInvariant()) -Attrs @{ enabled = $enabled } -EvidenceType 'registry' -EvidenceRef "$path :: Enabled"
    }

    foreach ($line in $summary) { Add-BoHit -Id 'EVT-INFO-001' -Type 'other' -Ref 'summary' -Excerpt $line }
    Publish-BoCheck
}
