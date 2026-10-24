# Module: tasks (category: audit, read-only). Dot-sourced by the audit entry points.
# Scheduled task inventory with command-line, location, hidden-task and privilege checks.

function ConvertFrom-BoSchtasksCsv {
    # Positional parse of 'schtasks /query /fo CSV /v' (column titles are localized, order is stable).
    param([string]$Text)
    $out = New-Object System.Collections.Generic.List[object]
    $rows = @($Text -split "`r?`n" | Where-Object { $_.Trim() } | ConvertFrom-Csv -Header (1..28 | ForEach-Object { "c$_" }))
    $seen = @{}
    foreach ($r in $rows) {
        $full = [string]$r.c2
        if (-not $full.StartsWith('\')) { continue }
        if ($seen.ContainsKey($full)) { continue }
        $seen[$full] = $true
        $idx = $full.LastIndexOf('\')
        $out.Add([pscustomobject]@{
                TaskName = $full.Substring($idx + 1); TaskPath = $full.Substring(0, $idx + 1)
                State = [string]$r.c4; Author = [string]$r.c8; UserId = [string]$r.c15; RunLevel = ''
                Hidden = $false; Execute = [string]$r.c9; Arguments = ''; Triggers = @()
            })
    }
    return @($out.ToArray())
}

function Invoke-BoTasksModule {
    [CmdletBinding()]
    param()
    $cat = 'scheduled-tasks'
    Register-BoCheck -Id 'TSK-INFO-001' -Title 'Non-Microsoft scheduled tasks' -Severity 'info' -Category $cat -Cap 300 `
        -Description 'Scheduled tasks outside \Microsoft\Windows\ with their action and run-as account.'
    Register-BoCheck -Id 'TSK-CMD-001' -Title 'Scheduled task command matches attacker tradecraft' -Severity 'high' -Category $cat `
        -Description 'Task actions using encoded PowerShell, downloaders or LOLBin abuse.' `
        -Remediation 'Export the task definition, collect the payload, then disable the task.' -Mitre @('T1053.005', 'T1059')
    Register-BoCheck -Id 'TSK-PATH-001' -Title 'Scheduled task runs a binary from a user-writable or unsigned location' -Severity 'medium' -Category $cat `
        -Description 'Task actions pointing at temp, public, download or unsigned per-user binaries.' `
        -Remediation 'Verify the binary and signature; remove the task if unexpected.' -Mitre @('T1053.005')
    Register-BoCheck -Id 'TSK-HIDDEN-001' -Title 'Hidden non-Microsoft scheduled task' -Severity 'medium' -Category $cat `
        -Description 'The Hidden setting keeps the task out of the default Task Scheduler view.' -Mitre @('T1564', 'T1053.005')
    Register-BoCheck -Id 'TSK-SYSTEM-001' -Title 'Privileged task runs a file outside standard program locations' -Severity 'low' -Category $cat `
        -Description 'Tasks running as SYSTEM or with highest privileges from non-standard directories are privilege-escalation targets if the path is writable.' `
        -Remediation 'Move the script to a protected directory and restrict its ACL.' -Mitre @('T1053.005', 'T1574')

    $res = Invoke-BoProvider -Name 'tasks.scheduled' -ErrorCode 'TASKS_UNREADABLE' -Message 'Get-ScheduledTask unavailable' -CheckId 'TSK-INFO-001' -NonMaterial -Live {
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
            $acts = @($t.Actions | ForEach-Object { [pscustomobject]@{ Execute = [string]$_.Execute; Arguments = [string]$_.Arguments } })
            $trig = @($t.Triggers | ForEach-Object { [string]$_.CimClass.CimClassName })
            $uid = ''; $rl = ''
            if ($null -ne $t.Principal) { $uid = [string]$t.Principal.UserId; $rl = [string]$t.Principal.RunLevel }
            $hid = $false
            if ($null -ne $t.Settings) { $hid = [bool]$t.Settings.Hidden }
            [pscustomobject]@{ TaskName = [string]$t.TaskName; TaskPath = [string]$t.TaskPath; State = [string]$t.State; Author = [string]$t.Author; UserId = $uid; RunLevel = $rl; Hidden = $hid; Actions = $acts; Triggers = $trig }
        }
    }
    $tasks = @()
    if ($res.Ok) { $tasks = @($res.Data) }
    else {
        $fb = Invoke-BoProvider -Name 'tasks.schtasks' -ErrorCode 'TASKS_UNAVAILABLE' -Message 'schtasks fallback failed; no scheduled task inventory' -CheckId 'TSK-INFO-001' -Text -Live {
            (& schtasks.exe /query /fo CSV /v 2>&1 | Out-String)
        }
        if ($fb.Ok) {
            $tasks = @(ConvertFrom-BoSchtasksCsv -Text $fb.Data)
            Add-BoError -Code 'TASKS_FALLBACK' -Message 'task data came from schtasks (Get-ScheduledTask unavailable); hidden flag and multiple actions are not visible' -CheckId 'TSK-HIDDEN-001' -Material $false
        }
    }
    foreach ($t in $tasks) {
        $path = [string](Get-BoProp $t 'TaskPath' '\')
        $name = [string](Get-BoProp $t 'TaskName' '')
        $full = $path + $name
        $user = [string](Get-BoProp $t 'UserId' '')
        $runLevel = [string](Get-BoProp $t 'RunLevel' '')
        $isMs = $path.StartsWith('\Microsoft\Windows\', [StringComparison]::OrdinalIgnoreCase)
        $actions = @(Get-BoProp $t 'Actions' @())
        if ($actions.Count -eq 0 -and (Get-BoProp $t 'Execute' '')) {
            $actions = @([pscustomobject]@{ Execute = [string](Get-BoProp $t 'Execute' ''); Arguments = [string](Get-BoProp $t 'Arguments' '') })
        }
        $privileged = ($user -match '(?i)^(SYSTEM|NT AUTHORITY\\SYSTEM|S-1-5-18)$' -or $runLevel -match 'Highest')
        $ref = "task:$full"
        foreach ($a in $actions) {
            $exe = [string](Get-BoProp $a 'Execute' '')
            $argText = [string](Get-BoProp $a 'Arguments' '')
            $line = ($exe + ' ' + $argText).Trim()
            if (-not $isMs) {
                Add-BoHit -Id 'TSK-INFO-001' -Type 'other' -Ref $ref -Excerpt "user=$user runlevel=$runLevel state=$([string](Get-BoProp $t 'State' '')) action=$line"
            }
            $reasons = Get-BoCommandReason $line
            if ($reasons.Strong.Count -gt 0) { Add-BoHit -Id 'TSK-CMD-001' -Type 'command' -Ref $ref -Excerpt "$($reasons.Strong -join '; '): $line" }
            $risk = Get-BoTargetRisk $exe
            if ($risk.Severity) { Add-BoHit -Id 'TSK-PATH-001' -Type 'file' -Ref $risk.Path -Excerpt "task $full ($($risk.Zone), signature: $($risk.Status))" -Severity $risk.Severity }
            if (-not $isMs -and $privileged -and $exe) {
                $zone = (Get-BoTargetRisk $exe).Zone
                $resolved = Get-BoExecutablePath $exe
                if (@('system', 'programfiles', 'programdata-known', 'temp', 'appdata', 'appdata-known') -notcontains $zone -and $resolved -notmatch '(?i)^(cmd|powershell|pwsh|wscript|cscript|schtasks|wevtutil|sc|net|netsh)(\.exe)?$' -and $resolved -match '^[A-Za-z]:\\') {
                    Add-BoHit -Id 'TSK-SYSTEM-001' -Type 'file' -Ref $resolved -Excerpt "task $full runs as $user ($runLevel)"
                }
            }
        }
        if (-not $isMs -and [bool](Get-BoProp $t 'Hidden' $false)) {
            Add-BoHit -Id 'TSK-HIDDEN-001' -Type 'other' -Ref $ref -Excerpt "user=$user"
        }
    }
    Publish-BoCheck
}
