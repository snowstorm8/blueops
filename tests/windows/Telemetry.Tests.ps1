# Windows telemetry: helper functions (pure, synthetic input) and the collector entry point.

BeforeDiscovery {
    $script:OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($PSVersionTable.Platform -eq 'Win32NT')
}

BeforeAll {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    . (Join-Path $script:RepoRoot 'windows\lib\Telemetry.ps1')
    $script:Collector = Join-Path $script:RepoRoot 'windows\telemetry\Invoke-TelemetryCollection.ps1'

    function New-TestEventXml {
        param([string]$Channel, [string]$Id, [hashtable]$Data, [string]$RecordId = '42')
        $items = ''
        foreach ($k in $Data.Keys) { $items += ('<Data Name="{0}">{1}</Data>' -f $k, [System.Security.SecurityElement]::Escape($Data[$k])) }
        return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>{0}</EventID><TimeCreated SystemTime="2026-03-01T09:00:00.1234567Z"/><EventRecordID>{1}</EventRecordID><Channel>{2}</Channel></System><EventData>{3}</EventData></Event>' -f $Id, $RecordId, $Channel, $items)
    }
}

Describe 'Hide-TelSecrets' {
    It 'redacts password-like assignments, switches and URL credentials' {
        (Hide-TelSecrets 'tool.exe password=hunter2 --mode x') | Should -Not -Match 'hunter2'
        (Hide-TelSecrets 'tool.exe -p hunter2') | Should -Not -Match 'hunter2'
        (Hide-TelSecrets 'curl https://bob:hunter2@host/x') | Should -Not -Match 'hunter2'
        (Hide-TelSecrets 'net user alice hunter2 /add') | Should -Not -Match 'hunter2'
    }
    It 'keeps harmless text and survives empty input' {
        (Hide-TelSecrets 'notepad.exe C:\notes.txt') | Should -Be 'notepad.exe C:\notes.txt'
        (Hide-TelSecrets '') | Should -Be ''
        (Hide-TelSecrets $null) | Should -Be ''
    }
}

Describe 'ConvertTo-TelAsciiJson' {
    It 'escapes every non-ASCII character so the stream is encoding independent' {
        $json = ConvertTo-TelAsciiJson ('{"a":"caf' + [char]0x00E9 + ' ' + [char]0x4E2D + '"}')
        $json | Should -Be '{"a":"caf\u00e9 \u4e2d"}'
        ($json.ToCharArray() | Where-Object { [int]$_ -gt 126 }).Count | Should -Be 0
    }
}

Describe 'Convert-TelEventXml' {
    It 'parses id, time, channel and named data' {
        $e = Convert-TelEventXml -Xml (New-TestEventXml -Channel 'Security' -Id '4625' -Data @{ TargetUserName = 'bob'; IpAddress = '203.0.113.5'; LogonType = '3' })
        $e.Id | Should -Be '4625'
        $e.Channel | Should -Be 'Security'
        $e.Time | Should -Be '2026-03-01T09:00:00.123Z'
        $e.Data['TargetUserName'] | Should -Be 'bob'
    }
    It 'returns null for malformed or foreign XML instead of throwing' {
        Convert-TelEventXml -Xml '<not xml' | Should -BeNullOrEmpty
        Convert-TelEventXml -Xml '<Event/>' | Should -BeNullOrEmpty
    }
    It 'does not resolve external entities' {
        $evil = '<!DOCTYPE e [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID></System><EventData><Data Name="a">&x;</Data></EventData></Event>'
        { Convert-TelEventXml -Xml $evil } | Should -Not -Throw
    }
}

Describe 'ConvertTo-TelRecord' {
    It 'maps a failed network logon to an auth_event' {
        $e = Convert-TelEventXml -Xml (New-TestEventXml -Channel 'Security' -Id '4625' -Data @{ TargetUserName = 'bob'; IpAddress = '203.0.113.5'; LogonType = '3'; SubStatus = '0xc000006a' })
        $r = @(ConvertTo-TelRecord -EventInfo $e)
        $r.Count | Should -Be 1
        $r[0].Category | Should -Be 'auth_event'
        $r[0].Attributes['action'] | Should -Be 'login_failure'
        $r[0].Attributes['result'] | Should -Be 'failure'
        $r[0].Attributes['user'] | Should -Be 'bob'
        $r[0].Attributes['source_address'] | Should -Be '203.0.113.5'
    }
    It 'ignores service logons, machine accounts and loopback sources' {
        $svc = Convert-TelEventXml -Xml (New-TestEventXml -Channel 'Security' -Id '4624' -Data @{ TargetUserName = 'svc'; LogonType = '5' })
        @(ConvertTo-TelRecord -EventInfo $svc).Count | Should -Be 0
        $mach = Convert-TelEventXml -Xml (New-TestEventXml -Channel 'Security' -Id '4624' -Data @{ TargetUserName = 'HOST$'; LogonType = '3' })
        @(ConvertTo-TelRecord -EventInfo $mach).Count | Should -Be 0
        $lo = Convert-TelEventXml -Xml (New-TestEventXml -Channel 'Security' -Id '4624' -Data @{ TargetUserName = 'bob'; LogonType = '2'; IpAddress = '::1' })
        $r = @(ConvertTo-TelRecord -EventInfo $lo)
        $r[0].Attributes.ContainsKey('source_address') | Should -BeFalse
    }
    It 'resolves the member SID of a local group addition to an account name' {
        $resolver = { param([string]$Sid) 'HOST\backdoor' }
        $e = Convert-TelEventXml -Xml (New-TestEventXml -Channel 'Security' -Id '4732' -Data @{ TargetUserName = 'Administrators'; MemberName = '-'; MemberSid = 'S-1-5-21-1-2-3-1001'; SubjectUserName = 'eve' })
        $r = @(ConvertTo-TelRecord -EventInfo $e -SidResolver $resolver)
        $r[0].Attributes['action'] | Should -Be 'group_change'
        $r[0].Attributes['user'] | Should -Be 'backdoor'
        $r[0].Attributes['group'] | Should -Be 'Administrators'
        $r[0].Attributes['change'] | Should -Be 'member_added'
    }
    It 'marks the user unknown when it cannot be determined' {
        $resolver = { param([string]$Sid) $null }
        $e = Convert-TelEventXml -Xml (New-TestEventXml -Channel 'Security' -Id '4732' -Data @{ TargetUserName = 'Administrators'; MemberName = '-'; MemberSid = 'S-1-5-21-9' })
        $r = @(ConvertTo-TelRecord -EventInfo $e -SidResolver $resolver)
        $r[0].Attributes['user'] | Should -BeNullOrEmpty
    }
    It 'records a cleared log as a security_event' {
        $e = Convert-TelEventXml -Xml (New-TestEventXml -Channel 'Security' -Id '1102' -Data @{ SubjectUserName = 'eve' })
        $r = @(ConvertTo-TelRecord -EventInfo $e)
        ($r | Where-Object { $_.Category -eq 'security_event' }).Attributes['event_id'] | Should -Be '1102'
    }
    It 'records a service install as security_event and config_change with the redacted path' {
        $e = Convert-TelEventXml -Xml (New-TestEventXml -Channel 'System' -Id '7045' -Data @{ ServiceName = 'evil'; ImagePath = 'C:\Users\Public\evil.exe -password=hunter2' })
        $r = @(ConvertTo-TelRecord -EventInfo $e)
        $cc = $r | Where-Object { $_.Category -eq 'config_change' }
        $cc.Attributes['object'] | Should -Be 'service'
        $cc.Attributes['name'] | Should -Be 'evil'
        $cc.Attributes['path'] | Should -Not -Match 'hunter2'
    }
    It 'ignores events outside the Security channel that share an auth event id' {
        $e = Convert-TelEventXml -Xml (New-TestEventXml -Channel 'Application' -Id '4625' -Data @{ TargetUserName = 'bob'; LogonType = '3' })
        @(ConvertTo-TelRecord -EventInfo $e).Count | Should -Be 0
    }
}

Describe 'Write-TelRecord' {
    It 'counts records and accepts null attributes (reported as unknown)' {
        $script:TelNow = '2026-03-01T10:00:00.000Z'
        $script:TelCount = 0
        { Write-TelRecord -Category 'process' -Key 'pid:1' -SourceType 'api' -SourceRef 'x' -Method 'm' -Attributes @{ pid = 1; name = 'a'; exe = $null; cmdline = ('caf' + [char]0x00E9) } } | Should -Not -Throw
        $script:TelCount | Should -Be 1
    }
}

Describe 'collector entry point' {
    It 'rejects an unknown category with exit code 2' -Skip:(-not $script:OnWindows) {
        $shell = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh' }
        & $shell -NoProfile -NonInteractive -File $script:Collector -Categories 'nonsense' 2>$null
        $LASTEXITCODE | Should -Be 2
    }
    It 'prints its version' -Skip:(-not $script:OnWindows) {
        $shell = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh' }
        $out = & $shell -NoProfile -NonInteractive -File $script:Collector -ShowVersion
        ($out -join "`n") | Should -Match 'Invoke-TelemetryCollection.ps1 \d+\.\d+\.\d+'
    }
    It 'produces a well-formed, ASCII, self-describing stream on a live Windows host' -Skip:(-not $script:OnWindows) {
        $shell = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh' }
        $out = @(& $shell -NoProfile -NonInteractive -File $script:Collector -SinceHours 1 -MaxEvents 50 2>$null)
        $LASTEXITCODE | Should -BeIn @(0, 6)
        $objs = @($out | ForEach-Object { $_ | ConvertFrom-Json })
        $objs[0].type | Should -Be 'header'
        $objs[0].host.os.family | Should -Be 'windows'
        $objs[-1].type | Should -Be 'end'
        $objs[-1].records | Should -Be @($objs | Where-Object { $_.type -eq 'record' }).Count
        $text = $out -join "`n"
        ($text.ToCharArray() | Where-Object { [int]$_ -gt 126 }).Count | Should -Be 0
        $cats = @($objs | Where-Object { $_.type -eq 'record' } | ForEach-Object { $_.category } | Sort-Object -Unique)
        $cats | Should -Contain 'process'
        $cats | Should -Contain 'user'
        $cats | Should -Contain 'service'
        $cov = @($objs | Where-Object { $_.type -eq 'coverage' })
        $cov.Count | Should -BeGreaterThan 5
    }
}
