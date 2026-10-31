# CLI contract tests for the Windows audit entry points (usage, output streams, report shape, safety).

BeforeDiscovery {
    $script:OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($PSVersionTable.Platform -eq 'Win32NT')
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    $script:Fx = Copy-BoTestFixture
    $script:Full = Invoke-BoAuditJson -Fixture $script:Fx -Modules @()
}

AfterAll {
    Remove-BoTestFixture $script:Fx
}

Describe 'usage and informational options' {
    It '-Help prints usage and states the tool is read-only' {
        $r = Invoke-BoTestRun -Fixture $script:Fx -Arguments @('-Help')
        $r.ExitCode | Should -Be 0
        $r.Out | Should -Match 'Usage: audit-windows'
        $r.Out | Should -Match 'READ-ONLY'
        $r.Out | Should -Match '-Modules'
    }

    It '-Version prints the tool version' {
        $r = Invoke-BoTestRun -Fixture $script:Fx -Arguments @('-Version')
        $r.ExitCode | Should -Be 0
        $r.Out | Should -Match '^audit-windows \d+\.\d+\.\d+'
    }

    It '-ListModules lists all eleven modules' {
        $r = Invoke-BoTestRun -Fixture $script:Fx -Arguments @('-ListModules')
        $r.ExitCode | Should -Be 0
        $names = @($r.Out -split "`r?`n" | Where-Object { $_ })
        $names.Count | Should -Be 11
        $names | Should -Contain 'persistence'
        $names | Should -Contain 'firewall'
        $names | Should -Contain 'tasks'
    }

    It 'rejects bad arguments with exit code 2' -ForEach @(
        @{ Name = 'unknown switch'; Arguments = @('-Bogus') }
        @{ Name = 'unknown module'; Arguments = @('-Modules', 'nosuch') }
        @{ Name = 'bad format'; Arguments = @('-Format', 'yaml') }
        @{ Name = 'zero recent days'; Arguments = @('-RecentDays', '0') }
        @{ Name = 'non-numeric recent days'; Arguments = @('-RecentDays', 'abc') }
        @{ Name = 'bad fail-on'; Arguments = @('-FailOn', 'severe') }
    ) {
        $r = Invoke-BoTestRun -Fixture $script:Fx -Arguments $Arguments
        $r.ExitCode | Should -Be 2
    }

    It 'refuses to run on a non-Windows host without a fixture (exit 3)' -Skip:$script:OnWindows {
        $r = Invoke-BoTestRun -NoFixture -Arguments @('-Modules', 'system')
        $r.ExitCode | Should -Be 3
        $r.Err | Should -Match 'Windows only'
    }

    It 'the persistence entry point has its own tool name and category' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @() -Script $script:PersistenceScript
        $r.Json.tool.name | Should -Be 'find-persistence'
        $r.Json.tool.category | Should -Be 'persistence'
        @($r.Json.findings | Where-Object { $_.id -notlike 'PER-*' }).Count | Should -Be 0
    }
}

Describe 'report shape' {
    It 'emits schema-shaped JSON with exit code 4 when findings exist' {
        $script:Full.ExitCode | Should -Be 4
        $j = $script:Full.Json
        $j.schema_version | Should -Be '0.2.0'
        $j.tool.name | Should -Be 'audit-windows'
        $j.tool.category | Should -Be 'audit'
        $j.run.mode | Should -Be 'read-only'
        $j.run.dry_run | Should -Be $false
        $j.run.exit_code | Should -Be 4
        $script:Full.Out | Should -Match '"started_at":\s*"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"'
        $j.host.os.family | Should -Be 'windows'
        $j.host.hostname | Should -Be 'FIXTURE-WS01'
    }

    It 'finding ids are unique, well-formed, and the summary counts match' {
        $ids = @($script:Full.Json.findings | ForEach-Object { $_.id })
        @($ids | Select-Object -Unique).Count | Should -Be $ids.Count
        foreach ($id in $ids) { $id | Should -Match '^[A-Z]{2,6}-[A-Z0-9]+-\d{3,}$' }
        $script:Full.Json.summary.total | Should -Be $ids.Count
        foreach ($sev in 'info', 'low', 'medium', 'high', 'critical') {
            $n = @($script:Full.Json.findings | Where-Object { $_.severity -eq $sev }).Count
            $script:Full.Json.summary.by_severity.$sev | Should -Be $n
        }
    }

    It 'every module contributes findings in a full audit' -ForEach @(
        @{ Prefix = 'SYS' }, @{ Prefix = 'USR' }, @{ Prefix = 'PRC' }, @{ Prefix = 'NET' }, @{ Prefix = 'SVC' }, @{ Prefix = 'TSK' },
        @{ Prefix = 'AUT' }, @{ Prefix = 'PER' }, @{ Prefix = 'FW' }, @{ Prefix = 'SEC' }, @{ Prefix = 'FS' }
    ) {
        @($script:Full.Json.findings | Where-Object { $_.id -like "$Prefix-*" }).Count | Should -BeGreaterThan 0
    }

    It 'every finding has a severity, category, description and valid evidence types' {
        $types = 'file', 'registry', 'process', 'network', 'command', 'log', 'other'
        foreach ($f in $script:Full.Json.findings) {
            $f.severity | Should -BeIn 'info', 'low', 'medium', 'high', 'critical'
            $f.category | Should -Not -BeNullOrEmpty
            foreach ($e in @($f.evidence)) { $e.type | Should -BeIn $types }
        }
    }
}

Describe 'output handling' {
    It '-Json keeps stdout machine-readable and sends human text to stderr' {
        $r = Invoke-BoTestRun -Fixture $script:Fx -Arguments @('-Json', '-Modules', 'users')
        { $r.Out | ConvertFrom-Json } | Should -Not -Throw
        $r.Err | Should -Match 'USR-HIDDEN-001'
        $r.Err | Should -Match 'Exit code: 4'
    }

    It '-Quiet -Json emits only JSON' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('system')
        $r.Err.Trim() | Should -BeNullOrEmpty
        $r.Json.tool.name | Should -Be 'audit-windows'
    }

    It 'text mode prints a human summary with severities and coverage gaps' {
        $r = Invoke-BoTestRun -Fixture $script:Fx -Arguments @('-Modules', 'users,processes')
        $r.ExitCode | Should -Be 4
        $r.Out | Should -Match 'Findings:'
        $r.Out | Should -Match '\[HIGH\] USR-HIDDEN-001'
        $r.Out | Should -Match 'Coverage gaps:'
        $r.Out | Should -Match 'Exit code: 4'
    }

    It '-Modules selects and de-duplicates modules' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('system', 'system', 'users')
        $prefixes = @($r.Json.findings | ForEach-Object { $_.id.Split('-')[0] } | Select-Object -Unique | Sort-Object)
        ($prefixes -join ',') | Should -Be 'SYS,USR'
    }

    It '-OutputDir writes report.json, report.txt and run.log without a BOM' {
        $out = Join-Path $script:Fx 'out'
        $r = Invoke-BoTestRun -Fixture $script:Fx -Arguments @('-Json', '-Quiet', '-Modules', 'system', '-OutputDir', $out)
        $r.Out.Trim() | Should -BeNullOrEmpty
        $dir = @(Get-ChildItem -LiteralPath $out -Directory)[0]
        $dir.Name | Should -Match '^blueops-run-\d{8}T\d{6}Z-audit-windows$'
        foreach ($n in 'report.json', 'report.txt', 'run.log') { Test-Path -LiteralPath (Join-Path $dir.FullName $n) | Should -BeTrue }
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path $dir.FullName 'report.json'))
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB) | Should -BeFalse
        ([System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json).tool.name | Should -Be 'audit-windows'
    }

    It '-FailOn critical ignores lower severities' {
        (Invoke-BoAuditJson -Fixture $script:Fx -Modules @('system') -Extra @('-FailOn', 'critical')).ExitCode | Should -Be 0
        (Invoke-BoAuditJson -Fixture $script:Fx -Modules @('users') -Extra @('-FailOn', 'critical')).ExitCode | Should -Be 0
        (Invoke-BoAuditJson -Fixture $script:Fx -Modules @('users') -Extra @('-FailOn', 'high')).ExitCode | Should -Be 4
    }
}

Describe 'safety and degradation' {
    It 'is read-only: the audited tree is byte- and time-identical afterwards' {
        $fx = Copy-BoTestFixture
        try {
            $before = Get-BoTreeDigest $fx
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @()
            $r.ExitCode | Should -Be 4
            Get-BoTreeDigest $fx | Should -Be $before
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'never prints secrets, encoded payloads or key material' {
        $r = Invoke-BoTestRun -Fixture $script:Fx -Arguments @('-Json')
        $all = $r.Out + $r.Err
        $all | Should -Not -Match 'hunter2'
        $all | Should -Not -Match 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'
        $all | Should -Not -Match 'DefaultPassword'
    }

    It 'missing data sources degrade to partial results (exit 6), not a crash' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('system', 'tasks') -Environment @{ BO_FORCE_MISSING = 'cim.Win32_OperatingSystem tasks.scheduled tasks.schtasks' }
        $r.ExitCode | Should -Be 6
        Test-BoErrorCode $r 'OS_UNREADABLE' | Should -BeTrue
        Test-BoErrorCode $r 'TASKS_UNAVAILABLE' | Should -BeTrue
        $r.Json.run.exit_code | Should -Be 6
        Get-BoFinding $r 'SYS-INFO-001' | Should -Not -BeNullOrEmpty
    }

    It 'a crashing module is reported and does not abort the others' {
        . (Join-Path $script:RepoRoot 'windows\lib\Common.ps1')
        . (Join-Path $script:RepoRoot 'windows\audit\Get-SystemAudit.ps1')
        function Invoke-BoCrashModule { throw 'synthetic crash' }
        $saved = $script:BoModuleFunctions['users']
        $script:BoModuleFunctions['users'] = 'Invoke-BoCrashModule'
        $env:BO_FIXTURE_DIR = $script:Fx
        $env:BO_TEST_MODE = '1'
        try {
            Mock Write-BoOut {}
            Mock Write-BoErr {}
            $code = Invoke-BoCli -Tool 'audit-windows' -Category 'audit' -AllowedModules $script:BoAllModules -Modules @('users', 'system') -Quiet $true
            $code | Should -Be 6
            @($script:Bo.Errors | Where-Object { $_['code'] -eq 'MODULE_FAILED' }).Count | Should -Be 1
            @($script:Bo.Findings | Where-Object { $_['id'] -eq 'SYS-INFO-001' }).Count | Should -Be 1
        }
        finally {
            $script:BoModuleFunctions['users'] = $saved
            Remove-Item Env:\BO_FIXTURE_DIR -ErrorAction SilentlyContinue
            Remove-Item Env:\BO_TEST_MODE -ErrorAction SilentlyContinue
        }
    }

    It 'a non-elevated run records NOT_ELEVATED as a non-material gap' {
        $fx = Copy-BoTestFixture
        try {
            Edit-BoFixtureJson -Fixture $fx -Name 'host' -Mutator { param($h) $h.elevated = $false }
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('system')
            Test-BoErrorCode $r 'NOT_ELEVATED' | Should -BeTrue
            $r.ExitCode | Should -Be 0
            $r.Json.host.elevated | Should -Be $false
        }
        finally { Remove-BoTestFixture $fx }
    }
}
