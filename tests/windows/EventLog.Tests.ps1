# Module tests: eventlog (registry-only configuration of the Windows event logs).
# Written without a local PowerShell: first run is on a Windows CI runner.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    $script:Hklm = 'Registry::HKEY_LOCAL_MACHINE'
    $script:SvcRoot = $script:Hklm + '\SYSTEM\CurrentControlSet\Services\EventLog'
    $script:PolRoot = $script:Hklm + '\SOFTWARE\Policies\Microsoft\Windows\EventLog'
    $script:ChanRoot = $script:Hklm + '\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels'
    function Invoke-BoEvtRun {
        param([string]$Fixture, [hashtable]$Environment = @{})
        return (Invoke-BoAuditJson -Fixture $Fixture -Modules @('eventlog') -Environment $Environment)
    }
}

Describe 'eventlog module' {
    It 'a host with no event-log configuration in the registry raises no finding but a summary' {
        $fx = Copy-BoTestFixture
        try {
            $r = Invoke-BoEvtRun -Fixture $fx
            $r.ExitCode | Should -Be 0
            Get-BoFinding $r 'EVT-INFO-001' | Should -Not -BeNullOrEmpty
            foreach ($id in 'EVT-SVC-001', 'EVT-SIZE-001', 'EVT-RET-001', 'EVT-CHAN-001') { Get-BoFinding $r $id | Should -BeNullOrEmpty }
            @($r.Json.inventory.coverage | Where-Object { $_.domain -eq 'config' -and $_.scope -eq 'eventlog' -and $_.status -eq 'complete' }).Count | Should -Be 1
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'a disabled Event Log service is high; automatic start is quiet' {
        $fx = Copy-BoTestFixture
        try {
            Set-BoFixtureRegistryValue -Fixture $fx -Path $script:SvcRoot -Values @{ Start = 4 }
            $f = Get-BoFinding (Invoke-BoEvtRun -Fixture $fx) 'EVT-SVC-001'
            $f.severity | Should -Be 'high'
            Get-BoEvidenceText $f | Should -Match 'disabled'
            Set-BoFixtureRegistryValue -Fixture $fx -Path $script:SvcRoot -Values @{ Start = 2 }
            Get-BoFinding (Invoke-BoEvtRun -Fixture $fx) 'EVT-SVC-001' | Should -BeNullOrEmpty
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'a small configured Security log is low, a large one is quiet, and Group Policy wins' {
        $fx = Copy-BoTestFixture
        try {
            Set-BoFixtureRegistryValue -Fixture $fx -Path ($script:SvcRoot + '\Security') -Values @{ MaxSize = 20971520 }
            $f = Get-BoFinding (Invoke-BoEvtRun -Fixture $fx) 'EVT-SIZE-001'
            $f.severity | Should -Be 'low'
            Get-BoEvidenceText $f | Should -Match 'Security log maximum 20480 KB'
            Set-BoFixtureRegistryValue -Fixture $fx -Path ($script:PolRoot + '\Security') -Values @{ MaxSize = 262144 }
            Get-BoFinding (Invoke-BoEvtRun -Fixture $fx) 'EVT-SIZE-001' | Should -BeNullOrEmpty
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'System and Application use the lower threshold' {
        $fx = Copy-BoTestFixture
        try {
            Set-BoFixtureRegistryValue -Fixture $fx -Path ($script:SvcRoot + '\Application') -Values @{ MaxSize = 33554432 }
            Set-BoFixtureRegistryValue -Fixture $fx -Path ($script:SvcRoot + '\System') -Values @{ MaxSize = 1048576 }
            $t = Get-BoEvidenceText (Get-BoFinding (Invoke-BoEvtRun -Fixture $fx) 'EVT-SIZE-001')
            $t | Should -Match 'System log maximum 1024 KB'
            $t | Should -Not -Match 'Application log'
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'never-overwrite retention is reported for both encodings of 0xFFFFFFFF' -ForEach @(
        @{ Value = 4294967295 }, @{ Value = -1 }
    ) {
        $fx = Copy-BoTestFixture
        try {
            Set-BoFixtureRegistryValue -Fixture $fx -Path ($script:SvcRoot + '\System') -Values @{ Retention = $Value }
            Get-BoFinding (Invoke-BoEvtRun -Fixture $fx) 'EVT-RET-001' | Should -Not -BeNullOrEmpty
            Set-BoFixtureRegistryValue -Fixture $fx -Path ($script:SvcRoot + '\System') -Values @{ Retention = 0 }
            Get-BoFinding (Invoke-BoEvtRun -Fixture $fx) 'EVT-RET-001' | Should -BeNullOrEmpty
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'only an explicit Enabled=0 marks a diagnostic channel as disabled' {
        $fx = Copy-BoTestFixture
        try {
            $ps = $script:ChanRoot + '\Microsoft-Windows-PowerShell/Operational'
            Set-BoFixtureRegistryValue -Fixture $fx -Path $ps -Values @{ Enabled = 0 }
            Set-BoFixtureRegistryValue -Fixture $fx -Path ($script:ChanRoot + '\Microsoft-Windows-WinRM/Operational') -Values @{ Enabled = 1 }
            $f = Get-BoFinding (Invoke-BoEvtRun -Fixture $fx) 'EVT-CHAN-001'
            $f.severity | Should -Be 'medium'
            $t = Get-BoEvidenceText $f
            $t | Should -Match 'PowerShell/Operational'
            $t | Should -Not -Match 'WinRM'
            $t | Should -Not -Match 'Defender'
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'malformed registry data never fails the module and never produces a finding' {
        $fx = Copy-BoTestFixture
        try {
            Set-BoFixtureRegistryValue -Fixture $fx -Path $script:SvcRoot -Values @{ Start = 'banana' }
            Set-BoFixtureRegistryValue -Fixture $fx -Path ($script:SvcRoot + '\Security') -Values @{ MaxSize = 'huge'; Retention = 'x' }
            $r = Invoke-BoEvtRun -Fixture $fx
            $r.Json | Should -Not -BeNullOrEmpty
            foreach ($id in 'EVT-SVC-001', 'EVT-SIZE-001', 'EVT-RET-001') { Get-BoFinding $r $id | Should -BeNullOrEmpty }
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'an unreadable registry gives unknown values, not judgements, and incomplete coverage' {
        $fx = Copy-BoTestFixture
        try {
            $r = Invoke-BoEvtRun -Fixture $fx -Environment @{ BO_FORCE_MISSING = 'registry' }
            foreach ($id in 'EVT-SVC-001', 'EVT-SIZE-001', 'EVT-RET-001', 'EVT-CHAN-001') { Get-BoFinding $r $id | Should -BeNullOrEmpty }
            $log = @($r.Json.inventory.records | Where-Object { $_.key -eq 'config:eventlog:log:security' })
            $log.Count | Should -Be 1
            $log[0].attrs.max_kb | Should -BeNullOrEmpty
            @($r.Json.inventory.coverage | Where-Object { $_.scope -eq 'eventlog' -and $_.status -eq 'complete' }).Count | Should -Be 0
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'is read-only: the fixture tree is unchanged by a run' {
        $fx = Copy-BoTestFixture
        try {
            $before = (Get-ChildItem -LiteralPath $fx -Recurse -File | ForEach-Object { "$($_.FullName)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" }) -join "`n"
            [void](Invoke-BoEvtRun -Fixture $fx)
            $after = (Get-ChildItem -LiteralPath $fx -Recurse -File | ForEach-Object { "$($_.FullName)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" }) -join "`n"
            $after | Should -Be $before
        }
        finally { Remove-BoTestFixture $fx }
    }
}
