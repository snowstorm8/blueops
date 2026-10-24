# Module tests: system, users, processes, network. Each module runs once against the synthetic host;
# mutations (a modified fixture copy) cover the remaining branches.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    $script:Fx = Copy-BoTestFixture
}

AfterAll {
    Remove-BoTestFixture $script:Fx
}

Describe 'system module' {
    BeforeAll { $script:Sys = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('system') }

    It 'reports an inventory with OS, domain, hardware and uptime' {
        $f = Get-BoFinding $script:Sys 'SYS-INFO-001'
        $f.severity | Should -Be 'info'
        $f.description | Should -Match 'Windows Server 2019 Standard 10.0.17763'
        $f.description | Should -Match 'corp.example.test \(domain-joined: True\)'
        $f.description | Should -Match 'CPUs 4'
        $f.description | Should -Match '8192 MiB'
        $f.description | Should -Match 'up 12d'
    }

    It 'a supported, patched, recently rebooted host has no system warnings' {
        $script:Sys.ExitCode | Should -Be 0
        @($script:Sys.Json.findings | Where-Object { $_.severity -ne 'info' }).Count | Should -Be 0
    }

    It 'flags end-of-support releases' -ForEach @(
        @{ Caption = 'Microsoft Windows 7 Professional'; Severity = 'medium' }
        @{ Caption = 'Microsoft Windows Server 2012 R2 Standard'; Severity = 'medium' }
        @{ Caption = 'Microsoft Windows 10 Pro'; Severity = 'low' }
    ) {
        $fx = Copy-BoTestFixture
        try {
            Edit-BoFixtureJson -Fixture $fx -Name 'cim.Win32_OperatingSystem' -Mutator { param($o) @($o)[0].Caption = $Caption; , @($o) }
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('system')
            (Get-BoFinding $r 'SYS-OS-001').severity | Should -Be $Severity
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'notes year-long uptime and stale patching' {
        $fx = Copy-BoTestFixture
        try {
            $old = [DateTime]::UtcNow.AddDays(-500).ToString('yyyy-MM-ddTHH:mm:ssZ')
            Edit-BoFixtureJson -Fixture $fx -Name 'cim.Win32_OperatingSystem' -Mutator { param($o) @($o)[0].LastBootUpTime = $old; , @($o) }
            Edit-BoFixtureJson -Fixture $fx -Name 'cim.Win32_QuickFixEngineering' -Mutator { param($o) foreach ($h in @($o)) { $h.InstalledOn = $old }; , @($o) }
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('system')
            Get-BoFinding $r 'SYS-UPTIME-001' | Should -Not -BeNullOrEmpty
            Get-BoFinding $r 'SYS-HOTFIX-001' | Should -Not -BeNullOrEmpty
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'an unreadable Win32_OperatingSystem is a material gap, not a crash' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('system') -Environment @{ BO_FORCE_MISSING = 'cim.Win32_OperatingSystem' }
        $r.ExitCode | Should -Be 6
        Test-BoErrorCode $r 'OS_UNREADABLE' | Should -BeTrue
    }
}

Describe 'users module' {
    BeforeAll { $script:Usr = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('users') }

    It 'flags hidden ($-suffixed) accounts as high' {
        (Get-BoFinding $script:Usr 'USR-HIDDEN-001').severity | Should -Be 'high'
        Get-BoEvidenceText (Get-BoFinding $script:Usr 'USR-HIDDEN-001') | Should -Match 'support\$'
    }

    It 'flags enabled accounts without a required password' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Usr 'USR-PWD-001')
        $t | Should -Match 'helpdesk'
        $t | Should -Not -Match 'Guest'
        $t | Should -Not -Match 'DefaultAccount'
    }

    It 'does not flag disabled built-in accounts (Administrator, Guest, DefaultAccount, WDAGUtilityAccount)' {
        Get-BoFinding $script:Usr 'USR-GUEST-001' | Should -BeNullOrEmpty
        Get-BoFinding $script:Usr 'USR-RID500-001' | Should -BeNullOrEmpty
        Get-BoEvidenceText (Get-BoFinding $script:Usr 'USR-PWD-002') | Should -Not -Match 'Administrator'
    }

    It 'notes service accounts whose password never expires as low severity' {
        $f = Get-BoFinding $script:Usr 'USR-PWD-002'
        $f.severity | Should -Be 'low'
        Get-BoEvidenceText $f | Should -Match 'svc_backup'
    }

    It 'lists administrators and flags only enabled local non-built-in members' {
        Get-BoEvidenceText (Get-BoFinding $script:Usr 'USR-ADMIN-001') | Should -Match 'Domain Admins'
        $t = Get-BoEvidenceText (Get-BoFinding $script:Usr 'USR-ADMIN-002')
        $t | Should -Match 'alice'
        $t | Should -Not -Match 'Domain Admins'
        $t | Should -Not -Match 'Administrator'
    }

    It 'lists Remote Desktop Users and logon sessions' {
        Get-BoEvidenceText (Get-BoFinding $script:Usr 'USR-RDP-001') | Should -Match 'helpdesk-ops'
        $t = Get-BoEvidenceText (Get-BoFinding $script:Usr 'USR-SESS-001')
        $t | Should -Match 'alice'
        $t | Should -Match 'remote-interactive'
    }

    It 'flags an enabled Guest or RID-500 account' {
        $fx = Copy-BoTestFixture
        try {
            Edit-BoFixtureJson -Fixture $fx -Name 'cim.Win32_UserAccount' -Mutator { param($u) foreach ($x in @($u)) { if ($x.Name -in 'Guest', 'Administrator') { $x.Disabled = $false } }; , @($u) }
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('users')
            (Get-BoFinding $r 'USR-GUEST-001').severity | Should -Be 'medium'
            (Get-BoFinding $r 'USR-RID500-001').severity | Should -Be 'low'
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'an unreadable group is a non-material gap and other checks continue' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('users') -Environment @{ BO_FORCE_MISSING = 'group.administrators' }
        Test-BoErrorCode $r 'GROUP_UNREADABLE' | Should -BeTrue
        Get-BoFinding $r 'USR-ADMIN-001' | Should -BeNullOrEmpty
        Get-BoFinding $r 'USR-HIDDEN-001' | Should -Not -BeNullOrEmpty
    }
}

Describe 'processes module' {
    BeforeAll { $script:Prc = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('processes') }

    It 'inventories processes with parent, name and path' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Prc 'PRC-INFO-001')
        $t | Should -Match 'ppid=560 name=svchost.exe path=C:\\Windows\\System32\\svchost.exe'
    }

    It 'flags system process names running from the wrong path' {
        $f = Get-BoFinding $script:Prc 'PRC-MASQ-001'
        $f.severity | Should -Be 'high'
        $t = Get-BoEvidenceText $f
        $t | Should -Match 'pid=2000'
        $t | Should -Match 'pid=2600'
        $t | Should -Not -Match 'pid=700'
    }

    It 'flags svchost and lsass with unexpected parents but not the real ones' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Prc 'PRC-PARENT-001')
        $t | Should -Match 'pid=2100'
        $t | Should -Match 'expected parent services.exe'
        $t | Should -Not -Match 'pid=700'
        $t | Should -Not -Match 'pid=570'
    }

    It 'flags a shell started by Word and encoded PowerShell, without printing the payload' {
        Get-BoEvidenceText (Get-BoFinding $script:Prc 'PRC-PARENT-002') | Should -Match 'pid=2300'
        $t = Get-BoEvidenceText (Get-BoFinding $script:Prc 'PRC-CMD-001')
        $t | Should -Match 'encoded PowerShell command'
        $t | Should -Match '<base64 \d+ chars>'
        $t | Should -Not -Match 'SQBFAFgA'
    }

    It 'flags unsigned user-writable images but not signed installers or known vendor paths' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Prc 'PRC-PATH-001')
        $t | Should -Match 'Downloads\\updater.exe'
        $t | Should -Match 'Public\\svchost.exe'
        $t | Should -Not -Match 'signed-setup'
        $t | Should -Not -Match 'OneDrive'
        $t | Should -Not -Match 'MsMpEng'
    }

    It 'benign processes produce no findings' -ForEach @(
        @{ ProcId = 1400; Why = 'Chrome from Program Files' }
        @{ ProcId = 1300; Why = 'OneDrive from a known per-user path' }
        @{ ProcId = 900; Why = 'MsMpEng from ProgramData\Microsoft' }
        @{ ProcId = 1500; Why = 'PowerShell running an admin script (policy bypass is weak context)' }
        @{ ProcId = 1200; Why = 'explorer.exe whose parent has exited' }
    ) {
        foreach ($id in 'PRC-MASQ-001', 'PRC-PARENT-001', 'PRC-PARENT-002', 'PRC-CMD-001', 'PRC-PATH-001') {
            Get-BoEvidenceText (Get-BoFinding $script:Prc $id) | Should -Not -Match "(?m)^pid=$ProcId\s*$"
        }
    }

    It 'redacts secrets in command lines' {
        $script:Prc.Out | Should -Not -Match 'hunter2'
        (Get-BoEvidenceText (Get-BoFinding $script:Prc 'PRC-INFO-001')) | Should -Match 'password <redacted>'
    }

    It 'unprivileged runs aggregate unreadable image paths into one non-material gap' {
        @($script:Prc.Json.errors | Where-Object { $_.code -eq 'PROC_PATH_UNREADABLE' }).Count | Should -Be 1
    }

    It 'no process source at all is a material coverage failure' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('processes') -Environment @{ BO_FORCE_MISSING = 'cim.Win32_Process' }
        Test-BoErrorCode $r 'PROCESS_UNAVAILABLE' | Should -BeTrue
        $r.ExitCode | Should -Be 6
    }
}

Describe 'network module' {
    BeforeAll { $script:Net = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('network') }

    It 'inventories listeners with owning processes' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-LISTEN-001')
        $t | Should -Match 'tcp 0.0.0.0:3389'
        $t | Should -Match 'svchost.exe'
        $t | Should -Match 'udp 0.0.0.0:5353'
    }

    It 'classifies exposed services by risk and ignores loopback' {
        (Get-BoFinding $script:Net 'NET-EXPOSE-001').severity | Should -Be 'high'
        Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-EXPOSE-001') | Should -Match ':23'
        $m = Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-EXPOSE-002')
        $m | Should -Match ':1433'
        $m | Should -Match ':6379'
        $m | Should -Match 'udp 0.0.0.0:161'
        $m | Should -Not -Match ':3306'
        $l = Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-EXPOSE-003')
        $l | Should -Match ':3389'
        $l | Should -Match ':445'
        $l | Should -Not -Match ':5353'
    }

    It 'flags listeners owned by shells or unsigned user-writable binaries' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-LISTEN-002')
        $t | Should -Match ':9999'
        $t | Should -Match 'Downloads\\updater.exe'
        $t | Should -Not -Match 'svchost.exe from C:\\Windows'
    }

    It 'flags shells with public connections and reverse-shell ports, not browsers or private peers' {
        $f = Get-BoFinding $script:Net 'NET-ESTAB-002'
        $f.severity | Should -Be 'high'
        $t = Get-BoEvidenceText $f
        $t | Should -Match 'cmd.exe'
        $t | Should -Match 'powershell.exe'
        $t | Should -Not -Match 'chrome'
        Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-ESTAB-003') | Should -Match '4444'
        Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-ESTAB-001') | Should -Not -Match '3306'
    }

    It 'reports DNS, adapters, custom hosts entries and vendor-domain overrides' {
        Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-DNS-001') | Should -Match 'dns=10.20.0.10,10.20.0.11'
        Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-IFACE-001') | Should -Match 'gw=10.20.0.1'
        $h = Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-HOSTS-001')
        $h | Should -Match 'fileserver'
        $h | Should -Not -Match 'localhost'
        $h | Should -Not -Match 'fixture-ws01'
        (Get-BoFinding $script:Net 'NET-HOSTS-002').severity | Should -Be 'medium'
        Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-HOSTS-002') | Should -Match 'update.microsoft.com'
    }

    It 'reports proxies in loaded user hives, custom shares and hidden shares' {
        Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-PROXY-001') | Should -Match 'proxy.corp.example.test:8080'
        $s = Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-SHARE-001')
        $s | Should -Match 'Public'
        $s | Should -Not -Match 'ADMIN\$'
        $s | Should -Not -Match 'C\$'
        Get-BoEvidenceText (Get-BoFinding $script:Net 'NET-SHARE-002') | Should -Match 'backup\$'
    }

    It 'IP forwarding is flagged only when enabled' {
        Get-BoFinding $script:Net 'NET-FWD-001' | Should -BeNullOrEmpty
        $fx = Copy-BoTestFixture
        try {
            Set-BoFixtureRegistryValue -Fixture $fx -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Values @{ IPEnableRouter = 1 }
            Get-BoFinding (Invoke-BoAuditJson -Fixture $fx -Modules @('network')) 'NET-FWD-001' | Should -Not -BeNullOrEmpty
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'falls back to netstat when the socket cmdlets are unavailable' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('network') -Environment @{ BO_FORCE_MISSING = 'net.tcp net.udp' }
        Test-BoErrorCode $r 'NETSTAT_FALLBACK' | Should -BeTrue
        Get-BoEvidenceText (Get-BoFinding $r 'NET-LISTEN-001') | Should -Match 'tcp 0.0.0.0:23'
        Get-BoEvidenceText (Get-BoFinding $r 'NET-ESTAB-001') | Should -Match '203.0.113.9:4444'
        Get-BoEvidenceText (Get-BoFinding $r 'NET-LISTEN-001') | Should -Not -Match '3306 .*pid=1400.*ESTAB'
    }

    It 'no socket source at all is a material gap' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('network') -Environment @{ BO_FORCE_MISSING = 'net.tcp net.udp net.netstat' }
        Test-BoErrorCode $r 'SOCKETS_MISSING' | Should -BeTrue
    }

    It 'a missing hosts file and adapter data degrade without failing the module' {
        $fx = Copy-BoTestFixture
        try {
            Remove-Item -LiteralPath (Join-Path $fx 'fs\Windows\System32\drivers\etc\hosts')
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('network') -Environment @{ BO_FORCE_MISSING = 'cim.Win32_NetworkAdapterConfiguration' }
            Test-BoErrorCode $r 'HOSTS_UNREADABLE' | Should -BeTrue
            Test-BoErrorCode $r 'NIC_UNREADABLE' | Should -BeTrue
            Get-BoFinding $r 'NET-LISTEN-001' | Should -Not -BeNullOrEmpty
        }
        finally { Remove-BoTestFixture $fx }
    }
}
