# Module tests: firewall, security configuration and filesystem.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    $script:Fx = Copy-BoTestFixture
    $script:FwRoot = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
}

AfterAll {
    Remove-BoTestFixture $script:Fx
}

Describe 'firewall module' {
    BeforeAll { $script:Fw = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('firewall') }

    It 'healthy profiles raise no profile or default-action findings' {
        Get-BoFinding $script:Fw 'FW-PROFILE-001' | Should -BeNullOrEmpty
        Get-BoFinding $script:Fw 'FW-DEFAULT-001' | Should -BeNullOrEmpty
    }

    It 'notes missing dropped-packet logging only for the profile without it' {
        $f = Get-BoFinding $script:Fw 'FW-LOG-001'
        $f.severity | Should -Be 'low'
        Get-BoEvidenceText $f | Should -Match 'Public profile'
        Get-BoEvidenceText $f | Should -Not -Match 'Domain profile'
    }

    It 'lists only custom inbound allow rules, not built-in or auto-generated ones' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Fw 'FW-RULE-001')
        $t | Should -Match 'Contoso Agent'
        $t | Should -Match 'Telnet'
        $t | Should -Not -Match 'FirewallAPI'
        $t | Should -Not -Match 'A1B2C3D4'
        $t | Should -Not -Match 'BlockOut'
    }

    It 'flags the allow-everything rule and a rule for a program in Public' {
        $a = Get-BoFinding $script:Fw 'FW-RULE-002'
        $a.severity | Should -Be 'high'
        Get-BoEvidenceText $a | Should -Match 'Allow Everything'
        Get-BoEvidenceText $a | Should -Not -Match 'Contoso'
        $t = Get-BoEvidenceText (Get-BoFinding $script:Fw 'FW-RULE-003')
        $t | Should -Match 'Public\\a.exe'
        $t | Should -Not -Match 'Teams'
        $t | Should -Not -Match 'chrome'
    }

    It 'flags sensitive ports open to any address but not scoped or disabled rules' {
        $f = Get-BoFinding $script:Fw 'FW-RULE-004'
        $f.severity | Should -Be 'high'
        $t = Get-BoEvidenceText $f
        $t | Should -Match 'lport=23'
        $t | Should -Match 'lport=1433'
        $t | Should -Match 'lport=3389'
        $t | Should -Not -Match 'lport=8443'
        $t | Should -Not -Match 'lport=445'
    }

    It 'flags disabled profiles and Allow default actions' {
        $fx = Copy-BoTestFixture
        try {
            Set-BoFixtureRegistryValue -Fixture $fx -Path "$($script:FwRoot)\PublicProfile" -Values @{ EnableFirewall = 0 }
            Set-BoFixtureRegistryValue -Fixture $fx -Path "$($script:FwRoot)\DomainProfile" -Values @{ EnableFirewall = 1; DefaultInboundAction = 0 }
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('firewall')
            (Get-BoFinding $r 'FW-PROFILE-001').severity | Should -Be 'high'
            Get-BoEvidenceText (Get-BoFinding $r 'FW-PROFILE-001') | Should -Match 'Public profile disabled'
            Get-BoEvidenceText (Get-BoFinding $r 'FW-DEFAULT-001') | Should -Match 'Domain profile allows inbound'
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'a policy (GPO) value overrides the local profile setting' {
        $fx = Copy-BoTestFixture
        try {
            Set-BoFixtureRegistryValue -Fixture $fx -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile' -Values @{ EnableFirewall = 0 }
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('firewall')
            Get-BoEvidenceText (Get-BoFinding $r 'FW-PROFILE-001') | Should -Match 'Private profile disabled \(policy\)'
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'an unreadable firewall policy is a material gap' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('firewall') -Environment @{ BO_FORCE_MISSING = 'registry' }
        Test-BoErrorCode $r 'FIREWALL_POLICY_MISSING' | Should -BeTrue
        $r.ExitCode | Should -Be 6
    }
}

Describe 'firewall AppContainer rules' {
    It 'an inbound allow rule scoped to an app package or capability is not an all-traffic rule' {
        $fx = Copy-BoTestFixture
        try {
            Edit-BoFixtureJson -Fixture $fx -Name 'registry' -Mutator {
                param($reg)
                $k = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
                $reg.PSObject.Properties[$k].Value.values | Add-Member -NotePropertyName 'AppX-In' -NotePropertyValue 'v2.31|Action=Allow|Active=TRUE|Dir=In|Name=Microsoft.Win32WebViewHost_cw5n1h2txyewy-In-Allow-ServerCapability|AppPkgId=S-1-15-2-1|LUAuth=O:LSD:|'
            }
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('firewall')
            $f = Get-BoFinding $r 'FW-RULE-002'
            if ($f) { Get-BoEvidenceText $f | Should -Not -Match 'WebViewHost' }
        }
        finally { Remove-BoTestFixture $fx }
    }
}

Describe 'security configuration module' {
    BeforeAll { $script:Sec = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('security') }

    It 'flags remote UAC filtering while accepting EnableLUA=1 and the default consent level' {
        $f = Get-BoFinding $script:Sec 'SEC-UAC-001'
        $f.severity | Should -Be 'medium'
        Get-BoEvidenceText $f | Should -Match 'LocalAccountTokenFilterPolicy'
        Get-BoEvidenceText $f | Should -Not -Match 'EnableLUA'
    }

    It 'reports weak credential settings by severity' {
        $f = Get-BoFinding $script:Sec 'SEC-LSA-001'
        $f.severity | Should -Be 'low'
        Get-BoEvidenceText $f | Should -Match 'RunAsPPL'
        Get-BoEvidenceText $f | Should -Not -Match 'WDigest'
        Get-BoEvidenceText $f | Should -Not -Match 'LmCompatibilityLevel'
    }

    It 'flags a weak password policy and missing lockout from net accounts' {
        (Get-BoFinding $script:Sec 'SEC-PWD-001').severity | Should -Be 'medium'
        Get-BoEvidenceText (Get-BoFinding $script:Sec 'SEC-PWD-001') | Should -Match 'length 6'
        Get-BoFinding $script:Sec 'SEC-PWD-002' | Should -Not -BeNullOrEmpty
    }

    It 'flags only the unaudited subcategory and the missing command-line auditing' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Sec 'SEC-AUDIT-001')
        $t | Should -Match 'Process Creation: No Auditing'
        $t | Should -Not -Match 'Logon'
        Get-BoFinding $script:Sec 'SEC-AUDIT-002' | Should -Not -BeNullOrEmpty
    }

    It 'flags broad Defender exclusions but not a narrow vendor path or a .log extension' {
        $b = Get-BoEvidenceText (Get-BoFinding $script:Sec 'SEC-DEF-002')
        $b | Should -Match 'Public'
        $b | Should -Not -Match 'Contoso'
        $b | Should -Not -Match '\.log'
        Get-BoEvidenceText (Get-BoFinding $script:Sec 'SEC-DEF-003') | Should -Match 'Contoso'
    }

    It 'RDP is reported as information when NLA is required' {
        (Get-BoFinding $script:Sec 'SEC-RDP-001').severity | Should -Be 'info'
        Get-BoFinding $script:Sec 'SEC-RDP-002' | Should -BeNullOrEmpty
    }

    It 'healthy SMB1, WDigest, autologon and Defender state raise nothing' {
        foreach ($id in 'SEC-SMB-001', 'SEC-AUTOLOGON-001', 'SEC-DEF-001', 'SEC-DEF-004', 'SEC-WINRM-001', 'SEC-UPDATE-001') {
            Get-BoFinding $script:Sec $id | Should -BeNullOrEmpty
        }
    }

    It 'detects each weakened setting' -ForEach @(
        @{ Id = 'SEC-UAC-001'; Path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Values = @{ EnableLUA = 0 }; Severity = 'high'; Pattern = 'EnableLUA' }
        @{ Id = 'SEC-LSA-001'; Path = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Values = @{ UseLogonCredential = 1 }; Severity = 'high'; Pattern = 'WDigest' }
        @{ Id = 'SEC-SMB-001'; Path = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Values = @{ SMB1 = 1; RequireSecuritySignature = 1 }; Severity = 'high'; Pattern = 'SMB1' }
        @{ Id = 'SEC-RDP-002'; Path = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Values = @{ UserAuthentication = 0; SecurityLayer = 2 }; Severity = 'high'; Pattern = 'NLA disabled' }
        @{ Id = 'SEC-AUTOLOGON-001'; Path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Values = @{ AutoAdminLogon = '1'; DefaultUserName = 'kiosk'; DefaultPassword = 'S3cretPass' }; Severity = 'high'; Pattern = 'user=kiosk passwordStoredInRegistry=True' }
        @{ Id = 'SEC-DEF-001'; Path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'; Values = @{ DisableAntiSpyware = 1 }; Severity = 'high'; Pattern = 'disabled by policy' }
        @{ Id = 'SEC-WINRM-001'; Path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Values = @{ AllowBasic = 1 }; Severity = 'medium'; Pattern = 'Basic' }
        @{ Id = 'SEC-UPDATE-001'; Path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Values = @{ NoAutoUpdate = 1 }; Severity = 'medium'; Pattern = 'automatic updates disabled' }
    ) {
        $fx = Copy-BoTestFixture
        try {
            Set-BoFixtureRegistryValue -Fixture $fx -Path ('Registry::' + $Path) -Values $Values
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('security')
            $f = Get-BoFinding $r $Id
            $f.severity | Should -Be $Severity
            Get-BoEvidenceText $f | Should -Match ([regex]::Escape($Pattern))
            $r.Out + $r.Err | Should -Not -Match 'S3cretPass'
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'out-of-date signatures and a stopped real-time engine are reported from Defender status' {
        $fx = Copy-BoTestFixture
        try {
            Edit-BoFixtureJson -Fixture $fx -Name 'defender.status' -Mutator { param($s) $s.RealTimeProtectionEnabled = $false; $s.AntivirusSignatureAge = 30 }
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('security')
            Get-BoEvidenceText (Get-BoFinding $r 'SEC-DEF-001') | Should -Match 'RealTimeProtectionEnabled=False'
            Get-BoEvidenceText (Get-BoFinding $r 'SEC-DEF-004') | Should -Match '30 days'
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'a strong password policy and lockout are not flagged' {
        $fx = Copy-BoTestFixture
        try {
            (Get-Content -LiteralPath (Join-Path $fx 'data\netaccounts.txt') -Raw) -replace 'length:\s+6', 'length:  14' -replace 'threshold:\s+Never', 'threshold:  5' | Set-Content -LiteralPath (Join-Path $fx 'data\netaccounts.txt')
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('security')
            Get-BoFinding $r 'SEC-PWD-001' | Should -BeNullOrEmpty
            Get-BoFinding $r 'SEC-PWD-002' | Should -BeNullOrEmpty
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'auditpol needing administrator rights is a non-material gap when not elevated' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('security') -Environment @{ BO_FORCE_MISSING = 'auditpol' }
        Test-BoErrorCode $r 'AUDITPOL_UNAVAILABLE' | Should -BeTrue
        Get-BoFinding $r 'SEC-AUDIT-001' | Should -BeNullOrEmpty
        Get-BoFinding $r 'SEC-PWD-001' | Should -Not -BeNullOrEmpty
    }

    It 'unparseable net accounts output is recorded, not guessed' {
        $fx = Copy-BoTestFixture
        try {
            Set-Content -LiteralPath (Join-Path $fx 'data\netaccounts.txt') -Value 'System error 5 has occurred.'
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('security')
            Test-BoErrorCode $r 'NETACCOUNTS_UNPARSED' | Should -BeTrue
            Get-BoFinding $r 'SEC-PWD-001' | Should -BeNullOrEmpty
        }
        finally { Remove-BoTestFixture $fx }
    }
}

Describe 'filesystem module' {
    BeforeAll { $script:Fs = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('filesystem') }

    It 'inventories fixed volumes' {
        Get-BoEvidenceText (Get-BoFinding $script:Fs 'FS-INFO-001') | Should -Match 'NTFS 100.0 GiB'
    }

    It 'flags unsigned executables in user-writable locations, not signed ones or vendor paths' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Fs 'FS-EXE-001')
        $t | Should -Match 'Public\\payload.exe'
        $t | Should -Match 'Downloads\\tool.exe'
        $t | Should -Match 'Local\\Temp\\tmp123.exe'
        $t | Should -Not -Match 'ChromeSetup'
        $t | Should -Not -Match 'signed-setup'
        $t | Should -Not -Match 'javaw'
        $t | Should -Not -Match 'Teams'
    }

    It 'flags scripts with tradecraft as high and plain scripts as medium; ignores text files' {
        $f = Get-BoFinding $script:Fs 'FS-SCRIPT-001'
        $f.severity | Should -Be 'high'
        $t = Get-BoEvidenceText $f
        $t | Should -Match 'tool.ps1'
        $t | Should -Match 'download-and-execute'
        $t | Should -Match 'stage.bat'
        $t | Should -Not -Match 'readme.txt'
        $t | Should -Not -Match 'dd_install.log'
    }

    It 'flags files at the drive root' {
        Get-BoEvidenceText (Get-BoFinding $script:Fs 'FS-ROOT-001') | Should -Match 'C:\\setup.ps1'
    }

    It 'flags recently modified unsigned system binaries and only counts signed ones' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Fs 'FS-RECENT-001')
        $t | Should -Match 'evilsvc.dll'
        $t | Should -Not -Match 'newpatched'
        $t | Should -Not -Match 'kernel32'
        Get-BoEvidenceText (Get-BoFinding $script:Fs 'FS-RECENT-002') | Should -Match '1 signed binaries'
    }

    It '-RecentDays widens or narrows the window' {
        $narrow = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('filesystem') -Extra @('-RecentDays', '1')
        Get-BoEvidenceText (Get-BoFinding $narrow 'FS-RECENT-001') | Should -Match 'evilsvc.dll'
        $wide = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('filesystem') -Extra @('-RecentDays', '500')
        Get-BoEvidenceText (Get-BoFinding $wide 'FS-RECENT-002') | Should -Match '2 signed binaries'
    }

    It 'flags system PATH directories writable by Users but not protected ones' {
        $f = Get-BoFinding $script:Fs 'FS-ACL-001'
        $f.severity | Should -Be 'high'
        Get-BoEvidenceText $f | Should -Match 'C:\\Tools\\bin'
        Get-BoEvidenceText $f | Should -Not -Match 'system32'
    }

    It '-FsPath restricts the scan to the given directory' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('filesystem') -Extra @('-FsPath', 'C:\Windows\Temp')
        Get-BoEvidenceText (Get-BoFinding $r 'FS-SCRIPT-001') | Should -Match 'stage.bat'
        Get-BoFinding $r 'FS-ROOT-001' | Should -BeNullOrEmpty
        Get-BoFinding $r 'FS-RECENT-001' | Should -BeNullOrEmpty
        Get-BoEvidenceText (Get-BoFinding $r 'FS-SCRIPT-001') | Should -Not -Match 'Public'
    }

    It 'a clean tree yields inventory only' {
        $fx = Copy-BoTestFixture
        try {
            foreach ($d in 'Users\Public', 'Windows\Temp', 'Users\alice\Downloads', 'Users\alice\AppData\Local\Temp', 'ProgramData\Oracle') { Remove-Item -LiteralPath (Join-Path $fx "fs\$d") -Recurse -Force }
            Remove-Item -LiteralPath (Join-Path $fx 'fs\setup.ps1') -Force
            Remove-Item -LiteralPath (Join-Path $fx 'fs\Windows\System32\evilsvc.dll') -Force
            Edit-BoFixtureJson -Fixture $fx -Name 'acl' -Mutator { param($a) $a.PSObject.Properties.Remove('C:\Tools\bin') }
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('filesystem')
            @($r.Json.findings | Where-Object { $_.severity -notin 'info' }).Count | Should -Be 0
            $r.ExitCode | Should -Be 0
        }
        finally { Remove-BoTestFixture $fx }
    }
}
