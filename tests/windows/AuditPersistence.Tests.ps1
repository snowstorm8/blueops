# Module tests: services, scheduled tasks, autoruns and the persistence detections.
# Every module includes realistic benign items that must NOT be flagged.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    $script:Fx = Copy-BoTestFixture
}

AfterAll {
    Remove-BoTestFixture $script:Fx
}

Describe 'services module' {
    BeforeAll { $script:Svc = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('services') }

    It 'inventories services with state, account and path' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Svc 'SVC-INFO-001')
        $t | Should -Match 'service:Spooler'
        $t | Should -Match 'account=NT AUTHORITY\\LocalService'
    }

    It 'flags unquoted paths with spaces, but not quoted paths or svchost command lines' {
        $f = Get-BoFinding $script:Svc 'SVC-UNQUOTED-001'
        $f.severity | Should -Be 'medium'
        $t = Get-BoEvidenceText $f
        $t | Should -Match 'ContosoAgent'
        $t | Should -Not -Match 'gupdate'
        $t | Should -Not -Match 'WinDefend'
        $t | Should -Not -Match 'W32Time'
    }

    It 'flags service images in user-writable locations and attacker command lines' {
        (Get-BoFinding $script:Svc 'SVC-PATH-001').severity | Should -Be 'high'
        Get-BoEvidenceText (Get-BoFinding $script:Svc 'SVC-PATH-001') | Should -Match 'Public\\wuhelper.exe'
        $c = Get-BoEvidenceText (Get-BoFinding $script:Svc 'SVC-CMD-001')
        $c | Should -Match 'SysCheck'
        $c | Should -Not -Match 'SQBFAFgA'
    }

    It 'flags enabled legacy services but not a disabled Remote Registry' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Svc 'SVC-LEGACY-001')
        $t | Should -Match 'TlntSvr'
        $t | Should -Not -Match 'RemoteRegistry'
    }

    It 'flags kernel drivers in temp locations but not system drivers' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Svc 'SVC-DRIVER-001')
        $t | Should -Match 'Windows\\Temp\\evil.sys'
        $t | Should -Not -Match 'beep.sys'
        $t | Should -Not -Match 'vmbus'
    }

    It 'lists named-account services as information' {
        (Get-BoFinding $script:Svc 'SVC-ACCOUNT-001').severity | Should -Be 'info'
        Get-BoEvidenceText (Get-BoFinding $script:Svc 'SVC-ACCOUNT-001') | Should -Match 'svc_backup'
    }

    It 'a healthy host has no SVC-SECURITY-001; stopping the firewall or event log is flagged' {
        Get-BoFinding $script:Svc 'SVC-SECURITY-001' | Should -BeNullOrEmpty
        $fx = Copy-BoTestFixture
        try {
            Edit-BoFixtureJson -Fixture $fx -Name 'cim.Win32_Service' -Mutator { param($s) foreach ($x in @($s)) { if ($x.Name -eq 'mpssvc') { $x.State = 'Stopped' }; if ($x.Name -eq 'WinDefend') { $x.StartMode = 'Disabled'; $x.State = 'Stopped' } }; , @($s) }
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('services')
            $f = Get-BoFinding $r 'SVC-SECURITY-001'
            $f.severity | Should -Be 'high'
            Get-BoEvidenceText $f | Should -Match 'mpssvc'
            Get-BoEvidenceText $f | Should -Match 'WinDefend'
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'falls back to Get-Service data with a recorded limitation' {
        $fx = Copy-BoTestFixture
        try {
            Set-Content -LiteralPath (Join-Path $fx 'data\services.fallback.json') -Value '[{"Name":"Spooler","DisplayName":"Print Spooler","State":"Running","StartMode":"Auto","PathName":"","StartName":""}]'
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('services') -Environment @{ BO_FORCE_MISSING = 'cim.Win32_Service' }
            Test-BoErrorCode $r 'SERVICE_PATHS_UNKNOWN' | Should -BeTrue
            Test-BoErrorCode $r 'SERVICES_UNREADABLE' | Should -BeTrue
            Get-BoEvidenceText (Get-BoFinding $r 'SVC-INFO-001') | Should -Match 'Spooler'
        }
        finally { Remove-BoTestFixture $fx }
    }
}

Describe 'scheduled tasks module' {
    BeforeAll { $script:Tsk = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('tasks') }

    It 'inventories only non-Microsoft tasks' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Tsk 'TSK-INFO-001')
        $t | Should -Match 'task:\\GoogleUpdateTaskMachineUA'
        $t | Should -Match 'task:\\Contoso Backup Nightly'
        $t | Should -Not -Match 'Windows Defender Scheduled Scan'
        $t | Should -Not -Match 'Schedule Scan'
    }

    It 'flags mshta from a URL and not routine vendor or Microsoft tasks' {
        $f = Get-BoFinding $script:Tsk 'TSK-CMD-001'
        $f.severity | Should -Be 'high'
        $t = Get-BoEvidenceText $f
        $t | Should -Match 'task:\\Updater'
        $t | Should -Not -Match 'Contoso Backup'
        $t | Should -Not -Match 'GoogleUpdate'
    }

    It 'flags hidden tasks and binaries in user-writable paths' {
        Get-BoEvidenceText (Get-BoFinding $script:Tsk 'TSK-HIDDEN-001') | Should -Match 'SysHealth'
        (Get-BoFinding $script:Tsk 'TSK-PATH-001').severity | Should -Be 'high'
        $p = Get-BoEvidenceText (Get-BoFinding $script:Tsk 'TSK-PATH-001')
        $p | Should -Match 'Public\\svc.exe'
        $p | Should -Not -Match 'OneDrive'
    }

    It 'notes privileged tasks running scripts outside standard locations as low severity' {
        $f = Get-BoFinding $script:Tsk 'TSK-SYSTEM-001'
        $f.severity | Should -Be 'low'
        $t = Get-BoEvidenceText $f
        $t | Should -Match 'Scripts\\cleanup.bat'
        $t | Should -Not -Match 'Contoso Backup'
        $t | Should -Not -Match 'GoogleUpdate'
    }

    It 'falls back to schtasks output when Get-ScheduledTask is unavailable' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('tasks') -Environment @{ BO_FORCE_MISSING = 'tasks.scheduled' }
        Test-BoErrorCode $r 'TASKS_FALLBACK' | Should -BeTrue
        Get-BoEvidenceText (Get-BoFinding $r 'TSK-CMD-001') | Should -Match 'task:\\Updater'
        Get-BoEvidenceText (Get-BoFinding $r 'TSK-INFO-001') | Should -Not -Match 'Schedule Scan'
    }
}

Describe 'autoruns module' {
    BeforeAll { $script:Aut = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('autoruns') }

    It 'inventories Run keys of the machine and loaded user hives' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Aut 'AUT-RUN-001')
        $t | Should -Match 'SecurityHealth'
        $t | Should -Match 'scope=FIXTURE-WS01\\alice'
        $t | Should -Match 'Adobe ARM'
    }

    It 'flags encoded PowerShell without printing the payload' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Aut 'AUT-CMD-001')
        $t | Should -Match 'Loader'
        $t | Should -Not -Match 'SQBFAFgA'
    }

    It 'flags unsigned user-writable targets but not OneDrive, Teams, Program Files or Windows entries' {
        $f = Get-BoFinding $script:Aut 'AUT-PATH-001'
        $t = Get-BoEvidenceText $f
        $t | Should -Match 'Updater'
        $t | Should -Match 'Public\\a.exe'
        $t | Should -Not -Match 'OneDrive'
        $t | Should -Not -Match 'Teams'
        $t | Should -Not -Match 'VMware'
        $t | Should -Not -Match 'SecurityHealth'
    }

    It 'accepts the default Winlogon values and flags a modified Shell or Userinit' {
        Get-BoFinding $script:Aut 'AUT-WINLOGON-001' | Should -BeNullOrEmpty
        $fx = Copy-BoTestFixture
        try {
            Set-BoFixtureRegistryValue -Fixture $fx -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Values @{ Shell = 'explorer.exe, C:\Users\Public\x.exe'; Userinit = 'C:\Windows\system32\userinit.exe,C:\Windows\Temp\y.exe' }
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('autoruns')
            (Get-BoFinding $r 'AUT-WINLOGON-001').severity | Should -Be 'high'
            (Get-BoEvidenceText (Get-BoFinding $r 'AUT-WINLOGON-001')) | Should -Match 'Shell'
            (Get-BoEvidenceText (Get-BoFinding $r 'AUT-WINLOGON-001')) | Should -Match 'Userinit'
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'flags scripts in Startup folders and lists shortcuts separately' {
        Get-BoEvidenceText (Get-BoFinding $script:Aut 'AUT-STARTUP-001') | Should -Match 'update.vbs'
        $s = Get-BoEvidenceText (Get-BoFinding $script:Aut 'AUT-STARTUP-002')
        $s | Should -Match 'Contoso Tray.lnk'
        $s | Should -Not -Match 'desktop.ini'
        Get-BoEvidenceText (Get-BoFinding $script:Aut 'AUT-STARTUP-001') | Should -Not -Match 'Contoso Tray'
    }

    It 'an unreadable registry is a coverage gap, not a crash' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('autoruns') -Environment @{ BO_FORCE_MISSING = 'registry' }
        Test-BoErrorCode $r 'REGISTRY_UNAVAILABLE' | Should -BeTrue
        Get-BoFinding $r 'AUT-STARTUP-001' | Should -Not -BeNullOrEmpty
    }
}

Describe 'persistence module' {
    BeforeAll { $script:Per = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('persistence') }

    It 'flags WMI command consumers and treats the default SCM consumer as inventory only' {
        $f = Get-BoFinding $script:Per 'PER-WMI-001'
        $f.severity | Should -Be 'high'
        $t = Get-BoEvidenceText $f
        $t | Should -Match 'WindowsUpdater'
        $t | Should -Not -Match 'SCM Event Log Consumer'
        Get-BoEvidenceText (Get-BoFinding $script:Per 'PER-WMI-002') | Should -Match 'SCM Event Log Consumer'
    }

    It 'flags an IFEO debugger on sethc.exe but not GlobalFlag or the Visual Studio JIT debugger' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Per 'PER-IFEO-001')
        $t | Should -Match 'sethc.exe'
        $t | Should -Not -Match 'notepad.exe'
        $t | Should -Not -Match 'devenv.exe'
    }

    It 'detects a command shell planted over an accessibility binary by hash' {
        $f = Get-BoFinding $script:Per 'PER-ACCESS-001'
        $f.severity | Should -Be 'high'
        $t = Get-BoEvidenceText $f
        $t | Should -Match 'utilman.exe'
        $t | Should -Not -Match 'sethc.exe'
        $t | Should -Not -Match 'osk.exe'
    }

    It 'flags per-user COM registrations to unsigned user-writable DLLs but not OneDrive shell extensions' {
        $t = Get-BoEvidenceText (Get-BoFinding $script:Per 'PER-COM-001')
        $t | Should -Match '2222'
        $t | Should -Not -Match '1111'
    }

    It 'flags PowerShell profile content that downloads and executes, and lists comment-only profiles as nothing' {
        $f = Get-BoFinding $script:Per 'PER-PROFILE-002'
        $f.severity | Should -Be 'high'
        Get-BoEvidenceText $f | Should -Match 'alice'
        $l = Get-BoEvidenceText (Get-BoFinding $script:Per 'PER-PROFILE-001')
        $l | Should -Match 'alice'
        $l | Should -Not -Match 'System32'
    }

    It 'flags BITS jobs with notification commands and lists the benign Windows Update job as low' {
        Get-BoEvidenceText (Get-BoFinding $script:Per 'PER-BITS-001') | Should -Match 'Backdoor'
        (Get-BoFinding $script:Per 'PER-BITS-002').severity | Should -Be 'low'
        Get-BoEvidenceText (Get-BoFinding $script:Per 'PER-BITS-001') | Should -Not -Match 'Windows Update'
    }

    It 'default LSA, NetSh, time-provider, print-monitor, AppInit, boot and screensaver settings are clean' {
        foreach ($id in 'PER-LSA-001', 'PER-NETSH-001', 'PER-TIMEPROV-001', 'PER-PORTMON-001', 'PER-APPINIT-001', 'PER-APPCERT-001', 'PER-BOOT-001', 'PER-SCRSAVE-001', 'PER-CMDAUTORUN-001', 'PER-LOGON-001', 'PER-SILENT-001') {
            Get-BoFinding $script:Per $id | Should -BeNullOrEmpty
        }
    }

    It 'detects tampering with each registry-based mechanism' -ForEach @(
        @{ Id = 'PER-LSA-001'; Path = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'; Values = @{ 'Authentication Packages' = @('msv1_0', 'evilauth'); 'Security Packages' = @('""'); 'Notification Packages' = @('scecli') }; Pattern = 'evilauth' }
        @{ Id = 'PER-APPINIT-001'; Path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Values = @{ AppInit_DLLs = 'C:\Users\Public\hook.dll'; LoadAppInit_DLLs = 1 }; Pattern = 'hook.dll' }
        @{ Id = 'PER-APPCERT-001'; Path = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs'; Values = @{ cert = 'C:\Windows\Temp\c.dll' }; Pattern = 'c.dll' }
        @{ Id = 'PER-BOOT-001'; Path = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager'; Values = @{ BootExecute = @('autocheck autochk *', 'C:\Windows\Temp\boot.exe') }; Pattern = 'boot.exe' }
        @{ Id = 'PER-NETSH-001'; Path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh'; Values = @{ ifmon = 'ifmon.dll'; evil = 'C:\Users\Public\helper.dll' }; Pattern = 'helper.dll' }
        @{ Id = 'PER-TIMEPROV-001'; Path = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'; Values = @{ DllName = 'C:\Windows\Temp\t.dll' }; Pattern = 't.dll' }
        @{ Id = 'PER-PORTMON-001'; Path = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors\Local Port'; Values = @{ Driver = 'C:\Windows\Temp\mon.dll' }; Pattern = 'mon.dll' }
        @{ Id = 'PER-CMDAUTORUN-001'; Path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor'; Values = @{ AutoRun = 'C:\Users\Public\r.bat' }; Pattern = 'r.bat' }
        @{ Id = 'PER-LOGON-001'; Path = 'HKEY_USERS\S-1-5-21-1000-2000-3000-1001\Environment'; Values = @{ UserInitMprLogonScript = 'C:\Users\Public\logon.bat' }; Pattern = 'logon.bat' }
        @{ Id = 'PER-SCRSAVE-001'; Path = 'HKEY_USERS\S-1-5-21-1000-2000-3000-1001\Control Panel\Desktop'; Values = @{ 'SCRNSAVE.EXE' = 'C:\Users\Public\saver.scr' }; Pattern = 'saver.scr' }
        @{ Id = 'PER-SILENT-001'; Path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe'; Values = @{ MonitorProcess = 'C:\Users\Public\m.exe' }; Pattern = 'm.exe' }
    ) {
        $fx = Copy-BoTestFixture
        try {
            Set-BoFixtureRegistryValue -Fixture $fx -Path ('Registry::' + $Path) -Values $Values
            $r = Invoke-BoAuditJson -Fixture $fx -Modules @('persistence')
            Get-BoEvidenceText (Get-BoFinding $r $Id) | Should -Match ([regex]::Escape($Pattern))
        }
        finally { Remove-BoTestFixture $fx }
    }

    It 'a missing WMI repository and BITS service are non-material gaps' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('persistence') -Environment @{ BO_FORCE_MISSING = 'wmi.subscriptions bits.jobs' }
        Test-BoErrorCode $r 'WMI_UNREADABLE' | Should -BeTrue
        Test-BoErrorCode $r 'BITS_UNREADABLE' | Should -BeTrue
        Get-BoFinding $r 'PER-IFEO-001' | Should -Not -BeNullOrEmpty
    }
}
