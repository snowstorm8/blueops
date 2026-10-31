# Windows hardening added after the engineering audit: test-hook gating, collision-safe run
# directories, run manifests, injective text escaping, System32 tool resolution and redaction of
# URL credentials. Synthetic fixtures only; the one test that audits the real host is read-only.

BeforeDiscovery {
    $script:OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($PSVersionTable.Platform -eq 'Win32NT')
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    . (Join-Path $script:RepoRoot 'windows\lib\Common.ps1')
    $script:Fx = Copy-BoTestFixture
}

AfterAll {
    Remove-BoTestFixture $script:Fx
}

Describe 'ConvertTo-BoSafeString' {
    It 'keeps different non-ASCII names different' {
        $a = ConvertTo-BoSafeString ('caf' + [char]0x00E9)
        $b = ConvertTo-BoSafeString ('caf' + [char]0x00FC)
        $a | Should -Not -Be $b
        $a | Should -Be 'caf\u00e9'
    }

    It 'does not let literal escape text collide with a real character' {
        ConvertTo-BoSafeString ('caf' + [char]0x00E9) | Should -Not -Be (ConvertTo-BoSafeString 'caf\u00e9')
    }

    It 'escapes control characters and leaves printable ASCII and paths untouched' {
        ConvertTo-BoSafeString "a`tb`nc" | Should -Be 'a\u0009b\u000ac'
        ConvertTo-BoSafeString 'C:\Program Files\Acme\tool.exe' | Should -Be 'C:\Program Files\Acme\tool.exe'
    }
}

Describe 'Protect-BoText URL and curl credentials' {
    It 'redacts credentials embedded in URLs and passed to curl' -ForEach @(
        @{ Text = 'git clone https://bob:Hunter2Secret@host.test/r.git'; Secret = 'Hunter2Secret' }
        @{ Text = 'curl.exe -u admin:Hunter2Secret http://host.test/x'; Secret = 'Hunter2Secret' }
        @{ Text = 'curl --user admin:Hunter2Secret http://host.test/x'; Secret = 'Hunter2Secret' }
    ) {
        Protect-BoText $Text | Should -Not -Match $Secret
    }

    It 'leaves ordinary URLs alone' {
        Protect-BoText 'curl.exe -s https://example.test/path?a=1' | Should -Be 'curl.exe -s https://example.test/path?a=1'
    }
}

Describe 'test hooks need BO_TEST_MODE' {
    It 'a fixture report says test_mode' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('system')
        $r.Json.host.test_mode | Should -BeTrue
    }

    It 'the hooks are ignored without BO_TEST_MODE, the run records it and audits the real host' -Skip:(-not $script:OnWindows) {
        $r = Invoke-BoTestRun -NoFixture -Arguments @('-Json', '-Quiet', '-Modules', 'system') -Environment @{ BO_FIXTURE_DIR = $script:Fx }
        (Test-BoErrorCode $r 'TEST_HOOKS_IGNORED') | Should -BeTrue
        # 6 when nothing reached the threshold; 4 when the real host has findings. Never 0: a material gap exists.
        $r.ExitCode | Should -BeIn @(4, 6)
        $r.Json.host.PSObject.Properties['test_mode'] | Should -BeNullOrEmpty
    }
}

Describe 'run directory' {
    It 'never reuses or overwrites an earlier run directory' {
        Initialize-BoRun -Tool 'audit-windows' -Category 'audit'
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ('bo-out-' + [guid]::NewGuid().ToString('N'))
        try {
            $dirs = @(1..4 | ForEach-Object { Write-BoRunDirectory -OutputDir $out -JsonText "{`"n`":$_}" -TextReport "t$_" })
            @($dirs | Select-Object -Unique).Count | Should -Be 4
            $i = 0
            foreach ($d in $dirs) {
                $i++
                [System.IO.File]::ReadAllText((Join-Path $d 'report.json')) | Should -Be "{`"n`":$i}"
            }
        }
        finally { Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'writes a manifest whose digests match the files' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ('bo-out-' + [guid]::NewGuid().ToString('N'))
        try {
            $r = Invoke-BoTestRun -Fixture $script:Fx -Arguments @('-OutputDir', $out, '-Modules', 'system', '-Quiet')
            $rd = @(Get-ChildItem -LiteralPath $out -Directory)[0].FullName
            $m = [System.IO.File]::ReadAllText((Join-Path $rd 'manifest.json')) | ConvertFrom-Json
            $m.kind | Should -Be 'run-manifest'
            $m.hash_algorithm | Should -Be 'sha256'
            $m.complete | Should -BeTrue
            @($m.files.path) | Should -Contain 'report.json'
            foreach ($f in @($m.files)) {
                (Get-FileHash -LiteralPath (Join-Path $rd $f.path) -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $f.sha256
            }
            @($m.collector | Where-Object { $_.path -like '*lib/Common.ps1' }).Count | Should -BeGreaterThan 0
            $report = [System.IO.File]::ReadAllText((Join-Path $rd 'report.json')) | ConvertFrom-Json
            $m.run.id | Should -Be $report.run.id
            $r.ExitCode | Should -BeIn @(0, 4, 6)
        }
        finally { Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Get-BoSystemToolPath' {
    It 'resolves a System32 tool by its full path' -Skip:(-not $script:OnWindows) {
        Get-BoSystemToolPath 'netstat.exe' | Should -BeLike '*\System32\netstat.exe'
    }

    It 'returns nothing for a name that is not in System32' {
        Get-BoSystemToolPath 'definitely-not-a-windows-tool.exe' | Should -BeNullOrEmpty
    }
}
