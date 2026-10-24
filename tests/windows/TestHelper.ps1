# Shared helpers for the Windows audit Pester tests (dot-sourced from BeforeAll blocks).
# Tests run the real entry points in a child PowerShell process against a synthetic fixture
# (BO_FIXTURE_DIR). On Windows the child is Windows PowerShell 5.1 unless BO_TEST_SHELL=pwsh.

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:FixtureSource = Join-Path $script:RepoRoot 'tests\fixtures\windows-host'
$script:AuditScript = Join-Path $script:RepoRoot 'windows\audit\Invoke-WindowsAudit.ps1'
$script:PersistenceScript = Join-Path $script:RepoRoot 'windows\persistence\Find-Persistence.ps1'

function Get-BoTestShell {
    if ($env:BO_TEST_SHELL) { return $env:BO_TEST_SHELL }
    $onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($PSVersionTable.Platform -eq 'Win32NT')
    if ($onWindows) { return 'powershell.exe' }
    return 'pwsh'
}

function Copy-BoTestFixture {
    # Copies the synthetic host to a temp directory, materializes date tokens, restores *.fixture
    # script names (kept inert in git) and applies the file ages from data/fs-ages.json.
    $dest = Join-Path ([System.IO.Path]::GetTempPath()) ('bo-fixture-' + [guid]::NewGuid().ToString('N'))
    Copy-Item -LiteralPath $script:FixtureSource -Destination $dest -Recurse
    foreach ($f in Get-ChildItem -LiteralPath $dest -Recurse -File -Filter '*.json') {
        $t = [System.IO.File]::ReadAllText($f.FullName)
        $t = [regex]::Replace($t, '@@AGO:(\d+)@@', {
                param($m) [DateTime]::UtcNow.AddDays(-[int]$m.Groups[1].Value).ToString('yyyy-MM-ddTHH:mm:ssZ')
            })
        [System.IO.File]::WriteAllText($f.FullName, $t)
    }
    $fs = Join-Path $dest 'fs'
    foreach ($f in Get-ChildItem -LiteralPath $fs -Recurse -File -Filter '*.fixture') {
        Move-Item -LiteralPath $f.FullName -Destination ($f.FullName -replace '\.fixture$', '')
    }
    foreach ($f in Get-ChildItem -LiteralPath $fs -Recurse -File) { $f.LastWriteTimeUtc = [DateTime]::UtcNow }
    $ages = Join-Path $dest 'data\fs-ages.json'
    if (Test-Path -LiteralPath $ages) {
        foreach ($p in ([System.IO.File]::ReadAllText($ages) | ConvertFrom-Json).PSObject.Properties) {
            (Get-Item -LiteralPath (Join-Path $fs ($p.Name -replace '/', [System.IO.Path]::DirectorySeparatorChar))).LastWriteTimeUtc = [DateTime]::UtcNow.AddDays(-[int]$p.Value)
        }
    }
    return $dest
}

function Remove-BoTestFixture {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test helper that only deletes its own temp fixture copy.')]
    param([string]$Path)
    if ($Path -and $Path -like '*bo-fixture-*' -and (Test-Path -LiteralPath $Path)) { Remove-Item -LiteralPath $Path -Recurse -Force }
}

function Edit-BoFixtureJson {
    # Reads data/<Name>.json, applies the mutator scriptblock to the parsed object (return value is
    # saved when not null) and writes it back.
    param([string]$Fixture, [string]$Name, [scriptblock]$Mutator)
    $p = Join-Path $Fixture "data\$Name.json"
    $obj = [System.IO.File]::ReadAllText($p) | ConvertFrom-Json
    $result = & $Mutator $obj
    if ($null -ne $result) { $obj = $result }
    [System.IO.File]::WriteAllText($p, (ConvertTo-Json -InputObject $obj -Depth 12))
}

function Set-BoFixtureRegistryValue {
    # Sets (or creates) a registry fixture key with the given values (replacing the key's values).
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Edits a temp fixture JSON copy only.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Used inside the mutator scriptblock closure.')]
    param([string]$Fixture, [string]$Path, [hashtable]$Values)
    Edit-BoFixtureJson -Fixture $Fixture -Name 'registry' -Mutator {
        param($reg)
        $entry = [pscustomobject]@{ values = ([pscustomobject]$Values) }
        if ($null -ne $reg.PSObject.Properties[$Path]) { $reg.PSObject.Properties[$Path].Value = $entry }
        else { $reg | Add-Member -NotePropertyName $Path -NotePropertyValue $entry }
    }
}

function Invoke-BoTestRun {
    param(
        [string]$Fixture,
        [string[]]$Arguments = @(),
        [hashtable]$Environment = @{},
        [string]$Script = $script:AuditScript,
        [switch]$NoFixture
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Get-BoTestShell
    $argList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Script) + $Arguments
    $psi.Arguments = (($argList | ForEach-Object { if ($_ -match '[\s"]' -or $_ -eq '') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    foreach ($k in @('BO_FIXTURE_DIR', 'BO_FORCE_MISSING')) { if ($psi.EnvironmentVariables.ContainsKey($k)) { [void]$psi.EnvironmentVariables.Remove($k) } }
    if (-not $NoFixture -and $Fixture) { $psi.EnvironmentVariables['BO_FIXTURE_DIR'] = $Fixture }
    foreach ($k in $Environment.Keys) { $psi.EnvironmentVariables[$k] = [string]$Environment[$k] }
    $p = [System.Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    $out = $outTask.Result
    $json = $null
    if ($out.TrimStart().StartsWith('{')) { $json = $out | ConvertFrom-Json }
    return [pscustomobject]@{ ExitCode = $p.ExitCode; Out = $out; Err = $errTask.Result; Json = $json }
}

function Invoke-BoAuditJson {
    # Runs the unified audit with -Json -Quiet for the given modules and returns the parsed run.
    param([string]$Fixture, [string[]]$Modules, [string[]]$Extra = @(), [hashtable]$Environment = @{}, [string]$Script = $script:AuditScript)
    $a = @('-Json', '-Quiet')
    if ($Modules.Count -gt 0) { $a += @('-Modules', ($Modules -join ',')) }
    return (Invoke-BoTestRun -Fixture $Fixture -Arguments ($a + $Extra) -Environment $Environment -Script $Script)
}

function Get-BoFinding {
    param($Run, [string]$Id)
    foreach ($f in @($Run.Json.findings)) { if ($f.id -eq $Id) { return $f } }
    return $null
}

function Get-BoEvidenceText {
    # All evidence refs and excerpts of a finding as one string for substring assertions.
    param($Finding)
    if ($null -eq $Finding) { return '' }
    $parts = @()
    foreach ($e in @($Finding.evidence)) {
        $parts += [string]$e.ref
        if ($null -ne $e.PSObject.Properties['excerpt']) { $parts += [string]$e.excerpt }
    }
    return ($parts -join "`n")
}

function Test-BoErrorCode {
    param($Run, [string]$Code)
    foreach ($e in @($Run.Json.errors)) { if ($e.code -eq $Code) { return $true } }
    return $false
}

function Get-BoTreeDigest {
    param([string]$Path)
    $sb = New-Object System.Text.StringBuilder
    foreach ($f in (Get-ChildItem -LiteralPath $Path -Recurse -File | Sort-Object -Property FullName)) {
        $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
        [void]$sb.AppendLine("$($f.FullName.Substring($Path.Length)) $h $($f.LastWriteTimeUtc.Ticks)")
    }
    return $sb.ToString()
}
