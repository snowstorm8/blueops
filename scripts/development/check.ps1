#Requires -Version 5.1
<#
.SYNOPSIS
    Run available PowerShell lint and test checks. Development helper only.
.DESCRIPTION
    Missing optional modules are reported as SKIPPED, never as passed.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path (Join-Path $PSScriptRoot '..') '..')
Set-Location $root
$failed = $false

$files = Get-ChildItem -Recurse -Include *.ps1, *.psm1 -File |
    Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }

if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
    foreach ($file in $files) {
        $results = Invoke-ScriptAnalyzer -Path $file.FullName -Settings ./PSScriptAnalyzerSettings.psd1
        if ($results) { $results | Format-Table -AutoSize | Out-String | Write-Output; $failed = $true }
    }
} else {
    Write-Warning 'SKIPPED: PSScriptAnalyzer not installed'
}

$tests = Get-ChildItem -Path tests/windows -Recurse -Filter *.Tests.ps1 -ErrorAction SilentlyContinue
if ($tests) {
    $pester = Get-Module -ListAvailable -Name Pester | Where-Object Version -ge ([version]'5.0')
    if ($pester) {
        $config = New-PesterConfiguration
        $config.Run.Path = 'tests/windows'
        $config.Run.PassThru = $true
        $run = Invoke-Pester -Configuration $config
        if ($run.FailedCount -gt 0) { $failed = $true }
    } else {
        Write-Warning 'SKIPPED: Pester 5 not installed'
    }
}

if ($failed) { Write-Error 'Some checks FAILED.'; exit 1 }
Write-Output 'All executed checks passed.'
