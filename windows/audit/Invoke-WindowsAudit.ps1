#Requires -Version 5.1
<#
.SYNOPSIS
    BlueOps unified READ-ONLY Windows host audit.
.DESCRIPTION
    Category: audit. Safety: read-only; never modifies the host (writes only to -OutputDir).
    Runs system, users, processes, network, services, tasks, autoruns, persistence, firewall,
    security and filesystem modules and emits a human summary and/or a JSON report conforming to
    shared/schemas/audit-report.schema.json. Use only on systems you are authorized to administer.
.EXAMPLE
    .\Invoke-WindowsAudit.ps1 -Json -OutputDir C:\Evidence
.EXAMPLE
    .\Invoke-WindowsAudit.ps1 -Modules users,network -Quiet -Json > report.json
#>
[CmdletBinding()]
param(
    [string[]]$Modules = @(),
    [switch]$Json,
    [string]$Format = 'text',
    [string]$OutputDir = '',
    [string]$FailOn = 'medium',
    [string]$RecentDays = '7',
    [string[]]$FsPath = @(),
    [switch]$Quiet,
    [switch]$NoColor,
    [switch]$ListModules,
    [switch]$Version,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Unknown = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$libDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'lib'
. (Join-Path $libDir 'Common.ps1')
. (Join-Path $PSScriptRoot 'Get-SystemAudit.ps1')
. (Join-Path $PSScriptRoot 'Get-UserAudit.ps1')
. (Join-Path $PSScriptRoot 'Get-ProcessAudit.ps1')
. (Join-Path $PSScriptRoot 'Get-NetworkAudit.ps1')
. (Join-Path $PSScriptRoot 'Get-ServiceAudit.ps1')
. (Join-Path $PSScriptRoot 'Get-ScheduledTaskAudit.ps1')
. (Join-Path $PSScriptRoot 'Get-AutorunAudit.ps1')
. (Join-Path $PSScriptRoot 'Get-FirewallAudit.ps1')
. (Join-Path $PSScriptRoot 'Get-SecurityConfigAudit.ps1')
. (Join-Path $PSScriptRoot 'Get-FilesystemAudit.ps1')
. (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'persistence') 'Get-PersistenceAudit.ps1')

$cli = @{
    Tool           = 'audit-windows'
    Category       = 'audit'
    AllowedModules = $script:BoAllModules
    Modules        = $Modules
    Format         = $Format
    Json           = [bool]$Json
    OutputDir      = $OutputDir
    FailOn         = $FailOn
    RecentDays     = $RecentDays
    FsPath         = $FsPath
    Quiet          = [bool]$Quiet
    VerboseOutput  = ($VerbosePreference -eq 'Continue')
    NoColor        = [bool]$NoColor
    ListModules    = [bool]$ListModules
    ShowVersion    = [bool]$Version
    ShowHelp       = [bool]$Help
    Unknown        = $Unknown
}
exit (Invoke-BoCli @cli)
