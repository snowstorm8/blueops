#Requires -Version 5.1
<#
.SYNOPSIS
    BlueOps READ-ONLY Windows persistence detection.
.DESCRIPTION
    Category: persistence. Safety: read-only. Detects WMI subscriptions, IFEO, AppInit/AppCert, LSA
    packages, COM hijacks, time providers, port monitors, accessibility-binary replacement, PowerShell
    profiles and BITS jobs. Use only on systems you are authorized to administer.
.EXAMPLE
    .\Find-Persistence.ps1 -Json -OutputDir C:\Evidence
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [string]$Format = 'text',
    [string]$OutputDir = '',
    [string]$FailOn = 'medium',
    [string]$RecentDays = '7',
    [switch]$Quiet,
    [switch]$NoColor,
    [switch]$Version,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Unknown = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$libDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'lib'
. (Join-Path $libDir 'Common.ps1')
. (Join-Path $PSScriptRoot 'Get-PersistenceAudit.ps1')

$cli = @{
    Tool           = 'find-persistence'
    Category       = 'persistence'
    AllowedModules = @('persistence')
    Modules        = @()
    Format         = $Format
    Json           = [bool]$Json
    OutputDir      = $OutputDir
    FailOn         = $FailOn
    RecentDays     = $RecentDays
    Quiet          = [bool]$Quiet
    VerboseOutput  = ($VerbosePreference -eq 'Continue')
    NoColor        = [bool]$NoColor
    ListModules    = $false
    ShowVersion    = [bool]$Version
    ShowHelp       = [bool]$Help
    Unknown        = $Unknown
}
exit (Invoke-BoCli @cli)
