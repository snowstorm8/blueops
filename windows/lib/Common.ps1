# BlueOps Windows common library. Dot-source only: this file has no top-level side effects.
#
# Provides run state, finding/error collection, data providers (the single seam that lets
# the same code run against live CIM/registry/filesystem data or synthetic test fixtures),
# command-line heuristics, and the report writer used by every Windows audit entry point.
#
# Test-only environment hooks (never use in production):
#   BO_FIXTURE_DIR   directory with data/*.json|txt and fs/ replacing live host data; also
#                    bypasses the Windows-only check.
#   BO_FORCE_MISSING space-separated provider names treated as unavailable.
#
# Compatible with Windows PowerShell 5.1 and PowerShell 7. Read-only: nothing here modifies
# the audited host (only the optional --OutputDir run directory is written).

$script:BoVersion = '0.1.0'
$script:BoSchemaVersion = '0.1.0'
$script:BoSeverityRank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }
$script:BoAllModules = @('system', 'users', 'processes', 'network', 'services', 'tasks',
    'autoruns', 'persistence', 'firewall', 'security', 'filesystem')
$script:BoModuleFunctions = @{
    system      = 'Invoke-BoSystemModule'
    users       = 'Invoke-BoUsersModule'
    processes   = 'Invoke-BoProcessesModule'
    network     = 'Invoke-BoNetworkModule'
    services    = 'Invoke-BoServicesModule'
    tasks       = 'Invoke-BoTasksModule'
    autoruns    = 'Invoke-BoAutorunsModule'
    persistence = 'Invoke-BoPersistenceModule'
    firewall    = 'Invoke-BoFirewallModule'
    security    = 'Invoke-BoSecurityModule'
    filesystem  = 'Invoke-BoFilesystemModule'
}
$script:Bo = $null
$script:BoChecks = @{}
$script:BoRegFixture = $null
$script:BoSigCache = @{}
$script:BoProcCache = $null
$script:HKLM = 'Registry::HKEY_LOCAL_MACHINE'
$script:HKU = 'Registry::HKEY_USERS'

# ----------------------------------------------------------------------------- basics

function Test-BoWindows {
    return (($PSVersionTable.PSEdition -eq 'Desktop') -or ($PSVersionTable.Platform -eq 'Win32NT'))
}

function Test-BoFixtureMode {
    return (-not [string]::IsNullOrEmpty($env:BO_FIXTURE_DIR))
}

function Get-BoUtcNow {
    return [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Get-BoProp {
    # StrictMode-safe property read for CIM objects, fixture objects and dictionaries.
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name) -and $null -ne $Object[$Name]) { return $Object[$Name] }
        return $Default
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -ne $p -and $null -ne $p.Value) { return $p.Value }
    return $Default
}

function ConvertTo-BoSafeString {
    # Replace control and non-ASCII characters so reports are valid, encoding-independent text.
    param([AllowNull()]$Text)
    if ($null -eq $Text) { return '' }
    return [regex]::Replace([string]$Text, '[^\x20-\x7E]', '?')
}

function Protect-BoText {
    # Redacts secrets from command lines and registry data before they reach any output.
    param([AllowNull()][string]$Text, [int]$MaxLength = 400)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = ConvertTo-BoSafeString $Text
    $t = [regex]::Replace($t, '(?i)\b(authorization)\s*[:=]\s*(bearer|basic)\s+[^\s"'']+', '$1: $2 <redacted>')
    $t = [regex]::Replace($t, '(?i)(-{1,2}|/)(password|passwd|pwd|pass|secret|token|apikey|api-key|accesskey|clientsecret)([\s=:]+)("[^"]*"|''[^'']*''|\S+)', '$1$2$3<redacted>')
    $t = [regex]::Replace($t, '(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*("[^"]*"|\S+)', '$1=<redacted>')
    $t = [regex]::Replace($t, '(?i)(/user:\S+\s+)(\S+)', '$1<redacted>')
    $t = [regex]::Replace($t, '(?i)(\s-(?:e|ec|enc|encodedcommand)\s+)([A-Za-z0-9+/=]{16,})', {
            param($m) $m.Groups[1].Value + '<base64 ' + $m.Groups[2].Value.Length + ' chars>'
        })
    if ($t.Length -gt $MaxLength) { $t = $t.Substring(0, $MaxLength) + '...' }
    return $t
}

function Get-BoSeverityRank {
    param([string]$Severity)
    return [int]$script:BoSeverityRank[$Severity]
}

# ----------------------------------------------------------------------------- run state

function Initialize-BoRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$Category,
        [int]$RecentDays = 7,
        [string]$FailOn = 'medium',
        [bool]$Quiet = $false,
        [bool]$VerboseOutput = $false
    )
    $elevated = $false
    if (Test-BoFixtureMode) {
        $hostFix = Get-BoFixtureJson 'host'
        $elevated = [bool](Get-BoProp $hostFix 'elevated' $false)
    }
    elseif (Test-BoWindows) {
        try {
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            $elevated = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        catch { Write-Verbose "elevation check failed: $($_.Exception.Message)" }
    }
    $script:BoChecks = @{}
    $script:BoSigCache = @{}
    $script:BoProcCache = $null
    $script:BoRegFixture = $null
    $script:Bo = @{
        Tool       = $Tool
        Category   = $Category
        RunId      = [guid]::NewGuid().ToString()
        Started    = Get-BoUtcNow
        RecentDays = $RecentDays
        FailOn     = $FailOn
        Quiet      = $Quiet
        Verbose    = $VerboseOutput
        Elevated   = $elevated
        Findings   = New-Object System.Collections.ArrayList
        Errors     = New-Object System.Collections.ArrayList
        Log        = New-Object System.Collections.ArrayList
        Module     = ''
        FsPath     = @()
        NoColor    = $false
    }
    Write-BoLog 'INFO' "run start tool=$Tool version=$script:BoVersion elevated=$elevated"
    if (-not $elevated) {
        Add-BoError -Code 'NOT_ELEVATED' -Message 'running without administrator rights; coverage reduced (other users, protected registry keys, exclusions, audit policy)' -Material $false
    }
}

function Write-BoLog {
    param([string]$Level, [string]$Message)
    if ($null -eq $script:Bo) { return }
    $mod = $script:Bo.Module
    if ([string]::IsNullOrEmpty($mod)) { $mod = 'core' }
    $line = '{0} {1} {2} {3}' -f (Get-BoUtcNow), $Level, $mod, (ConvertTo-BoSafeString $Message)
    [void]$script:Bo.Log.Add($line)
    if ($script:Bo.Verbose -and -not $script:Bo.Quiet) { Write-BoErr $line }
}

function Write-BoErr {
    param([string]$Text)
    [Console]::Error.WriteLine($Text)
}

function Write-BoOut {
    param([string]$Text)
    [Console]::Out.WriteLine($Text)
}

function Add-BoError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Message,
        [string]$CheckId = '',
        [bool]$Material = $true
    )
    $e = [ordered]@{ code = $Code; message = (ConvertTo-BoSafeString $Message) }
    if ($CheckId) { $e['check_id'] = $CheckId }
    $e['material'] = $Material
    [void]$script:Bo.Errors.Add($e)
    Write-BoLog 'WARN' "$Code $Message"
}

function Add-BoPermError {
    # Access problems are expected (and not material) when not elevated.
    param([string]$Message, [string]$CheckId = '')
    Add-BoError -Code 'PERM_DENIED' -Message $Message -CheckId $CheckId -Material ([bool]$script:Bo.Elevated)
}

function Add-BoFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Z]{2,6}-[A-Z0-9]+-\d{3,}$')][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('info', 'low', 'medium', 'high', 'critical')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [string]$Description = '',
        [ValidateSet('low', 'medium', 'high')][string]$Confidence = 'medium',
        [object[]]$Evidence = @(),
        [string]$Remediation = '',
        [string[]]$Mitre = @()
    )
    $f = [ordered]@{
        id          = $Id
        title       = ConvertTo-BoSafeString $Title
        severity    = $Severity
        confidence  = $Confidence
        category    = $Category
        description = ConvertTo-BoSafeString $Description
    }
    if ($Evidence.Count -gt 0) { $f['evidence'] = @($Evidence) }
    if ($Remediation) { $f['remediation'] = ConvertTo-BoSafeString $Remediation }
    if ($Mitre.Count -gt 0) { $f['mitre_attack'] = @($Mitre) }
    [void]$script:Bo.Findings.Add($f)
    Write-BoLog 'INFO' "finding $Id $Severity"
}

function ConvertTo-BoEvidence {
    param(
        [Parameter(Mandatory)][ValidateSet('file', 'registry', 'process', 'network', 'command', 'log', 'other')][string]$Type,
        [Parameter(Mandatory)][string]$Ref,
        [string]$Excerpt = ''
    )
    $e = [ordered]@{ type = $Type; ref = (ConvertTo-BoSafeString $Ref) }
    if ($Excerpt) { $e['excerpt'] = Protect-BoText $Excerpt 1000 }
    return $e
}

# Checks aggregate hits per finding ID (one finding per check, evidence per item).
function Register-BoCheck {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [string]$Description = '',
        [string]$Confidence = 'medium',
        [string]$Remediation = '',
        [string[]]$Mitre = @(),
        [int]$Cap = 100
    )
    $script:BoChecks[$Id] = @{
        Id = $Id; Title = $Title; Severity = $Severity; Category = $Category
        Description = $Description; Confidence = $Confidence; Remediation = $Remediation
        Mitre = $Mitre; Cap = $Cap; Hits = (New-Object System.Collections.ArrayList); Total = 0; MaxRank = -1
    }
}

function Add-BoHit {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Ref,
        [string]$Excerpt = '',
        [string]$Severity = ''
    )
    $c = $script:BoChecks[$Id]
    $c.Total++
    # A hit may carry its own severity; the finding takes the highest severity among its hits.
    $hitSeverity = $c.Severity
    if ($Severity) { $hitSeverity = $Severity }
    $rank = Get-BoSeverityRank $hitSeverity
    if ($rank -gt $c.MaxRank) { $c.MaxRank = $rank }
    if ($c.Hits.Count -lt $c.Cap) { [void]$c.Hits.Add((ConvertTo-BoEvidence -Type $Type -Ref $Ref -Excerpt $Excerpt)) }
}

function Publish-BoCheck {
    # Emits one finding for every registered check that has hits, then clears the registry.
    foreach ($id in @($script:BoChecks.Keys | Sort-Object)) {
        $c = $script:BoChecks[$id]
        if ($c.Total -eq 0) { continue }
        $desc = $c.Description
        $sev = $c.Severity
        foreach ($name in $script:BoSeverityRank.Keys) { if ($script:BoSeverityRank[$name] -eq $c.MaxRank) { $sev = $name } }
        if ($c.Total -gt $c.Hits.Count) { $desc = "$desc (showing $($c.Hits.Count) of $($c.Total))" }
        Add-BoFinding -Id $c.Id -Title $c.Title -Severity $sev -Category $c.Category `
            -Description $desc -Confidence $c.Confidence -Evidence @($c.Hits) `
            -Remediation $c.Remediation -Mitre $c.Mitre
    }
    $script:BoChecks = @{}
}

# ----------------------------------------------------------------------------- data providers

function Get-BoFixtureJson {
    param([string]$Name)
    $p = Join-Path (Join-Path $env:BO_FIXTURE_DIR 'data') ($Name + '.json')
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    $raw = [System.IO.File]::ReadAllText($p)
    return ($raw | ConvertFrom-Json)
}

function Get-BoData {
    # The single data seam: live scriptblock on a real host, fixture file under BO_FIXTURE_DIR in tests.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Live,
        [switch]$Text
    )
    if ($env:BO_FORCE_MISSING) {
        $forced = $env:BO_FORCE_MISSING -split '\s+'
        if ($forced -contains $Name) { throw "data source '$Name' unavailable (forced)" }
    }
    if (Test-BoFixtureMode) {
        $ext = '.json'
        if ($Text) { $ext = '.txt' }
        $p = Join-Path (Join-Path $env:BO_FIXTURE_DIR 'data') ($Name + $ext)
        if (-not (Test-Path -LiteralPath $p)) { throw "data source '$Name' unavailable (no fixture)" }
        $raw = [System.IO.File]::ReadAllText($p)
        if ($Text) { return $raw }
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return ($raw | ConvertFrom-Json)
    }
    return (& $Live)
}

function Invoke-BoProvider {
    # Wraps Get-BoData; failures become coverage gaps and Ok=$false instead of exceptions.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Live,
        [Parameter(Mandatory)][string]$ErrorCode,
        [Parameter(Mandatory)][string]$Message,
        [string]$CheckId = '',
        [switch]$Text,
        [switch]$Scalar,
        [switch]$NonMaterial
    )
    try {
        $data = Get-BoData -Name $Name -Live $Live -Text:$Text
        if (-not $Scalar -and -not $Text) { $data = @($data) }
        return [pscustomobject]@{ Ok = $true; Data = $data }
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'denied|UnauthorizedAccess|not have permission|privilege is not held|requires administrator|must be an administrator|elevat') {
            Add-BoPermError -Message "$Message ($msg)" -CheckId $CheckId
        }
        else {
            Add-BoError -Code $ErrorCode -Message "$Message ($msg)" -CheckId $CheckId -Material (-not $NonMaterial)
        }
        return [pscustomobject]@{ Ok = $false; Data = $null }
    }
}

function Get-BoRegKey {
    # Returns $null when the key does not exist, else @{ Path; Values (hashtable); SubKeys (string[]) }.
    # Values keep REG_EXPAND_SZ unexpanded. Throws on access problems.
    param([Parameter(Mandatory)][string]$Path)
    if ($env:BO_FORCE_MISSING -and (($env:BO_FORCE_MISSING -split '\s+') -contains 'registry')) {
        throw "data source 'registry' unavailable (forced)"
    }
    if (Test-BoFixtureMode) {
        if ($null -eq $script:BoRegFixture) {
            $raw = Get-BoFixtureJson 'registry'
            $map = @{}
            if ($null -ne $raw) {
                foreach ($p in $raw.PSObject.Properties) { $map[$p.Name.TrimEnd('\').ToLowerInvariant()] = $p.Value }
            }
            $script:BoRegFixture = $map
        }
        $key = $Path.TrimEnd('\').ToLowerInvariant()
        $subs = New-Object System.Collections.Generic.List[string]
        $prefix = $key + '\'
        $exists = $script:BoRegFixture.ContainsKey($key)
        foreach ($k in $script:BoRegFixture.Keys) {
            if ($k.StartsWith($prefix)) {
                $exists = $true
                $first = $k.Substring($prefix.Length).Split('\')[0]
                if (-not $subs.Contains($first)) { $subs.Add($first) }
            }
        }
        if (-not $exists) { return $null }
        $vals = @{}
        if ($script:BoRegFixture.ContainsKey($key)) {
            $entry = $script:BoRegFixture[$key]
            $v = Get-BoProp $entry 'values' $null
            if ($null -ne $v) { foreach ($p in $v.PSObject.Properties) { $vals[$p.Name] = $p.Value } }
        }
        # Subkey display names come from the original-case fixture paths when available.
        return [pscustomobject]@{ Path = $Path; Values = $vals; SubKeys = @($subs) }
    }
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    }
    catch [System.Management.Automation.ItemNotFoundException] { return $null }
    $vals = @{}
    foreach ($n in $item.GetValueNames()) {
        $label = $n
        if ($label -eq '') { $label = '(default)' }
        $vals[$label] = $item.GetValue($n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    }
    return [pscustomobject]@{ Path = $Path; Values = $vals; SubKeys = @($item.GetSubKeyNames()) }
}

function Get-BoRegValue {
    # Single value helper: returns $Default when the key or value is absent (or unreadable).
    param([string]$Path, [string]$Name, $Default = $null)
    try {
        $k = Get-BoRegKey -Path $Path
    }
    catch {
        Write-BoLog 'DEBUG' "registry read failed for $Path"
        return $Default
    }
    if ($null -eq $k) { return $Default }
    if ($k.Values.ContainsKey($Name)) { return $k.Values[$Name] }
    return $Default
}

function Get-BoRegKeyChecked {
    # Like Get-BoRegKey but records access problems as coverage gaps and returns $null.
    param([string]$Path, [string]$CheckId = '')
    try { return (Get-BoRegKey -Path $Path) }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'denied|UnauthorizedAccess|Requested registry access') { Add-BoPermError -Message "registry key $Path ($msg)" -CheckId $CheckId }
        else { Add-BoError -Code 'REGISTRY_UNAVAILABLE' -Message "registry key $Path ($msg)" -CheckId $CheckId }
        return $null
    }
}

function Get-BoUserHive {
    # Loaded user hives (HKEY_USERS\S-1-5-21-*); read-only, never loads NTUSER.DAT files.
    $res = Invoke-BoProvider -Name 'users.hives' -ErrorCode 'HIVES_UNAVAILABLE' -Message 'cannot enumerate loaded user registry hives' -Live {
        $root = Get-Item -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop
        foreach ($n in $root.GetSubKeyNames()) {
            if ($n -match '^S-1-5-21-[\d-]+$') {
                $name = $n
                try { $name = (New-Object Security.Principal.SecurityIdentifier $n).Translate([Security.Principal.NTAccount]).Value }
                catch { Write-Verbose "cannot translate $n" }
                [pscustomobject]@{ Sid = $n; Name = $name }
            }
        }
    } -NonMaterial
    if (-not $res.Ok) { return @() }
    return @($res.Data)
}

function Resolve-BoFsPath {
    # Maps a Windows path to the real path (identity live; <fixture>/fs/... under test).
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-BoFixtureMode)) { return $Path }
    $rel = ($Path -replace '^[A-Za-z]:', '') -replace '\\', '/'
    return (Join-Path (Join-Path $env:BO_FIXTURE_DIR 'fs') $rel.TrimStart('/'))
}

function Test-BoPath {
    param([Parameter(Mandatory)][string]$Path)
    return (Test-Path -LiteralPath (Resolve-BoFsPath $Path))
}

function Get-BoChildDirectory {
    param([Parameter(Mandatory)][string]$Path)
    $real = Resolve-BoFsPath $Path
    if (-not (Test-Path -LiteralPath $real -PathType Container)) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($d in [System.IO.Directory]::EnumerateDirectories($real)) {
            $out.Add(($Path.TrimEnd('\') + '\' + [System.IO.Path]::GetFileName($d)))
        }
    }
    catch { Add-BoPermError -Message "cannot list directory $Path" }
    return @($out.ToArray())
}

function Get-BoChildFile {
    # Depth-limited file listing. Returns objects with a Windows-style FullPath, never follows reparse points.
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxDepth = 1,
        [string[]]$Extension = @(),
        [int]$Limit = 20000
    )
    $real = Resolve-BoFsPath $Path
    $out = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $real -PathType Container)) { return @() }
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@($real, ($Path.TrimEnd('\')), 0))
    $denied = 0
    while ($stack.Count -gt 0 -and $out.Count -lt $Limit) {
        $cur = $stack.Pop()
        $dirReal = $cur[0]; $dirVirt = $cur[1]; $depth = $cur[2]
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($dirReal)) {
                $name = [System.IO.Path]::GetFileName($f)
                $ext = [System.IO.Path]::GetExtension($name).ToLowerInvariant()
                if ($Extension.Count -gt 0 -and $Extension -notcontains $ext) { continue }
                $fi = New-Object System.IO.FileInfo $f
                $out.Add([pscustomobject]@{
                        FullPath     = $dirVirt + '\' + $name
                        Name         = $name
                        Extension    = $ext
                        Length       = $fi.Length
                        LastWriteUtc = $fi.LastWriteTimeUtc
                    })
                if ($out.Count -ge $Limit) { break }
            }
            if ($depth -lt $MaxDepth) {
                foreach ($d in [System.IO.Directory]::EnumerateDirectories($dirReal)) {
                    $di = New-Object System.IO.DirectoryInfo $d
                    if (($di.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    $stack.Push(@($d, ($dirVirt + '\' + $di.Name), ($depth + 1)))
                }
            }
        }
        catch { $denied++ }
    }
    if ($denied -gt 0) { Add-BoPermError -Message "$denied director(ies) under $Path could not be read" }
    return @($out.ToArray())
}

function Get-BoSignature {
    # Authenticode status for a path: Valid, NotSigned, Invalid, Missing or Unknown. Cached per run.
    param([Parameter(Mandatory)][string]$Path)
    $key = $Path.ToLowerInvariant()
    if ($script:BoSigCache.ContainsKey($key)) { return $script:BoSigCache[$key] }
    $r = [pscustomobject]@{ Status = 'Unknown'; Signer = '' }
    if (Test-BoFixtureMode) {
        $map = Get-BoFixtureJson 'signatures'
        if ($null -ne $map) {
            $entry = $null
            foreach ($p in $map.PSObject.Properties) { if ($p.Name.ToLowerInvariant() -eq $key) { $entry = $p.Value } }
            if ($null -ne $entry) {
                $r = [pscustomobject]@{ Status = [string](Get-BoProp $entry 'status' 'Unknown'); Signer = [string](Get-BoProp $entry 'signer' '') }
            }
        }
    }
    elseif (Test-Path -LiteralPath $Path -PathType Leaf) {
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $status = 'Invalid'
            if ($s.Status -eq 'Valid') { $status = 'Valid' }
            elseif ($s.Status -eq 'NotSigned') { $status = 'NotSigned' }
            $signer = ''
            if ($null -ne $s.SignerCertificate) { $signer = [string]$s.SignerCertificate.Subject }
            $r = [pscustomobject]@{ Status = $status; Signer = $signer }
        }
        catch { Write-BoLog 'DEBUG' "signature check failed for $Path" }
    }
    elseif (-not (Test-Path -LiteralPath $Path)) {
        $r = [pscustomobject]@{ Status = 'Missing'; Signer = '' }
    }
    $script:BoSigCache[$key] = $r
    return $r
}

function Get-BoFileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-BoFixtureMode) {
        $map = Get-BoFixtureJson 'hashes'
        if ($null -ne $map) {
            foreach ($p in $map.PSObject.Properties) { if ($p.Name.ToLowerInvariant() -eq $Path.ToLowerInvariant()) { return [string]$p.Value } }
        }
        return ''
    }
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    catch { return '' }
}

function Get-BoBroadWriter {
    # Names of broad groups (Everyone, Users, Authenticated Users) with write access to a directory.
    param([Parameter(Mandatory)][string]$Path)
    if (Test-BoFixtureMode) {
        $map = Get-BoFixtureJson 'acl'
        if ($null -ne $map) {
            foreach ($p in $map.PSObject.Properties) { if ($p.Name.ToLowerInvariant() -eq $Path.ToLowerInvariant()) { return @($p.Value) } }
        }
        return @()
    }
    $out = New-Object System.Collections.Generic.List[string]
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
        $writeMask = [int](([System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, CreateFiles, Delete, ChangePermissions, TakeOwnership'))
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if (([int]$ace.FileSystemRights -band $writeMask) -eq 0) { continue }
            $sid = ''
            try { $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $sid = '' }
            if ($broad -contains $sid) { $out.Add([string]$ace.IdentityReference.Value) }
        }
    }
    catch { Write-BoLog 'DEBUG' "ACL read failed for $Path" }
    return @($out.ToArray())
}

# ----------------------------------------------------------------------------- path & command heuristics

function Expand-BoEnvPath {
    # Deterministic expansion of the system-wide variables; per-user ones are left in place.
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $root = 'C:\Windows'
    $pf = 'C:\Program Files'
    $pf86 = 'C:\Program Files (x86)'
    $pd = 'C:\ProgramData'
    if (-not (Test-BoFixtureMode) -and $env:SystemRoot) {
        $root = $env:SystemRoot; $pf = $env:ProgramFiles; $pd = $env:ProgramData
        if (${env:ProgramFiles(x86)}) { $pf86 = ${env:ProgramFiles(x86)} }
    }
    $t = $Text
    $t = [regex]::Replace($t, '(?i)%(systemroot|windir)%', $root.Replace('$', '$$'))
    $t = [regex]::Replace($t, '(?i)%programfiles%', $pf.Replace('$', '$$'))
    $t = [regex]::Replace($t, '(?i)%programfiles\(x86\)%', $pf86.Replace('$', '$$'))
    $t = [regex]::Replace($t, '(?i)%programdata%', $pd.Replace('$', '$$'))
    $t = [regex]::Replace($t, '(?i)%systemdrive%', 'C:')
    $t = [regex]::Replace($t, '(?i)^\\\?\?\\', '')
    $t = [regex]::Replace($t, '(?i)^\\SystemRoot', $root.Replace('$', '$$'))
    return $t
}

function Get-BoExecutablePath {
    # Extracts the program path from a command line / service ImagePath.
    param([AllowNull()][string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return '' }
    $c = (Expand-BoEnvPath $Command).Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
        return $c.Trim('"')
    }
    $m = [regex]::Match($c, '(?i)^(.*?\.(exe|dll|sys|bat|cmd|com|scr|vbs|js|ps1|msi|cpl|hta))(\s|$|,)')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

function Get-BoPathZone {
    # Classifies where a binary lives: system, programfiles, temp (high-risk writable),
    # programdata, appdata, appdata-known (well-known per-user vendor dirs) or other.
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return 'other' }
    $p = (Expand-BoEnvPath $Path).ToLowerInvariant().Replace('/', '\')
    if ($p -match '\\(windows\\temp|windows\\tasks|windows\\debug|windows\\tracing|perflogs|users\\public|\$recycle\.bin|recycler)\\') { return 'temp' }
    if ($p -match '%(temp|tmp|public)%') { return 'temp' }
    if ($p -match '\\(temp|tmp|downloads)\\') { return 'temp' }
    if ($p -match '^c:\\windows\\') { return 'system' }
    if ($p -match '^c:\\program files( \(x86\))?\\') { return 'programfiles' }
    if ($p -match '\\appdata\\(local|roaming)\\|%(appdata|localappdata|userprofile)%') {
        $known = @(
            '\appdata\local\microsoft\onedrive\', '\appdata\local\programs\', '\appdata\local\microsoft\teams\',
            '\appdata\local\microsoft\windowsapps\', '\appdata\local\google\chrome\', '\appdata\local\google\update\',
            '\appdata\local\microsoft\edge\', '\appdata\local\microsoftedge\', '\appdata\local\discord\',
            '\appdata\local\slack\', '\appdata\local\zoom\', '\appdata\roaming\zoom\', '\appdata\local\githubdesktop\',
            '\appdata\local\microsoft\edgeupdate\', '\appdata\local\microsoft\windows\'
        )
        foreach ($k in $known) { if ($p.Contains($k)) { return 'appdata-known' } }
        if ($p -match '%(localappdata)%\\(microsoft\\onedrive|programs|microsoft\\teams|google|slack|discord)\\') { return 'appdata-known' }
        return 'appdata'
    }
    if ($p -match '^c:\\programdata\\') {
        if ($p -match '^c:\\programdata\\(microsoft|package cache)\\') { return 'programdata-known' }
        return 'programdata'
    }
    if ($p -match '%programdata%') { return 'programdata' }
    return 'other'
}

function Get-BoTargetRisk {
    # Combines location and signature into a severity ('' = not suspicious). Used for autoruns,
    # services, tasks, processes and similar "what does this run?" questions.
    param([AllowNull()][string]$Path)
    $exe = Get-BoExecutablePath $Path
    if ([string]::IsNullOrEmpty($exe)) { return [pscustomobject]@{ Severity = ''; Zone = 'other'; Status = 'Unknown'; Path = '' } }
    $zone = Get-BoPathZone $exe
    $sig = $null
    $status = 'Unknown'
    if (@('temp', 'appdata', 'programdata') -contains $zone) {
        $sig = Get-BoSignature -Path $exe
        $status = $sig.Status
    }
    $sev = ''
    switch ($zone) {
        'temp' {
            if ($status -eq 'Valid' -or $status -eq 'Missing') { $sev = '' }
            elseif ($status -eq 'Unknown') { $sev = 'medium' }
            else { $sev = 'high' }
        }
        'appdata' {
            if ($status -eq 'NotSigned' -or $status -eq 'Invalid') { $sev = 'medium' }
            elseif ($status -eq 'Unknown') { $sev = 'low' }
        }
        'programdata' {
            if ($status -eq 'NotSigned' -or $status -eq 'Invalid') { $sev = 'medium' }
            elseif ($status -eq 'Unknown') { $sev = 'low' }
        }
        default { $sev = '' }
    }
    return [pscustomobject]@{ Severity = $sev; Zone = $zone; Status = $status; Path = $exe }
}

function Get-BoCommandReason {
    # Pattern-based reasons a command line is suspicious. Strong = typical attacker tradecraft with
    # little legitimate use; Weak = common with benign uses (informational context only).
    param([AllowNull()][string]$Command)
    $strong = New-Object System.Collections.Generic.List[string]
    $weak = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($Command)) {
        $c = $Command
        $isPs = ($c -match '(?i)\b(powershell|pwsh)(\.exe)?\b')
        if ($isPs -and $c -match '(?i)\s-(e|ec|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+[A-Za-z0-9+/=]{16,}') { $strong.Add('encoded PowerShell command') }
        if ($c -match '(?i)\b(iex|invoke-expression)\b') { $strong.Add('Invoke-Expression') }
        if ($c -match '(?i)(downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|invoke-restmethod|start-bitstransfer|\biwr\b|\birm\b)') {
            if ($c -match '(?i)(\|\s*iex|\biex\b|invoke-expression|-enc|;\s*start|\.exe)') { $strong.Add('download-and-execute') }
            else { $weak.Add('web download from PowerShell') }
        }
        if ($c -match '(?i)\bmshta(\.exe)?\b.*(https?:|vbscript:|javascript:)') { $strong.Add('mshta remote/script content') }
        if ($c -match '(?i)\bregsvr32(\.exe)?\b.*(scrobj\.dll|/i:https?)') { $strong.Add('regsvr32 scriptlet execution') }
        if ($c -match '(?i)\brundll32(\.exe)?\b.*(javascript:|comsvcs\.dll.*minidump|url\.dll.*fileprotocolhandler.*https?)') { $strong.Add('rundll32 abuse') }
        if ($c -match '(?i)\bcertutil(\.exe)?\b.*-urlcache.*https?:') { $strong.Add('certutil download') }
        if ($c -match '(?i)\bbitsadmin(\.exe)?\b.*/transfer') { $strong.Add('bitsadmin transfer') }
        if ($c -match '(?i)\b(wscript|cscript)(\.exe)?\b.*\\(temp|appdata|users\\public|programdata)\\') { $strong.Add('script host running from a user-writable path') }
        if ($c -match '(?i)\bwmic(\.exe)?\b.*process\s+call\s+create') { $strong.Add('wmic process creation') }
        if ($c -match '(?i)\bnet1?(\.exe)?\s+user\s+\S+\s+\S+\s+/add') { $strong.Add('local user creation') }
        if ($c -match '(?i)\bnet1?(\.exe)?\s+localgroup\s+(administrators|remote desktop users)\s+\S+\s+/add') { $strong.Add('local group membership change') }
        if ($c -match '(?i)\bvssadmin(\.exe)?\b.*delete\s+shadows') { $strong.Add('shadow copy deletion') }
        if ($c -match '(?i)\bwevtutil(\.exe)?\b.*\scl\s') { $strong.Add('event log clearing') }
        if ($c -match '(?i)\bnetsh(\.exe)?\b.*(advfirewall.*state\s+off|firewall.*opmode.*disable)') { $strong.Add('firewall disabled via netsh') }
        if ($c -match '(?i)(mimikatz|sekurlsa|procdump.*lsass|lsass.*\.dmp)') { $strong.Add('credential access tooling') }
        if ($c -match '(?i)(\bnc(at)?(\.exe)?\s.*\s-e\s|TCPClient|System\.Net\.Sockets\.TCPClient)') { $strong.Add('reverse shell indicator') }
        if ($isPs -and $c -match '(?i)-w(indowstyle)?\s+hidden') { $weak.Add('hidden window') }
        if ($isPs -and $c -match '(?i)-ex(ec(utionpolicy)?)?\s+bypass') { $weak.Add('execution policy bypass') }
        if ($c -match '(?i)\bcmd(\.exe)?\s+/c\b.*\b(powershell|mshta|certutil|bitsadmin)\b') { $weak.Add('cmd launching a script/LOLBin') }
    }
    return [pscustomobject]@{ Strong = @($strong | Select-Object -Unique); Weak = @($weak | Select-Object -Unique) }
}

function Get-BoProcessTable {
    # pid -> process object (cached per run). Returns an empty table when CIM is unavailable.
    if ($null -ne $script:BoProcCache) { return $script:BoProcCache }
    $t = @{}
    $res = Invoke-BoProvider -Name 'cim.Win32_Process' -ErrorCode 'PROCESS_UNREADABLE' -Message 'cannot enumerate processes via CIM' -NonMaterial -Live {
        Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
    }
    if ($res.Ok) { foreach ($p in $res.Data) { $t[[int](Get-BoProp $p 'ProcessId' 0)] = $p } }
    $script:BoProcCache = $t
    return $t
}

function Test-BoPrivateAddress {
    param([AllowNull()][string]$Address)
    if ([string]::IsNullOrEmpty($Address)) { return $true }
    $a = $Address.ToLowerInvariant().Trim('[', ']')
    if ($a -match '^(0\.0\.0\.0|::|::1|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|fe80:|fc|fd|ff0)') { return $true }
    if ($a -match '^::ffff:(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)') { return $true }
    return $false
}

function Test-BoLoopbackAddress {
    param([AllowNull()][string]$Address)
    if ([string]::IsNullOrEmpty($Address)) { return $false }
    $a = $Address.Trim('[', ']')
    return ($a -match '^(127\.|::1$|::ffff:127\.)')
}

# ----------------------------------------------------------------------------- host info

function Get-BoHostInfo {
    $hostname = 'unknown'; $osName = 'Windows'; $osVer = 'unknown'; $arch = 'unknown'; $user = ''
    if (Test-BoFixtureMode) {
        $h = Get-BoFixtureJson 'host'
        $hostname = [string](Get-BoProp $h 'hostname' 'fixture-host')
        $osName = [string](Get-BoProp $h 'os_name' 'Windows')
        $osVer = [string](Get-BoProp $h 'os_version' 'unknown')
        $arch = [string](Get-BoProp $h 'arch' 'AMD64')
        $user = [string](Get-BoProp $h 'user' '')
    }
    else {
        try { $hostname = [Environment]::MachineName } catch { Write-Verbose 'hostname unavailable' }
        try { $user = [Environment]::UserDomainName + '\' + [Environment]::UserName } catch { Write-Verbose 'user unavailable' }
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $osName = [string]$os.Caption
            $osVer = [string]$os.Version + ' build ' + [string]$os.BuildNumber
            $arch = [string]$os.OSArchitecture
        }
        catch { Write-BoLog 'WARN' 'Win32_OperatingSystem unavailable for host info' }
    }
    $h = [ordered]@{
        hostname = $hostname
        os       = [ordered]@{ family = 'windows'; name = (ConvertTo-BoSafeString $osName); version = (ConvertTo-BoSafeString $osVer) }
        arch     = (ConvertTo-BoSafeString $arch)
    }
    if ($user) { $h['user'] = ConvertTo-BoSafeString $user }
    $h['elevated'] = [bool]$script:Bo.Elevated
    return $h
}

# ----------------------------------------------------------------------------- report

function Get-BoExitCode {
    $thr = Get-BoSeverityRank $script:Bo.FailOn
    $hit = $false
    foreach ($f in $script:Bo.Findings) { if ((Get-BoSeverityRank $f['severity']) -ge $thr) { $hit = $true } }
    if ($hit) { return 4 }
    foreach ($e in $script:Bo.Errors) { if ($e['material']) { return 6 } }
    return 0
}

function ConvertTo-BoReportObject {
    param([int]$ExitCode)
    $by = [ordered]@{ info = 0; low = 0; medium = 0; high = 0; critical = 0 }
    foreach ($f in $script:Bo.Findings) { $by[[string]$f['severity']]++ }
    $errs = @()
    foreach ($e in $script:Bo.Errors) {
        $o = [ordered]@{ code = $e['code']; message = $e['message'] }
        if ($e.Contains('check_id')) { $o['check_id'] = $e['check_id'] }
        $errs += , $o
    }
    $report = [ordered]@{
        schema_version = $script:BoSchemaVersion
        tool           = [ordered]@{ name = $script:Bo.Tool; version = $script:BoVersion; category = $script:Bo.Category }
        run            = [ordered]@{
            id = $script:Bo.RunId; started_at = $script:Bo.Started; finished_at = (Get-BoUtcNow)
            mode = 'read-only'; dry_run = $false; exit_code = $ExitCode
        }
        host           = (Get-BoHostInfo)
        findings       = @($script:Bo.Findings)
        errors         = @($errs)
        summary        = [ordered]@{ total = $script:Bo.Findings.Count; by_severity = $by }
    }
    return $report
}

function ConvertTo-BoJsonText {
    param($Report)
    $json = ConvertTo-Json -InputObject $Report -Depth 10
    return $json
}

function ConvertTo-BoTextReport {
    param($Report, [int]$ExitCode, [string[]]$Modules)
    $sb = New-Object System.Text.StringBuilder
    $h = $Report['host']
    [void]$sb.AppendLine("BlueOps $($script:Bo.Tool) $script:BoVersion (read-only) - authorized systems only")
    [void]$sb.AppendLine("Host: $($h['hostname'])  OS: $($h['os']['name']) $($h['os']['version'])  Arch: $($h['arch'])")
    $who = ''
    if ($h.Contains('user')) { $who = $h['user'] }
    [void]$sb.AppendLine("User: $who  Elevated: $($h['elevated'])  Modules: $($Modules -join ',')")
    [void]$sb.AppendLine("Started: $($script:Bo.Started)")
    [void]$sb.AppendLine('')
    $s = $Report['summary']['by_severity']
    [void]$sb.AppendLine("Findings: $($Report['summary']['total'])  (critical $($s['critical']), high $($s['high']), medium $($s['medium']), low $($s['low']), info $($s['info']))")
    [void]$sb.AppendLine('')
    $sorted = @($script:Bo.Findings | Sort-Object -Property @{ Expression = { Get-BoSeverityRank $_['severity'] }; Descending = $true }, @{ Expression = { $_['id'] } })
    foreach ($f in $sorted) {
        $sev = ([string]$f['severity']).ToUpperInvariant()
        [void]$sb.AppendLine("[$sev] $($f['id']) $($f['title'])")
        if ($f['description']) { [void]$sb.AppendLine("    $($f['description'])") }
        if ($f.Contains('evidence')) {
            $limit = 5
            if ($f['severity'] -eq 'info') { $limit = 3 }
            $n = 0
            foreach ($e in $f['evidence']) {
                if ($n -ge $limit) { [void]$sb.AppendLine("    ... $(@($f['evidence']).Count - $limit) more in JSON output"); break }
                $x = ''
                if ($e.Contains('excerpt')) { $x = ' :: ' + $e['excerpt'] }
                [void]$sb.AppendLine("    - $($e['ref'])$x")
                $n++
            }
        }
    }
    if ($script:Bo.Errors.Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Coverage gaps:')
        foreach ($e in $script:Bo.Errors) {
            $mat = ''
            if ($e['material']) { $mat = ' (material)' }
            [void]$sb.AppendLine("  - $($e['code'])$mat $($e['message'])")
        }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("Exit code: $ExitCode")
    return $sb.ToString()
}

function Write-BoRunDirectory {
    param([string]$OutputDir, [string]$JsonText, [string]$TextReport)
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $dir = Join-Path $OutputDir ("blueops-run-$stamp-" + $script:Bo.Tool)
    [void][System.IO.Directory]::CreateDirectory($dir)
    if (Test-BoWindows) {
        try {
            $acl = Get-Acl -LiteralPath $dir
            $acl.SetAccessRuleProtection($true, $false)
            $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $dir -AclObject $acl
        }
        catch { Add-BoError -Code 'OUTPUT_ACL' -Message "could not restrict permissions on $dir" -Material $false }
    }
    else {
        try { [System.IO.File]::SetUnixFileMode($dir, 'UserRead, UserWrite, UserExecute') }
        catch { Write-Verbose 'SetUnixFileMode unavailable' }
    }
    $enc = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText((Join-Path $dir 'report.json'), $JsonText, $enc)
    [System.IO.File]::WriteAllText((Join-Path $dir 'report.txt'), $TextReport, $enc)
    [System.IO.File]::WriteAllText((Join-Path $dir 'run.log'), (($script:Bo.Log -join "`n") + "`n"), $enc)
    return $dir
}

# ----------------------------------------------------------------------------- CLI driver

function Get-BoUsageText {
    param([string]$Tool, [string[]]$Modules)
    return @"
Usage: $Tool [-Modules LIST] [-Json] [-Format text|json] [-OutputDir DIR] [-FailOn SEV]
             [-RecentDays N] [-FsPath DIR] [-Quiet] [-Verbose] [-NoColor] [-ListModules] [-Version] [-Help]

READ-ONLY host audit for Windows. Use only on systems you are authorized to administer.
Nothing on the host is modified; the only writes are to -OutputDir (restricted run directory).

  -Modules LIST   comma-separated subset of: $($Modules -join ', ') (default: all)
  -Json           JSON report on stdout (human text goes to stderr); same as -Format json
  -OutputDir DIR  create DIR\blueops-run-<UTC>-$Tool\ with report.json, report.txt, run.log
  -FailOn SEV     lowest severity that yields exit 4 (info|low|medium|high|critical; default medium)
  -RecentDays N   window for 'recently modified' checks (default 7)
  -FsPath DIR     restrict the filesystem module's executable scan to DIR (repeatable)
  -Quiet          suppress human output
  -Verbose        log progress to stderr
  -ListModules    print module names and exit
  -Version        print version and exit

Exit codes: 0 ok, 2 usage, 3 not Windows/precondition, 4 findings at/above -FailOn,
            6 material coverage gap. Run as Administrator for full coverage.
"@
}

function Invoke-BoCli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string[]]$AllowedModules,
        [string[]]$Modules = @(),
        [string]$Format = 'text',
        [bool]$Json = $false,
        [string]$OutputDir = '',
        [string]$FailOn = 'medium',
        [string]$RecentDays = '7',
        [string[]]$FsPath = @(),
        [bool]$Quiet = $false,
        [bool]$VerboseOutput = $false,
        [bool]$NoColor = $false,
        [bool]$ListModules = $false,
        [bool]$ShowVersion = $false,
        [bool]$ShowHelp = $false,
        [string[]]$Unknown = @()
    )
    if ($Unknown.Count -gt 0) {
        Write-BoErr "$Tool`: unknown argument(s): $($Unknown -join ' ')"
        Write-BoErr (Get-BoUsageText -Tool $Tool -Modules $AllowedModules)
        return 2
    }
    if ($ShowHelp) { Write-BoOut (Get-BoUsageText -Tool $Tool -Modules $AllowedModules); return 0 }
    if ($ShowVersion) { Write-BoOut "$Tool $script:BoVersion"; return 0 }
    if ($ListModules) { foreach ($m in $AllowedModules) { Write-BoOut $m }; return 0 }
    if (@('text', 'json') -notcontains $Format.ToLowerInvariant()) { Write-BoErr "$Tool`: invalid -Format '$Format' (text|json)"; return 2 }
    if (-not $script:BoSeverityRank.ContainsKey($FailOn.ToLowerInvariant())) { Write-BoErr "$Tool`: invalid -FailOn '$FailOn'"; return 2 }
    $days = 0
    if (-not [int]::TryParse($RecentDays, [ref]$days) -or $days -lt 1 -or $days -gt 3650) { Write-BoErr "$Tool`: invalid -RecentDays '$RecentDays' (1-3650)"; return 2 }
    $selected = New-Object System.Collections.Generic.List[string]
    if ($Modules.Count -eq 0) { foreach ($m in $AllowedModules) { $selected.Add($m) } }
    else {
        foreach ($raw in $Modules) {
            foreach ($m in ($raw -split '[,\s]+')) {
                if ([string]::IsNullOrWhiteSpace($m)) { continue }
                $m = $m.ToLowerInvariant()
                if ($AllowedModules -notcontains $m) { Write-BoErr "$Tool`: unknown module '$m' (valid: $($AllowedModules -join ', '))"; return 2 }
                if (-not $selected.Contains($m)) { $selected.Add($m) }
            }
        }
    }
    if ($selected.Count -eq 0) { Write-BoErr "$Tool`: no modules selected"; return 2 }
    if (-not (Test-BoWindows) -and -not (Test-BoFixtureMode)) {
        Write-BoErr "$Tool`: Windows only (this host is not Windows). Nothing was inspected."
        return 3
    }
    $wantJson = ($Json -or $Format.ToLowerInvariant() -eq 'json')
    Initialize-BoRun -Tool $Tool -Category $Category -RecentDays $days -FailOn $FailOn.ToLowerInvariant() -Quiet $Quiet -VerboseOutput $VerboseOutput
    $script:Bo.FsPath = @($FsPath | Where-Object { $_ })
    $script:Bo.NoColor = $NoColor
    foreach ($m in $selected) {
        $fn = $script:BoModuleFunctions[$m]
        $script:Bo.Module = $m
        Write-BoLog 'INFO' "module start $m"
        if (-not (Get-Command -Name $fn -CommandType Function -ErrorAction SilentlyContinue)) {
            Add-BoError -Code 'MODULE_MISSING' -Message "module '$m' is not loaded" -Material $true
            continue
        }
        try { & $fn }
        catch { Add-BoError -Code 'MODULE_FAILED' -Message "module '$m' crashed: $($_.Exception.Message)" -Material $true }
        $script:BoChecks = @{}
    }
    $script:Bo.Module = ''
    $exit = Get-BoExitCode
    $report = ConvertTo-BoReportObject -ExitCode $exit
    $jsonText = ConvertTo-BoJsonText -Report $report
    $textReport = ConvertTo-BoTextReport -Report $report -ExitCode $exit -Modules @($selected)
    if ($OutputDir) {
        try {
            $dir = Write-BoRunDirectory -OutputDir $OutputDir -JsonText $jsonText -TextReport $textReport
            if (-not $Quiet) { Write-BoErr "Report written to $dir" }
        }
        catch { Write-BoErr "$Tool`: cannot write to -OutputDir: $($_.Exception.Message)"; return 1 }
    }
    elseif ($wantJson) { Write-BoOut $jsonText }
    if (-not $Quiet) {
        if ($wantJson) { Write-BoErr $textReport }
        elseif (-not $OutputDir) { Write-BoOut $textReport }
        else { Write-BoOut $textReport }
    }
    return $exit
}
