# BlueOps Windows telemetry helpers. Dot-source only: no top-level side effects.
#
# Pure functions (no host access) used by windows/telemetry/Invoke-TelemetryCollection.ps1: JSON
# line emission, secret redaction and Windows event parsing. They are separate so that they can be
# unit tested with synthetic input on any PowerShell.
#
# Compatible with Windows PowerShell 5.1 and PowerShell 7. Read-only.

$script:TelVersion = '1.0.0'
$script:TelCount = 0
$script:TelNow = ''
$script:TelCovState = @{}
$script:TelSidCache = @{}
# The default resolver asks Windows to translate a SID to an account name; tests pass their own.
$script:TelDefaultSidResolver = {
    param([string]$Sid)
    try {
        $o = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        return $o.Translate([System.Security.Principal.NTAccount]).Value
    }
    catch { return $null }
}

# Windows event ids mapped to what they mean for the telemetry model.
$script:TelAuthEvents = @{
    '4624' = @{ Action = 'login_success'; Result = 'success' }
    '4625' = @{ Action = 'login_failure'; Result = 'failure' }
    '4648' = @{ Action = 'credential_use'; Result = 'success' }
    '4720' = @{ Action = 'account_change'; Result = 'success'; Change = 'created' }
    '4722' = @{ Action = 'account_change'; Result = 'success'; Change = 'enabled' }
    '4724' = @{ Action = 'account_change'; Result = 'success'; Change = 'password_reset' }
    '4725' = @{ Action = 'account_change'; Result = 'success'; Change = 'disabled' }
    '4726' = @{ Action = 'account_change'; Result = 'success'; Change = 'deleted' }
    '4738' = @{ Action = 'account_change'; Result = 'success'; Change = 'modified' }
    '4740' = @{ Action = 'lockout'; Result = 'failure' }
    '4728' = @{ Action = 'group_change'; Result = 'success'; Change = 'member_added' }
    '4732' = @{ Action = 'group_change'; Result = 'success'; Change = 'member_added' }
    '4756' = @{ Action = 'group_change'; Result = 'success'; Change = 'member_added' }
    '4729' = @{ Action = 'group_change'; Result = 'success'; Change = 'member_removed' }
    '4733' = @{ Action = 'group_change'; Result = 'success'; Change = 'member_removed' }
    '4757' = @{ Action = 'group_change'; Result = 'success'; Change = 'member_removed' }
}
# Logon types worth recording: 2 interactive, 3 network, 7 unlock, 8 network cleartext, 9 new
# credentials, 10 remote interactive, 11 cached interactive. Service (5) and batch (4) logons are
# very frequent and not user activity; they are not recorded (a documented limitation).
$script:TelLogonTypes = @('2', '3', '7', '8', '9', '10', '11')
$script:TelSecurityEventIds = @('1102', '104', '4719', '4697', '7045')

function Get-TelSystemToolPath {
    # Native tools are run from System32 by absolute path: a writable PATH entry must not be able
    # to substitute the program that reports what the host looks like.
    param([Parameter(Mandatory)][string]$Name)
    if ([string]::IsNullOrEmpty($env:SystemRoot)) { return $null }
    $p = Join-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32') -ChildPath $Name
    if (Test-Path -LiteralPath $p -PathType Leaf) { return $p }
    return $null
}

function Test-TelWindows {
    return (($PSVersionTable.PSEdition -eq 'Desktop') -or ($PSVersionTable.Platform -eq 'Win32NT'))
}

function Get-TelProp {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $Default }
    if ($null -eq $p.Value) { return $Default }
    return $p.Value
}

function ConvertTo-TelAsciiJson {
    param([Parameter(Mandatory)][string]$Json)
    # Output encoding differs between Windows PowerShell 5.1 consoles and redirected pipes; plain
    # ASCII (everything else as \uXXXX) is identical everywhere.
    return [regex]::Replace($Json, '[^\x20-\x7E]', { param($m) ('\u{0:x4}' -f [int][char]$m.Value) })
}

function Write-TelLine {
    param([Parameter(Mandatory)]$Object)
    $json = $Object | ConvertTo-Json -Compress -Depth 6
    [Console]::Out.WriteLine((ConvertTo-TelAsciiJson -Json $json))
}

function Limit-TelText {
    param($Text, [int]$Max = 300)
    if ($null -eq $Text) { return '' }
    $s = [string]$Text
    $s = [regex]::Replace($s, '[\x00-\x1F\x7F]', ' ')
    if ($s.Length -gt $Max) { return $s.Substring(0, $Max - 3) + '...' }
    return $s
}

function Hide-TelSecret {
    # Redacts obvious secrets from command lines and registry values. Documented residual risk:
    # secrets in positional arguments of arbitrary programs and in files are not detectable.
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = $Text
    $t = [regex]::Replace($t, '(?i)(\b(?:pass(?:word|wd)?|pwd|secret|token|api[-_]?key)[A-Za-z_]*\s*[=:]\s*)[^\s"'']+', '$1<redacted>')
    $t = [regex]::Replace($t, '(?i)(\s[-/](?:p|pw|pass|password|pwd)\s+)\S+', '$1<redacted>')
    $t = [regex]::Replace($t, '(?i)(://[^/\s:@]+:)[^@\s/]+@', '$1<redacted>@')
    $t = [regex]::Replace($t, '(?i)(\bnet\s+user\s+\S+\s+)\S+', '$1<redacted>')
    return $t
}

function ConvertTo-TelIso {
    param($Time)
    if ($null -eq $Time) { return '' }
    try {
        $utc = ([datetime]$Time).ToUniversalTime()
        return $utc.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    catch { return '' }
}

# ---------------------------------------------------------------------------- stream output

function Write-TelCoverage {
    param([string]$Category, [string]$Status, [string]$Reason = '', [string]$Scope = '')
    $o = [ordered]@{ type = 'coverage'; category = $Category; status = $Status }
    if ($Reason) { $o['reason'] = (Limit-TelText $Reason 500) }
    if ($Scope) { $o['scope'] = $Scope }
    Write-TelLine $o
    $script:TelCovState[$Category] = $Status
}

function Write-TelError {
    param([string]$Code, [string]$Message, [string]$Category = '')
    $o = [ordered]@{ type = 'error'; code = $Code; message = (Limit-TelText $Message 500) }
    if ($Category) { $o['category'] = $Category }
    Write-TelLine $o
    [Console]::Error.WriteLine(('{0} {1}: {2}' -f $script:TelNow, $Code, (Limit-TelText $Message 300)))
}

function Write-TelRecord {
    # Attributes whose value is $null are emitted as null and listed as unknown_attributes: "could
    # not be collected", which is different from an attribute that is simply absent.
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$SourceType,
        [string]$SourceRef = '',
        [string]$Method = 'unspecified',
        [string]$EventTime = '',
        [string]$Scope = '',
        [hashtable]$Attributes = @{}
    )
    $attrs = [ordered]@{}
    $unknown = @()
    foreach ($k in ($Attributes.Keys | Sort-Object)) {
        $v = $Attributes[$k]
        if ($null -eq $v) { $unknown += $k }
        if ($v -is [string]) { $v = Limit-TelText $v 600 }
        $attrs[$k] = $v
    }
    $o = [ordered]@{
        type = 'record'
        category = $Category
        key = (Limit-TelText $Key 500)
        source = [ordered]@{ type = $SourceType; ref = (Limit-TelText $SourceRef 400) }
        method = $Method
        observed_at = $script:TelNow
        attributes = $attrs
        unknown_attributes = @($unknown)
    }
    if ($Scope) { $o['scope'] = $Scope }
    if ($EventTime) { $o['event_time'] = $EventTime }
    Write-TelLine $o
    $script:TelCount = $script:TelCount + 1
}

# ---------------------------------------------------------------------------- event parsing

function Convert-TelEventXml {
    # Parses one event's XML into a flat description; returns $null for unusable input.
    param([Parameter(Mandatory)][string]$Xml)
    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null   # never resolve external entities from log content
        $doc.LoadXml($Xml)
    }
    catch { return $null }
    $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    $sys = $doc.SelectSingleNode('//e:Event/e:System', $ns)
    if ($null -eq $sys) { return $null }
    $idNode = $sys.SelectSingleNode('e:EventID', $ns)
    $timeNode = $sys.SelectSingleNode('e:TimeCreated', $ns)
    $recNode = $sys.SelectSingleNode('e:EventRecordID', $ns)
    $provNode = $sys.SelectSingleNode('e:Provider', $ns)
    $chanNode = $sys.SelectSingleNode('e:Channel', $ns)
    if ($null -eq $idNode) { return $null }
    $data = @{}
    foreach ($d in @($doc.SelectNodes('//e:Event/e:EventData/e:Data', $ns))) {
        $name = $d.GetAttribute('Name')
        if ($name) { $data[$name] = [string]$d.InnerText }
    }
    foreach ($d in @($doc.SelectNodes('//e:Event/e:UserData/*/*', $ns))) {
        if ($d.LocalName) { $data[$d.LocalName] = [string]$d.InnerText }
    }
    $when = ''
    if ($null -ne $timeNode) {
        $st = $timeNode.GetAttribute('SystemTime')
        if ($st) {
            try {
                $when = ConvertTo-TelIso ([datetime]::Parse($st, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal))
            }
            catch { $when = '' }
        }
    }
    $prov = ''
    if ($null -ne $provNode) { $prov = $provNode.GetAttribute('Name') }
    $chan = ''
    if ($null -ne $chanNode) { $chan = [string]$chanNode.InnerText }
    $rec = ''
    if ($null -ne $recNode) { $rec = [string]$recNode.InnerText }
    return [pscustomobject]@{
        Id = ([string]$idNode.InnerText).Trim()
        RecordId = $rec
        Time = $when
        Provider = $prov
        Channel = $chan
        Data = $data
    }
}

function Resolve-TelSid {
    param([string]$Sid, [scriptblock]$Resolver = $null)
    if ([string]::IsNullOrEmpty($Sid) -or $Sid -eq '-') { return $null }
    $useCache = ($null -eq $Resolver)
    if ($useCache -and $script:TelSidCache.ContainsKey($Sid)) { return $script:TelSidCache[$Sid] }
    if ($null -eq $Resolver) { $Resolver = $script:TelDefaultSidResolver }
    $name = $null
    $r = & $Resolver $Sid
    if ($r) {
        $name = [string]$r
        $i = $name.LastIndexOf('\')
        if ($i -ge 0) { $name = $name.Substring($i + 1) }
    }
    if ($useCache) { $script:TelSidCache[$Sid] = $name }
    return $name
}

function Get-TelDataValue {
    param($Data, [string]$Name)
    if ($Data.ContainsKey($Name)) {
        $v = [string]$Data[$Name]
        if ($v -and $v -ne '-') { return $v }
    }
    return $null
}

function ConvertTo-TelRecord {
    # Maps a parsed event to zero or more telemetry records:
    #   @{ Category; Key; Time; Attributes; Source }
    param([Parameter(Mandatory)]$EventInfo, [scriptblock]$SidResolver = $null)
    $id = [string]$EventInfo.Id
    $d = $EventInfo.Data
    $out = @()
    $ref = '{0}#{1}' -f $EventInfo.Channel, $EventInfo.RecordId
    if ($script:TelAuthEvents.ContainsKey($id) -and $EventInfo.Channel -eq 'Security') {
        $m = $script:TelAuthEvents[$id]
        $action = $m.Action
        $change = $null
        if ($m.ContainsKey('Change')) { $change = $m.Change }
        $user = Get-TelDataValue $d 'TargetUserName'
        $actor = Get-TelDataValue $d 'SubjectUserName'
        $src = Get-TelDataValue $d 'IpAddress'
        if ($src -eq '::1' -or $src -eq '127.0.0.1') { $src = $null }
        $logon = Get-TelDataValue $d 'LogonType'
        if ($id -eq '4624' -or $id -eq '4625') {
            if ($script:TelLogonTypes -notcontains [string]$logon) { return @() }
            if ($user -and $user.EndsWith('$')) { return @() }   # machine accounts: noise
        }
        if ($id -eq '4648') { $user = Get-TelDataValue $d 'TargetUserName'; $src = Get-TelDataValue $d 'IpAddress' }
        $group = $null
        if ($action -eq 'group_change') {
            $group = Get-TelDataValue $d 'TargetUserName'
            $member = Get-TelDataValue $d 'MemberName'
            $user = $null
            if ($member -and $member -match 'CN=([^,]+)') { $user = $Matches[1] }
            elseif ($member) { $user = $member }
            if (-not $user) { $user = Resolve-TelSid -Sid (Get-TelDataValue $d 'MemberSid') -Resolver $SidResolver }
        }
        $attrs = @{
            action = $action
            result = $m.Result
            user = $user
            service = 'windows'
            event_id = $id
        }
        if ($src) { $attrs['source_address'] = $src }
        if ($logon) { $attrs['logon_type'] = $logon }
        if ($change) { $attrs['change'] = $change }
        if ($group) { $attrs['group'] = $group }
        if ($actor) { $attrs['actor'] = $actor }
        $ws = Get-TelDataValue $d 'WorkstationName'
        if ($ws) { $attrs['workstation'] = $ws }
        if ($id -eq '4625') {
            $sub = Get-TelDataValue $d 'SubStatus'
            if ($sub) { $attrs['failure_reason'] = $sub }
        }
        # An event without the account it concerns cannot support account-based analysis.
        if (-not $user) { $attrs['user'] = $null }
        $out += @{ Category = 'auth_event'; Key = ('win:{0}:{1}' -f $EventInfo.Channel, $EventInfo.RecordId); Time = $EventInfo.Time; Attributes = $attrs; Source = $ref }
    }
    if ($script:TelSecurityEventIds -contains $id) {
        $outcome = 'success'
        $summary = ''
        $actor2 = Get-TelDataValue $d 'SubjectUserName'
        if ($id -eq '1102' -or $id -eq '104') { $summary = 'event log cleared' }
        elseif ($id -eq '4719') { $summary = 'system audit policy changed' }
        elseif ($id -eq '4697') { $summary = 'service installed: ' + (Get-TelDataValue $d 'ServiceName') }
        elseif ($id -eq '7045') { $summary = 'service installed: ' + (Get-TelDataValue $d 'ServiceName') }
        $sa = @{ event_id = $id; source = $EventInfo.Channel; outcome = $outcome; summary = (Hide-TelSecret $summary) }
        if ($actor2) { $sa['actor'] = $actor2 }
        $out += @{ Category = 'security_event'; Key = ('win:{0}:{1}:{2}' -f $EventInfo.Channel, $EventInfo.RecordId, $id); Time = $EventInfo.Time; Attributes = $sa; Source = $ref }
        $cc = $null
        if ($id -eq '4697' -or $id -eq '7045') {
            $name = Get-TelDataValue $d 'ServiceName'
            $path = Get-TelDataValue $d 'ImagePath'
            if (-not $path) { $path = Get-TelDataValue $d 'ImagePathName' }
            $cc = @{ object = 'service'; change = 'added'; name = $name; path = (Hide-TelSecret $path); actor = $actor2 }
        }
        elseif ($id -eq '4719') {
            $cc = @{ object = 'audit_policy'; change = 'modified'; name = (Get-TelDataValue $d 'SubcategoryGuid'); actor = $actor2 }
        }
        if ($null -ne $cc) {
            $out += @{ Category = 'config_change'; Key = ('win:{0}:{1}:{2}:cc' -f $EventInfo.Channel, $EventInfo.RecordId, $id); Time = $EventInfo.Time; Attributes = $cc; Source = $ref }
        }
    }
    if (($id -eq '4698' -or $id -eq '4699' -or $id -eq '4702') -and $EventInfo.Channel -eq 'Security') {
        $chg = 'added'
        if ($id -eq '4699') { $chg = 'deleted' }
        if ($id -eq '4702') { $chg = 'modified' }
        $cc = @{ object = 'scheduled_task'; change = $chg; name = (Get-TelDataValue $d 'TaskName'); actor = (Get-TelDataValue $d 'SubjectUserName') }
        $out += @{ Category = 'config_change'; Key = ('win:{0}:{1}:{2}:cc' -f $EventInfo.Channel, $EventInfo.RecordId, $id); Time = $EventInfo.Time; Attributes = $cc; Source = $ref }
    }
    return $out
}
