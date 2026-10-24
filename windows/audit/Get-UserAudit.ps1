# Module: users (category: audit, read-only). Dot-sourced by the audit entry points.
# Local account inventory, privileged group membership and interactive sessions.

function Get-BoLocalGroupMember {
    # Members of a local group identified by well-known SID (locale-independent).
    param([Parameter(Mandatory)][string]$Sid, [Parameter(Mandatory)][string]$DataName, [string]$CheckId)
    $res = Invoke-BoProvider -Name $DataName -ErrorCode 'GROUP_UNREADABLE' -Message "cannot read members of local group $Sid" -CheckId $CheckId -NonMaterial -Live {
        try {
            Get-LocalGroup -SID $Sid -ErrorAction Stop | Get-LocalGroupMember -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = [string]$_.Name; SID = [string]$_.SID.Value; ObjectClass = [string]$_.ObjectClass }
            }
        }
        catch {
            # Get-LocalGroupMember fails on orphaned SIDs in Windows PowerShell 5.1; fall back to ADSI.
            $g = Get-CimInstance -ClassName Win32_Group -Filter "SID='$Sid'" -ErrorAction Stop
            $grp = [ADSI]("WinNT://./" + $g.Name + ",group")
            foreach ($m in @($grp.Invoke('Members'))) {
                $a = [ADSI]$m
                $sidBytes = $a.InvokeGet('objectSid')
                [pscustomobject]@{ Name = [string]$a.Path.Replace('WinNT://', '').Replace('/', '\'); SID = (New-Object Security.Principal.SecurityIdentifier($sidBytes, 0)).Value; ObjectClass = [string]$a.SchemaClassName }
            }
        }
    }
    if (-not $res.Ok) { return $null }
    return @($res.Data)
}

function Invoke-BoUsersModule {
    [CmdletBinding()]
    param()
    $cat = 'accounts'
    Register-BoCheck -Id 'USR-INFO-001' -Title 'Local account inventory' -Severity 'info' -Category $cat -Cap 200
    Register-BoCheck -Id 'USR-ADMIN-001' -Title 'Local Administrators group members' -Severity 'info' -Category $cat -Cap 200 `
        -Description 'Members of the local Administrators group (local and domain principals).'
    Register-BoCheck -Id 'USR-ADMIN-002' -Title 'Enabled non-built-in local account is an administrator' -Severity 'low' -Category $cat `
        -Description 'Review that each of these accounts is expected to have administrator rights.' `
        -Remediation 'Remove unneeded accounts from Administrators; use named, audited admin accounts.' -Mitre @('T1078.003')
    Register-BoCheck -Id 'USR-GUEST-001' -Title 'Guest account is enabled' -Severity 'medium' -Category $cat `
        -Description 'The built-in Guest account allows unauthenticated-style local access.' `
        -Remediation 'Disable the Guest account.' -Mitre @('T1078.001')
    Register-BoCheck -Id 'USR-PWD-001' -Title 'Enabled account does not require a password' -Severity 'high' -Category $cat `
        -Description 'PasswordRequired is false, so the account may have an empty password.' `
        -Remediation 'Set a strong password or disable the account.' -Mitre @('T1078.003')
    Register-BoCheck -Id 'USR-PWD-002' -Title 'Enabled account password never expires' -Severity 'low' -Category $cat `
        -Description 'Common for service accounts, but long-lived passwords widen the window for credential theft.'
    Register-BoCheck -Id 'USR-HIDDEN-001' -Title 'Local account name ends with $ (hidden account)' -Severity 'high' -Category $cat `
        -Description 'Trailing $ hides local accounts from some tools and is a known persistence trick.' `
        -Remediation 'Verify the account is legitimate; disable it if not.' -Mitre @('T1136.001', 'T1564.002')
    Register-BoCheck -Id 'USR-RID500-001' -Title 'Built-in Administrator account is enabled' -Severity 'low' -Category $cat `
        -Description 'The RID-500 account is a well-known target for password guessing.' `
        -Remediation 'Disable it or rename it and protect it with a unique strong password.'
    Register-BoCheck -Id 'USR-RDP-001' -Title 'Remote Desktop Users group members' -Severity 'info' -Category $cat -Cap 100 `
        -Description 'Accounts allowed to sign in through Remote Desktop in addition to administrators.'
    Register-BoCheck -Id 'USR-SESS-001' -Title 'Interactive and remote logon sessions' -Severity 'info' -Category $cat -Cap 100

    $users = Invoke-BoProvider -Name 'cim.Win32_UserAccount' -ErrorCode 'USERS_UNREADABLE' -Message 'cannot enumerate local accounts' -CheckId 'USR-INFO-001' -Live {
        Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop
    }
    $enabledAdminCandidates = @{}
    if ($users.Ok) {
        foreach ($u in $users.Data) {
            $name = [string](Get-BoProp $u 'Name' '')
            $sid = [string](Get-BoProp $u 'SID' '')
            $disabled = [bool](Get-BoProp $u 'Disabled' $false)
            $pwdReq = [bool](Get-BoProp $u 'PasswordRequired' $true)
            $pwdExp = [bool](Get-BoProp $u 'PasswordExpires' $true)
            $state = 'enabled'
            if ($disabled) { $state = 'disabled' }
            Add-BoHit -Id 'USR-INFO-001' -Type 'other' -Ref "user:$name" -Excerpt "$state sid=$sid passwordRequired=$pwdReq passwordExpires=$pwdExp"
            if ($sid -match '-503$' -or $sid -match '-504$') { continue }
            if (-not $disabled) {
                $enabledAdminCandidates[$name.ToLowerInvariant()] = $sid
                if (-not $pwdReq) { Add-BoHit -Id 'USR-PWD-001' -Type 'other' -Ref "user:$name" -Excerpt 'PasswordRequired=false' }
                if (-not $pwdExp -and $sid -notmatch '-500$') { Add-BoHit -Id 'USR-PWD-002' -Type 'other' -Ref "user:$name" -Excerpt 'PasswordExpires=false' }
                if ($sid -match '-501$') { Add-BoHit -Id 'USR-GUEST-001' -Type 'other' -Ref "user:$name" }
                if ($sid -match '-500$') { Add-BoHit -Id 'USR-RID500-001' -Type 'other' -Ref "user:$name" }
            }
            if ($name.EndsWith('$')) { Add-BoHit -Id 'USR-HIDDEN-001' -Type 'other' -Ref "user:$name" -Excerpt "sid=$sid disabled=$disabled" }
        }
    }

    $admins = Get-BoLocalGroupMember -Sid 'S-1-5-32-544' -DataName 'group.administrators' -CheckId 'USR-ADMIN-001'
    if ($null -ne $admins) {
        foreach ($m in $admins) {
            $mName = [string](Get-BoProp $m 'Name' '')
            $mSid = [string](Get-BoProp $m 'SID' '')
            $cls = [string](Get-BoProp $m 'ObjectClass' '')
            Add-BoHit -Id 'USR-ADMIN-001' -Type 'other' -Ref "admin:$mName" -Excerpt "sid=$mSid class=$cls"
            $short = ($mName -split '\\')[-1].ToLowerInvariant()
            $isLocal = ($mName -match '^[^\\]*\\' -and $users.Ok -and $enabledAdminCandidates.ContainsKey($short))
            if ($isLocal -and $mSid -notmatch '-500$') { Add-BoHit -Id 'USR-ADMIN-002' -Type 'other' -Ref "admin:$mName" -Excerpt "sid=$mSid" }
        }
    }
    $rdp = Get-BoLocalGroupMember -Sid 'S-1-5-32-555' -DataName 'group.remotedesktopusers' -CheckId 'USR-RDP-001'
    if ($null -ne $rdp) {
        foreach ($m in $rdp) { Add-BoHit -Id 'USR-RDP-001' -Type 'other' -Ref "rdpuser:$([string](Get-BoProp $m 'Name' ''))" -Excerpt "sid=$([string](Get-BoProp $m 'SID' ''))" }
    }

    $sess = Invoke-BoProvider -Name 'users.sessions' -ErrorCode 'SESSIONS_UNREADABLE' -Message 'cannot enumerate logon sessions' -CheckId 'USR-SESS-001' -NonMaterial -Live {
        $ls = @(Get-CimInstance -ClassName Win32_LogonSession -ErrorAction Stop | Where-Object { @(2, 7, 10, 11) -contains [int]$_.LogonType })
        $map = @{}
        foreach ($l in @(Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction Stop)) {
            $map[[string]$l.Dependent.LogonId] = ([string]$l.Antecedent.Domain + '\' + [string]$l.Antecedent.Name)
        }
        foreach ($s in $ls) {
            $who = ''
            if ($map.ContainsKey([string]$s.LogonId)) { $who = $map[[string]$s.LogonId] }
            [pscustomobject]@{ LogonId = [string]$s.LogonId; LogonType = [int]$s.LogonType; StartTime = [string]$s.StartTime; User = $who }
        }
    }
    if ($sess.Ok) {
        $types = @{ 2 = 'interactive'; 7 = 'unlock'; 10 = 'remote-interactive'; 11 = 'cached-interactive' }
        foreach ($s in $sess.Data) {
            $t = [int](Get-BoProp $s 'LogonType' 0)
            Add-BoHit -Id 'USR-SESS-001' -Type 'other' -Ref "session:$([string](Get-BoProp $s 'LogonId' ''))" -Excerpt "$([string](Get-BoProp $s 'User' '')) type=$($types[$t]) start=$([string](Get-BoProp $s 'StartTime' ''))"
        }
    }
    Publish-BoCheck
}
