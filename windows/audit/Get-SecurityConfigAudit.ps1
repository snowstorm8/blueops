# Module: security (category: audit, read-only). Dot-sourced by the audit entry points.
# Security-relevant configuration: UAC, LSA/credential protections, SMB, RDP, Defender, audit and
# password policy, PowerShell logging, WinRM and Windows Update policy.

function ConvertFrom-BoNetAccount {
    # 'net accounts' prints values in a fixed order in every locale; parse positionally.
    param([string]$Text)
    $vals = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($Text -split "`r?`n")) {
        $t = $line.Trim()
        if (-not $t -or $t.IndexOf(':') -lt 0) { continue }
        $vals.Add($t.Substring($t.LastIndexOf(':') + 1).Trim())
        if ($vals.Count -ge 8) { break }
    }
    if ($vals.Count -lt 8) { return $null }
    $min = 0; $thr = 0
    [void][int]::TryParse($vals[3], [ref]$min)
    [void][int]::TryParse($vals[5], [ref]$thr)
    return [pscustomobject]@{ MinLength = $min; LockoutThreshold = $thr }
}

function Invoke-BoSecurityModule {
    [CmdletBinding()]
    param()
    $cat = 'security-config'
    Register-BoCheck -Id 'SEC-INFO-001' -Title 'Security configuration summary' -Severity 'info' -Category $cat -Cap 40
    Register-BoCheck -Id 'SEC-UAC-001' -Title 'User Account Control is weakened' -Severity 'medium' -Category $cat `
        -Description 'UAC is disabled, admin approval is silent, or remote local-account tokens are unfiltered.' `
        -Remediation 'Set EnableLUA=1, ConsentPromptBehaviorAdmin to 2 or 5, and remove LocalAccountTokenFilterPolicy.' -Mitre @('T1548.002')
    Register-BoCheck -Id 'SEC-LSA-001' -Title 'LSA or credential-protection setting is weak' -Severity 'low' -Category $cat `
        -Description 'Settings that weaken credential storage or authentication (WDigest, LM hashes, NTLM level, blank-password network logon, anonymous access).' `
        -Remediation 'Restore the secure defaults and enable LSA protection (RunAsPPL).' -Mitre @('T1003.001', 'T1556')
    Register-BoCheck -Id 'SEC-SMB-001' -Title 'SMBv1 is enabled' -Severity 'medium' -Category $cat `
        -Description 'SMBv1 has no integrity protection and is the vector of wormable exploits.' `
        -Remediation 'Disable SMBv1 (server and client).' -Mitre @('T1210')
    Register-BoCheck -Id 'SEC-SMB-002' -Title 'SMB signing is not required' -Severity 'low' -Category $cat `
        -Description 'Without required signing, SMB sessions can be relayed or tampered with.' -Mitre @('T1557')
    Register-BoCheck -Id 'SEC-RDP-001' -Title 'Remote Desktop is enabled' -Severity 'info' -Category $cat `
        -Description 'Remote Desktop connections are allowed on this host.'
    Register-BoCheck -Id 'SEC-RDP-002' -Title 'Remote Desktop does not require Network Level Authentication' -Severity 'high' -Category $cat `
        -Description 'Without NLA, unauthenticated users reach the logon screen and the pre-auth attack surface.' `
        -Remediation 'Set UserAuthentication=1 and SecurityLayer to 2 for RDP-Tcp.' -Mitre @('T1021.001')
    Register-BoCheck -Id 'SEC-AUTOLOGON-001' -Title 'Automatic logon is configured' -Severity 'high' -Category $cat `
        -Description 'AutoAdminLogon stores credentials in the registry and logs in without a password prompt (value not shown).' `
        -Remediation 'Disable AutoAdminLogon and remove DefaultPassword.' -Mitre @('T1552.002')
    Register-BoCheck -Id 'SEC-LLMNR-001' -Title 'LLMNR is not disabled' -Severity 'low' -Category $cat `
        -Description 'LLMNR name resolution can be poisoned to capture NTLM hashes.' -Mitre @('T1557.001')
    Register-BoCheck -Id 'SEC-DEF-001' -Title 'Microsoft Defender protection is disabled' -Severity 'high' -Category $cat `
        -Description 'Defender antivirus or real-time protection is turned off by policy or status.' `
        -Remediation 'Re-enable protection unless another endpoint product is registered; investigate who changed it.' -Mitre @('T1562.001')
    Register-BoCheck -Id 'SEC-DEF-002' -Title 'Broad Microsoft Defender exclusions' -Severity 'high' -Category $cat `
        -Description 'Exclusions for drive roots, temp/public directories, ProgramData or executable extensions blind the scanner.' `
        -Remediation 'Remove the exclusion unless a vendor requires a narrower path.' -Mitre @('T1562.001')
    Register-BoCheck -Id 'SEC-DEF-003' -Title 'Microsoft Defender exclusions' -Severity 'info' -Category $cat -Cap 100 `
        -Description 'Configured path, extension and process exclusions.'
    Register-BoCheck -Id 'SEC-DEF-004' -Title 'Microsoft Defender signatures are out of date' -Severity 'low' -Category $cat `
        -Description 'Antivirus signatures are more than 7 days old.'
    Register-BoCheck -Id 'SEC-AUDIT-001' -Title 'Key audit subcategories are not audited' -Severity 'medium' -Category $cat `
        -Description 'Logon, process creation, account management, group management, policy change and lockout auditing underpin incident response.' `
        -Remediation 'Enable Success (and Failure for logon/lockout) auditing via Advanced Audit Policy.' -Mitre @('T1562.002')
    Register-BoCheck -Id 'SEC-AUDIT-002' -Title 'Process creation events do not include the command line' -Severity 'low' -Category $cat `
        -Description 'Event 4688 lacks command lines unless ProcessCreationIncludeCmdLine_Enabled is 1.'
    Register-BoCheck -Id 'SEC-PWD-001' -Title 'Weak minimum password length' -Severity 'low' -Category $cat `
        -Description 'The local password policy allows short passwords.' -Remediation 'Require at least 12 characters.'
    Register-BoCheck -Id 'SEC-PWD-002' -Title 'Account lockout is not configured' -Severity 'medium' -Category $cat `
        -Description 'No lockout threshold lets attackers guess passwords without limit.' -Remediation 'Set a lockout threshold of 5-10 attempts.' -Mitre @('T1110')
    Register-BoCheck -Id 'SEC-PS-001' -Title 'PowerShell logging is not fully enabled' -Severity 'low' -Category $cat `
        -Description 'Script block and module logging are missing, limiting visibility into PowerShell abuse.' `
        -Remediation 'Enable ScriptBlockLogging and ModuleLogging by policy.' -Mitre @('T1059.001')
    Register-BoCheck -Id 'SEC-WINRM-001' -Title 'WinRM allows unencrypted or Basic authentication' -Severity 'medium' -Category $cat `
        -Description 'Unencrypted traffic or Basic authentication exposes credentials.' -Mitre @('T1021.006')
    Register-BoCheck -Id 'SEC-UPDATE-001' -Title 'Automatic Windows Updates are disabled by policy' -Severity 'medium' -Category $cat `
        -Description 'NoAutoUpdate=1 prevents the host from receiving security updates automatically.'

    $sum = New-Object System.Collections.Generic.List[string]
    # UAC
    $sysPol = $script:HKLM + '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $sp = Get-BoRegKeyChecked -Path $sysPol -CheckId 'SEC-UAC-001'
    $lua = 1; $cpb = 5
    if ($null -ne $sp) {
        $lua = [int](Get-BoProp $sp.Values 'EnableLUA' 1)
        $cpb = [int](Get-BoProp $sp.Values 'ConsentPromptBehaviorAdmin' 5)
        if ($lua -eq 0) { Add-BoHit -Id 'SEC-UAC-001' -Type 'registry' -Ref "$sysPol :: EnableLUA" -Excerpt 'UAC disabled' -Severity 'high' }
        if ($cpb -eq 0) { Add-BoHit -Id 'SEC-UAC-001' -Type 'registry' -Ref "$sysPol :: ConsentPromptBehaviorAdmin" -Excerpt 'elevate without prompting' -Severity 'medium' }
        if ([int](Get-BoProp $sp.Values 'LocalAccountTokenFilterPolicy' 0) -eq 1) { Add-BoHit -Id 'SEC-UAC-001' -Type 'registry' -Ref "$sysPol :: LocalAccountTokenFilterPolicy" -Excerpt 'remote UAC filtering disabled' -Severity 'medium' }
    }
    $sum.Add("UAC EnableLUA=$lua ConsentPromptBehaviorAdmin=$cpb")

    # LSA / credentials
    $lsaPath = $script:HKLM + '\SYSTEM\CurrentControlSet\Control\Lsa'
    $lsa = Get-BoRegKeyChecked -Path $lsaPath -CheckId 'SEC-LSA-001'
    if ($null -ne $lsa) {
        if ([int](Get-BoProp $lsa.Values 'RunAsPPL' 0) -eq 0) { Add-BoHit -Id 'SEC-LSA-001' -Type 'registry' -Ref "$lsaPath :: RunAsPPL" -Excerpt 'LSA protection (RunAsPPL) not enabled' }
        if ([int](Get-BoProp $lsa.Values 'LmCompatibilityLevel' 3) -lt 3) { Add-BoHit -Id 'SEC-LSA-001' -Type 'registry' -Ref "$lsaPath :: LmCompatibilityLevel" -Excerpt "level $([string]$lsa.Values['LmCompatibilityLevel']) permits LM/NTLMv1" -Severity 'medium' }
        if ([int](Get-BoProp $lsa.Values 'NoLMHash' 1) -eq 0) { Add-BoHit -Id 'SEC-LSA-001' -Type 'registry' -Ref "$lsaPath :: NoLMHash" -Excerpt 'LM hashes are stored' -Severity 'medium' }
        if ([int](Get-BoProp $lsa.Values 'LimitBlankPasswordUse' 1) -eq 0) { Add-BoHit -Id 'SEC-LSA-001' -Type 'registry' -Ref "$lsaPath :: LimitBlankPasswordUse" -Excerpt 'blank-password accounts may log on over the network' -Severity 'high' }
        if ([int](Get-BoProp $lsa.Values 'EveryoneIncludesAnonymous' 0) -eq 1) { Add-BoHit -Id 'SEC-LSA-001' -Type 'registry' -Ref "$lsaPath :: EveryoneIncludesAnonymous" -Excerpt 'Everyone includes anonymous users' -Severity 'medium' }
        if ([int](Get-BoProp $lsa.Values 'RestrictAnonymousSAM' 1) -eq 0) { Add-BoHit -Id 'SEC-LSA-001' -Type 'registry' -Ref "$lsaPath :: RestrictAnonymousSAM" -Excerpt 'anonymous SAM enumeration allowed' }
        if ([int](Get-BoProp $lsa.Values 'RestrictAnonymous' 0) -eq 2) { Write-BoLog 'DEBUG' 'RestrictAnonymous=2' }
    }
    $wd = $script:HKLM + '\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
    if ([int](Get-BoRegValue -Path $wd -Name 'UseLogonCredential' -Default 0) -eq 1) {
        Add-BoHit -Id 'SEC-LSA-001' -Type 'registry' -Ref "$wd :: UseLogonCredential" -Excerpt 'WDigest stores plaintext credentials in memory' -Severity 'high'
    }

    # SMB
    $lm = $script:HKLM + '\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $lmk = Get-BoRegKeyChecked -Path $lm -CheckId 'SEC-SMB-001'
    if ($null -ne $lmk) {
        if ([int](Get-BoProp $lmk.Values 'SMB1' 0) -eq 1) { Add-BoHit -Id 'SEC-SMB-001' -Type 'registry' -Ref "$lm :: SMB1" -Excerpt 'SMB1 server enabled' -Severity 'high' }
        if ([int](Get-BoProp $lmk.Values 'RequireSecuritySignature' 0) -ne 1) { Add-BoHit -Id 'SEC-SMB-002' -Type 'registry' -Ref "$lm :: RequireSecuritySignature" -Excerpt 'server signing not required' }
    }
    $m10 = $script:HKLM + '\SYSTEM\CurrentControlSet\Services\mrxsmb10'
    $m10k = Get-BoRegKeyChecked -Path $m10 -CheckId 'SEC-SMB-001'
    if ($null -ne $m10k -and [int](Get-BoProp $m10k.Values 'Start' 4) -ne 4) { Add-BoHit -Id 'SEC-SMB-001' -Type 'registry' -Ref "$m10 :: Start" -Excerpt "SMB1 client driver start type $([string]$m10k.Values['Start'])" }

    # RDP
    $ts = $script:HKLM + '\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $tsk = Get-BoRegKeyChecked -Path $ts -CheckId 'SEC-RDP-001'
    $rdpOn = $false
    if ($null -ne $tsk -and [int](Get-BoProp $tsk.Values 'fDenyTSConnections' 1) -eq 0) {
        $rdpOn = $true
        Add-BoHit -Id 'SEC-RDP-001' -Type 'registry' -Ref "$ts :: fDenyTSConnections" -Excerpt 'Remote Desktop connections allowed'
        $rt = $ts + '\WinStations\RDP-Tcp'
        $rk = Get-BoRegKeyChecked -Path $rt -CheckId 'SEC-RDP-002'
        if ($null -ne $rk) {
            if ([int](Get-BoProp $rk.Values 'UserAuthentication' 1) -eq 0) { Add-BoHit -Id 'SEC-RDP-002' -Type 'registry' -Ref "$rt :: UserAuthentication" -Excerpt 'NLA disabled' }
            if ([int](Get-BoProp $rk.Values 'SecurityLayer' 2) -eq 0) { Add-BoHit -Id 'SEC-RDP-002' -Type 'registry' -Ref "$rt :: SecurityLayer" -Excerpt 'RDP security layer (no TLS/NLA)' }
        }
    }
    $sum.Add("RDP enabled=$rdpOn")

    # Winlogon autologon and cached credentials
    $wl = $script:HKLM + '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $wlk = Get-BoRegKeyChecked -Path $wl -CheckId 'SEC-AUTOLOGON-001'
    if ($null -ne $wlk) {
        if ([string](Get-BoProp $wlk.Values 'AutoAdminLogon' '0') -eq '1') {
            $hasPw = $wlk.Values.ContainsKey('DefaultPassword')
            Add-BoHit -Id 'SEC-AUTOLOGON-001' -Type 'registry' -Ref "$wl :: AutoAdminLogon" -Excerpt "user=$([string](Get-BoProp $wlk.Values 'DefaultUserName' '')) passwordStoredInRegistry=$hasPw"
        }
    }
    # LLMNR
    $dnsPol = $script:HKLM + '\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    if ([int](Get-BoRegValue -Path $dnsPol -Name 'EnableMulticast' -Default 1) -ne 0) { Add-BoHit -Id 'SEC-LLMNR-001' -Type 'registry' -Ref "$dnsPol :: EnableMulticast" -Excerpt 'EnableMulticast not set to 0' }

    # Defender
    $defPol = $script:HKLM + '\SOFTWARE\Policies\Microsoft\Windows Defender'
    $defKey = $script:HKLM + '\SOFTWARE\Microsoft\Windows Defender'
    if ([int](Get-BoRegValue -Path $defPol -Name 'DisableAntiSpyware' -Default 0) -eq 1) { Add-BoHit -Id 'SEC-DEF-001' -Type 'registry' -Ref "$defPol :: DisableAntiSpyware" -Excerpt 'Defender disabled by policy' }
    if ([int](Get-BoRegValue -Path $defKey -Name 'DisableAntiSpyware' -Default 0) -eq 1) { Add-BoHit -Id 'SEC-DEF-001' -Type 'registry' -Ref "$defKey :: DisableAntiSpyware" -Excerpt 'Defender disabled' }
    foreach ($rtp in @("$defPol\Real-Time Protection", "$defKey\Real-Time Protection")) {
        if ([int](Get-BoRegValue -Path $rtp -Name 'DisableRealtimeMonitoring' -Default 0) -eq 1) { Add-BoHit -Id 'SEC-DEF-001' -Type 'registry' -Ref "$rtp :: DisableRealtimeMonitoring" -Excerpt 'real-time protection disabled' }
    }
    $st = Invoke-BoProvider -Name 'defender.status' -ErrorCode 'DEFENDER_STATUS_UNAVAILABLE' -Message 'Get-MpComputerStatus unavailable (Defender not installed, third-party AV, or not elevated)' -CheckId 'SEC-DEF-001' -NonMaterial -Scalar -Live {
        $s = Get-MpComputerStatus -ErrorAction Stop
        [pscustomobject]@{ AMServiceEnabled = [bool]$s.AMServiceEnabled; RealTimeProtectionEnabled = [bool]$s.RealTimeProtectionEnabled; AntivirusSignatureAge = [int]$s.AntivirusSignatureAge }
    }
    if ($st.Ok -and $null -ne $st.Data) {
        if (-not [bool](Get-BoProp $st.Data 'RealTimeProtectionEnabled' $true)) { Add-BoHit -Id 'SEC-DEF-001' -Type 'command' -Ref 'Get-MpComputerStatus' -Excerpt 'RealTimeProtectionEnabled=False' }
        if (-not [bool](Get-BoProp $st.Data 'AMServiceEnabled' $true)) { Add-BoHit -Id 'SEC-DEF-001' -Type 'command' -Ref 'Get-MpComputerStatus' -Excerpt 'AMServiceEnabled=False' }
        $age = [int](Get-BoProp $st.Data 'AntivirusSignatureAge' 0)
        if ($age -gt 7) { Add-BoHit -Id 'SEC-DEF-004' -Type 'command' -Ref 'Get-MpComputerStatus' -Excerpt "signatures are $age days old" }
        $sum.Add("Defender realtime=$([string](Get-BoProp $st.Data 'RealTimeProtectionEnabled' '?')) sigAgeDays=$age")
    }
    foreach ($ex in @(@('Paths', 'path'), @('Extensions', 'extension'), @('Processes', 'process'))) {
        foreach ($root in @("$defKey\Exclusions\$($ex[0])", "$defPol\Exclusions\$($ex[0])")) {
            $k = Get-BoRegKeyChecked -Path $root -CheckId 'SEC-DEF-002'
            if ($null -eq $k) { continue }
            foreach ($n in $k.Values.Keys) {
                Add-BoHit -Id 'SEC-DEF-003' -Type 'registry' -Ref "$root :: $n" -Excerpt "$($ex[1]) exclusion"
                Add-BoInventory -Domain 'config' -Scope 'security' -Key "config:security:defender-exclusion:$($root.ToLowerInvariant())::$($n.ToLowerInvariant())" -Attrs @{ kind = $ex[1]; value = $n } -EvidenceType 'registry' -EvidenceRef "$root :: $n"
                $x = $n.ToLowerInvariant().Trim()
                $broad = $false
                if ($ex[1] -eq 'path') {
                    if ($x -match '^[a-z]:\\?\*?$' -or $x -match '^[a-z]:\\(windows|users|programdata)\\?\*?$' -or $x -match '\\(temp|tmp)\\?\*?$' -or $x -match '\\users\\public\\?\*?$' -or $x -match '\\downloads\\?\*?$') { $broad = $true }
                }
                elseif ($ex[1] -eq 'extension') {
                    if ($x.TrimStart('.') -match '^(exe|dll|ps1|bat|cmd|vbs|js|scr)$') { $broad = $true }
                }
                if ($broad) { Add-BoHit -Id 'SEC-DEF-002' -Type 'registry' -Ref "$root :: $n" -Excerpt "$($ex[1]) exclusion is overly broad" }
            }
        }
    }

    # Audit policy
    $ap = Invoke-BoProvider -Name 'auditpol' -ErrorCode 'AUDITPOL_UNAVAILABLE' -Message 'auditpol unavailable' -CheckId 'SEC-AUDIT-001' -Text -NonMaterial -Live {
        $o = (& (Get-BoSystemToolPath 'auditpol.exe') /get /category:* /r 2>&1 | Out-String)
        if ($o -match '0x00000522|privilege') { throw 'auditpol requires administrator rights' }
        $o
    }
    if ($ap.Ok) {
        $want = @{
            '0CCE9215-69AE-11D9-BED3-505054503030' = 'Logon'
            '0CCE922B-69AE-11D9-BED3-505054503030' = 'Process Creation'
            '0CCE9235-69AE-11D9-BED3-505054503030' = 'User Account Management'
            '0CCE9237-69AE-11D9-BED3-505054503030' = 'Security Group Management'
            '0CCE922F-69AE-11D9-BED3-505054503030' = 'Audit Policy Change'
            '0CCE9217-69AE-11D9-BED3-505054503030' = 'Account Lockout'
        }
        $english = ($ap.Data -match '(?i)success|failure|no auditing')
        if (-not $english) {
            Add-BoError -Code 'AUDITPOL_LOCALE' -Message 'auditpol output is not in a recognized language; audit policy check skipped' -CheckId 'SEC-AUDIT-001' -Material $false
        }
        else {
            $found = @{}
            foreach ($row in @($ap.Data -split "`r?`n" | Where-Object { $_.Trim() } | ConvertFrom-Csv)) {
                $guid = ''
                foreach ($prop in $row.PSObject.Properties) { if ([string]$prop.Value -match '^\{?([0-9A-Fa-f-]{36})\}?$') { $guid = $Matches[1].ToUpperInvariant() } }
                if (-not $guid -or -not $want.ContainsKey($guid)) { continue }
                $setting = ''
                foreach ($prop in $row.PSObject.Properties) { if ([string]$prop.Value -match '(?i)^(no auditing|success|failure|success and failure)$') { $setting = [string]$prop.Value } }
                $found[$guid] = $setting
            }
            foreach ($g in $want.Keys) {
                if ($found.ContainsKey($g) -and $found[$g] -match '(?i)^no auditing$') {
                    Add-BoHit -Id 'SEC-AUDIT-001' -Type 'command' -Ref 'auditpol /get /category:*' -Excerpt "$($want[$g]): No Auditing"
                }
            }
        }
    }
    $pc = Get-BoRegValue -Path ($sysPol + '\Audit') -Name 'ProcessCreationIncludeCmdLine_Enabled' -Default 0
    if ([int]$pc -ne 1) { Add-BoHit -Id 'SEC-AUDIT-002' -Type 'registry' -Ref "$sysPol\Audit :: ProcessCreationIncludeCmdLine_Enabled" -Excerpt 'command line not included in 4688' }

    # Password policy
    $na = Invoke-BoProvider -Name 'netaccounts' -ErrorCode 'NETACCOUNTS_UNAVAILABLE' -Message 'net accounts unavailable' -CheckId 'SEC-PWD-001' -Text -NonMaterial -Live { (& (Get-BoSystemToolPath 'net.exe') accounts 2>&1 | Out-String) }
    if ($na.Ok) {
        $pol = ConvertFrom-BoNetAccount -Text $na.Data
        if ($null -eq $pol) { Add-BoError -Code 'NETACCOUNTS_UNPARSED' -Message 'net accounts output could not be parsed' -CheckId 'SEC-PWD-001' -Material $false }
        else {
            if ($pol.MinLength -lt 8) { Add-BoHit -Id 'SEC-PWD-001' -Type 'command' -Ref 'net accounts' -Excerpt "minimum password length $($pol.MinLength)" -Severity 'medium' }
            elseif ($pol.MinLength -lt 12) { Add-BoHit -Id 'SEC-PWD-001' -Type 'command' -Ref 'net accounts' -Excerpt "minimum password length $($pol.MinLength)" }
            if ($pol.LockoutThreshold -eq 0) { Add-BoHit -Id 'SEC-PWD-002' -Type 'command' -Ref 'net accounts' -Excerpt 'lockout threshold Never' }
            Add-BoInventory -Domain 'config' -Scope 'security' -Key 'config:security:password-policy' -Attrs @{ min_length = $pol.MinLength; lockout_threshold = $pol.LockoutThreshold } -EvidenceType 'command' -EvidenceRef 'net accounts'
            $sum.Add("PasswordPolicy minLength=$($pol.MinLength) lockout=$($pol.LockoutThreshold) (local policy; domain policy applies on domain accounts)")
        }
    }

    # PowerShell logging
    $psPol = $script:HKLM + '\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    $missing = New-Object System.Collections.Generic.List[string]
    if ([int](Get-BoRegValue -Path "$psPol\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Default 0) -ne 1) { $missing.Add('ScriptBlockLogging') }
    if ([int](Get-BoRegValue -Path "$psPol\ModuleLogging" -Name 'EnableModuleLogging' -Default 0) -ne 1) { $missing.Add('ModuleLogging') }
    if ($missing.Count -gt 0) { Add-BoHit -Id 'SEC-PS-001' -Type 'registry' -Ref $psPol -Excerpt ("not enabled: " + ($missing -join ', ')) }

    # WinRM and Windows Update policy
    $wr = $script:HKLM + '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    if ([int](Get-BoRegValue -Path $wr -Name 'AllowUnencryptedTraffic' -Default 0) -eq 1) { Add-BoHit -Id 'SEC-WINRM-001' -Type 'registry' -Ref "$wr :: AllowUnencryptedTraffic" -Excerpt 'unencrypted WinRM allowed' }
    if ([int](Get-BoRegValue -Path $wr -Name 'AllowBasic' -Default 0) -eq 1) { Add-BoHit -Id 'SEC-WINRM-001' -Type 'registry' -Ref "$wr :: AllowBasic" -Excerpt 'Basic authentication allowed' }
    $au = $script:HKLM + '\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    if ([int](Get-BoRegValue -Path $au -Name 'NoAutoUpdate' -Default 0) -eq 1) { Add-BoHit -Id 'SEC-UPDATE-001' -Type 'registry' -Ref "$au :: NoAutoUpdate" -Excerpt 'automatic updates disabled' }

    # Security-relevant registry settings as structured config records. An unset value is the
    # string '<unset>' (a real, comparable state); an unreadable key is unknown (null) and a
    # coverage gap.
    $secSettings = @(
        @($sysPol, 'EnableLUA'), @($sysPol, 'ConsentPromptBehaviorAdmin'), @($sysPol, 'LocalAccountTokenFilterPolicy'),
        @($lsaPath, 'RunAsPPL'), @($lsaPath, 'LmCompatibilityLevel'), @($lsaPath, 'NoLMHash'), @($lsaPath, 'LimitBlankPasswordUse'),
        @($lsaPath, 'RestrictAnonymous'), @($lsaPath, 'RestrictAnonymousSAM'), @($lsaPath, 'EveryoneIncludesAnonymous'),
        @($wd, 'UseLogonCredential'), @($lm, 'SMB1'), @($lm, 'RequireSecuritySignature'), @($m10, 'Start'),
        @($ts, 'fDenyTSConnections'), @(($ts + '\WinStations\RDP-Tcp'), 'UserAuthentication'), @(($ts + '\WinStations\RDP-Tcp'), 'SecurityLayer'),
        @($wl, 'AutoAdminLogon'), @($wl, 'DefaultUserName'), @($dnsPol, 'EnableMulticast'),
        @($defPol, 'DisableAntiSpyware'), @($defKey, 'DisableAntiSpyware'),
        @(($defPol + '\Real-Time Protection'), 'DisableRealtimeMonitoring'), @(($defKey + '\Real-Time Protection'), 'DisableRealtimeMonitoring'),
        @(($psPol + '\ScriptBlockLogging'), 'EnableScriptBlockLogging'), @(($psPol + '\ModuleLogging'), 'EnableModuleLogging'),
        @($wr, 'AllowUnencryptedTraffic'), @($wr, 'AllowBasic'), @($au, 'NoAutoUpdate'),
        @(($sysPol + '\Audit'), 'ProcessCreationIncludeCmdLine_Enabled')
    )
    foreach ($ss in $secSettings) {
        # Get-BoRegValue hides access errors behind the default; a permission gap must stay
        # unknown ($null), never become the comparable value '<unset>'.
        $errBefore = $script:Bo.Errors.Count
        $sk = Get-BoRegKeyChecked -Path $ss[0] -CheckId 'SEC-INFO-001'
        if ($script:Bo.Errors.Count -gt $errBefore) { $sv = $null }
        elseif ($null -ne $sk -and $sk.Values.ContainsKey($ss[1])) { $sv = $sk.Values[$ss[1]] }
        else { $sv = '<unset>' }
        Add-BoInventory -Domain 'config' -Scope 'security' -Key "config:security:reg:$($ss[0].ToLowerInvariant())::$($ss[1].ToLowerInvariant())" -Attrs @{ value = $sv } -EvidenceType 'registry' -EvidenceRef "$($ss[0]) :: $($ss[1])"
    }

    foreach ($line in $sum) { Add-BoHit -Id 'SEC-INFO-001' -Type 'other' -Ref 'summary' -Excerpt $line }
    Publish-BoCheck
}
