# Module: firewall (category: audit, read-only). Dot-sourced by the audit entry points.
# Windows Defender Firewall profile state and rules, read directly from the policy registry keys
# (fast, available on every supported release, and independent of the NetSecurity module).

function ConvertFrom-BoFirewallRule {
    # Parses a 'v2.31|Action=Allow|Active=TRUE|Dir=In|...' rule string into a hashtable.
    param([string]$Rule)
    $h = @{}
    foreach ($part in ($Rule -split '\|')) {
        $i = $part.IndexOf('=')
        if ($i -lt 1) { continue }
        $key = $part.Substring(0, $i)
        $val = $part.Substring($i + 1)
        if ($h.ContainsKey($key)) { $h[$key] = $h[$key] + ',' + $val } else { $h[$key] = $val }
    }
    return $h
}

function Invoke-BoFirewallModule {
    [CmdletBinding()]
    param()
    $cat = 'firewall'
    Register-BoCheck -Id 'FW-PROFILE-001' -Title 'Windows Firewall profile is disabled' -Severity 'high' -Category $cat `
        -Description 'A disabled firewall profile leaves every listening service reachable on that network type.' `
        -Remediation 'Enable the profile (Set-NetFirewallProfile -Enabled True) after confirming no policy intentionally disables it.' -Mitre @('T1562.004')
    Register-BoCheck -Id 'FW-DEFAULT-001' -Title 'Default inbound action is Allow' -Severity 'high' -Category $cat `
        -Description 'With an Allow default, any service without an explicit block rule is exposed.' `
        -Remediation 'Set the default inbound action to Block.' -Mitre @('T1562.004')
    Register-BoCheck -Id 'FW-LOG-001' -Title 'Dropped-packet logging is disabled' -Severity 'low' -Category $cat `
        -Description 'Without firewall logs, scanning and blocked intrusion attempts leave no trace.' `
        -Remediation 'Enable LogDroppedPackets for each profile.'
    Register-BoCheck -Id 'FW-RULE-001' -Title 'Custom enabled inbound allow rules' -Severity 'info' -Category $cat -Cap 200 `
        -Description 'Enabled inbound allow rules that are not built-in Windows rules.'
    Register-BoCheck -Id 'FW-RULE-002' -Title 'Inbound allow rule matches all traffic' -Severity 'high' -Category $cat `
        -Description 'An enabled inbound allow rule with no program, service, protocol, port or remote-address restriction defeats the firewall.' `
        -Remediation 'Delete or scope the rule.' -Mitre @('T1562.004')
    Register-BoCheck -Id 'FW-RULE-003' -Title 'Inbound allow rule for a program in a user-writable location' -Severity 'medium' -Category $cat `
        -Description 'Allow rules for binaries in temp, public or per-user directories are commonly created by malware.' `
        -Remediation 'Verify the program; remove the rule if unexpected.' -Mitre @('T1562.004')
    Register-BoCheck -Id 'FW-RULE-004' -Title 'Inbound allow rule exposes a sensitive port to any remote address' -Severity 'low' -Category $cat `
        -Description 'Remote-access, file-sharing or database ports are allowed from any source.' `
        -Remediation 'Restrict the remote address scope to management networks.'

    $fp = $script:HKLM + '\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
    $pol = $script:HKLM + '\SOFTWARE\Policies\Microsoft\WindowsFirewall'
    $profiles = @(@('DomainProfile', 'Domain'), @('StandardProfile', 'Private'), @('PublicProfile', 'Public'))
    $probe = Get-BoRegKeyChecked -Path $fp -CheckId 'FW-PROFILE-001'
    if ($null -eq $probe) {
        Add-BoError -Code 'FIREWALL_POLICY_MISSING' -Message 'firewall policy registry key not readable; profile and rule checks skipped' -CheckId 'FW-PROFILE-001' -Material $true
        Publish-BoCheck
        return
    }
    foreach ($p in $profiles) {
        $local = Get-BoRegKeyChecked -Path "$fp\$($p[0])" -CheckId 'FW-PROFILE-001'
        $gpo = Get-BoRegKeyChecked -Path "$pol\$($p[0])" -CheckId 'FW-PROFILE-001'
        $vals = @{}
        if ($null -ne $local) { foreach ($k in $local.Values.Keys) { $vals[$k] = $local.Values[$k] } }
        if ($null -ne $gpo) { foreach ($k in $gpo.Values.Keys) { $vals[$k] = $gpo.Values[$k] } }
        $src = 'local'
        if ($null -ne $gpo -and $gpo.Values.Count -gt 0) { $src = 'policy' }
        $enabled = [int](Get-BoProp $vals 'EnableFirewall' 1)
        $inbound = [int](Get-BoProp $vals 'DefaultInboundAction' 1)
        if ($enabled -eq 0) { Add-BoHit -Id 'FW-PROFILE-001' -Type 'registry' -Ref "$fp\$($p[0]) :: EnableFirewall" -Excerpt "$($p[1]) profile disabled ($src)" }
        elseif ($inbound -eq 0) { Add-BoHit -Id 'FW-DEFAULT-001' -Type 'registry' -Ref "$fp\$($p[0]) :: DefaultInboundAction" -Excerpt "$($p[1]) profile allows inbound by default ($src)" }
        if ($enabled -ne 0) {
            $lg = Get-BoRegKeyChecked -Path "$fp\$($p[0])\Logging" -CheckId 'FW-LOG-001'
            $lgp = Get-BoRegKeyChecked -Path "$pol\$($p[0])\Logging" -CheckId 'FW-LOG-001'
            $dropped = 0
            if ($null -ne $lg) { $dropped = [int](Get-BoProp $lg.Values 'LogDroppedPackets' 0) }
            if ($null -ne $lgp -and $lgp.Values.ContainsKey('LogDroppedPackets')) { $dropped = [int]$lgp.Values['LogDroppedPackets'] }
            if ($dropped -eq 0) { Add-BoHit -Id 'FW-LOG-001' -Type 'registry' -Ref "$fp\$($p[0])\Logging" -Excerpt "$($p[1]) profile: LogDroppedPackets=0" }
        }
    }

    $sensitiveHigh = @(23, 5900, 5901, 2375)
    $sensitiveMed = @(445, 139, 1433, 3306, 5432, 6379, 27017, 21, 69)
    $sensitiveLow = @(3389, 5985, 5986)
    $ruleSets = @("$fp\FirewallRules", "$pol\FirewallRules")
    $total = 0
    foreach ($rs in $ruleSets) {
        $rk = Get-BoRegKeyChecked -Path $rs -CheckId 'FW-RULE-001'
        if ($null -eq $rk) { continue }
        foreach ($n in $rk.Values.Keys) {
            $r = ConvertFrom-BoFirewallRule ([string]$rk.Values[$n])
            $total++
            if ((Get-BoProp $r 'Active' 'FALSE') -ne 'TRUE' -or (Get-BoProp $r 'Dir' '') -ne 'In' -or (Get-BoProp $r 'Action' '') -ne 'Allow') { continue }
            $display = [string](Get-BoProp $r 'Name' $n)
            $builtIn = ($display.StartsWith('@') -or $display -match '^\{[0-9A-Fa-f-]{36}\}$')
            $app = Expand-BoEnvPath ([string](Get-BoProp $r 'App' ''))
            $svc = [string](Get-BoProp $r 'Svc' '')
            $proto = [string](Get-BoProp $r 'Protocol' '')
            $lport = [string](Get-BoProp $r 'LPort' '')
            $ra = [string](Get-BoProp $r 'RA4' '') + [string](Get-BoProp $r 'RA6' '')
            $ref = "$rs :: $n"
            $label = "$display app=$app svc=$svc proto=$proto lport=$lport remote=$ra"
            if (-not $builtIn) { Add-BoHit -Id 'FW-RULE-001' -Type 'registry' -Ref $ref -Excerpt $label }
            if (-not $app -and -not $svc -and -not $proto -and -not $lport -and -not $ra) {
                Add-BoHit -Id 'FW-RULE-002' -Type 'registry' -Ref $ref -Excerpt $label
            }
            if ($app) {
                $zone = Get-BoPathZone $app
                if ($zone -eq 'temp') { Add-BoHit -Id 'FW-RULE-003' -Type 'registry' -Ref $ref -Excerpt $label -Severity 'high' }
                elseif ($zone -eq 'appdata' -or $zone -eq 'programdata') { Add-BoHit -Id 'FW-RULE-003' -Type 'registry' -Ref $ref -Excerpt $label }
            }
            if ($lport -and -not $ra) {
                foreach ($pt in ($lport -split ',')) {
                    $pi = 0
                    if (-not [int]::TryParse($pt, [ref]$pi)) { continue }
                    if ($sensitiveHigh -contains $pi) { Add-BoHit -Id 'FW-RULE-004' -Type 'registry' -Ref $ref -Excerpt $label -Severity 'high' }
                    elseif ($sensitiveMed -contains $pi) { Add-BoHit -Id 'FW-RULE-004' -Type 'registry' -Ref $ref -Excerpt $label -Severity 'medium' }
                    elseif ($sensitiveLow -contains $pi) { Add-BoHit -Id 'FW-RULE-004' -Type 'registry' -Ref $ref -Excerpt $label }
                }
            }
        }
    }
    Write-BoLog 'INFO' "firewall rules parsed: $total"
    Publish-BoCheck
}
