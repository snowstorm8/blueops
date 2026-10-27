# Structured inventory (schema 0.2.0) emitted by the Windows audit for offline baseline comparison.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    $script:Fx = Copy-BoTestFixture
    $script:Full = Invoke-BoAuditJson -Fixture $script:Fx -Modules @()
    $script:Inv = $script:Full.Json.inventory
    $script:Domains = @('users', 'groups', 'services', 'processes', 'listeners', 'scheduled_tasks', 'persistence', 'config')
}

AfterAll {
    Remove-BoTestFixture $script:Fx
}

Describe 'inventory shape' {
    It 'is present with coverage and records, and the report declares schema 0.2.0' {
        $script:Full.Json.schema_version | Should -Be '0.2.0'
        $script:Inv | Should -Not -BeNullOrEmpty
        @($script:Inv.coverage).Count | Should -BeGreaterThan 0
        @($script:Inv.records).Count | Should -BeGreaterThan 0
    }

    It 'every record has a known domain, a non-empty key and an attrs object' {
        foreach ($r in @($script:Inv.records)) {
            $script:Domains | Should -Contain $r.domain
            [string]$r.key | Should -Not -BeNullOrEmpty
            $r.PSObject.Properties['attrs'] | Should -Not -BeNullOrEmpty
        }
    }

    It 'keys are stable identifiers: no pid, no ephemeral process data in a key' {
        foreach ($r in @($script:Inv.records | Where-Object { $_.domain -in 'processes', 'services', 'users' })) {
            $r.key | Should -Not -Match 'pid[=:]\d'
        }
    }

    It 'every inventory domain is populated by a full audit' -ForEach @(
        @{ Domain = 'users' }, @{ Domain = 'groups' }, @{ Domain = 'services' }, @{ Domain = 'processes' },
        @{ Domain = 'listeners' }, @{ Domain = 'scheduled_tasks' }, @{ Domain = 'persistence' }, @{ Domain = 'config' }
    ) {
        @($script:Inv.records | Where-Object { $_.domain -eq $Domain }).Count | Should -BeGreaterThan 0
    }

    It 'keys are unique within a domain and scope (processes and listeners may repeat: the engine aggregates them)' {
        $seen = @{}
        foreach ($r in @($script:Inv.records | Where-Object { $_.domain -notin 'processes', 'listeners' })) {
            $scope = ''
            if ($null -ne $r.PSObject.Properties['scope']) { $scope = [string]$r.scope }
            $id = "$($r.domain)|$scope|$(([string]$r.key).ToLowerInvariant())"
            $seen.ContainsKey($id) | Should -BeFalse -Because "duplicate inventory key $id"
            $seen[$id] = $true
        }
    }

    It 'timestamps remain ISO 8601 UTC' {
        # ConvertFrom-Json turns date strings into DateTime, so check the raw output.
        $script:Full.Out | Should -Match '"started_at":\s*"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"'
        $script:Full.Out | Should -Match '"finished_at":\s*"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"'
    }
}

Describe 'inventory content' {
    It 'identifies local accounts by SID, not by name alone' {
        $u = @($script:Inv.records | Where-Object { $_.domain -eq 'users' })
        foreach ($r in $u) { $r.key | Should -Match '^user:S-1-5-' }
    }

    It 'records Administrators membership as a set of SIDs' {
        $g = @($script:Inv.records | Where-Object { $_.key -eq 'group:S-1-5-32-544' })
        $g.Count | Should -Be 1
        foreach ($m in @($g[0].attrs.members)) { $m | Should -Match '^S-1-' }
    }

    It 'keeps the owning pid of a listener volatile, never in attrs or the key' {
        $l = @($script:Inv.records | Where-Object { $_.domain -eq 'listeners' })
        foreach ($r in $l) {
            $r.key | Should -Match '^listener:(tcp|udp)/'
            $r.attrs.PSObject.Properties['pid'] | Should -BeNullOrEmpty
        }
    }

    It 'keeps process ids volatile' {
        $p = @($script:Inv.records | Where-Object { $_.domain -eq 'processes' })
        $p.Count | Should -BeGreaterThan 0
        foreach ($r in $p) {
            $r.attrs.PSObject.Properties['pid'] | Should -BeNullOrEmpty
            $r.PSObject.Properties['volatile'] | Should -Not -BeNullOrEmpty
        }
    }

    It 'never stores secrets in inventory records' {
        $text = ($script:Inv.records | ConvertTo-Json -Depth 8)
        $text | Should -Not -Match '(?i)(password|passwd|secret|token|apikey)\s*[=:]\s*(?!<redacted>)[^\s",<]{4,}'
    }

    It 'every record that has evidence uses a schema evidence type' {
        foreach ($r in @($script:Inv.records)) {
            if ($null -eq $r.PSObject.Properties['evidence']) { continue }
            foreach ($e in @($r.evidence)) {
                @('file', 'registry', 'process', 'network', 'command', 'log', 'other') | Should -Contain $e.type
                [string]$e.ref | Should -Not -BeNullOrEmpty
            }
        }
    }
}

Describe 'inventory coverage' {
    It 'declares coverage for every collected domain partition' {
        $cov = @{}
        foreach ($c in @($script:Inv.coverage)) {
            $scope = ''
            if ($null -ne $c.PSObject.Properties['scope']) { $scope = [string]$c.scope }
            $cov["$($c.domain)|$scope"] = $c.status
        }
        foreach ($r in @($script:Inv.records)) {
            $scope = ''
            if ($null -ne $r.PSObject.Properties['scope']) { $scope = [string]$r.scope }
            $cov.ContainsKey("$($r.domain)|$scope") | Should -BeTrue -Because "no coverage for $($r.domain)/$scope"
        }
    }

    It 'only uses the documented statuses' {
        foreach ($c in @($script:Inv.coverage)) {
            @('complete', 'degraded', 'partial', 'unavailable') | Should -Contain $c.status
        }
    }

    It 'a missing data source degrades coverage instead of looking like removals' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('users') -Environment @{ BO_FORCE_MISSING = 'group.administrators' }
        $g = @($r.Json.inventory.coverage | Where-Object { $_.domain -eq 'groups' })
        $g.Count | Should -BeGreaterThan 0
        foreach ($c in $g) { $c.status | Should -Not -Be 'complete' }
        @($r.Json.inventory.records | Where-Object { $_.key -eq 'group:S-1-5-32-544' }).Count | Should -Be 0
    }

    It 'does not claim coverage for modules that did not run' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('users')
        @($r.Json.inventory.coverage | Where-Object { $_.domain -eq 'services' }).Count | Should -Be 0
        @($r.Json.inventory.records | Where-Object { $_.domain -eq 'services' }).Count | Should -Be 0
    }

    It 'the services fallback marks image paths and accounts unknown (null), not empty' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('services') -Environment @{ BO_FORCE_MISSING = 'cim.Win32_Service' }
        $svc = @($r.Json.inventory.records | Where-Object { $_.domain -eq 'services' })
        if ($svc.Count -gt 0) {
            foreach ($s in $svc) { $s.attrs.image_path | Should -BeNullOrEmpty }
            @($r.Json.inventory.coverage | Where-Object { $_.domain -eq 'services' -and $_.status -ne 'complete' }).Count | Should -BeGreaterThan 0
        }
    }

    It 'an unreadable registry is an unknown value, never the comparable string <unset>' {
        $r = Invoke-BoAuditJson -Fixture $script:Fx -Modules @('security') -Environment @{ BO_FORCE_MISSING = 'registry' }
        $reg = @($r.Json.inventory.records | Where-Object { $_.key -like 'config:security:reg:*' })
        $reg.Count | Should -BeGreaterThan 0
        foreach ($x in $reg) { $x.attrs.value | Should -BeNullOrEmpty }
        @($reg | Where-Object { $_.attrs.value -eq '<unset>' }).Count | Should -Be 0
        @($r.Json.inventory.coverage | Where-Object { $_.domain -eq 'config' -and $_.scope -eq 'security' -and $_.status -eq 'complete' }).Count | Should -Be 0
    }
}
