@{
    Severity     = @('Error', 'Warning')
    IncludeRules = @('*')
    ExcludeRules = @()
    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}
