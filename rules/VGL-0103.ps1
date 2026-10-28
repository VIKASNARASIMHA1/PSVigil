@{
    Id        = 'VGL-0103'
    Title     = 'Obfuscated PowerShell followed by defense evasion or download'
    Technique = 'T1059'
    Tactic    = 'Execution'
    Severity  = 'Critical'
    Response  = @('Collect', 'Notify')
    Correlation = @{
        WindowSeconds = 300
        Key   = { param($e) $e.Host }
        Steps = @(
            @{ Name = 'encoded/obfuscated PowerShell'; Rules = @('VGL-0001', 'VGL-0012') }
            @{ Name = 'Defender tampering or download cradle'; Rules = @('VGL-0009', 'VGL-0011') }
        )
    }
}
