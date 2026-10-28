@{
    Id        = 'VGL-0102'
    Title     = 'New account followed by persistence mechanism'
    Technique = 'T1136'
    Tactic    = 'Persistence'
    Severity  = 'High'
    Response  = @('Collect', 'Notify')
    Correlation = @{
        WindowSeconds = 600
        Key   = { param($e) $e.Host }
        Steps = @(
            @{ Name = 'new local user'; Rules = @('VGL-0003') }
            @{ Name = 'scheduled task or service'; Rules = @('VGL-0004', 'VGL-0005') }
        )
    }
}
