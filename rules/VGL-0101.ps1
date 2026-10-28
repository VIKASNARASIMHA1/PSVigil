@{
    Id        = 'VGL-0101'
    Title     = 'Brute force followed by successful logon (same source)'
    Technique = 'T1110.001'
    Tactic    = 'Credential Access'
    Severity  = 'Critical'
    Response  = @('BlockIp', 'Collect', 'Notify')
    Correlation = @{
        WindowSeconds = 900
        # events are correlated per source IP; events without a usable IP are ignored
        Key   = { param($e) if ($e.SourceIp -and $e.SourceIp -ne '-') { $e.SourceIp } else { $null } }
        Steps = @(
            @{ Name = '5+ failed logons'; MinCount = 5; Match = { param($e) $e.EventId -eq 4625 } }
            @{ Name = 'successful network/RDP logon'; Match = { param($e) $e.EventId -eq 4624 -and ($e.Data['LogonType'] -eq '3' -or $e.Data['LogonType'] -eq '10') } }
        )
    }
}
