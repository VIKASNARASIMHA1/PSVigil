@{
    Id        = 'VGL-0001'
    Title     = 'Encoded PowerShell command'
    Technique = 'T1059.001'
    Tactic    = 'Execution'
    Severity  = 'High'
    Response  = @('Collect', 'Notify')
    # Hardened after evasion testing: accepts -e / -ec / -en* / -enc* / -EncodedCommand in any case, accepts short
    # payloads (8+ chars) and requires powershell/pwsh in the command line so "git commit -e something" is not flagged.
    Match     = {
        param($e)
        ($e.EventId -eq 1 -or $e.EventId -eq 4688) -and
        $e.CommandLine -match '(?i)(powershell|pwsh)' -and
        $e.CommandLine -match '(?i)\s-e(?:n\w*|c)?\s+[A-Za-z0-9+/=]{8,}'
    }
    # Windows logs the same launch as 4688 and Sysmon 1: count it once
    Dedupe    = @{ Key = { param($e) "$($e.Host)|$($e.CommandLine)" }; WindowSeconds = 5 }
}
