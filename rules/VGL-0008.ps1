@{
    Id        = 'VGL-0008'
    Title     = 'Event log cleared'
    Technique = 'T1070.001'
    Tactic    = 'Defense Evasion'
    Severity  = 'High'
    Response  = @('Collect', 'Notify')
    Match     = { param($e) $e.EventId -eq 1102 -or ($e.EventId -eq 104 -and $e.Channel -eq 'System') }
    Detail    = { param($e) "Log '$($e.Data['Channel'])' cleared by '$($e.Data['SubjectUserName'])'" }
}
