@{
    Id        = 'VGL-0006'
    Title     = 'Registry Run key persistence (needs Sysmon)'
    Technique = 'T1547.001'
    Tactic    = 'Persistence'
    Severity  = 'Medium'
    Response  = @('Collect')
    Match     = {
        param($e)
        $e.EventId -eq 13 -and $e.Data['TargetObject'] -match '(?i)\\CurrentVersion\\Run(Once)?\\'
    }
    Detail    = { param($e) "$($e.Data['Image']) set $($e.Data['TargetObject']) = $($e.Data['Details'])" }
}
