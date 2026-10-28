@{
    Id        = 'VGL-0005'
    Title     = 'New service installed'
    Technique = 'T1543.003'
    Tactic    = 'Persistence'
    Severity  = 'Medium'
    Response  = @('Collect')
    Match     = { param($e) $e.EventId -eq 7045 -or $e.EventId -eq 4697 }
    # One service install writes both 7045 (System) and 4697 (Security): collapse them into one alert
    Dedupe    = @{ Key = { param($e) "$($e.Host)|$($e.Data['ServiceName'])" }; WindowSeconds = 10 }
    Detail    = { param($e) "Service '$($e.Data['ServiceName'])' -> $($e.Data['ImagePath'])$($e.Data['ServiceFileName'])" }
}
