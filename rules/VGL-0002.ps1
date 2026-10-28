@{
    Id        = 'VGL-0002'
    Title     = 'Brute force: repeated failed logons'
    Technique = 'T1110'
    Tactic    = 'Credential Access'
    Severity  = 'High'
    Response  = @('BlockIp', 'Notify')
    Match     = { param($e) $e.EventId -eq 4625 }
    Threshold = @{
        Count         = 5
        WindowSeconds = 300
        GroupBy       = { param($e) "$($e.Host)|$($e.SourceIp)" }
    }
    Detail    = { param($e) "Failed logons from '$($e.SourceIp)' (last target account: $($e.Data['TargetUserName']))" }
}
