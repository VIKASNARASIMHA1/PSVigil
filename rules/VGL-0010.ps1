@{
    Id        = 'VGL-0010'
    Title     = 'RDP logon from non-private address'
    Technique = 'T1021.001'
    Tactic    = 'Lateral Movement'
    Severity  = 'Medium'
    Response  = @('Notify')
    Match     = {
        param($e)
        $e.EventId -eq 4624 -and $e.Data['LogonType'] -eq '10' -and
        $e.SourceIp -and $e.SourceIp -ne '-' -and
        $e.SourceIp -notmatch '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:)'
    }
    Detail    = { param($e) "RDP logon for '$($e.Data['TargetUserName'])' from $($e.SourceIp)" }
}
