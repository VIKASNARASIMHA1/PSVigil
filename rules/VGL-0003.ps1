@{
    Id        = 'VGL-0003'
    Title     = 'New local user account created'
    Technique = 'T1136.001'
    Tactic    = 'Persistence'
    Severity  = 'Medium'
    Response  = @('Collect', 'DisableUser')
    Match     = { param($e) $e.EventId -eq 4720 }
    Detail    = { param($e) "User '$($e.Data['TargetUserName'])' created by '$($e.Data['SubjectUserName'])'" }
}
