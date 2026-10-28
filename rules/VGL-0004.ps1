@{
    Id        = 'VGL-0004'
    Title     = 'Scheduled task created'
    Technique = 'T1053.005'
    Tactic    = 'Persistence'
    Severity  = 'Medium'
    Response  = @('Collect')
    # Tuning: built-in Microsoft tasks are noisy, so they are excluded.
    Match     = { param($e) $e.EventId -eq 4698 -and $e.Data['TaskName'] -notlike '\Microsoft\*' }
    Detail    = { param($e) "Task '$($e.Data['TaskName'])' created by '$($e.Data['SubjectUserName'])'" }
}
