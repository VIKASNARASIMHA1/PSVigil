@{
    Id        = 'VGL-0007'
    Title     = 'LSASS memory access (needs Sysmon)'
    Technique = 'T1003.001'
    Tactic    = 'Credential Access'
    Severity  = 'Critical'
    Response  = @('Collect', 'Notify')
    # Tuning: known-good readers of LSASS are excluded.
    Match     = {
        param($e)
        $e.EventId -eq 10 -and
        $e.Data['TargetImage'] -match '(?i)\\lsass\.exe$' -and
        $e.Data['GrantedAccess'] -match '(?i)^0x(1010|1410|1438|143a|1fffff|1f3fff|1f1fff)$' -and
        $e.Data['SourceImage'] -notmatch '(?i)\\(Windows\\System32\\|Windows Defender\\|MsMpEng\.exe$)'
    }
    Detail    = { param($e) "$($e.Data['SourceImage']) opened LSASS with access $($e.Data['GrantedAccess'])" }
}
