@{
    Id        = 'VGL-0009'
    Title     = 'Microsoft Defender tampering'
    Technique = 'T1562.001'
    Tactic    = 'Defense Evasion'
    Severity  = 'High'
    Response  = @('Collect', 'Notify')
    Match     = {
        param($e)
        $e.EventId -eq 5001 -or
        ($e.EventId -eq 4104 -and
         $e.Data['ScriptBlockText'] -match '(?i)(Set|Add)-MpPreference\s+.*-(DisableRealtimeMonitoring|DisableIOAVProtection|ExclusionPath|ExclusionProcess)')
    }
    Detail    = { param($e) if ($e.EventId -eq 5001) { 'Defender real-time protection disabled' } else { 'Defender preference change in script block' } }
}
