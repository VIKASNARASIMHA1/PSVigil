@{
    Id        = 'VGL-0011'
    Title     = 'PowerShell download cradle'
    Technique = 'T1105'
    Tactic    = 'Command and Control'
    Severity  = 'High'
    Response  = @('Collect', 'Notify')
    Match     = {
        param($e)
        $e.EventId -eq 4104 -and (
            $e.Data['ScriptBlockText'] -match '(?i)(DownloadString|DownloadFile)\s*\(\s*[''"]https?://' -or
            $e.Data['ScriptBlockText'] -match '(?i)(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\s+\S*https?://\S+.*\|\s*(iex|Invoke-Expression)'
        )
    }
    Dedupe    = @{ Key = { param($e) $e.Host }; WindowSeconds = 5 }
    Detail    = { param($e) 'Download cradle found in script block' }
}
