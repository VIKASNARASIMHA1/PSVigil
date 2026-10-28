@{
    Id        = 'VGL-0012'
    Title     = 'Runtime base64 decode and execute'
    Technique = 'T1027'
    Tactic    = 'Defense Evasion'
    Severity  = 'High'
    Response  = @('Collect', 'Notify')
    # Added after evasion testing: attackers avoid the encoded-command switch by decoding a base64 string
    # in-line and piping it to the expression evaluator. The regexes below use character classes so that this
    # rule file does not match its own source text when PowerShell script block logging records it.
    Match     = {
        param($e)
        $t = if ($e.EventId -eq 4104) { $e.Data['ScriptBlockText'] } else { $e.CommandLine }
        ($e.EventId -eq 1 -or $e.EventId -eq 4688 -or $e.EventId -eq 4104) -and
        $t -match '(?i)From[B]ase64String' -and
        $t -match '(?i)\b(ie[x]|Invoke-Expressio[n])\b'
    }
    # The process command line (4688) and its script block (4104) describe the same execution
    Dedupe    = @{ Key = { param($e) $e.Host }; WindowSeconds = 10 }
    Detail    = { param($e) 'Base64 payload decoded and executed at runtime' }
}
