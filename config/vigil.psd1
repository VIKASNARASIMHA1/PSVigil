@{
    # How far back a one-shot scan looks (minutes)
    LookbackMinutes = 30

    # Stream mode: minutes of recent history loaded silently so correlation rules have context
    StreamBackfillMinutes = 15

    # Watch mode: seconds between polls
    PollSeconds     = 10

    # Output folder (relative to the project root)
    OutputDir       = 'output'

    # IPs that response actions must never block (gateway, DNS, your analyst box...)
    ProtectedIps    = @()

    # Optional Slack / Teams incoming-webhook URL for the 'Notify' action
    WebhookUrl      = ''

    # Event sources to collect. Missing logs (e.g. Sysmon) are skipped silently.
    Logs = @(
        @{ LogName = 'Security';                                 Id = 4688, 4624, 4625, 4720, 4698, 4697, 1102 }
        @{ LogName = 'System';                                   Id = 7045, 104 }
        @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 }
        @{ LogName = 'Microsoft-Windows-Sysmon/Operational';     Id = 1, 10, 13 }
        @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5001 }
    )
}
