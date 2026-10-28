#Requires -RunAsAdministrator
<#
.SYNOPSIS
  PSVigil - PowerShell-native detection & response.
.EXAMPLE
  .\Invoke-PSVigil.ps1 -Mode Scan -Minutes 30          # one-shot scan, dry-run responses
  .\Invoke-PSVigil.ps1 -Mode Stream                    # event-driven live monitoring (local machine, Ctrl+C to stop)
  .\Invoke-PSVigil.ps1 -Mode Watch                     # polling live monitoring (works with -ComputerName too)
  .\Invoke-PSVigil.ps1 -Mode Scan -EnableResponse      # actually run response actions (lab only!)
  .\Invoke-PSVigil.ps1 -Mode Scan -ComputerName SRV01  # collect from a remote host over RPC/WinRM
#>
[CmdletBinding()]
param(
    [ValidateSet('Scan', 'Watch', 'Stream')][string]$Mode = 'Scan',
    [int]$Minutes,
    [string[]]$ComputerName,
    [pscredential]$Credential,
    [switch]$EnableResponse,
    [switch]$OpenReport
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src\PSVigil.psm1') -Force
$cfg    = Get-VigilConfig
$outDir = Join-Path $PSScriptRoot $cfg.OutputDir
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$rules  = @(Import-VigilRule)
if ($Minutes -le 0) { $Minutes = $cfg.LookbackMinutes }

$colors = @{ Critical = 'Magenta'; High = 'Red'; Medium = 'Yellow'; Low = 'Green' }
$session = New-Object System.Collections.Generic.List[object]

function Write-AlertAndRespond {
    param($Alert)
    $session.Add($Alert)
    Write-Host ("[{0}] {1} {2} - {3} ({4})" -f $Alert.Severity.ToUpper(), $Alert.RuleId, $Alert.Title, $Alert.Technique, $Alert.Host) -ForegroundColor $colors[$Alert.Severity]
    Write-Host ("    {0}" -f $Alert.Detail)
    if ($Mode -ne 'Scan') { Write-Host ("    event -> alert: {0} s" -f $Alert.LatencySec) -ForegroundColor DarkGray }
    if ($Alert.Decoded) { Write-Host ("    decoded payload: {0}" -f $Alert.Decoded) -ForegroundColor DarkYellow }
    $Alert | ConvertTo-Json -Compress -Depth 4 | Add-Content -Path (Join-Path $outDir 'alerts.jsonl')
    if ($Alert.Response) {
        Invoke-VigilResponse -Alert $Alert -Action $Alert.Response -WhatIf:(-not $EnableResponse)
    }
}

function Save-Outputs {
    New-VigilReport -Rules $rules -Alerts $session.ToArray() -Path (Join-Path $outDir 'report.html')
    Export-VigilNavigatorLayer -Rules $rules -Alerts $session.ToArray() -Path (Join-Path $outDir 'navigator-layer.json')
    Write-Host "`nReport : $(Join-Path $outDir 'report.html')"
    Write-Host "Layer  : $(Join-Path $outDir 'navigator-layer.json')  (load at https://mitre-attack.github.io/attack-navigator/)"
    if ($OpenReport) { Invoke-Item (Join-Path $outDir 'report.html') }
}

Write-Host "PSVigil | mode=$Mode | rules=$($rules.Count) | response=$(if ($EnableResponse) { 'ENABLED' } else { 'dry-run' })" -ForegroundColor Cyan

if ($Mode -eq 'Scan') {
    $start  = (Get-Date).AddMinutes(-$Minutes)
    $events = @(Get-VigilEvent -StartTime $start -ComputerName $ComputerName -Credential $Credential)
    Write-Host "Collected $($events.Count) events from the last $Minutes minute(s)."
    if ($events.Count -eq 0) { Write-Warning 'No events collected. Run Setup-Telemetry.ps1 and Invoke-Simulations.ps1 first, then scan again.' }
    foreach ($a in Invoke-VigilDetection -Events $events -Rules $rules) { Write-AlertAndRespond $a }
    Write-Host "`nDone: $($session.Count) alert(s)."
    Save-Outputs
}
elseif ($Mode -eq 'Watch') {
    Write-Host "Watching by polling every $($cfg.PollSeconds)s. Press Ctrl+C to stop and write the report."
    try {
        Start-VigilWatch -Rules $rules -PollSeconds $cfg.PollSeconds -ComputerName $ComputerName |
            ForEach-Object { Write-AlertAndRespond $_ }
    }
    finally { Save-Outputs }
}
else {
    if ($ComputerName) { throw 'Stream mode reads the local event logs only. Use -Mode Watch with -ComputerName.' }
    Write-Host 'Streaming events as they are written (EventLogWatcher). Press Ctrl+C to stop and write the report.'
    try {
        Start-VigilStream -Rules $rules -BackfillMinutes $cfg.StreamBackfillMinutes |
            ForEach-Object { Write-AlertAndRespond $_ }
    }
    finally { Save-Outputs }
}
