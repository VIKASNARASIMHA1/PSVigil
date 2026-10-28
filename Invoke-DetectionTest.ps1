#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Detection validation harness. Runs each benign simulation, waits for the matching rule to fire in the REAL logs,
  and records detected / missed and time-to-detect. Writes output\detection-results.json and .md (paste the table
  into your README as evidence).
.EXAMPLE
  .\Invoke-DetectionTest.ps1                          # basic + variants + chains
  .\Invoke-DetectionTest.ps1 -Group variants          # only the evasion attempts
  .\Invoke-DetectionTest.ps1 -TimeoutSeconds 45 -IncludeLogCleared
#>
[CmdletBinding()]
param(
    [ValidateSet('basic', 'variants', 'chains')][string[]]$Group = @('basic', 'variants', 'chains'),
    [int]$TimeoutSeconds = 30,
    [switch]$IncludeLogCleared
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src\PSVigil.psm1') -Force
. (Join-Path $PSScriptRoot 'simulations\Catalog.ps1')
$cfg    = Get-VigilConfig
$outDir = Join-Path $PSScriptRoot $cfg.OutputDir
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$rules  = @(Import-VigilRule)

$hasSysmon = [bool](Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue)
$cases = foreach ($k in $Catalog.Keys) {
    $c = $Catalog[$k]
    if ($Group -notcontains $c.Group) { continue }
    if ($c.Confirm -and -not $IncludeLogCleared) { Write-Host "  skipping $k (use -IncludeLogCleared)" -ForegroundColor DarkGray; continue }
    if ($c.NeedsSysmon -and -not $hasSysmon) { Write-Host "  skipping $k (needs Sysmon)" -ForegroundColor DarkGray; continue }
    [pscustomobject]@{ Name = $k; Group = $c.Group; Technique = $c.Technique; Rules = $c.Rules; Script = $c.Script }
}

Write-Host "Running $(@($cases).Count) detection tests (timeout $TimeoutSeconds s each)...`n" -ForegroundColor Cyan
$results = @(Invoke-VigilValidation -Cases @($cases) -Rules $rules -TimeoutSeconds $TimeoutSeconds)

$total = $results.Count
$hit   = @($results | Where-Object Detected).Count
$times = @($results | Where-Object { $_.Detected } | ForEach-Object { $_.TimeToDetectSec })
$avg   = if ($times.Count) { [math]::Round(($times | Measure-Object -Average).Average, 1) } else { $null }
Write-Host "`n$hit of $total detected ($([math]::Round(100 * $hit / [math]::Max($total, 1)))%), average time to detect: $avg s" -ForegroundColor Cyan
$missed = @($results | Where-Object { -not $_.Detected })
if ($missed.Count) {
    Write-Host 'Gaps (missed):' -ForegroundColor Yellow
    $missed | ForEach-Object { Write-Host ("  {0} (expected {1}){2}" -f $_.Case, $_.Expected, $(if ($_.Error) { " - error: $($_.Error)" })) }
}

$results | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $outDir 'detection-results.json') -Encoding UTF8
$md = @('| Test | Group | ATT&CK | Expected rule | Result | Time to detect (s) |', '|---|---|---|---|---|---|')
$md += $results | ForEach-Object {
    '| {0} | {1} | {2} | {3} | {4} | {5} |' -f $_.Case, $_.Group, $_.Technique, $_.Expected, $(if ($_.Detected) { 'Detected' } else { '**MISSED**' }), $_.TimeToDetectSec
}
$md += ''
$md += "Detection rate: $hit/$total. Average time to detect: $avg s (measured from the end of each simulation until the rule fired, 1 s polling)."
Set-Content -Path (Join-Path $outDir 'detection-results.md') -Value $md -Encoding UTF8
Write-Host "`nSaved: $(Join-Path $outDir 'detection-results.md')"
