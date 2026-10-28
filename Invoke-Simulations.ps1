#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Safe, self-cleaning simulations that generate the same telemetry as real attack techniques.
  Run only in a lab VM. Nothing here dumps credentials, disables security tools, or touches other machines.
.EXAMPLE
  .\Invoke-Simulations.ps1 -List
  .\Invoke-Simulations.ps1 -Run All                 # the basic set: one example per technique
  .\Invoke-Simulations.ps1 -Run Variants            # evasion attempts (-enc, -ec, tiny payload, in-line decode...)
  .\Invoke-Simulations.ps1 -Run Chains              # multi-step sequences for the correlation rules
  .\Invoke-Simulations.ps1 -Run NewLocalUser,NewService
  .\Invoke-Simulations.ps1 -Run LogCleared          # clears the *Application* log; asks for confirmation
#>
[CmdletBinding()]
param(
    [string[]]$Run,
    [switch]$List
)

. (Join-Path $PSScriptRoot 'simulations\Catalog.ps1')

if ($List -or -not $Run) {
    $Catalog.GetEnumerator() | ForEach-Object {
        '{0,-26} {1,-9} {2,-10} {3}' -f $_.Key, $_.Value.Group, ($_.Value.Rules -join ','), $_.Value.Desc
    }
    Write-Host "`nUse -Run All (basic set, excludes LogCleared), -Run Variants, -Run Chains, or -Run <Name>[,<Name>]."
    Write-Host "Not simulated (needs real attack tooling): VGL-0007 LSASS access, VGL-0010 RDP logon - covered by fixture tests."
    return
}

$names = foreach ($r in $Run) {
    switch ($r) {
        'All'      { $Catalog.Keys | Where-Object { $Catalog[$_].Group -eq 'basic' -and -not $Catalog[$_].Confirm } }
        'Variants' { $Catalog.Keys | Where-Object { $Catalog[$_].Group -eq 'variants' } }
        'Chains'   { $Catalog.Keys | Where-Object { $Catalog[$_].Group -eq 'chains' } }
        default    { $r }
    }
}
foreach ($n in $names) {
    if (-not $Catalog.Contains($n)) { Write-Warning "Unknown simulation '$n'"; continue }
    $s = $Catalog[$n]
    if ($s.Confirm -and (Read-Host "Run '$n'? ($($s.Desc)) [y/N]") -ne 'y') { continue }
    Write-Host ("Simulating {0,-26} -> expect {1}" -f $n, ($s.Rules -join ',')) -ForegroundColor Yellow
    try { & $s.Script } catch { Write-Warning "  $n failed: $($_.Exception.Message)" }
}
Write-Host "`nWait ~10 seconds for events to flush, then run: .\Invoke-PSVigil.ps1 -Mode Scan -Minutes 10 -OpenReport"
