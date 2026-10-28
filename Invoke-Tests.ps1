<#
.SYNOPSIS
  Dependency-free tests using fixture events (no admin rights, no real logs needed).
  Exit code 0 = all passed, 1 = at least one failure (CI friendly).
#>
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src/PSVigil.psm1') -Force
. (Join-Path $PSScriptRoot 'tests/Scenarios.ps1')

$rules  = @(Import-VigilRule)
$failed = 0
$checks = 0
function Report([bool]$ok, [string]$id, [string]$name, [string]$why = '') {
    $script:checks++
    if ($ok) { Write-Host ("PASS  {0,-9} {1}" -f $id, $name) -ForegroundColor Green }
    else { $script:failed++; Write-Host ("FAIL  {0,-9} {1} {2}" -f $id, $name, $why) -ForegroundColor Red }
}

foreach ($s in $Scenarios) {
    $alerts = @(Invoke-VigilDetection -Events $s.Events -Rules $rules | Where-Object { $_.RuleId -eq $s.Rule })
    if ($s.ContainsKey('ExpectCount')) { Report ($alerts.Count -eq $s.ExpectCount) $s.Rule $s.Name "(expected $($s.ExpectCount) alert(s), got $($alerts.Count))" }
    else { Report (($alerts.Count -gt 0) -eq $s.Expect) $s.Rule $s.Name "(expected fire=$($s.Expect), got $($alerts.Count))" }
}

# ---- Rolling state (backs Watch and Stream modes): events arrive in batches, each alert is emitted exactly once
$state = New-VigilState
$ip    = '10.9.9.9'
$batch1 = @(1..6 | ForEach-Object { New-FakeEvent -Id 4625 -SourceIp $ip -SecondsAgo (60 - $_) })
$out1   = @(Step-VigilState -State $state -Fresh $batch1 -Rules $rules)
Report (@($out1 | Where-Object RuleId -eq 'VGL-0002').Count -eq 1) 'STATE' 'batch 1: brute force alert emitted'
Report (@($out1 | Where-Object RuleId -eq 'VGL-0101').Count -eq 0) 'STATE' 'batch 1: no chain alert yet'
$out2 = @(Step-VigilState -State $state -Fresh @() -Rules $rules)
Report ($out2.Count -eq 0) 'STATE' 'empty batch: nothing re-emitted'
$batch3 = @(New-FakeEvent -Id 4624 -SourceIp $ip -SecondsAgo 1 -Data @{ LogonType = '3'; TargetUserName = 'admin' })
$out3   = @(Step-VigilState -State $state -Fresh $batch3 -Rules $rules)
Report (@($out3 | Where-Object RuleId -eq 'VGL-0101').Count -eq 1) 'STATE' 'batch 3: chain completes across batches'
Report (@($out3 | Where-Object RuleId -eq 'VGL-0002').Count -eq 0) 'STATE' 'batch 3: earlier alert not repeated'
$state2 = New-VigilState
$null   = @(Step-VigilState -State $state2 -Fresh $batch1 -Rules $rules -Silent)
$out4   = @(Step-VigilState -State $state2 -Fresh $batch3 -Rules $rules)
Report (@($out4 | Where-Object RuleId -eq 'VGL-0101').Count -eq 1 -and @($out4 | Where-Object RuleId -eq 'VGL-0002').Count -eq 0) 'STATE' 'silent backfill seeds history without re-alerting'

# ---- Self-trigger guard: PowerShell script block logging records the TEXT of every script that runs, including this
# project's own files. None of them may match the script-block rules, or the tool would alert on itself and the
# detection-test results would be meaningless.
$scriptFiles = Get-ChildItem -Path $PSScriptRoot -Recurse -Include *.ps1, *.psm1 | Where-Object { $_.FullName -notmatch '[\\/]output[\\/]' }
$selfHits = foreach ($f in $scriptFiles) {
    $ev = New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = (Get-Content -Raw -Path $f.FullName) }
    foreach ($a in Invoke-VigilDetection -Events @($ev) -Rules $rules) { "$($f.Name) -> $($a.RuleId)" }
}
Report (-not $selfHits) 'SELF' "no project script triggers a script-block rule ($(@($scriptFiles).Count) files checked)" ($selfHits -join '; ')

# ---- Every rule must have at least one positive and one negative scenario
foreach ($r in $rules) {
    $pos = @($Scenarios | Where-Object { $_.Rule -eq $r.Id -and (($_.ContainsKey('Expect') -and $_.Expect) -or ($_.ContainsKey('ExpectCount') -and $_.ExpectCount -ge 1)) }).Count
    $neg = @($Scenarios | Where-Object { $_.Rule -eq $r.Id -and $_.ContainsKey('Expect') -and -not $_.Expect }).Count
    Report ($pos -ge 1 -and $neg -ge 1) $r.Id "has positive ($pos) and negative ($neg) tests"
}

Write-Host ("`n{0} checks, {1} failed. Rules loaded: {2}" -f $checks, $failed, $rules.Count)
exit $(if ($failed) { 1 } else { 0 })
