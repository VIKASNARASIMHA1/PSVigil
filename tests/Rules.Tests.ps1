# Pester 5 wrapper around the same fixtures:  Invoke-Pester .\tests
BeforeDiscovery {
    . (Join-Path $PSScriptRoot 'Scenarios.ps1')
}
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\src\PSVigil.psm1') -Force
    . (Join-Path $PSScriptRoot 'Scenarios.ps1')
    $script:rules = @(Import-VigilRule)
}
Describe 'Detection rules' {
    It '<Name>' -ForEach $Scenarios {
        $alerts = @(Invoke-VigilDetection -Events $Events -Rules $script:rules | Where-Object { $_.RuleId -eq $Rule })
        if ($ExpectCount -ne $null) { $alerts.Count | Should -Be $ExpectCount }
        else { ($alerts.Count -gt 0) | Should -Be $Expect }
    }
}
