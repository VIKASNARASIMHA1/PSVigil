# PSVigil - a PowerShell-native mini SIEM: collect -> normalize -> detect -> respond -> report
$script:Root = Split-Path -Parent $PSScriptRoot

function Get-VigilConfig {
    Import-PowerShellDataFile -Path (Join-Path (Join-Path $script:Root 'config') 'vigil.psd1')
}

function Get-VigilRoot { $script:Root }

# ---------------------------------------------------------------- Normalizer
function ConvertFrom-WinEventRecord {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline, Mandatory)]$InputObject)
    process {
        $xml  = [xml]$InputObject.ToXml()
        $data = @{}
        $evt  = $xml.Event
        if ($evt.EventData -and $evt.EventData.Data) {
            foreach ($d in @($evt.EventData.Data)) {
                if ($d.Name) { $data[$d.Name] = [string]$d.'#text' }
            }
        }
        if ($evt.UserData) {
            # e.g. 1102 / 104 (log cleared) keep their fields under UserData
            $first = $evt.UserData.ChildNodes | Where-Object { $_.NodeType -eq 'Element' } | Select-Object -First 1
            if ($first) {
                foreach ($c in $first.ChildNodes) {
                    if ($c.NodeType -eq 'Element') { $data[$c.LocalName] = $c.InnerText }
                }
            }
        }
        $id   = [int]$InputObject.Id
        $user = $data['SubjectUserName']
        if (($id -eq 4624 -or $id -eq 4625) -and $data['TargetUserName']) { $user = $data['TargetUserName'] }
        if (-not $user) { $user = $data['User'] }
        $proc = $data['NewProcessName']
        if (-not $proc) { $proc = $data['Image'] }

        [pscustomobject]@{
            Time        = $InputObject.TimeCreated.ToUniversalTime()
            Host        = $InputObject.MachineName
            Channel     = $InputObject.LogName
            EventId     = $id
            RecordId    = $InputObject.RecordId
            User        = $user
            SourceIp    = $data['IpAddress']
            Process     = $proc
            CommandLine = $data['CommandLine']
            Data        = $data
        }
    }
}

# ---------------------------------------------------------------- Collector
function Get-VigilEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$StartTime,
        [string[]]$ComputerName,
        [pscredential]$Credential
    )
    $cfg     = Get-VigilConfig
    $targets = if ($ComputerName) { @($ComputerName) } else { @('') }   # '' = local machine
    foreach ($computer in $targets) {
        foreach ($log in $cfg.Logs) {
            $gw = @{
                FilterHashtable = @{ LogName = $log.LogName; Id = $log.Id; StartTime = $StartTime }
                ErrorAction     = 'Stop'
            }
            if ($computer) {
                $gw.ComputerName = $computer
                if ($Credential) { $gw.Credential = $Credential }
            }
            try {
                Get-WinEvent @gw | ConvertFrom-WinEventRecord
            }
            catch {
                $m = $_.Exception.Message
                if ($m -match 'No events were found') { continue }
                if ($m -match 'not an event log|no event log|There is not an event log') {
                    Write-Verbose "Log '$($log.LogName)' not present, skipping."; continue
                }
                Write-Warning "Collect failed for '$($log.LogName)': $m"
            }
        }
    }
}

# ---------------------------------------------------------------- Rules
function Import-VigilRule {
    [CmdletBinding()]
    param([string]$Path = (Join-Path $script:Root 'rules'))
    foreach ($f in Get-ChildItem -Path $Path -Filter '*.ps1' -ErrorAction Stop | Sort-Object Name) {
        $r = & $f.FullName
        foreach ($k in 'Id', 'Title', 'Technique', 'Severity') {
            if (-not $r.ContainsKey($k)) { throw "Rule file $($f.Name) is missing '$k'." }
        }
        if (-not $r.ContainsKey('Match') -and -not $r.ContainsKey('Correlation')) {
            throw "Rule file $($f.Name) needs either 'Match' or 'Correlation'."
        }
        $r
    }
}

# ---------------------------------------------------------------- Detection engine
function New-VigilAlert {
    param($Rule, $Event, [int]$Count = 1)

    $detail = $null
    if ($Rule.Detail) { $detail = [string](& $Rule.Detail $Event) }
    if (-not $detail) { $detail = $Event.CommandLine }
    if (-not $detail) { $detail = "EventId $($Event.EventId) on $($Event.Channel)" }

    # Enrichment 1: decode -EncodedCommand payloads
    $decoded = $null
    if ($Event.CommandLine -match '(?i)\s-e(?:n\w*|c)?\s+([A-Za-z0-9+/=]{8,})') {
        try { $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1])) } catch { }
    }
    # Enrichment 2: SHA256 of the process image (only if it exists on this machine)
    $hash = $null
    if ($Event.Process -and $Event.Host -like "$($env:COMPUTERNAME)*") {
        try {
            if (Test-Path -LiteralPath $Event.Process -PathType Leaf) {
                $hash = (Get-FileHash -LiteralPath $Event.Process -Algorithm SHA256).Hash
            }
        } catch { }
    }

    [pscustomobject]@{
        Time       = $Event.Time.ToString('o')
        Host       = $Event.Host
        RuleId     = $Rule.Id
        Title      = $Rule.Title
        Technique  = $Rule.Technique
        Tactic     = $Rule.Tactic
        Severity   = $Rule.Severity
        User       = $Event.User
        Target     = $Event.Data['TargetUserName']
        SourceIp   = $Event.SourceIp
        Count      = $Count
        Detail     = $detail
        Decoded    = $decoded
        Sha256     = $hash
        LatencySec = [math]::Round(((Get-Date).ToUniversalTime() - $Event.Time).TotalSeconds, 2)
        Response   = @($Rule.Response | Where-Object { $_ })
    }
}

function Test-VigilStep {
    # A correlation step matches an event if it matches any referenced base rule (Rules = @('VGL-0004',...)) or its own Match block.
    param($Step, $Event, $ById)
    try {
        if ($Step.Rules) {
            foreach ($rid in $Step.Rules) {
                $r = $ById[$rid]
                if ($r -and $r.Match -and (& $r.Match $Event)) { return $true }
            }
            return $false
        }
        if ($Step.Match) { return [bool](& $Step.Match $Event) }
    } catch { Write-Verbose "Step error: $_" }
    return $false
}

function Invoke-VigilCorrelation {
    # Ordered multi-step chain per key (host, source IP...) inside a time window.
    param($Rule, [object[]]$Events, $ById)
    $c      = $Rule.Correlation
    $steps  = @($c.Steps)
    $window = [int]$c.WindowSeconds
    $names  = (@($steps | ForEach-Object { $_.Name }) -join ' -> ')

    $keyed = foreach ($ev in $Events) {
        $k = $null
        try { $k = [string](& $c.Key $ev) } catch { }
        if ($k) { [pscustomobject]@{ Key = $k; Event = $ev } }
    }
    foreach ($g in ($keyed | Group-Object -Property Key)) {
        $items = @($g.Group | ForEach-Object { $_.Event } | Sort-Object Time)
        $match = New-Object 'object[]' $items.Count
        for ($i = 0; $i -lt $items.Count; $i++) {
            $row = New-Object 'bool[]' $steps.Count
            for ($s = 0; $s -lt $steps.Count; $s++) { $row[$s] = Test-VigilStep -Step $steps[$s] -Event $items[$i] -ById $ById }
            $match[$i] = $row
        }
        for ($a = 0; $a -lt $items.Count; $a++) {
            if (-not $match[$a][0]) { continue }
            $t0 = $items[$a].Time; $pos = $a - 1; $total = 0; $ok = $true
            for ($s = 0; $s -lt $steps.Count; $s++) {
                $need  = 1
                if ($steps[$s].MinCount) { $need = [int]$steps[$s].MinCount }
                $found = 0; $k = $pos + 1
                while ($k -lt $items.Count -and ($items[$k].Time - $t0).TotalSeconds -le $window) {
                    if ($match[$k][$s]) { $found++; if ($found -ge $need) { break } }
                    $k++
                }
                if ($found -lt $need) { $ok = $false; break }
                $pos = $k; $total += $found
            }
            if ($ok) {
                $alert = New-VigilAlert -Rule $Rule -Event $items[$pos] -Count $total
                $alert.Detail = "Chain [$names] key='$($g.Name)'"
                $alert
                break
            }
        }
    }
}

function Invoke-VigilDetection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Events,
        [Parameter(Mandatory)][object[]]$Rules
    )
    $byId = @{}
    foreach ($r in $Rules) { $byId[$r.Id] = $r }

    foreach ($rule in $Rules) {
        if ($rule.Correlation) { Invoke-VigilCorrelation -Rule $rule -Events $Events -ById $byId; continue }

        $matched = New-Object System.Collections.Generic.List[object]
        foreach ($ev in $Events) {
            $hit = $false
            try { $hit = [bool](& $rule.Match $ev) } catch { Write-Verbose "Rule $($rule.Id) error: $_" }
            if ($hit) { $matched.Add($ev) }
        }
        if ($matched.Count -eq 0) { continue }

        # De-duplication: collapse events that describe the same thing (e.g. 7045 + 4697 for one service install)
        if ($rule.Dedupe -and $matched.Count -gt 1) {
            $keep = New-Object System.Collections.Generic.List[object]
            $last = @{}
            foreach ($ev in ($matched | Sort-Object Time)) {
                $dk = [string](& $rule.Dedupe.Key $ev)
                if ($last.ContainsKey($dk) -and ($ev.Time - $last[$dk]).TotalSeconds -le [int]$rule.Dedupe.WindowSeconds) { continue }
                $last[$dk] = $ev.Time
                $keep.Add($ev)
            }
            $matched = $keep
        }

        if (-not $rule.Threshold) {
            foreach ($ev in $matched) { New-VigilAlert -Rule $rule -Event $ev }
            continue
        }

        # Threshold rule: N matching events inside a sliding window, per group key
        $need   = [int]$rule.Threshold.Count
        $window = [int]$rule.Threshold.WindowSeconds
        $keyed  = foreach ($m in $matched) {
            [pscustomobject]@{ Key = [string](& $rule.Threshold.GroupBy $m); Event = $m }
        }
        foreach ($g in ($keyed | Group-Object -Property Key)) {
            $items = @($g.Group | ForEach-Object { $_.Event } | Sort-Object Time)
            $i = 0
            for ($j = 0; $j -lt $items.Count; $j++) {
                while (($items[$j].Time - $items[$i].Time).TotalSeconds -gt $window) { $i++ }
                if (($j - $i + 1) -ge $need) {
                    New-VigilAlert -Rule $rule -Event $items[$j] -Count ($j - $i + 1)
                    break
                }
            }
        }
    }
}

# ---------------------------------------------------------------- Rolling state shared by Watch and Stream
function New-VigilState {
    @{ Buffer = @(); Alerted = (New-Object System.Collections.Generic.HashSet[string]) }
}

function Step-VigilState {
    <# Adds fresh events to a 15-minute rolling buffer, re-runs detection, returns only alerts not seen before.
       -Silent records alerts as seen without emitting them (used to seed history). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$State,
        [AllowEmptyCollection()][object[]]$Fresh = @(),
        [Parameter(Mandatory)][object[]]$Rules,
        [int]$BufferMinutes = 15,
        [switch]$Silent
    )
    $cutoff = (Get-Date).ToUniversalTime().AddMinutes(-$BufferMinutes)
    $State.Buffer = @(@($State.Buffer) + @($Fresh) | Where-Object { $_ -and $_.Time -ge $cutoff })
    foreach ($a in Invoke-VigilDetection -Events $State.Buffer -Rules $Rules) {
        if ($State.Alerted.Add("$($a.RuleId)|$($a.Host)|$($a.Time)|$($a.Detail)") -and -not $Silent) { $a }
    }
}

# ---------------------------------------------------------------- Live collection, mode 1: polling
function Start-VigilWatch {
    <# Polls the logs every few seconds and emits new alerts to the pipeline. Ctrl+C to stop. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Rules,
        [int]$PollSeconds = 10,
        [string[]]$ComputerName
    )
    $state = New-VigilState
    $seen  = New-Object System.Collections.Generic.HashSet[string]
    $since = (Get-Date).AddMinutes(-1)
    while ($true) {
        $pollStart = Get-Date
        $fresh = @(Get-VigilEvent -StartTime $since -ComputerName $ComputerName | Where-Object {
            $seen.Add("$($_.Host)|$($_.Channel)|$($_.RecordId)")
        })
        $since = $pollStart.AddSeconds(-3)     # small overlap; duplicates are removed via $seen
        if ($seen.Count -gt 50000) { $seen.Clear() }
        if ($fresh.Count -gt 0) { Step-VigilState -State $state -Fresh $fresh -Rules $Rules }
        Start-Sleep -Seconds $PollSeconds
    }
}

# ---------------------------------------------------------------- Live collection, mode 2: event-driven
function Start-VigilStream {
    <# Subscribes to the Windows event logs with EventLogWatcher (a .NET class): events arrive the moment they are
       written, no polling of the logs. Local machine only. Emits alerts to the pipeline. Ctrl+C to stop. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Rules,
        [int]$BackfillMinutes = 15
    )
    $cfg   = Get-VigilConfig
    $state = New-VigilState
    if ($BackfillMinutes -gt 0) {
        # Seed the correlation buffer with recent history without re-alerting on it
        $old = @(Get-VigilEvent -StartTime (Get-Date).AddMinutes(-$BackfillMinutes))
        $null = @(Step-VigilState -State $state -Fresh $old -Rules $Rules -Silent)
    }
    $watchers = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($log in $cfg.Logs) {
            $sid = "Vigil.$($log.LogName)"
            try {
                $ids   = (@($log.Id) | ForEach-Object { "EventID=$_" }) -join ' or '
                $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($log.LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, "*[System[($ids)]]")
                $w     = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher($query)
                $null  = Register-ObjectEvent -InputObject $w -EventName EventRecordWritten -SourceIdentifier $sid
                $w.Enabled = $true
                $watchers.Add($w)
                Write-Host "  subscribed: $($log.LogName)"
            }
            catch {
                Write-Host "  skipped:    $($log.LogName) (not available)" -ForegroundColor DarkGray
                Unregister-Event -SourceIdentifier $sid -ErrorAction SilentlyContinue
            }
        }
        while ($true) {
            $pending = @(Get-Event -ErrorAction SilentlyContinue | Where-Object { $_.SourceIdentifier -like 'Vigil.*' })
            if ($pending.Count -eq 0) { Start-Sleep -Milliseconds 250; continue }
            $fresh = foreach ($p in $pending) {
                $rec = $p.SourceEventArgs.EventRecord
                if ($rec) {
                    try { $rec | ConvertFrom-WinEventRecord } catch { Write-Verbose "Convert failed: $_" } finally { $rec.Dispose() }
                }
                Remove-Event -EventIdentifier $p.EventIdentifier -ErrorAction SilentlyContinue
            }
            Step-VigilState -State $state -Fresh @($fresh) -Rules $Rules
        }
    }
    finally {
        foreach ($w in $watchers) { try { $w.Enabled = $false; $w.Dispose() } catch { } }
        Get-EventSubscriber -ErrorAction SilentlyContinue | Where-Object { $_.SourceIdentifier -like 'Vigil.*' } | Unregister-Event -Force -ErrorAction SilentlyContinue
        Get-Event -ErrorAction SilentlyContinue | Where-Object { $_.SourceIdentifier -like 'Vigil.*' } | Remove-Event -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- Detection validation harness
function Invoke-VigilValidation {
    <# For each case: run the (benign) simulation, then poll the real logs until one of the expected rules fires or
       the timeout expires. Emits one result per case with the measured time-to-detect (seconds after the action ended). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Cases,
        [Parameter(Mandatory)][object[]]$Rules,
        [int]$TimeoutSeconds = 30,
        [int]$PollSeconds = 1
    )
    foreach ($case in $Cases) {
        Write-Host ("  testing {0,-26} expect {1}" -f $case.Name, (@($case.Rules) -join ',')) -NoNewline
        $start = Get-Date
        $err   = $null
        try { & $case.Script } catch { $err = $_.Exception.Message }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $detected = $false; $ttd = $null; $by = $null
        while ($true) {
            Start-Sleep -Seconds $PollSeconds
            $ev  = @(Get-VigilEvent -StartTime $start.AddSeconds(-2))
            $hit = @(Invoke-VigilDetection -Events $ev -Rules $Rules | Where-Object { @($case.Rules) -contains $_.RuleId })
            if ($hit.Count -gt 0) { $detected = $true; $ttd = [math]::Round($sw.Elapsed.TotalSeconds, 1); $by = $hit[0].RuleId; break }
            if ($sw.Elapsed.TotalSeconds -ge $TimeoutSeconds) { break }
        }
        Write-Host $(if ($detected) { "  DETECTED in ${ttd}s" } else { '  MISSED' }) -ForegroundColor $(if ($detected) { 'Green' } else { 'Red' })
        [pscustomobject]@{
            Case = $case.Name; Group = $case.Group; Technique = $case.Technique
            Expected = (@($case.Rules) -join ','); Detected = $detected; DetectedBy = $by
            TimeToDetectSec = $ttd; Error = $err
        }
    }
}

# ---------------------------------------------------------------- Response
function Write-VigilActionLog {
    param($Alert, [string]$Action, [string]$Mode, [string]$Result)
    $cfg = Get-VigilConfig
    $dir = Join-Path $script:Root $cfg.OutputDir
    New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null
    [pscustomobject]@{
        Time = (Get-Date).ToString('o'); RuleId = $Alert.RuleId; Action = $Action; Mode = $Mode; Result = $Result
    } | ConvertTo-Json -Compress | Add-Content -Path (Join-Path $dir 'actions.jsonl') -WhatIf:$false
}

function Invoke-VigilResponse {
    <# Runs response actions for an alert. Use -WhatIf for a dry run. #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Alert,
        [string[]]$Action
    )
    $cfg  = Get-VigilConfig
    $mode = if ($WhatIfPreference) { 'dry-run' } else { 'executed' }

    foreach ($a in $Action) {
        $result = if ($WhatIfPreference) { 'would run (dry-run)' } else { 'ok' }
        switch ($a) {
            'BlockIp' {
                $ip = $Alert.SourceIp
                $parsed = $null
                if (-not $ip -or -not [ipaddress]::TryParse($ip, [ref]$parsed) -or
                    [ipaddress]::IsLoopback($parsed) -or $ip -in '0.0.0.0', '::') {
                    $result = "skipped (no blockable source IP: '$ip')"; break
                }
                if ($cfg.ProtectedIps -contains $ip) { $result = "skipped (protected IP $ip)"; break }
                $name = "PSVigil-Block-$ip"
                if ($PSCmdlet.ShouldProcess($ip, 'Create inbound firewall block rule')) {
                    if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
                        New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Block -RemoteAddress $ip | Out-Null
                    }
                    $result = "blocked $ip"
                }
            }
            'DisableUser' {
                $u = $Alert.Target
                if (-not $u -or $u -eq 'Administrator' -or $u -eq $env:USERNAME -or $u.EndsWith('$')) {
                    $result = "skipped (protected or empty account '$u')"; break
                }
                $lu = Get-LocalUser -Name $u -ErrorAction SilentlyContinue
                if (-not $lu) { $result = "skipped (local user '$u' no longer exists)"; break }
                if ($PSCmdlet.ShouldProcess($u, 'Disable local user')) {
                    Disable-LocalUser -Name $u
                    $result = "disabled $u"
                }
            }
            'Collect' {
                $dir  = Join-Path (Join-Path $script:Root $cfg.OutputDir) 'triage'
                $file = Join-Path $dir ("{0}_{1}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $Alert.RuleId)
                if ($PSCmdlet.ShouldProcess($file, 'Write triage snapshot')) {
                    New-Item -ItemType Directory -Path $dir -Force | Out-Null
                    $runKeys = foreach ($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run') {
                        $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                        if ($p) {
                            $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
                                ForEach-Object { [pscustomobject]@{ Key = $k; Name = $_.Name; Value = $_.Value } }
                        }
                    }
                    [ordered]@{
                        Alert       = $Alert
                        Processes   = Get-Process | Select-Object Name, Id, Path
                        Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                                      Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
                        LocalUsers  = Get-LocalUser | Select-Object Name, Enabled, LastLogon
                        RunKeys     = @($runKeys)
                    } | ConvertTo-Json -Depth 5 | Set-Content -Path $file -Encoding UTF8
                    $result = "saved $file"
                }
            }
            'Notify' {
                if (-not $cfg.WebhookUrl) { $result = 'skipped (no WebhookUrl configured)'; break }
                if ($PSCmdlet.ShouldProcess('webhook', 'Send alert notification')) {
                    $text = "[PSVigil] $($Alert.Severity) $($Alert.RuleId) $($Alert.Title) on $($Alert.Host): $($Alert.Detail)"
                    Invoke-RestMethod -Uri $cfg.WebhookUrl -Method Post -ContentType 'application/json' -Body (@{ text = $text } | ConvertTo-Json) | Out-Null
                    $result = 'sent'
                }
            }
            default { $result = "unknown action '$a'" }
        }
        Write-VigilActionLog -Alert $Alert -Action $a -Mode $mode -Result $result
        Write-Host ("    [{0}] {1}: {2}" -f $mode, $a, $result) -ForegroundColor DarkCyan
    }
}

# ---------------------------------------------------------------- Reporting
function Export-VigilNavigatorLayer {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Rules, [object[]]$Alerts = @(), [Parameter(Mandatory)][string]$Path)
    $fired = @($Alerts | ForEach-Object { $_.RuleId } | Select-Object -Unique)
    $techniques = foreach ($g in ($Rules | Group-Object Technique)) {
        $score = if (@($g.Group | Where-Object { $fired -contains $_.Id }).Count -gt 0) { 2 } else { 1 }
        [ordered]@{
            techniqueID = $g.Name
            score       = $score
            comment     = (($g.Group | ForEach-Object { "$($_.Id) $($_.Title)" }) -join '; ')
        }
    }
    [ordered]@{
        name        = 'PSVigil coverage'
        versions    = [ordered]@{ attack = '15'; navigator = '5.1.0'; layer = '4.5' }
        domain      = 'enterprise-attack'
        description = '1 = rule exists, 2 = rule fired in the latest run'
        gradient    = [ordered]@{ colors = @('#ffffff', '#66b1ff', '#ff6666'); minValue = 0; maxValue = 2 }
        techniques  = @($techniques)
    } | ConvertTo-Json -Depth 6 | Set-Content -Path $Path -Encoding UTF8
}

function New-VigilReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Rules, [object[]]$Alerts = @(), [Parameter(Mandatory)][string]$Path)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $sevClass = @{ Critical = 'crit'; High = 'high'; Medium = 'med'; Low = 'low' }

    $coverage = foreach ($r in $Rules | Sort-Object { $_.Id }) {
        $n = @($Alerts | Where-Object { $_.RuleId -eq $r.Id }).Count
        $type = if ($r.Correlation) { 'Correlation' } elseif ($r.Threshold) { 'Threshold' } else { 'Single' }
        "<tr><td>$(& $enc $r.Id)</td><td>$(& $enc $r.Title)</td><td>$(& $enc $r.Technique)</td><td>$(& $enc $r.Tactic)</td><td>$type</td>" +
        "<td><span class='b $($sevClass[$r.Severity])'>$(& $enc $r.Severity)</span></td><td>$n</td></tr>"
    }
    $rows = foreach ($a in $Alerts | Sort-Object Time -Descending) {
        $extra = if ($a.Decoded) { "<br><small>decoded: $(& $enc $a.Decoded)</small>" } else { '' }
        "<tr><td>$(& $enc $a.Time)</td><td>$(& $enc $a.Host)</td><td>$(& $enc $a.RuleId)</td><td>$(& $enc $a.Title)</td>" +
        "<td>$(& $enc $a.Technique)</td><td><span class='b $($sevClass[$a.Severity])'>$(& $enc $a.Severity)</span></td>" +
        "<td>$(& $enc $a.LatencySec)</td><td>$(& $enc $a.Detail)$extra</td></tr>"
    }
    $firedRules = @($Alerts | ForEach-Object { $_.RuleId } | Select-Object -Unique).Count
    $firedIds = @($Alerts | ForEach-Object { $_.RuleId } | Select-Object -Unique)
    $tacticOrder = 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
                   'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'
    $matrixCols = foreach ($t in $tacticOrder) {
        $rs = @($Rules | Where-Object { $_.Tactic -eq $t } | Sort-Object { $_.Technique })
        $chips = if ($rs.Count -gt 0) {
            ($rs | ForEach-Object {
                $cls = if ($firedIds -contains $_.Id) { 'fired' } else { 'covered' }
                "<div class='chip $cls'><b>$(& $enc $_.Technique)</b><br>$(& $enc $_.Title)</div>"
            }) -join ''
        } else { "<div class='chip none'>no rule</div>" }
        "<div class='col'><h3>$(& $enc $t)</h3>$chips</div>"
    }
    $techCount = @($Rules | ForEach-Object { $_.Technique } | Select-Object -Unique).Count
    $alertRows  = if ($rows) { $rows -join "`n" } else { '<tr><td colspan="8">No alerts in this run.</td></tr>' }
    $html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>PSVigil report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1f23;background:#fff}
h1{margin-bottom:4px}.sub{color:#57606a;margin-top:0}
.cards{display:flex;gap:12px;margin:16px 0}.card{border:1px solid #d0d7de;border-radius:8px;padding:12px 18px}
.card b{display:block;font-size:26px}
table{border-collapse:collapse;width:100%;margin:12px 0 28px;font-size:14px}
th,td{border:1px solid #d0d7de;padding:6px 10px;text-align:left;vertical-align:top}th{background:#f6f8fa}
.b{padding:2px 8px;border-radius:10px;color:#fff;font-size:12px}
.crit{background:#82071e}.high{background:#cf222e}.med{background:#bf8700}.low{background:#2da44e}
small{color:#57606a}
.matrix{display:grid;grid-template-columns:repeat(12,minmax(118px,1fr));gap:6px;overflow-x:auto;margin:12px 0 8px}
.col h3{font-size:12px;margin:0 0 6px;padding:6px;background:#24292f;color:#fff;border-radius:4px;text-align:center}
.chip{font-size:11px;padding:6px;border-radius:4px;margin-bottom:5px;line-height:1.3}
.chip.covered{background:#ddf4ff;border:1px solid #54aeff}.chip.fired{background:#ffebe9;border:1px solid #ff8182}
.chip.none{background:#f6f8fa;border:1px dashed #d0d7de;color:#8c959f;text-align:center}
.legend span{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;margin-right:8px}
</style></head><body>
<h1>PSVigil report</h1><p class="sub">Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<div class="cards">
<div class="card"><b>$(@($Alerts).Count)</b>alerts</div>
<div class="card"><b>$(@($Rules).Count)</b>rules loaded</div>
<div class="card"><b>$firedRules</b>rules fired</div>
</div>
<h2>ATT&amp;CK coverage matrix</h2>
<p class="legend"><span class="chip fired">fired in this run</span><span class="chip covered">rule exists</span><span class="chip none">gap: no rule</span> $techCount techniques covered. Tactic names follow the classic ATT&amp;CK matrix.</p>
<div class="matrix">
$($matrixCols -join "`n")
</div>
<h2>Detection coverage</h2>
<table><tr><th>Rule</th><th>Title</th><th>ATT&amp;CK</th><th>Tactic</th><th>Type</th><th>Severity</th><th>Alerts</th></tr>
$($coverage -join "`n")</table>
<h2>Alerts</h2>
<table><tr><th>Time (UTC)</th><th>Host</th><th>Rule</th><th>Title</th><th>ATT&amp;CK</th><th>Severity</th><th>Event to alert (s)</th><th>Detail</th></tr>
$alertRows</table>
</body></html>
"@
    Set-Content -Path $Path -Value $html -Encoding UTF8
}

Export-ModuleMember -Function Get-VigilConfig, Get-VigilRoot, ConvertFrom-WinEventRecord, Get-VigilEvent,
    Import-VigilRule, Invoke-VigilDetection, New-VigilState, Step-VigilState, Start-VigilWatch, Start-VigilStream,
    Invoke-VigilValidation, Invoke-VigilResponse, Export-VigilNavigatorLayer, New-VigilReport