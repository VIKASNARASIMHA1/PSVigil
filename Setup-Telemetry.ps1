#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Turns on the Windows logging PSVigil relies on. Run this in a LAB VM (take a snapshot first).
.PARAMETER InstallSysmon
  Also downloads Sysmon from Microsoft Sysinternals and installs it with config\sysmon-minimal.xml.
  Needed only for rules VGL-0006 (Run keys) and VGL-0007 (LSASS access).
#>
[CmdletBinding()]
param([switch]$InstallSysmon)

$ErrorActionPreference = 'Stop'

function Set-Audit([string]$Guid, [string]$Label) {
    # GUIDs keep this independent of the Windows display language
    & auditpol.exe /set /subcategory:"$Guid" /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host "  [ok] audit: $Label" } else { Write-Warning "  could not set audit policy: $Label" }
}

Write-Host '1) Audit policy'
Set-Audit '{0CCE922B-69AE-11D9-BED3-505054503030}' 'Process Creation (4688)'
Set-Audit '{0CCE9215-69AE-11D9-BED3-505054503030}' 'Logon (4624/4625)'
Set-Audit '{0CCE9235-69AE-11D9-BED3-505054503030}' 'User Account Management (4720)'
Set-Audit '{0CCE9227-69AE-11D9-BED3-505054503030}' 'Other Object Access (4698 scheduled tasks)'
Set-Audit '{0CCE9211-69AE-11D9-BED3-505054503030}' 'Security System Extension (4697 services)'

Write-Host '2) Command line in process-creation events'
$p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $p -Force | Out-Null
Set-ItemProperty -Path $p -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
Write-Host '  [ok]'

Write-Host '3) PowerShell script block logging (4104)'
$p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $p -Force | Out-Null
Set-ItemProperty -Path $p -Name EnableScriptBlockLogging -Value 1 -Type DWord
Write-Host '  [ok]'

Write-Host '4) Log sizes'
& wevtutil.exe sl Security /ms:268435456
& wevtutil.exe sl 'Microsoft-Windows-PowerShell/Operational' /ms:134217728
Write-Host '  [ok] Security=256MB, PowerShell/Operational=128MB'

if ($InstallSysmon) {
    Write-Host '5) Sysmon'
    $tmp = Join-Path $env:TEMP 'psvigil-sysmon'
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile (Join-Path $tmp 'Sysmon.zip') -UseBasicParsing
    Expand-Archive -Path (Join-Path $tmp 'Sysmon.zip') -DestinationPath $tmp -Force
    $exe = if ([Environment]::Is64BitOperatingSystem) { 'Sysmon64.exe' } else { 'Sysmon.exe' }
    $cfg = Join-Path $PSScriptRoot 'config\sysmon-minimal.xml'
    if (Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue) {
        & (Join-Path $tmp $exe) -accepteula -c $cfg | Out-Null
        Write-Host '  [ok] Sysmon config updated'
    } else {
        & (Join-Path $tmp $exe) -accepteula -i $cfg | Out-Null
        Write-Host '  [ok] Sysmon installed'
    }
}
Write-Host "`nTelemetry ready. Next: .\Invoke-Simulations.ps1 -Run All ; then .\Invoke-PSVigil.ps1 -Mode Scan -Minutes 10 -OpenReport"
