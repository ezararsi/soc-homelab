<#
.SYNOPSIS
    Installiert Wazuh-Agent und Sysmon auf einem Windows-Domänenmitglied und bindet das Sysmon-Log an.

.DESCRIPTION
    Idempotentes Verteilungsskript für das SOC-Lab. Jeder Schritt prüft zuerst, ob er bereits
    erledigt ist, und überspringt ihn dann. Dadurch kann das Skript beliebig oft ausgeführt werden.

    Ablage im Lab:  \\soclab.internal\NETLOGON\Install-SOCAgent.ps1
    Ausführung auf dem Client (als Domänen-Administrator, erhöhte PowerShell):
        powershell -ExecutionPolicy Bypass -File \\soclab.internal\NETLOGON\Install-SOCAgent.ps1

    SICHERHEIT: NETLOGON/SYSVOL ist für alle Domänenbenutzer lesbar.
    Dieses Skript enthält deshalb keinerlei Zugangsdaten (MITRE ATT&CK T1552.006).

.NOTES
    Wazuh-Agent-Version muss <= Manager-Version sein (Manager: 4.14.9).
#>

[CmdletBinding()]
param(
    [string]$Manager = '10.10.20.10',
    [string]$Version = '4.14.9-1',
    [string]$WorkDir = 'C:\Tools'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'   # beschleunigt Invoke-WebRequest deutlich

function Write-Step([string]$Text) { Write-Host "[*] $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text)   { Write-Host "[+] $Text" -ForegroundColor Green }

# --- 0. Voraussetzungen ---------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Bitte in einer PowerShell mit Administratorrechten ausführen.' }

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

Write-Step "Prüfe Erreichbarkeit des Wazuh-Managers $Manager (Port 1515)"
if (-not (Test-NetConnection -ComputerName $Manager -Port 1515 -InformationLevel Quiet)) {
    throw "Manager $Manager auf Port 1515 nicht erreichbar (Firewall-Regel Wazuh_Agent / Dienststatus prüfen)."
}
Write-Ok 'Manager erreichbar'

# --- 1. Wazuh-Agent ---------------------------------------------------------------
if (Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue) {
    Write-Ok 'Wazuh-Agent bereits installiert - übersprungen'
} else {
    $msi = Join-Path $WorkDir "wazuh-agent-$Version.msi"
    $log = Join-Path $WorkDir 'wazuh-agent-install.log'
    Write-Step "Lade Wazuh-Agent $Version"
    Invoke-WebRequest "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version.msi" -OutFile $msi

    Write-Step 'Installiere Wazuh-Agent (still, mit Protokoll)'
    # -Wait: msiexec kehrt sonst sofort zurück, während die Installation im Hintergrund läuft
    $msiArgs = "/i `"$msi`" /qn WAZUH_MANAGER=$Manager WAZUH_AGENT_NAME=$env:COMPUTERNAME /l*v `"$log`""
    $p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "msiexec ExitCode $($p.ExitCode) - siehe $log" }
    Write-Ok "Wazuh-Agent installiert (Agent-Name: $env:COMPUTERNAME)"
}

# --- 2. Sysmon ------------------------------------------------------------------
$sysmonDir = Join-Path $WorkDir 'Sysmon'
if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
    Write-Ok 'Sysmon bereits installiert - übersprungen'
} else {
    New-Item -ItemType Directory -Path $sysmonDir -Force | Out-Null
    Write-Step 'Lade Sysmon und SwiftOnSecurity-Konfiguration'
    Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$sysmonDir\Sysmon.zip"
    Expand-Archive "$sysmonDir\Sysmon.zip" -DestinationPath $sysmonDir -Force
    Invoke-WebRequest 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' `
        -OutFile "$sysmonDir\sysmonconfig.xml"

    Write-Step 'Installiere Sysmon'
    & "$sysmonDir\Sysmon64.exe" -accepteula -i "$sysmonDir\sysmonconfig.xml" | Out-Null
    Write-Ok 'Sysmon installiert'
}

# --- 3. Sysmon-Log an den Agenten anbinden ---------------------------------------
$conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
if (Select-String -Path $conf -Pattern 'Microsoft-Windows-Sysmon/Operational' -Quiet) {
    Write-Ok 'Sysmon-Log bereits angebunden - übersprungen'
} else {
    Copy-Item $conf "$conf.bak" -Force          # Backup vor jeder Konfigurationsänderung
    $block = @'

<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
'@
    Add-Content -Path $conf -Value $block -Encoding ASCII   # ASCII: kein BOM in der XML-Datei
    Write-Ok 'Sysmon-Log in ossec.conf eingetragen (Backup: ossec.conf.bak)'
}

# --- 4. Agent (neu) starten -------------------------------------------------------
Write-Step 'Starte Wazuh-Agent neu'
# Restart-Service überschreitet beim Stoppen gelegentlich die Zeitgrenze -> Prozess gezielt beenden
Stop-Process -Name wazuh-agent -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Service WazuhSvc

Get-Service WazuhSvc, Sysmon64 | Select-Object Name, Status | Format-Table -AutoSize
Write-Ok 'Fertig. Agent sollte im Wazuh-Dashboard als "Active" erscheinen.'
