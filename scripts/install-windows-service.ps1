#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ProxyUrl,

    [Parameter(Mandatory = $true)]
    [string]$DomainsFile,

    [string]$Binary = ".\target\x86_64-pc-windows-gnu\release\selective-proxy.exe",

    [string]$Nssm = ".\nssm.exe",

    [ValidateRange(1, 65535)]
    [int]$Port = 12345,

    [string]$ServiceName = "SelectiveProxy"
)

$ErrorActionPreference = "Stop"
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$domainsPath = (Resolve-Path -LiteralPath $DomainsFile).Path
$nssmPath = (Resolve-Path -LiteralPath $Nssm).Path
$binaryDirectory = Split-Path -Parent $binaryPath

foreach ($file in @("WinDivert.dll", "WinDivert64.sys")) {
    if (-not (Test-Path -LiteralPath (Join-Path $binaryDirectory $file))) {
        throw "$file must be placed next to $binaryPath"
    }
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    if ($existing.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(15))
    }
    & $nssmPath remove $ServiceName confirm | Out-Null
    Start-Sleep -Seconds 1
}

& $nssmPath install $ServiceName $binaryPath | Out-Null
& $nssmPath set $ServiceName AppDirectory $binaryDirectory | Out-Null
& $nssmPath set $ServiceName AppParameters "run --domains `"$domainsPath`" --proxy `"$ProxyUrl`" --user service --port $Port" | Out-Null
& $nssmPath set $ServiceName DisplayName "Selective HTTP HTTPS Proxy" | Out-Null
& $nssmPath set $ServiceName Description "Selective transparent HTTP/HTTPS proxy using WinDivert" | Out-Null
& $nssmPath set $ServiceName Start SERVICE_DELAYED_AUTO_START | Out-Null
& $nssmPath set $ServiceName AppExit Default Restart | Out-Null
& $nssmPath set $ServiceName AppRestartDelay 3000 | Out-Null
& $nssmPath set $ServiceName AppStopMethodConsole 5000 | Out-Null
& $nssmPath set $ServiceName AppStopMethodWindow 5000 | Out-Null
& $nssmPath set $ServiceName AppStopMethodThreads 5000 | Out-Null

Start-Service -Name $ServiceName
Get-Service -Name $ServiceName | Format-Table -AutoSize

Write-Host "Service installed and started: $ServiceName"
Write-Host "Remove: Stop-Service $ServiceName; & `"$nssmPath`" remove $ServiceName confirm"
