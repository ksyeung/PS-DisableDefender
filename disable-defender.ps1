<#
Steps taken from the pre-installation instructions at 
https://github.com/mandiant/flare-vm

https://www.maketecheasier.com/permanently-disable-windows-defender-windows-10
Note: you still need to disable Tamper Protection before proceeding via
(Settings > Privacy & Security > Windows Security), this can't be automated.
#>

# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Relaunching script as administrator..." -ForegroundColor Yellow
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Define the backup file path using the script's directory
$backupFile = Join-Path -Path $PSScriptRoot -ChildPath "RegistryBackup_$((Get-Date).ToString('yyyyMMdd_HHmmss')).reg"

# Export the registry to the script's directory and suppress the output
cmd /c "reg export HKLM $backupFile /y" > $null 2>&1

if (Test-Path $backupFile) {
    Write-Host "Registry backup was successful. Backup saved to: $backupFile" -ForegroundColor Green
} else {
    Write-Host "Registry backup failed." -ForegroundColor Red
}

# Disable AntiSpyware
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -ErrorAction Stop
    Write-Host "Disabled Windows Defender AntiSpyware." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Windows Defender AntiSpyware." -ForegroundColor Red
}

# Signature Updates - Force Update from Microsoft Update
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ForceUpdateFromMU" -Value 0 -Type DWord -ErrorAction Stop
    Write-Host "Disabled Signature Updates for Defender." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Signature Updates for Defender." -ForegroundColor Red
}

# Real-Time Protection settings
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -ErrorAction Stop
    Write-Host "Disabled Real-time Monitoring." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Real-time Monitoring." -ForegroundColor Red
}

try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWord -ErrorAction Stop
    Write-Host "Disabled On-Access Protection." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable On-Access Protection." -ForegroundColor Red
}

try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -ErrorAction Stop
    Write-Host "Disabled Behavior Monitoring." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Behavior Monitoring." -ForegroundColor Red
}

try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -ErrorAction Stop
    Write-Host "Disabled Scan on Real-time Enable." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Scan on Real-time Enable." -ForegroundColor Red
}

# Spynet settings
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -Value 1 -Type DWord -ErrorAction Stop
    Write-Host "Disabled Block at First Sight." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Block at First Sight." -ForegroundColor Red
}

# Disable all tasks in the Windows Defender folder and suppress the output
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" | ForEach-Object {
    try {
        Disable-ScheduledTask -TaskPath $_.TaskPath -TaskName $_.TaskName -ErrorAction Stop
        Write-Host "Disabled scheduled task: $($_.TaskName)" -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable scheduled task: $($_.TaskName)" -ForegroundColor Red
    }
} | Out-Null

# Define the full registry key path for \Windows Defender\Scan
$fullKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"

# Create the full key path if it doesn't exist
New-Item -Path $fullKeyPath -Force | Out-Null

# Set the AllowPeriodicScanning value to 0 (disabled) and suppress the output
cmd /c "reg add `"$($fullKeyPath.Replace('HKLM:', 'HKLM'))`" /v AllowPeriodicScanning /t REG_DWORD /d 0 /f" > $null 2>&1
Write-Host "Disabled AllowPeriodicScanning." -ForegroundColor Green

# Function to set service startup type and handle errors
function Set-ServiceStartupType {
    param (
        [string]$ServiceName,
        [string]$DisplayName
    )

    try {
        Set-Service -Name $ServiceName -StartupType Manual -ErrorAction Stop
        Write-Host "Set $DisplayName service startup type to Manual." -ForegroundColor Green
    } catch {
        Write-Host "Access is denied for $DisplayName service." -ForegroundColor Red
    }
}

# Set Microsoft Defender Antivirus service (WinDefend) startup type to Manual
Set-ServiceStartupType -ServiceName "WinDefend" -DisplayName "Microsoft Defender Antivirus Service"

# Set Microsoft Defender Antivirus Network Inspection Service (WdNisSvc) startup type to Manual
Set-ServiceStartupType -ServiceName "WdNisSvc" -DisplayName "Microsoft Defender Antivirus Network Inspection Service"

# Set Windows Defender Firewall service (mpssvc) startup type to Manual
Set-ServiceStartupType -ServiceName "mpssvc" -DisplayName "Windows Defender Firewall"
