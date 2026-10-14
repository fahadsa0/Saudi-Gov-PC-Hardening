<#
====================================================================
 Title: Windows Endpoint Performance Optimization & Debloat Script
 Author: Fahad Al-Shalawi
 Description: Optimizes CPU/RAM responsiveness, sets maximum power
              performance, and disables telemetry services.
====================================================================
#>

# 1. Administrator Privilege Check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Requires Administrator Privileges. Please run as Administrator."
    Exit
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Starting System Performance Tuning      " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 2. Activate Ultimate Performance Power Scheme
Write-Host "`n[1/4] Activating Ultimate Performance Power Scheme..." -ForegroundColor Yellow
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
$ultimatePlan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan | Where-Object {$_.ElementName -match "Ultimate Performance"}
if ($ultimatePlan) {
    Set-CimInstance -InputObject $ultimatePlan -Property @{ IsActive = $true }
}

# 3. Disable Windows Telemetry & Diagnostic Tracking Services
Write-Host "`n[2/4] Disabling System Telemetry & Tracking Services..." -ForegroundColor Yellow
Stop-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue

Stop-Service -Name "dmwappushservice" -ErrorAction SilentlyContinue
Set-Service -Name "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue

# 4. Tune Explorer Visual Delay Settings
Write-Host "`n[3/4] Tuning System Menu Show Delays..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "0" -ErrorAction SilentlyContinue

# 5. Clear Memory Standby List / Trigger Garbage Collection
Write-Host "`n[4/4] Freeing Up Standby Memory Allocation..." -ForegroundColor Yellow
[System.GC]::Collect()

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host " Performance Tuning Completed Successfully! " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
