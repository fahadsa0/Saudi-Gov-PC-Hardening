<#
====================================================================
 Title: Removable Media Security & Storage Hardening Script
 Author: Fahad Al-Shalawi
 Description: Disables AutoRun/AutoPlay for external drives and 
              enforces BitLocker status checks and audit logs.
====================================================================
#>

# 1. Administrator Privilege Check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Requires Administrator Privileges. Please run as Administrator."
    Exit
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Applying Storage & Removable Media Rules " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 2. Disable AutoRun and AutoPlay for All Drives
Write-Host "`n[1/3] Disabling AutoRun & AutoPlay Features..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWORD -Force

# 3. Enable Removable Storage Device Audit Events
Write-Host "`n[2/3] Enabling Audit Logging for Removable Storage Devices..." -ForegroundColor Yellow
auditpol /set /subcategory:"PNP Activity" /success:enable /failure:enable | Out-Null

# 4. Check BitLocker Encryption Status on OS Drive
Write-Host "`n[3/3] Verifying BitLocker System Volume Status..." -ForegroundColor Yellow
$bitlocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($bitlocker.ProtectionStatus -eq "On") {
    Write-Host " BitLocker Protection is Active on C:" -ForegroundColor Green
} else {
    Write-Warning " BitLocker is NOT active on C:. Encryption is recommended for sensitive environments."
}

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host " Storage Hardening Applied Successfully! " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
