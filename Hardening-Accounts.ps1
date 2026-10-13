<#
====================================================================
 Title: Windows Endpoint Account & Access Control Hardening Script
 Author: Fahad Al-Shalawi
 Description: Enforces local account security policies, disables
              unused guest accounts, and mandates NLA for RDP.
====================================================================
#>

# 1. Administrator Privilege Check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Requires Administrator Privileges. Please run as Administrator."
    Exit
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Applying Account & Access Control Rules " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 2. Disable Built-in Guest Account
Write-Host "`n[1/4] Disabling Built-in Guest Account..." -ForegroundColor Yellow
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

# 3. Enforce Network Level Authentication (NLA) for Remote Desktop
Write-Host "`n[2/4] Mandating Network Level Authentication (NLA) for RDP..." -ForegroundColor Yellow
(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace "root\cimv2\terminalservices" -Filter "TerminalName='RDP-Tcp'").SetUserAuthenticationRequired(1) | Out-Null

# 4. Enforce Screen Saver Lock After Inactivity (Interactive Logon Timeout)
Write-Host "`n[3/4] Setting Screen Auto-Lock Timeout Policy..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900 -Type DWORD -Force

# 5. Prevent Storing Plaintext Passwords in Memory (LSASS Protection)
Write-Host "`n[4/4] Enabling LSASS RunAsPPL Credential Guard Protection..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWORD -Force

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host " Account Hardening Applied Successfully! " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
