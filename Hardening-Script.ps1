<#
====================================================================
 Title: Windows Endpoint Hardening & Security Baseline Script
 Author: Fahad Al-Shalawi
 Description: Automated PowerShell script designed to apply security
              baselines, disable vulnerable protocols, and execute
              safe system cleanup for endpoints.
====================================================================
#>

# 1. Verification of Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Requires Administrator Privileges. Please run as Administrator."
    Exit
}

Write-Host "=========================================" -ForegroundColor Green
Write-Host " Starting System Hardening & Maintenance " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green

# 2. Disable Legacy & Vulnerable Protocols (SMBv1)
Write-Host "`n[1/5] Disabling SMBv1 Protocol to protect against ransomware..." -ForegroundColor Yellow
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# 3. Ensure Windows Firewall Profile is Active
Write-Host "`n[2/5] Enforcing Windows Firewall Profiles..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

# 4. Flush DNS Cache to Prevent DNS Spoofing
Write-Host "`n[3/5] Flushing DNS Client Cache..." -ForegroundColor Yellow
Clear-DnsClientCache

# 5. Clean Temporary Files and System Cache
Write-Host "`n[4/5] Executing Safe System & Log Cleanup..." -ForegroundColor Yellow
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

# 6. Apply Execution Policy Standard
Write-Host "`n[5/5] Setting Script Execution Policy to RemoteSigned..." -ForegroundColor Yellow
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host " Security Baseline Applied Successfully! " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
