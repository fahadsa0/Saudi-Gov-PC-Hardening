<#
====================================================================
 Title: Advanced Network & Port Hardening Script
 Author: Fahad Al-Shalawi
 Description: Closes vulnerable network protocols (NetBIOS, LLMNR)
              and enforces strict port-level security rules.
====================================================================
#>

# 1. Administrator Privilege Check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Requires Administrator Privileges. Please run as Administrator."
    Exit
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Applying Network Security Hardening Rules  " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 2. Disable NetBIOS over TCP/IP
Write-Host "`n[1/3] Disabling NetBIOS over TCP/IP on Network Adapters..." -ForegroundColor Yellow
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2) | Out-Null
}

# 3. Disable LLMNR Protocol via Registry Policy
Write-Host "`n[2/3] Disabling Link-Local Multicast Name Resolution (LLMNR)..." -ForegroundColor Yellow
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWORD -Force

# 4. Block Legacy Unencrypted Telnet Port (Port 23)
Write-Host "`n[3/3] Enforcing Firewall Rule to Block Telnet (Port 23)..." -ForegroundColor Yellow
New-NetFirewallRule -DisplayName "Block_Legacy_Telnet_Port23" -Direction Inbound -Action Block -Protocol TCP -LocalPort 23 -ErrorAction SilentlyContinue | Out-Null

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host " Network Hardening Policy Applied Successfully! " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
