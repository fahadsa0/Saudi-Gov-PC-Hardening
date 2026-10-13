<#
====================================================================
 Title: Windows Automated System Integrity & Repair Script
 Author: Fahad Al-Shalawi
 Description: Scans component stores and executes DISM/SFC commands
              to repair corrupted system files automatically.
====================================================================
#>

# 1. Administrator Privilege Check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Requires Administrator Privileges. Please run as Administrator."
    Exit
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Running Automated System Health Diagnostics " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 2. Scan DISM Health
Write-Host "`n[1/3] Scanning Windows Component Store Health (DISM)..." -ForegroundColor Yellow
dism /online /cleanup-image /scanhealth

# 3. Restore DISM Health
Write-Host "`n[2/3] Repairing Windows Component Store (DISM RestoreHealth)..." -ForegroundColor Yellow
dism /online /cleanup-image /restorehealth

# 4. Run System File Checker (SFC)
Write-Host "`n[3/3] Executing System File Checker (SFC Scan)..." -ForegroundColor Yellow
sfc /scannow

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host " System Integrity Check & Repair Finished! " -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
