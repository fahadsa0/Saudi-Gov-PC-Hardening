<#
.SYNOPSIS
    Rolls back changes recorded by the hardening scripts.

.DESCRIPTION
    Each hardening run that changes something writes a JSON file to
    %ProgramData%\EndpointHardening\Backup. This script replays that file in
    reverse order and restores:
      - registry values (previous value, or deletes values the script created)
      - firewall rules created by the scripts
      - firewall profile settings
      - the LocalMachine execution policy
      - the advanced audit policy

    NOT restored by design (re-enabling them lowers security; do it manually if needed):
      SMBv1, PowerShell v2, the Guest account, local password/lockout policy
      (previous values are written to the Accounts log), LSA protection set with a UEFI lock.
    Reboot after restoring.

.PARAMETER List        Show available backup files and exit.
.PARAMETER BackupFile  Backup JSON file to restore (must be inside the Backup folder).

.EXAMPLE
    .\Restore-Hardening.ps1 -List
    .\Restore-Hardening.ps1 -BackupFile "$env:ProgramData\EndpointHardening\Backup\Network-20261020-101500.json" -WhatIf
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$List,
    [string]$BackupFile
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
Initialize-Hardening -Name 'Restore' -NoBackupFile

$allowedRoot = $script:BackupDir.TrimEnd('\') + '\'

function Assert-InBackupFolder {
    param([Parameter(Mandatory)][string]$Path)
    $full = (Resolve-Path -LiteralPath $Path).Path
    if (-not $full.StartsWith($allowedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to use '$full': it is outside $allowedRoot"
    }
    return $full
}

if ($List) {
    $files = @(Get-ChildItem -LiteralPath $script:BackupDir -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($files.Count -eq 0) { Write-Log 'No backup files found.' 'WARN' }
    foreach ($f in $files) { Write-Log ('{0}  {1}' -f $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $f.FullName) }
    exit 0
}

if (-not $BackupFile) {
    Write-Log 'Specify -BackupFile <path> (see -List).' 'ERROR'
    exit 1
}

$backupPath = Assert-InBackupFolder -Path $BackupFile
$entries    = @(Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json)
[array]::Reverse($entries)
Write-Log "Restoring $($entries.Count) recorded change(s) from $backupPath"

foreach ($e in $entries) {
    Invoke-Step "Restore $($e.Kind)" {
        switch ($e.Kind) {
            'Registry' {
                if ($e.Path -notmatch '^HKLM:\\') { throw "Refusing non-HKLM registry path: $($e.Path)" }
                if ($e.Existed) {
                    if ($e.OldType -eq 'Binary') { Write-Log "Skipped binary value $($e.Path)\$($e.Name) (restore manually)." 'WARN'; return }
                    if ($PSCmdlet.ShouldProcess("$($e.Path)\$($e.Name)", "Restore previous value '$($e.OldValue)'")) {
                        if (-not (Test-Path -LiteralPath $e.Path)) { New-Item -Path $e.Path -Force | Out-Null }
                        New-ItemProperty -LiteralPath $e.Path -Name $e.Name -Value $e.OldValue -PropertyType $e.OldType -Force | Out-Null
                        Write-Log "Restored $($e.Path)\$($e.Name)" 'OK'
                    }
                } else {
                    if ($PSCmdlet.ShouldProcess("$($e.Path)\$($e.Name)", 'Remove value created by hardening')) {
                        Remove-ItemProperty -LiteralPath $e.Path -Name $e.Name -ErrorAction SilentlyContinue
                        Write-Log "Removed $($e.Path)\$($e.Name)" 'OK'
                    }
                }
            }
            'FirewallRule' {
                if ($e.Name -notlike 'EH_*') { throw "Refusing to remove non-hardening rule '$($e.Name)'" }
                if ($PSCmdlet.ShouldProcess("Firewall rule $($e.Name)", 'Remove')) {
                    Remove-NetFirewallRule -Name $e.Name -ErrorAction SilentlyContinue
                    Write-Log "Removed firewall rule $($e.Name)" 'OK'
                }
            }
            'FirewallProfile' {
                if ($PSCmdlet.ShouldProcess("Firewall profile $($e.Name)", 'Restore previous settings')) {
                    $p = @{ Name = $e.Name; Enabled = $e.Enabled; DefaultInboundAction = $e.DefaultInboundAction; LogBlocked = $e.LogBlocked }
                    if ([int]$e.LogMaxSizeKilobytes -gt 0) { $p['LogMaxSizeKilobytes'] = [int]$e.LogMaxSizeKilobytes }
                    Set-NetFirewallProfile @p
                    Write-Log "Restored firewall profile $($e.Name)" 'OK'
                }
            }
            'ExecutionPolicy' {
                if ($PSCmdlet.ShouldProcess('LocalMachine execution policy', "Restore '$($e.Value)'")) {
                    Set-ExecutionPolicy -ExecutionPolicy $e.Value -Scope LocalMachine -Force
                    Write-Log "Execution policy restored to $($e.Value)" 'OK'
                }
            }
            'AuditPolicy' {
                $file = Assert-InBackupFolder -Path $e.File
                if ($PSCmdlet.ShouldProcess('Advanced audit policy', "Restore from $file")) {
                    & auditpol.exe /restore "/file:$file" | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "auditpol /restore failed (exit code $LASTEXITCODE)" }
                    Write-Log 'Audit policy restored.' 'OK'
                }
            }
            default { Write-Log "Unknown entry kind '$($e.Kind)' skipped." 'WARN' }
        }
    }
}

Write-Log 'Reboot recommended. SMBv1, PowerShell v2, Guest account and password policy are not auto-restored (see Get-Help .\Restore-Hardening.ps1).' 'WARN'
exit (Complete-Hardening)
