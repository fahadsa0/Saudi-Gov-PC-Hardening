<#
.SYNOPSIS
    Shared helpers for the Endpoint Hardening scripts (dot-source only).

.DESCRIPTION
    Provides: administrator check, logging, per-step error handling,
    registry changes that automatically save the previous value (rollback),
    and a final summary with a meaningful exit code.
    Do not run this file directly.

    Data folder (SYSTEM + Administrators only):
        %ProgramData%\EndpointHardening\Logs
        %ProgramData%\EndpointHardening\Backup
#>

Set-StrictMode -Version 1.0

$script:Root          = Join-Path $env:ProgramData 'EndpointHardening'
$script:LogDir        = Join-Path $script:Root 'Logs'
$script:BackupDir     = Join-Path $script:Root 'Backup'
$script:LogFile       = $null
$script:BackupFile    = $null
$script:BackupEntries = New-Object System.Collections.ArrayList
$script:Results       = New-Object System.Collections.ArrayList
$script:WarnCount     = 0

function Initialize-Hardening {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [switch]$NoBackupFile
    )

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'ERROR: Administrator privileges are required. Re-run PowerShell as Administrator.' -ForegroundColor Red
        exit 1
    }

    $firstRun = -not (Test-Path -LiteralPath $script:Root)
    foreach ($d in @($script:Root, $script:LogDir, $script:BackupDir)) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
    if ($firstRun) {
        # Only SYSTEM and local Administrators may read/write logs and rollback data.
        & icacls.exe $script:Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "WARNING: could not restrict permissions on $script:Root" -ForegroundColor Yellow
        }
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:LogFile = Join-Path $script:LogDir "$Name-$stamp.log"
    if (-not $NoBackupFile) {
        $script:BackupFile = Join-Path $script:BackupDir "$Name-$stamp.json"
    }

    Write-Log "=== $Name started on $env:COMPUTERNAME by $env:USERNAME ==="
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','OK','WARN','ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $color = 'Cyan'
    if ($Level -eq 'OK')    { $color = 'Green' }
    if ($Level -eq 'WARN')  { $color = 'Yellow'; $script:WarnCount++ }
    if ($Level -eq 'ERROR') { $color = 'Red' }
    Write-Host $line -ForegroundColor $color
    if ($script:LogFile) {
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
    }
}

function Get-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    if (Test-Path -LiteralPath $Path) {
        $key = Get-Item -LiteralPath $Path
        if ($key.GetValueNames() -contains $Name) { return $key.GetValue($Name) }
    }
    return $null
}

function Save-Backup {
    if ($script:BackupEntries.Count -eq 0) { return }
    if (-not $script:BackupFile) { return }
    $json = ConvertTo-Json -InputObject @($script:BackupEntries) -Depth 5
    Set-Content -LiteralPath $script:BackupFile -Value $json -Encoding UTF8
}

function Add-BackupAction {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Entry)
    [void]$script:BackupEntries.Add([pscustomobject]$Entry)
    Save-Backup
}

function Set-RegistryValue {
    <#
        Sets a registry value, but only if it differs from the desired value,
        and records the previous state so Restore-Hardening.ps1 can undo it.
        Honors -WhatIf of the calling script.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DWord','String','QWord','MultiString','ExpandString')][string]$Type = 'DWord'
    )

    $existed = $false
    $old     = $null
    $oldKind = $null
    if (Test-Path -LiteralPath $Path) {
        $key = Get-Item -LiteralPath $Path
        if ($key.GetValueNames() -contains $Name) {
            $existed = $true
            $old     = $key.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
            $oldKind = $key.GetValueKind($Name).ToString()
        }
    }

    if ($existed -and ($old -eq $Value)) {
        Write-Log "Already set: $Path\$Name = $Value"
        return
    }

    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value")) {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Add-BackupAction @{
            Kind = 'Registry'; Path = $Path; Name = $Name
            Existed = $existed; OldValue = $old; OldType = $oldKind
        }
        Write-Log "Registry set: $Path\$Name = $Value" 'OK'
    }
}

function Backup-AuditPolicy {
    <# Saves the full advanced audit policy once so it can be restored exactly. #>
    [CmdletBinding()]
    param()
    $file = Join-Path $script:BackupDir ('audit-{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    & auditpol.exe /backup "/file:$file" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol /backup failed (exit code $LASTEXITCODE)" }
    Add-BackupAction @{ Kind = 'AuditPolicy'; File = $file }
}

function Invoke-Step {
    <# Runs one hardening step; a failure is logged and does not stop the other steps. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Log "Step: $Name"
    try {
        & $Action
        [void]$script:Results.Add([pscustomobject]@{ Step = $Name; Status = 'OK' })
    }
    catch {
        Write-Log "Step failed [$Name]: $($_.Exception.Message)" 'ERROR'
        [void]$script:Results.Add([pscustomobject]@{ Step = $Name; Status = 'FAILED' })
    }
}

function Complete-Hardening {
    <# Prints an honest summary. Use as:  exit (Complete-Hardening)  #>
    [CmdletBinding()]
    param()
    $failed = @($script:Results | Where-Object { $_.Status -eq 'FAILED' })
    $level  = 'OK'
    if ($script:WarnCount -gt 0) { $level = 'WARN' }
    if ($failed.Count -gt 0)     { $level = 'ERROR' }

    Write-Log ('Finished: {0} step(s), {1} failed, {2} warning(s).' -f $script:Results.Count, $failed.Count, $script:WarnCount) $level
    foreach ($f in $failed) { Write-Log "  FAILED: $($f.Step)" 'ERROR' }
    if ($script:BackupFile -and (Test-Path -LiteralPath $script:BackupFile)) {
        Write-Log "Rollback data saved: $script:BackupFile"
    }
    Write-Log "Log file: $script:LogFile"

    if ($failed.Count -gt 0) { return 1 }
    return 0
}
