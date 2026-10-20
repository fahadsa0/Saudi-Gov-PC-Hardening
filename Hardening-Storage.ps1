<#
.SYNOPSIS
    Removable media and storage hardening.

.DESCRIPTION
    - Disables AutoRun / AutoPlay on all drive types
    - Enables removable-device audit logging (language-independent, by GUID):
        * Plug and Play Events
        * Removable Storage
    - Reports BitLocker status of every volume (reports only, never enables it:
      enabling without escrowing the recovery key can lock users out of their data)
    - Optional: block writes to removable drives not protected by BitLocker
    - Optional: block all removable disk access

    Supports -WhatIf. Registry and audit-policy changes can be undone with
    Restore-Hardening.ps1.

.PARAMETER BlockUnencryptedRemovableWrite
    Deny write access to removable drives that are not BitLocker-protected.

.PARAMETER BlockAllRemovableStorage
    Deny read and write access to removable disks entirely (strict).

.EXAMPLE
    .\Hardening-Storage.ps1 -WhatIf
    .\Hardening-Storage.ps1 -BlockUnencryptedRemovableWrite
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$BlockUnencryptedRemovableWrite,
    [switch]$BlockAllRemovableStorage
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
Initialize-Hardening -Name 'Storage'

Invoke-Step 'Disable AutoRun and AutoPlay' {
    $exp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Set-RegistryValue -Path $exp -Name 'NoDriveTypeAutoRun' -Value 255
    Set-RegistryValue -Path $exp -Name 'NoAutorun'          -Value 1
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' `
                      -Name 'NoAutoplayfornonVolume' -Value 1
}

Invoke-Step 'Enable removable-media audit logging' {
    if ($PSCmdlet.ShouldProcess('Advanced audit policy', 'Enable PNP Activity and Removable Storage auditing')) {
        Backup-AuditPolicy
        $subcategories = @(
            '{0CCE9248-69AE-11D9-BED3-505054503030}',   # Plug and Play Events
            '{0CCE9245-69AE-11D9-BED3-505054503030}'    # Removable Storage
        )
        foreach ($g in $subcategories) {
            & auditpol.exe /set "/subcategory:$g" /success:enable /failure:enable | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "auditpol /set failed for $g (exit code $LASTEXITCODE)" }
        }
        Write-Log 'Audit logging enabled. Make sure the Security event log size/retention is adequate.' 'OK'
    }
}

Invoke-Step 'Optional: block unencrypted removable writes' {
    if (-not $BlockUnencryptedRemovableWrite) { Write-Log 'Not requested (-BlockUnencryptedRemovableWrite).'; return }
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'RDVDenyWriteAccess' -Value 1
}

Invoke-Step 'Optional: block all removable storage' {
    if (-not $BlockAllRemovableStorage) { Write-Log 'Not requested (-BlockAllRemovableStorage).'; return }
    $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
    Set-RegistryValue -Path $k -Name 'Deny_Write' -Value 1
    Set-RegistryValue -Path $k -Name 'Deny_Read'  -Value 1
}

Invoke-Step 'Report BitLocker status' {
    if (-not (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        Write-Log 'BitLocker cmdlets are unavailable on this edition/configuration; cannot verify encryption.' 'WARN'
        return
    }
    foreach ($v in @(Get-BitLockerVolume -ErrorAction Stop)) {
        $text = '{0} protection={1} status={2} encrypted={3}%' -f $v.MountPoint, $v.ProtectionStatus, $v.VolumeStatus, $v.EncryptionPercentage
        if ([string]$v.ProtectionStatus -eq 'On') {
            Write-Log "BitLocker OK: $text" 'OK'
            $hasRecovery = @($v.KeyProtector | Where-Object { [string]$_.KeyProtectorType -eq 'RecoveryPassword' }).Count -gt 0
            if (-not $hasRecovery) { Write-Log "  $($v.MountPoint) has no recovery-password protector. Add one and escrow it (AD/Entra ID/secure storage)." 'WARN' }
        } else {
            Write-Log "BitLocker NOT protecting: $text. Encryption is strongly recommended." 'WARN'
        }
    }
}

exit (Complete-Hardening)
