<#
.SYNOPSIS
    Account and access-control hardening.

.DESCRIPTION
    - Disables the built-in Guest account (found by SID, so renaming does not matter)
    - Local password / lockout policy (net accounts)
    - RDP: requires NLA + TLS security layer + high encryption
    - Machine inactivity lock
    - LSA protection (RunAsPPL)
    - Disables WDigest plaintext credential caching

    Supports -WhatIf. Registry changes can be undone with Restore-Hardening.ps1.
    On domain-joined machines, Group Policy overrides local policy settings.

.PARAMETER LockoutThreshold   Failed attempts before lockout (default 5).
.PARAMETER LockoutMinutes     Lockout duration and observation window (default 15).
.PARAMETER MinPasswordLength  Minimum password length, 8-20 (default 14).
.PARAMETER InactivitySeconds  Idle time before lock (default 900).
.PARAMETER SkipPasswordPolicy Do not touch local password/lockout policy.
.PARAMETER SkipLsaProtection  Do not enable LSA protection.
.PARAMETER AcceptUefiLock     Allow RunAsPPL=1 on builds older than Windows 11 22H2.
                              WARNING: on UEFI systems this sets a lock that deleting the
                              registry value does NOT remove.

.EXAMPLE
    .\Hardening-Accounts.ps1 -WhatIf
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(1, 999)][int]$LockoutThreshold = 5,
    [ValidateRange(1, 99999)][int]$LockoutMinutes = 15,
    [ValidateRange(8, 20)][int]$MinPasswordLength = 14,
    [ValidateRange(60, 599940)][int]$InactivitySeconds = 900,
    [switch]$SkipPasswordPolicy,
    [switch]$SkipLsaProtection,
    [switch]$AcceptUefiLock
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
Initialize-Hardening -Name 'Accounts'

Invoke-Step 'Disable built-in Guest account' {
    $guest = @(Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-501' })
    if ($guest.Count -eq 0) { Write-Log 'Built-in Guest account not found.'; return }
    if ($guest[0].Enabled) {
        if ($PSCmdlet.ShouldProcess($guest[0].Name, 'Disable account')) {
            Disable-LocalUser -SID $guest[0].SID
            Write-Log "Guest account '$($guest[0].Name)' disabled." 'OK'
        }
    } else {
        Write-Log 'Guest account already disabled.'
    }
}

Invoke-Step 'Local password and lockout policy' {
    if ($SkipPasswordPolicy) { Write-Log 'Skipped (-SkipPasswordPolicy).'; return }
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        Write-Log 'Machine is domain-joined: domain Group Policy will override local password/lockout policy.' 'WARN'
    }
    if ($PSCmdlet.ShouldProcess('Local account policy', "Lockout $LockoutThreshold tries / $LockoutMinutes min, min length $MinPasswordLength")) {
        Write-Log 'Policy BEFORE change (kept for manual rollback):'
        foreach ($l in @(& net.exe accounts)) { if ($l.Trim()) { Write-Log "  $l" } }
        & net.exe accounts "/lockoutthreshold:$LockoutThreshold" "/lockoutduration:$LockoutMinutes" `
                           "/lockoutwindow:$LockoutMinutes" "/minpwlen:$MinPasswordLength" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "net accounts failed (exit code $LASTEXITCODE)" }
        Write-Log 'Local password/lockout policy applied. Existing passwords are not changed.' 'OK'
        Write-Log 'Note: lockout also applies to the local Administrator over the network; keep a second admin account.' 'WARN'
    }
}

Invoke-Step 'RDP: require NLA, TLS, high encryption' {
    $win = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    Set-RegistryValue -Path $win -Name 'UserAuthentication' -Value 1
    Set-RegistryValue -Path $win -Name 'SecurityLayer'      -Value 2
    Set-RegistryValue -Path $pol -Name 'UserAuthentication' -Value 1
    Set-RegistryValue -Path $pol -Name 'SecurityLayer'      -Value 2
    Set-RegistryValue -Path $pol -Name 'MinEncryptionLevel' -Value 3
}

Invoke-Step "Inactivity lock ($InactivitySeconds s)" {
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                      -Name 'InactivityTimeoutSecs' -Value $InactivitySeconds
}

Invoke-Step 'LSA protection (RunAsPPL)' {
    if ($SkipLsaProtection) { Write-Log 'Skipped (-SkipLsaProtection).'; return }
    $lsa     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $current = Get-RegistryValue -Path $lsa -Name 'RunAsPPL'
    if ($current -eq 1 -or $current -eq 2) { Write-Log "RunAsPPL already enabled ($current)."; return }

    $build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
    $mode  = $null
    if ($build -ge 22621)  { $mode = 2 }          # Windows 11 22H2+: enabled WITHOUT UEFI lock
    elseif ($AcceptUefiLock) { $mode = 1 }        # older builds: UEFI-locked
    if ($null -eq $mode) {
        Write-Log 'Skipped: on this Windows build RunAsPPL=1 creates a UEFI lock that cannot be undone by deleting the registry value. Re-run with -AcceptUefiLock if you accept that.' 'WARN'
        return
    }
    Set-RegistryValue -Path $lsa -Name 'RunAsPPL' -Value $mode
    Write-Log 'LSA protection configured. REBOOT required. Test AV/EDR, smart-card and third-party credential providers before wide rollout.' 'WARN'
}

Invoke-Step 'Disable WDigest plaintext credential caching' {
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
                      -Name 'UseLogonCredential' -Value 0
}

exit (Complete-Hardening)
