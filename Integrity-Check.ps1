<#
.SYNOPSIS
    System integrity check/repair (DISM + SFC) and hardening-script verification.

.DESCRIPTION
    Default mode:
      1. Warns if a reboot is pending (can make DISM/SFC fail)
      2. Scans the component store (Repair-WindowsImage -ScanHealth)
      3. Repairs it ONLY if corruption is reported (-RestoreHealth)
      4. Runs sfc /scannow (after DISM, as recommended)

    Verification modes (they run instead of the repair):
      -CreateManifest : writes SHA256SUMS.txt for the *.ps1 files next to this script
      -VerifyScripts  : reports Authenticode signature status and compares hashes
                        with SHA256SUMS.txt. Use this before running the scripts on
                        a new machine to make sure nobody modified them.

    DISM RestoreHealth normally needs access to Windows Update; use -Source for
    offline/air-gapped devices.

.PARAMETER Source     Repair source, e.g. "WIM:D:\sources\install.wim:1" (limits Windows Update access).
.PARAMETER SkipSfc    Skip sfc /scannow.
.PARAMETER CreateManifest
.PARAMETER VerifyScripts

.EXAMPLE
    .\Integrity-Check.ps1
    .\Integrity-Check.ps1 -CreateManifest
    .\Integrity-Check.ps1 -VerifyScripts
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Source,
    [switch]$SkipSfc,
    [switch]$CreateManifest,
    [switch]$VerifyScripts
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
Initialize-Hardening -Name 'Integrity' -NoBackupFile

$manifest = Join-Path $PSScriptRoot 'SHA256SUMS.txt'

# --- Verification modes ---------------------------------------------------
if ($CreateManifest) {
    Invoke-Step 'Create SHA256 manifest' {
        $lines = foreach ($f in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | Sort-Object Name)) {
            '{0}  {1}' -f (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower(), $f.Name
        }
        Set-Content -LiteralPath $manifest -Value $lines -Encoding ASCII
        Write-Log "Manifest written: $manifest ($(@($lines).Count) files). Store a copy somewhere trusted/offline." 'OK'
    }
    exit (Complete-Hardening)
}

if ($VerifyScripts) {
    Invoke-Step 'Verify hardening scripts' {
        $expected = @{}
        if (Test-Path -LiteralPath $manifest) {
            foreach ($l in @(Get-Content -LiteralPath $manifest)) {
                if ($l -match '^([0-9a-fA-F]{64})\s+(.+)$') { $expected[$Matches[2].Trim()] = $Matches[1].ToLower() }
            }
        } else {
            Write-Log 'SHA256SUMS.txt not found: hash comparison skipped (create it with -CreateManifest).' 'WARN'
        }
        $bad = 0
        foreach ($f in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | Sort-Object Name)) {
            $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower()
            $sig  = (Get-AuthenticodeSignature -LiteralPath $f.FullName).Status
            if ($expected.Count -gt 0) {
                if (-not $expected.ContainsKey($f.Name))   { Write-Log "UNLISTED : $($f.Name) (not in manifest) signature=$sig" 'WARN'; $bad++ }
                elseif ($expected[$f.Name] -ne $hash)       { Write-Log "MODIFIED : $($f.Name) hash differs from manifest! signature=$sig" 'ERROR'; $bad++ }
                else                                        { Write-Log "OK       : $($f.Name) signature=$sig" 'OK' }
            } else {
                Write-Log "$($f.Name) sha256=$hash signature=$sig"
            }
        }
        foreach ($n in $expected.Keys) {
            if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $n))) { Write-Log "MISSING  : $n is in the manifest but not on disk" 'ERROR'; $bad++ }
        }
        if ($bad -gt 0) { throw "$bad integrity problem(s) found. Do NOT run these scripts until resolved." }
    }
    exit (Complete-Hardening)
}

# --- Repair mode ----------------------------------------------------------
$script:ImageState = 'Unknown'

function Test-PendingReboot {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($k in $keys) { if (Test-Path -LiteralPath $k) { return $true } }
    if ($null -ne (Get-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations')) { return $true }
    return $false
}

Invoke-Step 'Check for pending reboot' {
    if (Test-PendingReboot) { Write-Log 'A reboot is pending. Reboot first for reliable DISM/SFC results.' 'WARN' }
    else { Write-Log 'No pending reboot detected.' }
}

Invoke-Step 'DISM: scan component store' {
    $r = Repair-WindowsImage -Online -ScanHealth
    $script:ImageState = [string]$r.ImageHealthState
    Write-Log "Component store state: $script:ImageState"
    if ($script:ImageState -ne 'Healthy' -and $script:ImageState -ne 'Repairable' -and $script:ImageState -ne 'NonRepairable') {
        throw "Unexpected image health state '$script:ImageState'"
    }
}

Invoke-Step 'DISM: repair component store (only if needed)' {
    if ($script:ImageState -eq 'Healthy')       { Write-Log 'Component store is healthy; no repair needed.' 'OK'; return }
    if ($script:ImageState -eq 'NonRepairable') { throw 'Component store is NOT repairable online. Provide a repair source (-Source) or reinstall/reset Windows.' }
    if ($script:ImageState -ne 'Repairable')    { Write-Log 'Skipped: scan did not complete.' 'WARN'; return }

    $p = @{ Online = $true; RestoreHealth = $true }
    if ($Source) { $p['Source'] = $Source; $p['LimitAccess'] = $true }
    $r = Repair-WindowsImage @p
    Write-Log "Component store state after repair: $([string]$r.ImageHealthState)" 'OK'
}

Invoke-Step 'SFC: verify and repair protected system files' {
    if ($SkipSfc) { Write-Log 'Skipped (-SkipSfc).'; return }
    & sfc.exe /scannow
    Write-Log "sfc exit code: $LASTEXITCODE"
    if ($LASTEXITCODE -ne 0) {
        Write-Log 'SFC returned a non-zero code. Review %windir%\Logs\CBS\CBS.log for details.' 'WARN'
    }
}

exit (Complete-Hardening)
