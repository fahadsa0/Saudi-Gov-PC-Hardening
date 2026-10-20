<#
.SYNOPSIS
    Core Windows endpoint security baseline.

.DESCRIPTION
    - Disables SMBv1 (server protocol and Windows feature)
    - Optionally requires SMB signing (server + client)
    - Enables all firewall profiles, blocks inbound by default, logs dropped packets
    - Enables PowerShell script-block logging and disables PowerShell v2
    - Sets the execution policy (never weakens a stricter existing setting)
    - Optional cleanup (DNS cache + temp files older than 7 days)

    Supports -WhatIf. Registry/firewall/execution-policy changes can be undone
    with Restore-Hardening.ps1. Removing SMBv1 / PowerShell v2 is intentionally
    NOT auto-restored (re-enabling them is insecure).

.PARAMETER ExecutionPolicy
    RemoteSigned (default) or AllSigned.

.PARAMETER RequireSmbSigning
    Require SMB signing. May break old NAS/printers that do not support signing.

.PARAMETER Cleanup
    Flush DNS cache and delete temp files older than 7 days.

.EXAMPLE
    .\Hardening-Script.ps1 -WhatIf
    .\Hardening-Script.ps1 -ExecutionPolicy AllSigned -RequireSmbSigning
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('RemoteSigned', 'AllSigned')][string]$ExecutionPolicy = 'RemoteSigned',
    [switch]$RequireSmbSigning,
    [switch]$Cleanup
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
Initialize-Hardening -Name 'Core'

function Remove-OldFiles {
    # Deletes files older than $Days. Never follows junctions/symlinks, which
    # prevents a low-privileged user from redirecting deletion elsewhere.
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Path, [int]$Days = 7)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $cutoff = (Get-Date).AddDays(-$Days)
    $stack  = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Path)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($item.PSIsContainer) { $stack.Push($item.FullName); continue }
            if ($item.LastWriteTime -lt $cutoff) {
                if ($PSCmdlet.ShouldProcess($item.FullName, 'Delete')) {
                    Remove-Item -LiteralPath $item.FullName -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
}

# --- 1. SMBv1 -------------------------------------------------------------
Invoke-Step 'Disable SMBv1 server protocol' {
    if ((Get-SmbServerConfiguration).EnableSMB1Protocol) {
        if ($PSCmdlet.ShouldProcess('SMB server', 'Disable SMBv1')) {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
            Write-Log 'SMBv1 server protocol disabled.' 'OK'
        }
    } else {
        Write-Log 'SMBv1 server protocol already disabled.'
    }
}

Invoke-Step 'Remove SMBv1 Windows feature' {
    $f = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue
    if ($f -and $f.State -eq 'Enabled') {
        if ($PSCmdlet.ShouldProcess('SMB1Protocol feature', 'Disable')) {
            Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart | Out-Null
            Write-Log 'SMB1Protocol feature disabled (takes full effect after reboot).' 'OK'
        }
    } else {
        Write-Log 'SMB1Protocol feature not present or already disabled.'
    }
}

Invoke-Step 'SMB signing' {
    if (-not $RequireSmbSigning) { Write-Log 'SMB signing not requested (use -RequireSmbSigning).'; return }
    $srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $cli = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    Set-RegistryValue -Path $srv -Name 'RequireSecuritySignature' -Value 1
    Set-RegistryValue -Path $srv -Name 'EnableSecuritySignature'  -Value 1
    Set-RegistryValue -Path $cli -Name 'RequireSecuritySignature' -Value 1
    Set-RegistryValue -Path $cli -Name 'EnableSecuritySignature'  -Value 1
}

# --- 2. Firewall ----------------------------------------------------------
Invoke-Step 'Enforce Windows Firewall profiles' {
    foreach ($p in @(Get-NetFirewallProfile -Profile Domain, Private, Public)) {
        $compliant = ([string]$p.Enabled -eq 'True') -and
                     ([string]$p.DefaultInboundAction -eq 'Block') -and
                     ([string]$p.LogBlocked -eq 'True') -and
                     ([int]$p.LogMaxSizeKilobytes -ge 16384)
        if ($compliant) { Write-Log "Firewall profile $($p.Name) already compliant."; continue }

        if ($PSCmdlet.ShouldProcess("Firewall profile $($p.Name)", 'Enable, block inbound by default, log drops')) {
            Add-BackupAction @{
                Kind = 'FirewallProfile'; Name = [string]$p.Name
                Enabled = [string]$p.Enabled
                DefaultInboundAction = [string]$p.DefaultInboundAction
                LogBlocked = [string]$p.LogBlocked
                LogMaxSizeKilobytes = [int]$p.LogMaxSizeKilobytes
            }
            Set-NetFirewallProfile -Name $p.Name -Enabled True -DefaultInboundAction Block `
                                   -LogBlocked True -LogMaxSizeKilobytes 16384
            Write-Log "Firewall profile $($p.Name) hardened." 'OK'
        }
    }
}

# --- 3. PowerShell --------------------------------------------------------
Invoke-Step 'PowerShell script-block logging' {
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
                      -Name 'EnableScriptBlockLogging' -Value 1
}

Invoke-Step 'Disable PowerShell v2 (downgrade-attack surface)' {
    $f = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction SilentlyContinue
    if ($f -and $f.State -eq 'Enabled') {
        if ($PSCmdlet.ShouldProcess('MicrosoftWindowsPowerShellV2Root', 'Disable')) {
            Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart | Out-Null
            Write-Log 'PowerShell v2 disabled.' 'OK'
        }
    } else {
        Write-Log 'PowerShell v2 not present or already disabled.'
    }
}

Invoke-Step "Execution policy ($ExecutionPolicy)" {
    $gpo = @(Get-ExecutionPolicy -List | Where-Object {
        ($_.Scope -eq 'MachinePolicy' -or $_.Scope -eq 'UserPolicy') -and [string]$_.ExecutionPolicy -ne 'Undefined'
    })
    if ($gpo.Count -gt 0) {
        Write-Log 'Execution policy is enforced by Group Policy; not changing it locally.' 'WARN'
        return
    }
    $rank    = @{ Restricted = 0; AllSigned = 1; RemoteSigned = 2; Default = 2; Unrestricted = 3; Bypass = 4; Undefined = 5 }
    $current = [string](Get-ExecutionPolicy -Scope LocalMachine)
    if ($rank[$current] -le $rank[$ExecutionPolicy]) {
        Write-Log "LocalMachine policy is already $current (same or stricter); leaving it unchanged."
        return
    }
    if ($PSCmdlet.ShouldProcess('LocalMachine execution policy', "Set to $ExecutionPolicy")) {
        Add-BackupAction @{ Kind = 'ExecutionPolicy'; Value = $current }
        Set-ExecutionPolicy -ExecutionPolicy $ExecutionPolicy -Scope LocalMachine -Force
        Write-Log "Execution policy set to $ExecutionPolicy (note: not a security boundary by itself)." 'OK'
    }
}

# --- 4. Optional cleanup --------------------------------------------------
Invoke-Step 'Optional cleanup (DNS cache, old temp files)' {
    if (-not $Cleanup) { Write-Log 'Cleanup not requested (use -Cleanup).'; return }
    if ($PSCmdlet.ShouldProcess('DNS client cache', 'Flush')) { Clear-DnsClientCache }
    Remove-OldFiles -Path $env:TEMP -Days 7
    Remove-OldFiles -Path (Join-Path $env:SystemRoot 'Temp') -Days 7
    Write-Log 'Cleanup finished.' 'OK'
}

exit (Complete-Hardening)
