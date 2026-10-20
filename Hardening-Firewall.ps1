<#
.SYNOPSIS
    Network protocol and inbound-port hardening.

.DESCRIPTION
    - Disables NetBIOS over TCP/IP on all interfaces (registry, works on PS 5.1 and 7)
    - Disables LLMNR and mDNS (name-poisoning / relay attack surface)
    - Disables insecure SMB guest logons
    - Creates idempotent inbound BLOCK rules for legacy cleartext services
      (Telnet 23, rexec/rlogin/rsh 512-514 TCP, TFTP 69 UDP). Block rules take
      precedence over allow rules in Windows Firewall.

    Supports -WhatIf. Registry values and the firewall rules created here can be
    removed with Restore-Hardening.ps1. NetBIOS is applied to existing interfaces;
    re-run after adding new network adapters.

.PARAMETER ExtraTcpPorts  Additional inbound TCP ports to block.
.PARAMETER ExtraUdpPorts  Additional inbound UDP ports to block.

.EXAMPLE
    .\Hardening-Firewall.ps1 -WhatIf
    .\Hardening-Firewall.ps1 -ExtraTcpPorts 5900
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(1, 65535)][int[]]$ExtraTcpPorts = @(),
    [ValidateRange(1, 65535)][int[]]$ExtraUdpPorts = @()
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
Initialize-Hardening -Name 'Network'

function New-BlockRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][ValidateSet('TCP', 'UDP')][string]$Protocol,
        [Parameter(Mandatory)][int[]]$Ports
    )
    $ports = @($Ports | Sort-Object -Unique)
    $name  = "EH_Block_${Protocol}_In"
    $list  = $ports -join ','
    if ($PSCmdlet.ShouldProcess("Firewall rule $name", "Block inbound $Protocol $list")) {
        if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {
            Remove-NetFirewallRule -Name $name
        }
        New-NetFirewallRule -Name $name `
                            -DisplayName "EndpointHardening: Block inbound $Protocol $list" `
                            -Group 'EndpointHardening' `
                            -Direction Inbound -Action Block -Protocol $Protocol `
                            -LocalPort ($ports | ForEach-Object { [string]$_ }) `
                            -Profile Any -Enabled True | Out-Null
        Add-BackupAction @{ Kind = 'FirewallRule'; Name = $name }
        Write-Log "Firewall rule $name set: block inbound $Protocol $list" 'OK'
    }
}

Invoke-Step 'Disable NetBIOS over TCP/IP' {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    $ifs  = @(Get-ChildItem -LiteralPath $base | Where-Object { $_.PSChildName -like 'Tcpip_*' })
    if ($ifs.Count -eq 0) { Write-Log 'No NetBT interfaces found.' 'WARN'; return }
    foreach ($i in $ifs) {
        Set-RegistryValue -Path (Join-Path $base $i.PSChildName) -Name 'NetbiosOptions' -Value 2
    }
}

Invoke-Step 'Disable LLMNR and mDNS' {
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0
    Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableMDNS' -Value 0
}

Invoke-Step 'Disable insecure SMB guest logons' {
    Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth' -Value 0
}

Invoke-Step 'Block legacy cleartext inbound ports' {
    New-BlockRule -Protocol TCP -Ports (@(23, 512, 513, 514) + $ExtraTcpPorts)
    New-BlockRule -Protocol UDP -Ports (@(69) + $ExtraUdpPorts)
}

exit (Complete-Hardening)
