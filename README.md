# 🛡️ Windows Endpoint Security Hardening Baseline

A modular suite of PowerShell scripts that applies a security baseline to Windows endpoints: protocol hardening, access control, removable-media protection, auditing, and integrity verification. Every script supports `-WhatIf`, logs what it does, records the previous state, and can be rolled back.

> **Read before using.** These scripts change security settings. Test on a non-production machine/VM first, review every change against your organization's policy, and keep a recovery plan. No script can guarantee a system is "100% secure"; this is a baseline, not a certification. It has **not** been audited against any specific standard (e.g. NCA ECC, CIS, Microsoft Security Baseline); map the settings to your required controls before claiming compliance.

---

## 🛠️ Modules

| File | Purpose |
|---|---|
| `Common.ps1` | Shared helpers (logging, per-step error handling, rollback data). Dot-sourced, not run directly. |
| `Hardening-Script.ps1` | Core baseline: disables SMBv1, firewall profiles (block inbound, log drops), PowerShell script-block logging, disables PowerShell v2, execution policy, optional SMB signing and cleanup. |
| `Hardening-Accounts.ps1` | Disables built-in Guest (by SID), local password/lockout policy, RDP NLA + TLS, inactivity lock, LSA protection (RunAsPPL), disables WDigest. |
| `Hardening-Storage.ps1` | Disables AutoRun/AutoPlay, enables removable-device audit logging, reports BitLocker status of all volumes, optional removable-media write/read blocking. |
| `Hardening-Firewall.ps1` | Disables NetBIOS over TCP/IP, LLMNR, mDNS and insecure SMB guest logons; idempotent inbound block rules for legacy cleartext ports. |
| `Integrity-Check.ps1` | DISM scan, repair only when needed, then SFC; plus `-CreateManifest` / `-VerifyScripts` to detect tampering of these scripts. |
| `Restore-Hardening.ps1` | Rolls back recorded changes. |

---

## 🚀 How to Run

1. Download the latest release ZIP from the **Releases** page (do not run scripts piped from the internet). Copy the SHA-256 hashes published in the **release notes**.
2. Open **PowerShell as Administrator** in the extracted folder.
3. Verify the files **without executing anything**, and compare with the hashes in the release notes (case-insensitive). A `SHA256SUMS.txt` inside the same ZIP only detects accidental corruption, so always compare against the separately published copy:
   ```powershell
   Get-FileHash .\*.ps1 -Algorithm SHA256 | Select-Object Hash, @{n='File';e={Split-Path $_.Path -Leaf}}
   ```
4. Unblock the files only after verification:
   ```powershell
   Get-ChildItem .\*.ps1 | Unblock-File
   ```
5. Preview, then apply (test on a VM first):
   ```powershell
   .\Hardening-Script.ps1   -WhatIf
   .\Hardening-Accounts.ps1 -WhatIf
   .\Hardening-Storage.ps1  -WhatIf
   .\Hardening-Firewall.ps1 -WhatIf

   .\Hardening-Script.ps1
   .\Hardening-Accounts.ps1
   .\Hardening-Storage.ps1
   .\Hardening-Firewall.ps1
   ```
6. Reboot (needed for LSA protection and SMBv1/PowerShell v2 feature removal).

Later re-checks on a machine you already trust can use `.\Integrity-Check.ps1 -VerifyScripts` (it compares against `SHA256SUMS.txt`, created with `-CreateManifest`).

> Independent project: not affiliated with or certified by any government body.

---

### Useful options

| Script | Option | Effect |
|---|---|---|
| Core | `-ExecutionPolicy AllSigned` | Stricter policy (never weakens an existing stricter one) |
| Core | `-RequireSmbSigning` | Require SMB signing (can break old NAS/printers) |
| Core | `-Cleanup` | Flush DNS + delete temp files older than 7 days (skips junctions) |
| Accounts | `-LockoutThreshold`, `-LockoutMinutes`, `-MinPasswordLength`, `-InactivitySeconds` | Tune policy values |
| Accounts | `-SkipPasswordPolicy`, `-SkipLsaProtection` | Opt out of a section |
| Accounts | `-AcceptUefiLock` | Allow RunAsPPL=1 on pre-Windows 11 22H2 (UEFI lock, hard to undo) |
| Storage | `-BlockUnencryptedRemovableWrite` | Deny writes to non-BitLocker removable drives |
| Storage | `-BlockAllRemovableStorage` | Deny all removable disk access |
| Firewall | `-ExtraTcpPorts`, `-ExtraUdpPorts` | Additional inbound ports to block |

---

## 📋 Logs, Backups, Rollback

* Logs: `%ProgramData%\EndpointHardening\Logs`
* Rollback data: `%ProgramData%\EndpointHardening\Backup` (folder restricted to SYSTEM + Administrators)
* Exit code is `0` on success and `1` if any step failed. A failed step never prints "success".

```powershell
.\Restore-Hardening.ps1 -List
.\Restore-Hardening.ps1 -BackupFile "$env:ProgramData\EndpointHardening\Backup\<file>.json" -WhatIf
```

Not auto-restored by design (re-enabling lowers security): SMBv1, PowerShell v2, Guest account, local password policy (old values are in the log), LSA protection with a UEFI lock.

---

## ⚠️ Compatibility notes

* **Domain / Intune-managed devices:** Group Policy/MDM overrides local settings. The scripts warn when they detect this.
* **LSA protection:** can break incompatible security agents or credential providers. Pilot first.
* **Account lockout:** also applies to the local Administrator over the network; keep a second admin account.
* **NetBIOS/LLMNR/SMB changes:** may affect legacy file shares, printers and name resolution.
* **BitLocker:** the script only reports. Enabling it must include recovery-key escrow.

## ✅ Suggested test checklist

1. Run with `-WhatIf` and read the output.
2. Apply on a VM snapshot; confirm login, RDP (if used), file shares, VPN, AV/EDR.
3. Reboot and re-check.
4. Run `Restore-Hardening.ps1` and confirm settings return.
5. Pilot on a few real machines before wide rollout.

## 📄 License

MIT. See `LICENSE`.
