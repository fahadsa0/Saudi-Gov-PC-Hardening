# 📘 Usage Guide

How to download, verify, run, and roll back the hardening scripts. العربية: [USAGE.ar.md](USAGE.ar.md)

> ⚠️ These scripts change Windows security settings. **Test on a virtual machine first.** Never run them on a production or work device without approval from your IT/security team.

---

## 1. Requirements

| Requirement | Details |
|---|---|
| OS | Windows 10 / 11 (Pro, Enterprise or Education recommended) |
| PowerShell | **Windows PowerShell 5.1** (built in; open "Windows PowerShell"). PowerShell 7 is not tested. |
| Rights | Local **Administrator** |
| Files | All `.ps1` files must stay **in the same folder** (the scripts load `Common.ps1`) |
| Home edition | Works, but BitLocker reporting will be unavailable |

---

## 2. Get and verify the files

1. Open the **Releases** page of this repository and download the latest ZIP.
2. Copy the SHA-256 hashes written in the **release notes**.
3. Extract the ZIP to a folder, e.g. `C:\Hardening`.
4. Right-click the Start button, choose **Terminal (Admin)** or **Windows PowerShell (Admin)**.
5. Go to the folder and compute the hashes (this does not execute anything):
   ```powershell
   cd C:\Hardening
   Get-FileHash .\*.ps1 -Algorithm SHA256 | Select-Object Hash, @{n='File';e={Split-Path $_.Path -Leaf}}
   ```
6. Compare each hash with the release notes. **If any hash differs, stop and do not run the scripts.**
7. Only after the hashes match, unblock the files:
   ```powershell
   Get-ChildItem .\*.ps1 | Unblock-File
   ```

> Why unblock? Files downloaded from the internet are marked as untrusted by Windows. The `RemoteSigned` policy refuses to run them until you unblock them.

---

## 3. What each script does

| Script | Changes made | Optional switches |
|---|---|---|
| `Hardening-Script.ps1` | Disables SMBv1, enables firewall (blocks inbound, logs drops), PowerShell script-block logging, disables PowerShell v2, sets execution policy | `-ExecutionPolicy AllSigned`, `-RequireSmbSigning`, `-Cleanup` |
| `Hardening-Accounts.ps1` | Disables Guest, password/lockout policy, RDP NLA + TLS, inactivity lock, LSA protection, disables WDigest | `-LockoutThreshold`, `-LockoutMinutes`, `-MinPasswordLength`, `-InactivitySeconds`, `-SkipPasswordPolicy`, `-SkipLsaProtection`, `-AcceptUefiLock` |
| `Hardening-Storage.ps1` | Disables AutoRun/AutoPlay, enables USB/removable-media auditing, reports BitLocker status | `-BlockUnencryptedRemovableWrite`, `-BlockAllRemovableStorage` |
| `Hardening-Firewall.ps1` | Disables NetBIOS, LLMNR, mDNS, insecure SMB guest logons; blocks legacy inbound ports (23, 512-514 TCP, 69 UDP) | `-ExtraTcpPorts`, `-ExtraUdpPorts` |
| `Integrity-Check.ps1` | DISM scan/repair (only if needed) then SFC | `-Source`, `-SkipSfc`, `-CreateManifest`, `-VerifyScripts` |
| `Restore-Hardening.ps1` | Rolls back recorded changes | `-List`, `-BackupFile`, `-WhatIf` |

---

## 4. Run the scripts

### Step 1: Preview (changes nothing)
```powershell
.\Hardening-Script.ps1   -WhatIf
.\Hardening-Accounts.ps1 -WhatIf
.\Hardening-Storage.ps1  -WhatIf
.\Hardening-Firewall.ps1 -WhatIf
```
Read the output. It lists what *would* change.

### Step 2: Apply
```powershell
.\Hardening-Script.ps1
.\Hardening-Accounts.ps1
.\Hardening-Storage.ps1
.\Hardening-Firewall.ps1
```
You can run only the scripts you need; they are independent.

### Step 3: Reboot
Required for LSA protection and for the SMBv1 / PowerShell v2 removal to take full effect.

### Examples with options
```powershell
.\Hardening-Script.ps1 -ExecutionPolicy AllSigned -RequireSmbSigning
.\Hardening-Accounts.ps1 -LockoutThreshold 3 -MinPasswordLength 12
.\Hardening-Storage.ps1 -BlockUnencryptedRemovableWrite
.\Hardening-Firewall.ps1 -ExtraTcpPorts 5900
```

---

## 5. Reading the output

| Level | Meaning |
|---|---|
| `[OK]` (green) | A change was applied successfully |
| `[INFO]` (cyan) | Information, or a setting was already correct |
| `[WARN]` (yellow) | Needs your attention (reboot, compatibility, BitLocker off, etc.) |
| `[ERROR]` (red) | A step failed; other steps still ran |

At the end each script prints a summary: steps run, failed, warnings. The exit code is `0` if no step failed, `1` otherwise.

**Logs:** `C:\ProgramData\EndpointHardening\Logs`  
**Rollback data:** `C:\ProgramData\EndpointHardening\Backup` (SYSTEM and Administrators only)

---

## 6. Roll back

```powershell
.\Restore-Hardening.ps1 -List
.\Restore-Hardening.ps1 -BackupFile "C:\ProgramData\EndpointHardening\Backup\<file>.json" -WhatIf
.\Restore-Hardening.ps1 -BackupFile "C:\ProgramData\EndpointHardening\Backup\<file>.json"
```
Restore each backup file you want to undo, then reboot.

**Not restored automatically** (turning them back on lowers security): SMBv1, PowerShell v2, the Guest account, local password policy (previous values are written in the Accounts log), and LSA protection applied with a UEFI lock.

---

## 7. Integrity checks

```powershell
.\Integrity-Check.ps1                     # DISM + SFC system repair (can take a long time)
.\Integrity-Check.ps1 -Source "WIM:D:\sources\install.wim:1"   # offline repair source
.\Integrity-Check.ps1 -CreateManifest     # write SHA256SUMS.txt for the scripts
.\Integrity-Check.ps1 -VerifyScripts      # compare scripts with SHA256SUMS.txt
```

---

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `running scripts is disabled on this system` or "not digitally signed" | Verify the hashes, then run `Get-ChildItem .\*.ps1 \| Unblock-File`. Check policy with `Get-ExecutionPolicy -List`. |
| `Common.ps1` cannot be found | Keep all scripts in the same folder and run them from that folder. |
| `Administrator privileges are required` | Reopen PowerShell with **Run as administrator**. |
| Warning that Group Policy overrides settings | The device is managed by a domain/Intune; ask your administrator to apply the settings centrally. |
| A step shows `[ERROR]` | Read the message and the log file; the other steps are unaffected. Open an Issue and attach the log (remove device/user names first). |
| Locked out by account lockout | Wait for the lockout duration, use a second admin account, or run Restore. |
| An app or shared printer stopped working after NetBIOS/SMB/firewall changes | Run `Restore-Hardening.ps1` for that backup, then re-apply without the affecting script. |

---

## 9. Recommended workflow for organizations

1. Test everything on a VM snapshot.
2. Review each setting against your security policy.
3. Pilot on a few devices for a week.
4. Roll out gradually, keeping logs.
5. For managed fleets, convert the settings to Group Policy / Intune instead of running scripts by hand.

This is an independent project. It is not affiliated with or certified by any government body, and it has not been audited against a specific standard.
