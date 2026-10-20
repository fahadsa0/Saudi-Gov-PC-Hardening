## 🚀 How to Run

1. Download the latest release ZIP from the **Releases** page (do not run scripts piped from the internet).
2. Open **PowerShell as Administrator** in the extracted folder.
3. Verify integrity against the published `SHA256SUMS.txt`:
```powershell
   .\Integrity-Check.ps1 -VerifyScripts
```
4. Unblock the files only after verification:
```powershell
   Get-ChildItem .\*.ps1 | Unblock-File
```
5. Preview, then apply (test on a VM first):
```powershell
   .\Hardening-Script.ps1 -WhatIf
   .\Hardening-Script.ps1
```

> Independent project: not affiliated with or certified by any government body.
