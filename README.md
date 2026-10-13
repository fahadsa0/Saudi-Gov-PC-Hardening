# 🛡️ Windows Endpoint Security Hardening & Performance Baseline

A comprehensive, modular suite of PowerShell scripts designed to apply security baselines, enforce access control, protect removable media, optimize endpoint performance, and automate system maintenance for Windows endpoints according to cybersecurity best practices.

---

## 🛠️ Included Modules & Scripts

* 🔒 **`Hardening-Script.ps1`**: Core security baseline module. Disables SMBv1, enforces firewall profiles across all networks, and manages script execution policies.
* 👤 **`Hardening-Accounts.ps1`**: Enforces account security policy, disables the built-in Guest account, mandates NLA for Remote Desktop, and protects LSASS memory credentials.
* 💾 **`Hardening-Storage.ps1`**: Secures removable drives by disabling AutoRun/AutoPlay, enabling USB device audit logging, and verifying BitLocker encryption status.
* 🌐 **`Hardening-Firewall.ps1`**: Network hardening module disabling legacy NetBIOS over TCP/IP and LLMNR protocols, while blocking vulnerable inbound ports.
* ⚡ **`Optimize-Performance.ps1`**: System optimization script activating the Ultimate Performance power plan, clearing memory standby lists, and disabling background telemetry.
* 🩺 **`Integrity-Check.ps1`**: Automated maintenance utility running DISM component store health restoration and SFC system file verification.

---

## 🚀 How to Run the Scripts

1. Open **PowerShell** as **Administrator**.
2. Clone this repository:
   ```powershell
 git clone https://github.com/fahadsa0/Saudi-Gov-PC-Hardening.git
