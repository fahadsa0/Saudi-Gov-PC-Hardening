# 🛡️ Windows Endpoint Security Hardening & Performance Baseline

A modular suite of PowerShell scripts designed to apply security baselines, optimize endpoint performance, enforce network security, and automate system maintenance for Windows systems according to cybersecurity best practices.

---

## 🛠️ Included Modules & Scripts

* 🔒 **`Hardening-Script.ps1`**: Main security baseline module. Disables SMBv1, enforces firewall profiles, and sets execution policies.
* ⚡ **`Optimize-Performance.ps1`**: Enables Ultimate Performance power plan, cleans memory standby allocations, and disables telemetry services.
* 🩺 **`Integrity-Check.ps1`**: Automated system maintenance tool running DISM health restoration and SFC file verification.
* 🌐 **`Hardening-Firewall.ps1`**: Network hardening script disabling NetBIOS over TCP/IP, LLMNR multicast, and blocking vulnerable ports.

---

## 🚀 How to Run the Scripts

1. Open **PowerShell** as **Administrator**.
2. Clone this repository:
   ```powershell
   git clone https://github.com/fahadsa0/Saudi-Gov-PC-Hardening.git
