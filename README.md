# 🛡️ Windows Endpoint Security Hardening & Maintenance Baseline

An automated PowerShell script template designed to enforce system hardening, disable vulnerable legacy protocols, and execute safe maintenance routines for Windows endpoints according to cybersecurity best practices.

---

## 🔑 Key Features
* 🔒 **Disable SMBv1 Protocol:** Mitigates risks associated with legacy network protocol vulnerabilities and ransomware threats.
* 🛡️ **Firewall Policy Enforcement:** Guarantees that Windows Firewall is active across Domain, Private, and Public profiles.
* 🌐 **DNS Cache Flush:** Clears cached DNS entries to safeguard against DNS spoofing and redirection attacks.
* 🧹 **Secure Maintenance:** Removes unnecessary temporary files and cached system logs safely.
* 📜 **Script Security Controls:** Enforces `RemoteSigned` execution policies to control untrusted script execution.

---

## 🚀 How to Run the Script

1. Open **PowerShell** as **Administrator**.
2. Clone this repository:
   ```powershell
git clone https://github.com/fahadsa0/Saudi-Gov-PC-Hardening.git
