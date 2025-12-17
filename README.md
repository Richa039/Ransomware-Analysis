# Cerber Ransomware Analysis

This repository contains an **in-depth static and dynamic malware analysis** of the **Cerber ransomware**, focusing on its execution flow, encryption logic, persistence mechanisms, evasion techniques, and network behavior.

The analysis was conducted in a controlled lab environment using industry-standard reverse engineering and malware analysis tools.


## Malware Overview
```
Malware Family: Cerber Ransomware
 Platform: Windows PE (x86)
 Hash (MD5): 8b6bc16fd137c09a08b02bbe1bb7d670
 Analysis Date: April 28, 2025
```

## Analysis Environment
```
OS: Windows 7 (VirtualBox)
 Tools Used:
  - Ghidra
  - x32dbg / OllyDbg
  - Process Monitor / Process Hacker
  - Regshot
  - INetSim
  - Wireshark
  - PEiD
```
---

## Analysis Scope

### Static Analysis
```
PE structure and entry point inspection
Imported Windows APIs
Embedded strings and obfuscation
XOR-based runtime decryption
Embedded cryptographic material (Base64, RSA public key)
```
### Dynamic Analysis
```
Process creation and mutex behavior
File system encryption activity
Registry modification for persistence and evasion
Firewall and system utility abuse (`netsh.exe`)
Ransom note deployment via `mshta.exe`
Network traffic analysis (Bitcoin payment tracking, Tor gateways)
```

## Key Findings
```
Uses **AES + RSA hybrid encryption**
Dynamically decrypts configuration data at runtime
Disables recovery mechanisms (Volume Shadow Copy)
Modifies firewall rules and registry keys for stealth
Targets user and service profile directories
Spawns `mshta.exe` and `notepad.exe` to display ransom notes
Monitors Bitcoin wallet activity via public blockchain APIs
```

---

## Network Indicators
```
Bitcoin block explorer APIs:
  - `api.blockcypher.com`
  - `btc.blockr.io`
  - `bitaps.com`
  - `chain.so`
- Uses Tor gateway domains via clearnet access
- Time-based evasion via `time.windows.com`

---
