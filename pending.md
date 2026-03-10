# Pending Tasks for OmniVulnScanner (Enterprise IT Edition)

The suite has been re-architected into specialized reconnaissance layers, matching the workflow of professional IT security developers.

## Current Progress
- [x] **Segregated Reconnaissance**:
    - [x] **Web Probe**: Specialized module using `BeautifulSoup` and specialized templates for web vulnerability detection (WAF, CORS, Subdomains).
    - [x] **Network Strike**: Dedicated `scapy` and `socket` based layer for local asset discovery and router assessment.
    - [x] **System Audit**: Low-level port scanning and service fingerprinting.
    - [x] **Full Scan**: Intelligent orchestration of all specialized layers.
- [x] **Intruder Pack ($15,000 Professional Native Suite)**:
    - [x] **14 Professional Tools**: Deepened with industrial-grade native logic.
    - [x] **Advanced SQLi Engine**: Time-based blind detection & expanded DB signatures.
    - [x] **Advanced Brute Force**: Added **POST Form-based** attacking for web logins.
    - [x] **Advanced WiFi Strike**: Precision **Passive AP Scanning** & Deauth pulse.
    - [x] **Advanced Harvester**: Phishing templates (**M365, Google**) & metadata capture.
    - [x] **Multi-Session Handler**: Manage and interact with concurrent reverse shells.
    - [x] **Stealth Banner Grab**: Internal version identification (Nmap fallback).
    - [x] **Advanced Bypasses**: Base64-Encoded PowerShell generation.
- [x] **24-Engine Architecture (Full Red Team Mapping)**:
    - [x] **INTRUDER PACK**: Exploit, ROPChain, Emulation, Disassembly, SSHBrute, Browser, Serial, Bluetooth, Remote, Packet.
    - [x] **RECON PACK**: Shodan, Domain, PacketCapture, AndroidRecon, BLERecon, WebCrawl, Osint.
    - [x] **ANALYSIS PACK**: ELFAnalysis, StaticAudit, Dependency, AndroidAnalysis.
    - [x] **SYSTEM ENGINES**: SystemMetrics, Settings, IPython.
    - [x] EventBus + WS Telemetry pipeline connected to all engines.
- [x] **Settings Suite (8 Categories)**:
    - [x] Engine Manager, Network & Proxy, Intruder Config, Recon Profiles.
    - [x] Dashboard Display, Security & Audit, Plugins, Advanced/Developer.
3. **Encrypted Vault**: Upgrade `settings.json` to an encrypted `vault.db`.
