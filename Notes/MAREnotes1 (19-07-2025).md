## 🦠 **Malware Analysis (MA)** – Complete Overview

> **Definition:**  
> Malware Analysis is the methodical process of examining malicious software to understand its **purpose**, **origin**, **capabilities**, **execution behavior**, **potential impact**, and most importantly—how to **detect, mitigate, and defend** against it.

* * *

## 🔍 **1. Types of Malware**

<table style="min-width: 50px"><colgroup><col style="min-width: 25px"><col style="min-width: 25px"></colgroup><tbody><tr><th colspan="1" rowspan="1"><p>Type</p></th><th colspan="1" rowspan="1"><p>Description</p></th></tr><tr><td colspan="1" rowspan="1"><p><strong>Virus</strong></p></td><td colspan="1" rowspan="1"><p>Attaches to legitimate files or programs and spreads through them. Needs user interaction to activate.</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Worm</strong></p></td><td colspan="1" rowspan="1"><p>Self-replicating; spreads independently over networks without user action.</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Trojan Horse</strong></p></td><td colspan="1" rowspan="1"><p>Disguises itself as benign software to trick users into installing it.</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Ransomware</strong></p></td><td colspan="1" rowspan="1"><p>Encrypts files or systems, demanding payment for decryption.</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Spyware</strong></p></td><td colspan="1" rowspan="1"><p>Silently gathers user data (e.g., keystrokes, credentials) without consent.</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Adware</strong></p></td><td colspan="1" rowspan="1"><p>Forces advertisements into your system or browser.</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Rootkit</strong></p></td><td colspan="1" rowspan="1"><p>Hides itself and other malware by modifying the OS or system tools.</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Backdoor</strong></p></td><td colspan="1" rowspan="1"><p>Creates unauthorized access paths into a system.</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Keylogger</strong></p></td><td colspan="1" rowspan="1"><p>Records every keystroke typed by the victim.</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Botnet Clients</strong></p></td><td colspan="1" rowspan="1"><p>Infected systems controlled remotely, used in DDoS, spamming, etc.</p></td></tr></tbody></table>

* * *

## 🎯 **2. Goals of Malware Analysis**

*   Understand **behavior** and **functionality** of the malware.
    
*   Identify **Indicators of Compromise (IOCs)**: domains, hashes, IPs, file names, registry keys.
    
*   Determine the **origin** (e.g., APT group attribution).
    
*   Improve **defensive mechanisms** (antivirus signatures, firewalls, detection rules).
    
*   Create **mitigation plans** and **patch recommendations**.
    
*   Understand **persistence mechanisms**.
    
*   Provide data for **threat intelligence**.
    

* * *

## 🧠 **3. Types of Malware Analysis**

<table style="min-width: 50px"><colgroup><col style="min-width: 25px"><col style="min-width: 25px"></colgroup><tbody><tr><th colspan="1" rowspan="1"><p>Type</p></th><th colspan="1" rowspan="1"><p>Description</p></th></tr><tr><td colspan="1" rowspan="1"><p><strong>Static Analysis</strong></p></td><td colspan="1" rowspan="1"><p>Analyzing the binary <em>without executing it</em>. Focuses on file structure, strings, imports, and disassembly.</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Dynamic Analysis</strong></p></td><td colspan="1" rowspan="1"><p>Observing malware <em>during execution</em> in a controlled environment (sandbox or VM).</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Hybrid Analysis</strong></p></td><td colspan="1" rowspan="1"><p>Combines both static and dynamic methods to maximize coverage.</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Automated Analysis</strong></p></td><td colspan="1" rowspan="1"><p>Using sandboxes and tools to produce automated reports.</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Memory Analysis</strong></p></td><td colspan="1" rowspan="1"><p>Analyzing RAM dumps to detect fileless malware or runtime behavior.</p></td></tr></tbody></table>

* * *

## 🛠️ **4. Tools of the Trade**

### 🧰 _Static Analysis Tools:_

*   `BinText` / `Strings` – Extract readable strings
    
*   `PEStudio` – Inspect PE headers and suspicious API usage
    
*   `Detect It Easy (DIE)` – Identify packers and obfuscators
    
*   `IDA Pro`, `Ghidra` – Disassemblers and decompilers
    
*   `Binary Ninja`, `Radare2` – Modern reverse engineering tools
    
*   `VirusTotal` – Check against public threat databases
    
*   `CFF Explorer` – Explore PE structures
    

### 🔬 _Dynamic Analysis Tools:_

*   **Cuckoo Sandbox** – Open-source malware analysis automation
    
*   **Process Monitor (ProcMon)** – Monitor system API calls
    
*   **Process Explorer** – View running processes and DLLs
    
*   **Wireshark** – Capture and analyze network traffic
    
*   **Fakenet-NG** – Simulate internet services for malware communication
    
*   **Regshot** – Snapshot registry changes
    
*   **ApateDNS** – DNS manipulation for malware redirection
    

### 💾 _Memory & Advanced Analysis:_

*   **Volatility Framework** – Memory forensics and malware detection
    
*   **Redline** – Host triage and memory inspection
    
*   **Sysinternals Suite** – Complete system monitoring toolkit  
    
    * * *
    
    ## ⚙️ **5. Malware Lifecycle & Behavior Flow**
    
    `[Initial Vector] | v [Dropper/Loader] --(writes to disk, unpacks)--> | v [Persistence Setup] --(registry, startup, services)--> | v [Execution & Payload Delivery] | v [C&C Communication] --> [Exfiltration | Lateral Movement] | v [Cleanup / Self-destruct / Dormant]`
    
    * * *
    
    ## 🧱 **5.2. Malware Analysis Lab Setup**
    
    *   **Isolated VM (VirtualBox / VMware / KVM)**
        
    *   **Snapshotting enabled**
        
    *   **No shared clipboard or drive**
        
    *   **Host-only or NAT networking**
        
    *   **Optional fake services (DNS, HTTP, SMTP)**
        
    *   Tools pre-installed: ProcMon, Wireshark, Regshot, PEStudio, etc.
        
    
    * * *
    
    ## ⚠️ **6. Common Challenges in Malware Analysis**
    
    *   Obfuscation / Packing / Encryption
        
    *   Anti-VM or Anti-Debugging techniques
        
    *   Fileless malware and in-memory execution
        
    *   Polymorphic or Metamorphic code
        
    *   C2 servers behind Tor or fast-flux DNS
        
    
    * * *
    
    ## 🧬 **7. Indicators of Compromise (IOCs)**
    
    <table style="min-width: 50px"><colgroup><col style="min-width: 25px"><col style="min-width: 25px"></colgroup><tbody><tr><th colspan="1" rowspan="1"><p>IOC Type</p></th><th colspan="1" rowspan="1"><p>Examples</p></th></tr><tr><td colspan="1" rowspan="1"><p><strong>File Hashes</strong></p></td><td colspan="1" rowspan="1"><p>MD5/SHA256 of the malware binary</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>File Names</strong></p></td><td colspan="1" rowspan="1"><p>Executables or DLLs dropped</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Registry Keys</strong></p></td><td colspan="1" rowspan="1"><p>Persistence keys added</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Network</strong></p></td><td colspan="1" rowspan="1"><p>IPs, domains, URLs contacted</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Mutexes</strong></p></td><td colspan="1" rowspan="1"><p>Unique names created by malware</p></td></tr><tr><td colspan="1" rowspan="1"><p><strong>Processes</strong></p></td><td colspan="1" rowspan="1"><p>Spawned child processes</p></td></tr></tbody></table>
    
    * * *
    
    ## 📖 **8. Real-World Applications of Malware Analysis**
    
    *   **Threat Intelligence feeds**
        
    *   **Endpoint Detection & Response (EDR)** signature creation
        
    *   **SOC operations** and triaging alerts
        
    *   **Incident Response & Forensics**
        
    *   **Research & Publication (APT attribution)**
        
          
          
        **📖 9. Identifying Malware Behaviours :**
        
    
    <table style="min-width: 215px"><colgroup><col style="width: 190px"><col style="min-width: 25px"></colgroup><tbody><tr><th colspan="1" rowspan="1" colwidth="190"><p><strong>Type</strong></p></th><th colspan="1" rowspan="1"><p><strong>Suspicious Indicators / Hints</strong></p></th></tr><tr><td colspan="1" rowspan="1" colwidth="190"><p><strong>Virus</strong></p></td><td colspan="1" rowspan="1"><p>- Unusual file sizes or sudden file corruptions.- Antivirus alerts on common files.- Modified or duplicated executables in odd locations.- System crashes after opening a document.</p></td></tr><tr><td colspan="1" rowspan="1" colwidth="190"><p><strong>Worm</strong></p></td><td colspan="1" rowspan="1"><p>- Network traffic spikes without user activity.- Multiple failed login attempts across machines.- Unexpected creation of new user accounts.- Strange outbound connections.</p></td></tr><tr><td colspan="1" rowspan="1" colwidth="190"><p><strong>Trojan Horse</strong></p></td><td colspan="1" rowspan="1"><p>- A program behaves differently than expected (e.g., a "game" opens a command prompt).- Disabled security tools.- High CPU/memory usage from seemingly innocent apps.- Unknown applications in startup.</p></td></tr><tr><td colspan="1" rowspan="1" colwidth="190"><p><strong>Ransomware</strong></p></td><td colspan="1" rowspan="1"><p>- Files suddenly encrypted with unknown extensions.- Ransom note (TXT/HTML) appearing on desktop.- Inability to open files previously accessible.- High disk activity.- Sudden shutdown of backup services.</p></td></tr><tr><td colspan="1" rowspan="1" colwidth="190"><p><strong>Spyware</strong></p></td><td colspan="1" rowspan="1"><p>- Browser redirects, slow browsing.- Credentials being used without consent.- Unusual traffic to unknown IPs.- Suspicious processes running in background.</p></td></tr><tr><td colspan="1" rowspan="1" colwidth="190"><p><strong>Adware</strong></p></td><td colspan="1" rowspan="1"><p>- Excessive pop-ups or ads outside the browser.- Browser homepage or search engine changed.- Installed unknown browser extensions.- Performance drop while browsing.</p></td></tr><tr><td colspan="1" rowspan="1" colwidth="190"><p><strong>Rootkit</strong></p></td><td colspan="1" rowspan="1"><p>- Antivirus fails to start.- Security updates blocked.- Hidden processes or files (visible only with special tools).- System utilities like <code>netstat</code>, <code>taskmgr</code> show abnormal behavior.- Kernel-mode errors in logs.</p></td></tr><tr><td colspan="1" rowspan="1" colwidth="190"><p><strong>Backdoor</strong></p></td><td colspan="1" rowspan="1"><p>- Open ports even when services are off.- New firewall rules or exceptions.- Suspicious scheduled tasks or services.- Outbound traffic to unusual foreign IPs.</p></td></tr><tr><td colspan="1" rowspan="1" colwidth="190"><p><strong>Keylogger</strong></p></td><td colspan="1" rowspan="1"><p>- Suspicious processes with names like <code>svch0st.exe</code>, <code>expl0rer.exe</code>, etc.- Logs appearing in obscure folders.- High CPU/memory for text-based processes.- Network packet inspection shows frequent small uploads.</p></td></tr><tr><td colspan="1" rowspan="1" colwidth="190"><p><strong>Botnet Clients</strong></p></td><td colspan="1" rowspan="1"><p>- Device participates in DDoS without user's knowledge.- Frequent connection to known botnet C2 servers (check threat intel feeds).- High bandwidth usage.- Similar behavior across multiple infected systems.</p></td></tr></tbody></table>
    
      
    Common General Clues:
    
    *   **Persistence mechanisms**: New registry entries, startup items.
        
    *   **Unusual logs**: Events showing privilege escalation or driver loading.
        
    *   **External communication**: Frequent or encrypted communication to unknown IPs/domains.
        
    *   **System slowness**: Especially after reboot or login.
        
    *   **Antivirus disabled or behaving oddly.**  
          
        🔬 Malware Behavioral Deep Dive
        
        Each malware class has **unique operational patterns** at various levels: **process behavior**, **registry modifications**, **network footprints**, **filesystem I/O**, **kernel interactions**, and more.
        
        * * *
        
        ### 🧪 1. **Virus**
        
        #### 🧠 _Behavior:_
        
        *   Attaches itself to host files like `.exe`, `.doc`, `.xls`, `.dll`.
            
        *   Executes **only when the infected host file is run** (needs user interaction).
            
        *   Uses **file replication** as its primary vector.
            
        
        #### 🧰 _Technical signs:_
        
        *   Increased hash mismatches (via integrity checks like `sigcheck` or `FCIV`)
            
        *   Time stamps modified unusually—“Time stomping”
            
        *   Appending code in PE header or unused sections of binaries
            
        *   Sudden antivirus alerts for common apps (like Notepad)
            
        
        #### 🔗 _Persistence tricks:_
        
        *   Hides in startup folder, registry `Run` keys
            
        *   Often uses filename mimicry (e.g., `svch0st.exe` instead of `svchost.exe`)
            
        
        * * *
        
        ### 🪱 2. **Worm**
        
        #### 🧠 _Behavior:_
        
        *   Fully **autonomous**: replicates and spreads without help.
            
        *   Exploits vulnerabilities in **network services or OS protocols** (like SMB, RPC).
            
        *   Leaves behind **worm payloads** or scripts on target systems.
            
        
        #### 🧰 _Technical signs:_
        
        *   Repeated `SMB`/`RPC`/`RDP` traffic across LAN
            
        *   `net use` or `psexec` usage in logs
            
        *   Creation of user accounts without admin approval
            
        *   Spikes in CPU/network usage
            
        
        #### 🔗 _Persistence tricks:_
        
        *   Drops itself in admin shares (`C$\Windows\System32`)
            
        *   Uses WMI or scheduled tasks to self-execute
            
        *   Often deploys dual-stage payload (like ransomware post-worm)
            
        
        * * *
        
        ### 🐴 3. **Trojan Horse**
        
        #### 🧠 _Behavior:_
        
        *   Masquerades as a **legitimate application** but delivers malicious code.
            
        *   Often does **nothing on first launch** to reduce suspicion.
            
        
        #### 🧰 _Technical signs:_
        
        *   Executables digitally unsigned or tampered
            
        *   Fake error messages (“Application could not start”) while running background payloads
            
        *   Outbound connections immediately after execution
            
        *   New autostart entries or PowerShell scripts triggered
            
        
        #### 🔗 _Persistence tricks:_
        
        *   Scheduled tasks (`schtasks /create`)
            
        *   Registry entries like `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
            
        *   Hidden services or DLL injection into known processes
            
        
        * * *
        
        ### 🪙 4. **Ransomware**
        
        #### 🧠 _Behavior:_
        
        *   Encrypts critical files using RSA/AES hybrid schemes
            
        *   Deletes volume shadow copies and disables recovery
            
        *   Often drops **note.txt**, `README.html`, etc.
            
        
        #### 🧰 _Technical signs:_
        
        *   File extensions changed (e.g., `.locked`, `.crypted`)
            
        *   Execution of `vssadmin delete shadows`, `bcdedit`, or `wmic` commands
            
        *   Sudden spike in disk I/O and CPU usage
            
        *   Attempts to disable antivirus via registry or PowerShell
            
        
        #### 🔗 _Persistence tricks:_
        
        *   May install rootkits to prevent removal
            
        *   Encrypts even USB drives or mapped network shares
            
        *   Keeps keys in memory for later exfiltration (e.g., in `lsass.exe`)
            
        
        * * *
        
        ### 🕵️ 5. **Spyware**
        
        #### 🧠 _Behavior:_
        
        *   Stays hidden to capture keystrokes, screenshots, clipboard, or browser activity
            
        *   Communicates with **C2 (Command & Control)** server silently
            
        
        #### 🧰 _Technical signs:_
        
        *   Network sniffers show low-bandwidth, consistent outbound traffic (to dynamic DNS domains)
            
        *   Hooks common APIs: `GetAsyncKeyState`, `GetForegroundWindow`, etc.
            
        *   Abnormal DLLs loaded in browsers or Office applications
            
        *   Registry changes in IE/Edge/Chrome zones
            
        
        #### 🔗 _Persistence tricks:_
        
        *   Injects into explorer.exe or chrome.exe
            
        *   Often appears as browser extension or helper object
            
        *   Disables browser security features silently
            
        
        * * *
        
        ### 📺 6. **Adware**
        
        #### 🧠 _Behavior:_
        
        *   Delivers pop-ups, redirects, sponsored search results, or banners
            
        *   Alters browser settings or default search provider
            
        
        #### 🧰 _Technical signs:_
        
        *   Auto-installed browser extensions
            
        *   Chrome flags like `--disable-blink-features`
            
        *   Fake software updates (e.g., Flash Player updaters)
            
        *   DNS settings changed to ad-serving proxy
            
        
        #### 🔗 _Persistence tricks:_
        
        *   Schedules update checks via hidden tasks
            
        *   Adds self to startup through `Startup` folder or Task Scheduler
            
        
        * * *
        
        ### 🧫 7. **Rootkit**
        
        #### 🧠 _Behavior:_
        
        *   Hides files, processes, network connections, or registry keys
            
        *   May tamper with **kernel modules** or drivers (Ring 0)
            
        
        #### 🧰 _Technical signs:_
        
        *   File listed by `WinObj` or `GMER`, but not in Explorer
            
        *   `tasklist` shows fewer processes than `Process Explorer`
            
        *   IRP hook detections in kernel-mode drivers
            
        *   Legit security tools fail or crash (e.g., `sysinternals` blocked)
            
        
        #### 🔗 _Persistence tricks:_
        
        *   Installs as kernel driver (`.sys`) via services
            
        *   Alters bootloader (`boot.ini`, MBR)
            
        *   Manipulates SSDT, IDT, or other kernel data structures
            
        
        * * *
        
        ### 🧨 8. **Backdoor**
        
        #### 🧠 _Behavior:_
        
        *   Grants **unauthorized remote access** to attacker
            
        *   Often silent until attacker sends a trigger signal
            
        
        #### 🧰 _Technical signs:_
        
        *   Listening on random high TCP/UDP ports
            
        *   Modified or new `inetinfo.exe`, `svchost.exe`, etc.
            
        *   Unusual firewall exceptions
            
        *   ICMP-based trigger mechanisms (e.g., packet with hidden signal)
            
        
        #### 🔗 _Persistence tricks:_
        
        *   DLL dropped in system path and side-loaded
            
        *   Reverse shell auto-launch from registry or service
            
        *   May piggyback on another malware as a secondary payload
            
        
        * * *
        
        ### ⌨️ 9. **Keylogger**
        
        #### 🧠 _Behavior:_
        
        *   Records keystrokes, clipboard, sometimes webcam/mic
            
        *   Stores logs locally or sends to attacker
            
        
        #### 🧰 _Technical signs:_
        
        *   Hooks APIs like `GetKeyboardState`, `ReadConsoleInput`
            
        *   Drops log files in `AppData`, `Temp`, or hidden folders
            
        *   Low-size frequent outbound HTTP/FTP packets
            
        *   Windows event logs show script execution anomalies
            
        
        #### 🔗 _Persistence tricks:_
        
        *   DLL injection into `explorer.exe` or browsers
            
        *   Launch via hidden `.lnk` or shortcut files
            
        *   Often bundled with spyware or trojans
            
        
        * * *
        
        ### 🤖 10. **Botnet Client**
        
        #### 🧠 _Behavior:_
        
        *   Connects to central server to receive tasks (spam, DDoS, crypto mining)
            
        *   Runs stealthily as background service or process
            
        
        #### 🧰 _Technical signs:_
        
        *   Periodic outbound pings to suspicious IPs/domains
            
        *   Excess CPU/GPU usage during idle times
            
        *   PC used for sending spam (mail server hits or SMTP logs)
            
        *   Irregular DNS queries (DGA: Domain Generation Algorithms)
            
        
        #### 🔗 _Persistence tricks:_
        
        *   May use polymorphism—code changes to avoid detection
            
        *   C2 communication via TOR, DNS tunneling, or social media APIs
            
        *   Drops itself in UAC-protected paths and elevates via exploits
            
        
        * * *
        
        ## 🧠 Final Note: Behavior ≠ Signature
        
        Traditional antivirus relies on **signatures**, but **malware behavior** is how advanced detection (EDR, XDR, SIEM) works.
        
        > Behavioral analysis looks for:
        > 
        > *   Process tree anomalies
        >     
        > *   Unexpected script execution
        >     
        > *   Fileless persistence
        >     
        > *   Lateral movement patterns
        >     
        > *   Unusual registry keys or system calls
        >
