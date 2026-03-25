"""
SIGIL Detection Rules — Sigma-inspired detection rules for DFIR triage.
Ported from the frontend JavaScript detection engine.
"""

DETECTION_RULES = {
    "windows_event_log": [
        {
            "id": "WIN-001",
            "name": "Brute Force Login Attempts",
            "description": "Detects multiple failed login attempts (Event ID 4625) from the same source within a short window, indicative of brute-force or password spraying attacks.",
            "severity": "high",
            "mitre": ["T1110"],
            "pattern": r"EventID[:\s]*4625",
            "alt_patterns": [r"event[_\s]?id[:\s=\"]*4625", r"logon[_\s]?type[:\s=\"]*(?:3|10)", r"an account failed to log on"],
            "keywords": ["failed", "logon", "audit failure"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Correlate source IPs with known threat intelligence feeds",
                "Check if any 4624 (successful logon) follows the failed attempts",
                "Review account lockout policies and recent lockout events (4740)",
                "Investigate targeted accounts for privilege level and exposure"
            ]
        },
        {
            "id": "WIN-002",
            "name": "New Service Installation",
            "description": "Detects installation of new Windows services (Event ID 7045/4697), commonly used for persistence or privilege escalation via malicious service creation.",
            "severity": "high",
            "mitre": ["T1543", "T1569"],
            "pattern": r"EventID[:\s]*(?:7045|4697)",
            "alt_patterns": [r"a (?:new )?service was installed", r"service\s+file\s+name", r"event[_\s]?id[:\s=\"]*(?:7045|4697)"],
            "keywords": ["service", "installed", "service file name"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Verify service binary path and check against known-good baselines",
                "Analyze the service executable with hash lookups (VirusTotal)",
                "Check if the service runs as SYSTEM or with elevated privileges",
                "Review who created the service and from which process"
            ]
        },
        {
            "id": "WIN-003",
            "name": "Event Log Cleared",
            "description": "Detects clearing of Windows event logs (Event ID 1102/104), a strong indicator of anti-forensic activity by adversaries attempting to cover their tracks.",
            "severity": "critical",
            "mitre": ["T1070"],
            "pattern": r"EventID[:\s]*(?:1102|1100)\b",
            "alt_patterns": [r"event[_\s]?id[:\s=\"]*1102", r"audit\s*log\s*(?:was\s*)?clear", r"event\s*log\s*(?:was\s*)?clear", r"the (?:audit|event) log was cleared"],
            "keywords": ["cleared", "audit log", "log was cleared"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "CRITICAL: Preserve all remaining logs immediately",
                "Check backup log sources (SIEM, Syslog forwarding, WEC)",
                "Investigate timeline around the clearing event for lateral movement",
                "Identify the account and process that performed the clearing"
            ]
        },
        {
            "id": "WIN-004",
            "name": "Suspicious PowerShell Execution",
            "description": "Detects encoded PowerShell commands, bypass flags, download cradles, and obfuscated payloads commonly used in fileless malware attacks.",
            "severity": "critical",
            "mitre": ["T1059", "T1027"],
            "pattern": r"(?:powershell|pwsh).*(?:-enc|-encoded|bypass|hidden|downloadstring|\biex\b|invoke-expression|webclient|Net\.WebClient|bitstransfer|start-bitstransfer)",
            "alt_patterns": [
                r"EventID[:\s]*(?:4104|4103).*(?:script\s*block|creating\s*scriptblock)",
                r"creating\s*scriptblock\s*text",
                r"frombase64string",
                r"\$EncodedCompressedFile",
                r"encodedcompressed",
                r"IO\.Compression",
                r"IO\.MemoryStream",
                r"System\.Convert.*FromBase64",
                r"\[Convert\]::FromBase64String",
                r"IO\.StreamReader",
                r"Reflection\.Assembly",
                r"DeflateStream|GZipStream",
                r"New-Object\s+(?:System\.)?(?:Net\.WebClient|IO\.)",
                r"Invoke-(?:WebRequest|RestMethod|Expression)",
                r"(?:Start-BitsTransfer|certutil.*-urlcache)",
                r"(?:\bIEX\b|\bsal\b|Set-Alias)\s*(?:\(|\{|\$)"
            ],
            "keywords": ["powershell", "encoded", "bypass", "downloadstring", "invoke-expression", "scriptblock", "EncodedCompressedFile", "FromBase64String", "MemoryStream", "Compression", "creating scriptblock"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Decode any Base64-encoded command blocks for analysis",
                "Check for compressed/deflated payloads (GZip/Deflate streams)",
                "Review ScriptBlock Event ID 4104 logs for full reconstructed script",
                "Identify parent process and execution chain via Event ID 4688",
                "Search for downloaded payloads in temp directories and user profiles",
                "Check if ScriptBlock fragments span multiple event records"
            ]
        },
        {
            "id": "WIN-011",
            "name": "Obfuscated PowerShell ScriptBlock",
            "description": "Detects PowerShell ScriptBlock logging events (4104) containing encoded/compressed payloads, reflection-based assembly loading, or shellcode injection. Only triggers on PowerShell provider logs.",
            "severity": "critical",
            "mitre": ["T1059", "T1027", "T1105"],
            "pattern": r"\$(?:Encoded(?:Compressed)?File|enc(?:oded)?(?:Cmd|Command|Payload|Data|Script|Block|Buf(?:fer)?)?)\s*=\s*['\"\@]",
            "alt_patterns": [
                r"EventID[:\s]*4104.*[A-Za-z0-9+/]{100,}",
                r"(?:creating\s*scriptblock).*(?:[A-Za-z0-9+/]{60,})",
                r"\[(?:System\.)?Reflection\.Assembly\]::Load",
                r"\[(?:System\.)?Runtime\.InteropServices\.Marshal\]",
                r"(?:Invoke-(?:Obfuscation|Encode|CradleCrafter))",
                r"-bxor|-band\s+0x",
                r"Add-Type\s+.*-TypeDefinition",
                r"\$(?:DoIt|var_code|shellcode|buf|payload)\s*=",
                r"VirtualAlloc|VirtualProtect|CreateThread|NtAllocateVirtualMemory",
                r"Get-ItemProperty\s+-Path\s+Registry::",
                r"IO\.Compression.*FromBase64",
                r"IO\.MemoryStream.*Convert",
                r"\[Convert\]::FromBase64String",
                r"DeflateStream|GZipStream"
            ],
            "keywords": ["EncodedCompressedFile", "FromBase64", "MemoryStream", "Reflection.Assembly", "DeflateStream", "GZipStream", "scriptblock", "VirtualAlloc", "shellcode", "Add-Type"],
            "provider_filter": r"powershell|microsoft-windows-powershell|4104|4103|scriptblock",
            "provider_exclude": r"bits-client|bits|chrome|update|wuauserv",
            "next_steps": [
                "CRITICAL: Extract and decode the full Base64 payload for malware analysis",
                "Reconstruct fragmented ScriptBlocks across sequential Event Record IDs",
                "Check for in-memory .NET assembly loading (fileless malware indicator)",
                "Submit decoded payload hash to VirusTotal / malware sandbox",
                "Identify if payload performs registry persistence, credential theft, or C2",
                "Correlate timestamps with network traffic for potential C2 beacon or data exfiltration"
            ]
        },
        {
            "id": "WIN-005",
            "name": "Account Created / Privilege Escalation",
            "description": "Detects new account creation (4720) and users being added to privileged groups (4732/4728).",
            "severity": "high",
            "mitre": ["T1136", "T1078"],
            "pattern": r"EventID[:\s]*(?:4720|4732|4728)\b",
            "alt_patterns": [r"event[_\s]?id[:\s=\"]*(?:4720|4732|4728)", r"user account was created", r"member was added.*(?:admin|group)"],
            "keywords": ["account created", "member added", "admin", "user account was created"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Verify the new account against authorized change requests",
                "Check if account was added to Domain Admins or local Administrators",
                "Review account attributes for anomalies (naming convention, SPN)",
                "Correlate with preceding reconnaissance or lateral movement events"
            ]
        },
        {
            "id": "WIN-006",
            "name": "RDP Lateral Movement",
            "description": "Detects Remote Desktop Protocol usage (Event ID 4624 LogonType 10, plus TerminalServices events).",
            "severity": "medium",
            "mitre": ["T1021"],
            "pattern": r"EventID[:\s]*4624.*logon\s*type[:\s]*10|logon\s*type[:\s]*10.*EventID[:\s]*4624|EventID[:\s]*1149",
            "alt_patterns": [r"event[_\s]?id[:\s=\"]*4624.*logon\s*type.*10", r"remote\s*desktop.*logon", r"TerminalServices"],
            "keywords": ["logon type 10", "rdp", "remote desktop", "terminal services"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Map source-to-destination RDP sessions for lateral movement path",
                "Check for unusual source workstations or off-hours access",
                "Verify RDP was expected and authorized for each account",
                "Look for evidence of pass-the-hash or credential reuse"
            ]
        },
        {
            "id": "WIN-007",
            "name": "Credential Dumping Activity",
            "description": "Detects indicators of credential dumping tools (Mimikatz, ProcDump targeting LSASS, comsvcs.dll MiniDump).",
            "severity": "critical",
            "mitre": ["T1003"],
            "pattern": r"(?:mimikatz|sekurlsa|lsass.*(?:dump|procdump|minidump)|comsvcs.*minidump|ntds\.dit)",
            "alt_patterns": [r"(?:4688|1).*(?:procdump|sqldumper).*lsass", r"privilege.*debug"],
            "keywords": ["mimikatz", "lsass", "procdump", "sekurlsa", "ntds.dit", "credential", "dump"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "CRITICAL: Assume all credentials on the host are compromised",
                "Initiate password reset for all accounts that were logged on",
                "Check for NTDS.dit exfiltration if a Domain Controller is involved",
                "Deploy Credential Guard or LSASS protection if not enabled"
            ]
        },
        {
            "id": "WIN-008",
            "name": "Scheduled Task Creation",
            "description": "Detects creation of scheduled tasks (Event ID 4698) commonly used for persistence.",
            "severity": "medium",
            "mitre": ["T1053"],
            "pattern": r"EventID[:\s]*4698\b",
            "alt_patterns": [r"event[_\s]?id[:\s=\"]*4698", r"schtasks.*/create", r"new.*scheduled.*task", r"task\s*(?:was\s*)?(?:registered|created)"],
            "keywords": ["schtasks", "scheduled task", "registered", "task was created"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Review the task action (command/script being executed)",
                "Check task schedule frequency and trigger conditions",
                "Verify task creator account and creation timestamp",
                "Compare against baseline of known legitimate scheduled tasks"
            ]
        },
        {
            "id": "WIN-009",
            "name": "Windows Firewall / Defender Disabled",
            "description": "Detects disabling of Windows Firewall or Defender (Event ID 5025/5001).",
            "severity": "critical",
            "mitre": ["T1562"],
            "pattern": r"EventID[:\s]*(?:5025|5001)\b|firewall.*(?:stop|disable)|defender.*(?:disable|turned\s*off)|antimalware.*protection.*disabled",
            "alt_patterns": [r"event[_\s]?id[:\s=\"]*(?:5025|5001)", r"windows\s*defender.*disable", r"tamper\s*protection", r"real-time\s*protection.*off"],
            "keywords": ["firewall", "defender", "disabled", "stopped", "tamper protection", "antimalware"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Determine who/what process disabled the security controls",
                "Check for subsequent malware execution or file drops",
                "Re-enable protections and investigate the timeline",
                "Search for Group Policy modifications that disable security"
            ]
        },
        {
            "id": "WIN-010",
            "name": "Shadow Copy Deletion",
            "description": "Detects deletion of Volume Shadow Copies, a hallmark of ransomware operations.",
            "severity": "critical",
            "mitre": ["T1490", "T1486"],
            "pattern": r"(?:vssadmin.*delete\s*shadows|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled.*no|wbadmin.*delete\s*catalog)",
            "alt_patterns": [r"shadow\s*cop(?:y|ies).*delet", r"disable.*recovery"],
            "keywords": ["vssadmin", "shadowcopy", "delete shadows", "bcdedit", "recoveryenabled", "wbadmin"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "CRITICAL: Likely pre-ransomware activity — isolate host immediately",
                "Check for encryption of files (.locked, .encrypted, ransom notes)",
                "Preserve network traffic logs for C2 and exfiltration evidence",
                "Engage incident response team and consider disconnecting from network"
            ]
        }
    ],
    "web_server_log": [
        {
            "id": "WEB-001",
            "name": "SQL Injection Attempts",
            "description": "Detects common SQL injection payloads in web request URIs and parameters.",
            "severity": "high",
            "mitre": ["T1190"],
            "pattern": r"(?:union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table|waitfor\s+delay|benchmark\s*\(|sleep\s*\(|1\s*=\s*1\s*--|0x[0-9a-f]{8,})",
            "alt_patterns": [r"(?:concat|char|0x).*(?:select|from|where)", r"information_schema"],
            "keywords": ["union select", "or 1=1", "drop table", "waitfor", "benchmark", "sleep", "information_schema"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Identify targeted parameter and application endpoint",
                "Check for successful injection (HTTP 200 with unexpected data)",
                "Review WAF logs for bypassed or allowed requests",
                "Audit the application code for parameterized query usage"
            ]
        },
        {
            "id": "WEB-002",
            "name": "Web Shell Access",
            "description": "Detects access to known web shell filenames and patterns.",
            "severity": "critical",
            "mitre": ["T1505"],
            "pattern": r"(?:cmd\.(?:asp|php|jsp)|shell\.(?:php|asp)|c99|r57|b374k|alfa\.php|(?:web)?shell|eval\s*\(\s*(?:base64_decode|gzinflate|\$_(?:POST|GET|REQUEST)))",
            "alt_patterns": [r"(?:POST|GET).*(?:cmd|exec|system|passthru)\s*=", r"php.*(?:eval|assert|preg_replace.*/e)"],
            "keywords": ["webshell", "cmd.php", "c99", "r57", "b374k", "eval", "base64_decode", "passthru"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "CRITICAL: Isolate the web server and preserve the shell file",
                "Calculate file hash and check against threat intelligence",
                "Review upload timestamps and web logs for initial access vector",
                "Search for additional shells — attackers often plant backups",
                "Check file system for recently modified files outside deployment"
            ]
        },
        {
            "id": "WEB-003",
            "name": "Directory Traversal / LFI",
            "description": "Detects path traversal sequences and local file inclusion attempts.",
            "severity": "high",
            "mitre": ["T1190"],
            "pattern": r"(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f){2,}|(?:\/etc\/(?:passwd|shadow|hosts)|\/proc\/self|win\.ini|boot\.ini|system32)",
            "alt_patterns": [r"(?:include|require|fopen|file_get_contents).*\.\.\/"],
            "keywords": ["../", "..\\", "etc/passwd", "etc/shadow", "win.ini", "proc/self", "traversal"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Check if traversal was successful (HTTP 200 with file contents)",
                "Identify the vulnerable parameter and application module",
                "Review for data exfiltration of sensitive files",
                "Check for escalation to Remote File Inclusion (RFI)"
            ]
        },
        {
            "id": "WEB-004",
            "name": "Suspicious User-Agent Strings",
            "description": "Detects scanner tools and exploit frameworks by User-Agent signatures.",
            "severity": "medium",
            "mitre": ["T1190", "T1105"],
            "pattern": r"(?:nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|burpsuite|havij|acunetix|nessus|openvas|zgrab|nuclei|metasploit|cobalt\s*strike)",
            "alt_patterns": [r"(?:python-requests|curl|wget|Go-http-client).*(?:\/admin|\/wp-|\/login)"],
            "keywords": ["nikto", "sqlmap", "nmap", "dirbuster", "gobuster", "burpsuite", "nuclei", "metasploit"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Identify scanning source IP and check reputation",
                "Review all requests from that IP for successful exploitation",
                "Check if any vulnerabilities were found and exploited",
                "Implement rate limiting and WAF rules for scanner signatures"
            ]
        },
        {
            "id": "WEB-005",
            "name": "Command Injection Attempts",
            "description": "Detects OS command injection payloads in web requests.",
            "severity": "critical",
            "mitre": ["T1059", "T1190"],
            "pattern": r"(?:;\s*(?:ls|cat|id|whoami|wget|curl|nc|bash|sh|python|perl|ruby)\b|`[^`]*`|\$\([^)]*\)|\|\s*(?:bash|sh|cmd)|%0a(?:ls|id|cat|whoami))",
            "alt_patterns": [r"(?:ping|nslookup|tracert).*(?:;|%0a|\|)"],
            "keywords": [";ls", "|bash", "whoami", "wget", "curl", "nc ", "netcat", "%0a", "command injection"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Determine if command execution was successful (check response)",
                "Review for reverse shell or data exfiltration attempts",
                "Identify the vulnerable endpoint and input vector",
                "Check for follow-up requests indicating interactive shell access"
            ]
        },
        {
            "id": "WEB-006",
            "name": "Excessive 4xx/5xx Error Rate",
            "description": "Detects high rates of client and server errors indicating scanning or exploitation.",
            "severity": "medium",
            "mitre": ["T1190"],
            "pattern": r"(?:HTTP\/\d\.\d\"\s*(?:4[0-9]{2}|5[0-9]{2}))",
            "alt_patterns": [r"\s(?:400|401|403|404|405|500|502|503)\s"],
            "keywords": [],
            "count_threshold": 50,
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Analyze error distribution — 403s suggest access brute-forcing",
                "High 500s may indicate successful but destructive injection",
                "Correlate with specific source IPs for scanning behavior",
                "Review targeted URLs for patterns (admin panels, API endpoints)"
            ]
        },
        {
            "id": "WEB-007",
            "name": "PHP File in Upload/Storage Directory",
            "description": "Detects access to .php files inside upload, storage, or temp directories — strong web shell indicator.",
            "severity": "critical",
            "mitre": ["T1505", "T1190"],
            "pattern": r"(?:GET|POST)\s+\/(?:[^\s]*\/)?(?:upload|storage|tmp|temp|media|files|documents|attachments|assets\/upload|public\/upload|var\/www)[^\s]*\.php\b",
            "alt_patterns": [r"\/storage\/[^\s]*\.php", r"\/uploads?\/[^\s]*\.php", r"\/tmp\/[^\s]*\.php", r"\/media\/[^\s]*\.php"],
            "keywords": ["storage", "upload", ".php", "public"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "CRITICAL: Likely web shell — isolate server and preserve the file",
                "Check the POST request that uploaded this file",
                "Calculate file hash and analyze the PHP file contents",
                "Identify which upload form was abused",
                "Check for path parameter manipulation",
                "Review all subsequent requests to this PHP file for C2 activity"
            ]
        },
        {
            "id": "WEB-008",
            "name": "Randomized / Base64-like PHP Filename",
            "description": "Detects PHP files with unusually long, random-looking filenames (20+ chars).",
            "severity": "critical",
            "mitre": ["T1505", "T1027"],
            "pattern": r"\/[A-Za-z0-9]{20,}\.php\b",
            "alt_patterns": [r"\/[A-Za-z0-9+\/]{30,}\.php", r"\/[a-f0-9]{32,}\.php"],
            "keywords": [".php"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "CRITICAL: Long random PHP filenames are a strong web shell indicator",
                "Trace back the POST request that created this file",
                "Check if the filename resembles Base64 encoding or MD5/SHA hash",
                "Analyze the file content on disk for backdoor functionality",
                "Search logs for all requests to this file",
                "Check for other files with similar naming patterns"
            ]
        },
        {
            "id": "WEB-009",
            "name": "Server Path Disclosure in Parameters",
            "description": "Detects query parameters containing server filesystem paths.",
            "severity": "high",
            "mitre": ["T1190", "T1083"],
            "pattern": r"\?[^\s]*(?:path|file|dir|include|page|doc|template)\s*=\s*(?:\/var\/|\/home\/|\/tmp\/|\/etc\/|C:\\|\/usr\/|\/opt\/|\/www\/)[^\s&]*",
            "alt_patterns": [r"\?[^\s]*=\s*\/var\/www\/", r"\?[^\s]*=\s*C:\\(?:inetpub|windows|users)\\", r"\?[^\s]*path=\s*\/[^\s&]*\/"],
            "keywords": ["path=", "/var/www", "inetpub", "/home/", "file="],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Check if the path parameter allowed access to unauthorized files",
                "Determine if this is an LFI/RFI vulnerability being exploited",
                "Review if the response contained sensitive file contents",
                "Check for web shell interaction patterns"
            ]
        },
        {
            "id": "WEB-010",
            "name": "POST to Upload Endpoint Followed by PHP Access",
            "description": "Detects POST requests to upload/form endpoints indicating potential web shell upload.",
            "severity": "critical",
            "mitre": ["T1505", "T1190"],
            "pattern": r"POST\s+\/[^\s]*(?:upload|certificate|attachment|document|file|import|avatar|media|proof)[^\s]*\s+HTTP",
            "alt_patterns": [r"POST\s+\/api\/[^\s]*(?:upload|store|create|submit|save)[^\s]*.*HTTP\/[12]", r"POST\s+\/[^\s]*\.php\?", r"multipart\/form-data"],
            "keywords": ["POST", "upload", "multipart", "certificate", "attachment", "proof"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "CRITICAL: Correlate this POST with subsequent GET requests to .php files",
                "Check the upload form for file type validation bypass",
                "Review the uploaded file on disk",
                "Look for double extensions (.php.jpg, .phtml, .php5)",
                "Identify if the upload path is web-accessible",
                "Check Content-Type headers for mismatches"
            ]
        }
    ],
    "registry": [
        {
            "id": "REG-001",
            "name": "Autorun / Persistence Keys Modified",
            "description": "Detects modifications to Windows Registry Run/RunOnce keys. Excludes CD/DVD Autoplay settings.",
            "severity": "high",
            "mitre": ["T1547", "T1112"],
            "pattern": r"(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\(?:Software\\Microsoft\\Windows\\CurrentVersion\\(?:Run(?:Once)?|Explorer\\(?:Shell\s*Folders|User\s*Shell\s*Folders))|Wow6432Node\\.*\\Run)",
            "alt_patterns": [r"CurrentVersion\\Run(?:Once)?\]", r"CurrentVersion\\Run(?:Once)?\\[^\]]*="],
            "keywords": ["CurrentVersion\\Run", "RunOnce", "Shell Folders"],
            "provider_filter": None,
            "provider_exclude": r"Autoplay\\|AutoplayHandlers|PolicyManager\\default\\Autoplay",
            "next_steps": [
                "List all values under the modified Run key",
                "Verify each executable path against known-good baseline",
                "Check file signatures and submit unknown binaries to sandbox",
                "Review modification timestamps against incident timeline"
            ]
        },
        {
            "id": "REG-002",
            "name": "Disabled Security Features via Registry",
            "description": "Detects registry modifications that disable UAC, Windows Defender, firewall, or other security features.",
            "severity": "critical",
            "mitre": ["T1562", "T1112"],
            "pattern": r"(?:EnableLUA.*(?:0|dword:00000000)|DisableAntiSpyware.*(?:1|dword:00000001)|DisableRealtimeMonitoring|DisableAntiVirus|EnableFirewall.*(?:0|dword:00000000))",
            "alt_patterns": [r"windows\s*defender\\.*disable", r"policies\\.*firewall"],
            "keywords": ["EnableLUA", "DisableAntiSpyware", "DisableRealtimeMonitoring", "EnableFirewall", "DisableAntiVirus"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "CRITICAL: Re-enable security controls immediately",
                "Identify the process/user that modified these values",
                "Check for malware execution following the disabling",
                "Audit Group Policy Objects for unauthorized changes"
            ]
        },
        {
            "id": "REG-003",
            "name": "Suspicious Service Registration",
            "description": "Detects new or modified Windows service entries in the registry.",
            "severity": "high",
            "mitre": ["T1543"],
            "pattern": r"(?:HKLM|HKEY_LOCAL_MACHINE)\\System\\(?:CurrentControlSet|ControlSet\d{3})\\Services\\",
            "alt_patterns": [r"services\\.*imagepath", r"servicedll"],
            "keywords": ["CurrentControlSet\\Services", "ImagePath", "ServiceDll", "ControlSet"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Extract the ImagePath/ServiceDll value for the service",
                "Verify the binary is signed and from a legitimate publisher",
                "Check service creation timestamp vs incident timeline",
                "Compare against known services baseline for the OS version"
            ]
        },
        {
            "id": "REG-004",
            "name": "Image File Execution Options (IFEO) Hijack",
            "description": "Detects modifications to IFEO debugger keys, used to hijack legitimate process execution.",
            "severity": "critical",
            "mitre": ["T1546"],
            "pattern": r"Image\s*File\s*Execution\s*Options.*(?:Debugger|GlobalFlag)",
            "alt_patterns": [r"ifeo", r"silent\s*process\s*exit"],
            "keywords": ["Image File Execution Options", "Debugger", "GlobalFlag", "IFEO", "SilentProcessExit"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Identify which process is being hijacked and the debugger path",
                "This is a high-confidence indicator of compromise — escalate",
                "Check for Accessibility Feature abuse (sethc.exe, utilman.exe)",
                "Remove the Debugger value and investigate the malicious binary"
            ]
        },
        {
            "id": "REG-005",
            "name": "Remote Desktop Enabled via Registry",
            "description": "Detects enabling of Remote Desktop Protocol through registry modification.",
            "severity": "medium",
            "mitre": ["T1021", "T1112"],
            "pattern": r"(?:fDenyTSConnections.*(?:0|dword:00000000)|Terminal\s*Server\\.*fDenyTSConnections)",
            "alt_patterns": [r"allow\s*remote\s*desktop", r"fDenyTSConnections"],
            "keywords": ["fDenyTSConnections", "Terminal Server", "Remote Desktop", "RDP", "TermService"],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "Verify if RDP was intentionally enabled by an administrator",
                "Check firewall rules for port 3389 exposure",
                "Review NLA (Network Level Authentication) settings",
                "Monitor for incoming RDP connections from unexpected sources"
            ]
        }
    ]
}