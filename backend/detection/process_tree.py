"""
SIGIL Process Inspector — Build process trees from Sysmon EID 1 and Security EID 4688.
Detects suspicious parent-child process chains with 30+ MITRE ATT&CK detection rules.

Architecture:
  1. Query SQLite for EID 1 (Sysmon) and EID 4688 (Security) events
  2. Build process nodes from event fields
  3. Link parent-child using ProcessGuid (Sysmon) or PID (Security 4688)
  4. Run detection rules against each chain
  5. Return tree structure + findings
"""

import re
import json
from collections import defaultdict


# ── Detection Rules ───────────────────────────────────────────────────────────
# Each rule: { id, name, severity, mitre, parent_re, child_re, desc, cmd_re? }
# parent_re matches parent process name, child_re matches child process name
# cmd_re optionally matches child command line for more specific detection

PROCESS_RULES = [
    # ── Office → Script Engine ──
    {"id": "PT-001", "name": "Office spawning script engine", "severity": "critical",
     "mitre": ["T1566.001", "T1059"], "desc": "Office application spawning a scripting engine — likely macro-based initial access.",
     "parent_re": r"(?i)(winword|excel|powerpnt|msaccess|outlook|onenote)\.exe$",
     "child_re": r"(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|bash)\.exe$"},

    {"id": "PT-002", "name": "Office spawning shell", "severity": "high",
     "mitre": ["T1566.001", "T1059.001"], "desc": "Office application spawning cmd.exe or PowerShell.",
     "parent_re": r"(?i)(winword|excel|powerpnt)\.exe$",
     "child_re": r"(?i)(cmd|powershell|pwsh)\.exe$"},

    # ── PowerShell suspicious usage ──
    {"id": "PT-003", "name": "PowerShell encoded command", "severity": "critical",
     "mitre": ["T1059.001", "T1027"], "desc": "PowerShell executed with encoded command — common evasion technique.",
     "parent_re": r".*",
     "child_re": r"(?i)(powershell|pwsh)\.exe$",
     "cmd_re": r"(?i)(-enc\s|-encodedcommand\s|-e\s+[A-Za-z0-9+/=]{20,})"},

    {"id": "PT-004", "name": "PowerShell download cradle", "severity": "critical",
     "mitre": ["T1059.001", "T1105"], "desc": "PowerShell downloading content — possible malware delivery.",
     "parent_re": r".*",
     "child_re": r"(?i)(powershell|pwsh)\.exe$",
     "cmd_re": r"(?i)(downloadstring|downloadfile|invoke-webrequest|iwr\s|wget\s|curl\s|bitstransfer|net\.webclient|start-bitstransfer)"},

    {"id": "PT-005", "name": "PowerShell bypass execution policy", "severity": "high",
     "mitre": ["T1059.001"], "desc": "PowerShell bypassing execution policy.",
     "parent_re": r".*",
     "child_re": r"(?i)(powershell|pwsh)\.exe$",
     "cmd_re": r"(?i)(-exec\s*bypass|-ep\s*bypass|set-executionpolicy\s*bypass)"},

    # ── Reconnaissance commands ──
    {"id": "PT-006", "name": "Reconnaissance command chain", "severity": "medium",
     "mitre": ["T1082", "T1016", "T1033"], "desc": "Common post-exploitation reconnaissance commands.",
     "parent_re": r"(?i)(cmd|powershell|pwsh)\.exe$",
     "child_re": r"(?i)(whoami|ipconfig|systeminfo|net\.exe|net1\.exe|nltest|dsquery|nslookup|arp|route|netstat|tasklist|qprocess|quser|query)\.exe$"},

    {"id": "PT-007", "name": "Net command enumeration", "severity": "medium",
     "mitre": ["T1087", "T1069"], "desc": "Net command used for user/group enumeration.",
     "parent_re": r".*",
     "child_re": r"(?i)net1?\.exe$",
     "cmd_re": r"(?i)(net\s+(user|localgroup|group|share|view|session|use|accounts)\s)"},

    # ── PsExec / Remote Execution ──
    {"id": "PT-008", "name": "PsExec service execution", "severity": "critical",
     "mitre": ["T1569.002", "T1021.002"], "desc": "PsExec service (PSEXESVC) spawning a process — lateral movement indicator.",
     "parent_re": r"(?i)(psexesvc|psexec)\.exe$",
     "child_re": r"(?i)(cmd|powershell|pwsh)\.exe$"},

    {"id": "PT-009", "name": "Services spawning shell", "severity": "high",
     "mitre": ["T1543.003", "T1569.002"], "desc": "Service control manager spawning command shell — may indicate malicious service.",
     "parent_re": r"(?i)services\.exe$",
     "child_re": r"(?i)(cmd|powershell|pwsh)\.exe$"},

    # ── WMI Lateral Movement ──
    {"id": "PT-010", "name": "WMI spawning process", "severity": "high",
     "mitre": ["T1047", "T1021"], "desc": "WMI provider host spawning shell or script — possible lateral movement.",
     "parent_re": r"(?i)(wmiprvse|scrcons)\.exe$",
     "child_re": r"(?i)(cmd|powershell|pwsh|wscript|cscript|mshta)\.exe$"},

    # ── LOLBins (Living Off the Land) ──
    {"id": "PT-011", "name": "Certutil download/decode", "severity": "critical",
     "mitre": ["T1105", "T1140"], "desc": "Certutil used for downloading or decoding — common LOLBin abuse.",
     "parent_re": r".*",
     "child_re": r"(?i)certutil\.exe$",
     "cmd_re": r"(?i)(-urlcache|-split|-decode|-decodehex|http)"},

    {"id": "PT-012", "name": "Mshta execution", "severity": "high",
     "mitre": ["T1218.005"], "desc": "Mshta executing script or URL — possible defense evasion.",
     "parent_re": r".*",
     "child_re": r"(?i)mshta\.exe$",
     "cmd_re": r"(?i)(http|javascript|vbscript|about:)"},

    {"id": "PT-013", "name": "Regsvr32 scriptlet execution", "severity": "critical",
     "mitre": ["T1218.010"], "desc": "Regsvr32 with scrobj.dll or URL — Squiblydoo attack.",
     "parent_re": r".*",
     "child_re": r"(?i)regsvr32\.exe$",
     "cmd_re": r"(?i)(/s\s|scrobj\.dll|/i:http)"},

    {"id": "PT-014", "name": "Rundll32 suspicious execution", "severity": "high",
     "mitre": ["T1218.011"], "desc": "Rundll32 loading unusual DLL — possible defense evasion.",
     "parent_re": r".*",
     "child_re": r"(?i)rundll32\.exe$",
     "cmd_re": r"(?i)(javascript|http|temp|appdata|public|downloads)"},

    {"id": "PT-015", "name": "BITSAdmin transfer", "severity": "high",
     "mitre": ["T1197", "T1105"], "desc": "BITSAdmin used for file transfer — evasion of security controls.",
     "parent_re": r".*",
     "child_re": r"(?i)bitsadmin\.exe$",
     "cmd_re": r"(?i)(/transfer|/create|/addfile|http)"},

    {"id": "PT-016", "name": "WMIC process creation", "severity": "high",
     "mitre": ["T1047"], "desc": "WMIC used for process creation or remote execution.",
     "parent_re": r".*",
     "child_re": r"(?i)wmic\.exe$",
     "cmd_re": r"(?i)(process\s+call\s+create|/node:|shadowcopy\s+delete)"},

    {"id": "PT-017", "name": "MSBuild execution", "severity": "high",
     "mitre": ["T1127.001"], "desc": "MSBuild executing inline tasks — trusted binary abuse.",
     "parent_re": r".*",
     "child_re": r"(?i)msbuild\.exe$"},

    # ── Credential Access ──
    {"id": "PT-018", "name": "LSASS access or dumping", "severity": "critical",
     "mitre": ["T1003.001"], "desc": "Process accessing or dumping LSASS — credential theft indicator.",
     "parent_re": r".*",
     "child_re": r"(?i)(procdump|mimikatz|sekurlsa|comsvcs)\.exe$"},

    {"id": "PT-019", "name": "Credential dumping via comsvcs", "severity": "critical",
     "mitre": ["T1003.001"], "desc": "Rundll32 with comsvcs.dll MiniDump — LSASS credential dumping.",
     "parent_re": r".*",
     "child_re": r"(?i)rundll32\.exe$",
     "cmd_re": r"(?i)comsvcs\.dll.+minidump"},

    # ── Defense Evasion ──
    {"id": "PT-020", "name": "Event log clearing", "severity": "critical",
     "mitre": ["T1070.001"], "desc": "Attempting to clear Windows event logs.",
     "parent_re": r".*",
     "child_re": r"(?i)(wevtutil|powershell|pwsh|cmd)\.exe$",
     "cmd_re": r"(?i)(wevtutil\s+cl|clear-eventlog|remove-eventlog)"},

    {"id": "PT-021", "name": "Shadow copy deletion", "severity": "critical",
     "mitre": ["T1490"], "desc": "Deleting volume shadow copies — pre-ransomware indicator.",
     "parent_re": r".*",
     "child_re": r"(?i)(vssadmin|wmic|powershell|cmd)\.exe$",
     "cmd_re": r"(?i)(delete\s+shadows|shadowcopy\s+delete|resize\s+shadowstorage)"},

    {"id": "PT-022", "name": "Disabling security software", "severity": "critical",
     "mitre": ["T1562.001"], "desc": "Attempting to disable antivirus or firewall.",
     "parent_re": r".*",
     "child_re": r"(?i)(sc|net|powershell|cmd|reg|netsh)\.exe$",
     "cmd_re": r"(?i)(stop\s+windefend|stop\s+mpssvc|set-mppreference\s+-disablerealtimemonitoring|advfirewall\s+set.*state\s+off)"},

    # ── Suspicious parent-child ──
    {"id": "PT-023", "name": "Explorer spawning script engine", "severity": "medium",
     "mitre": ["T1204.002"], "desc": "Explorer spawning script — user executed suspicious file.",
     "parent_re": r"(?i)explorer\.exe$",
     "child_re": r"(?i)(powershell|pwsh|cmd|wscript|cscript|mshta)\.exe$"},

    {"id": "PT-024", "name": "Svchost spawning shell", "severity": "high",
     "mitre": ["T1055", "T1543"], "desc": "Svchost spawning command shell — possible injection or malicious service.",
     "parent_re": r"(?i)svchost\.exe$",
     "child_re": r"(?i)(cmd|powershell|pwsh)\.exe$"},

    {"id": "PT-025", "name": "Taskeng/TaskHostW execution", "severity": "medium",
     "mitre": ["T1053.005"], "desc": "Scheduled task executing process.",
     "parent_re": r"(?i)(taskeng|taskhostw)\.exe$",
     "child_re": r"(?i)(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32)\.exe$"},

    # ── Execution from suspicious paths ──
    {"id": "PT-026", "name": "Execution from temp directory", "severity": "high",
     "mitre": ["T1204"], "desc": "Process executed from temp or user profile directory.",
     "parent_re": r".*",
     "child_re": r"(?i).*\\(temp|tmp|appdata|downloads|public|programdata)\\.*\.exe$"},

    {"id": "PT-027", "name": "Execution from recycle bin", "severity": "critical",
     "mitre": ["T1564.001"], "desc": "Process executing from Recycle Bin — hiding malware.",
     "parent_re": r".*",
     "child_re": r"(?i).*\\\$recycle\.bin\\.*\.exe$"},

    # ── Lateral movement indicators ──
    {"id": "PT-028", "name": "Remote scheduled task creation", "severity": "high",
     "mitre": ["T1053.005"], "desc": "Creating scheduled task on remote system.",
     "parent_re": r".*",
     "child_re": r"(?i)schtasks\.exe$",
     "cmd_re": r"(?i)(/create\s+/s\s|/run\s+/s\s)"},

    {"id": "PT-029", "name": "Remote service creation", "severity": "high",
     "mitre": ["T1543.003"], "desc": "Creating or starting service on remote system.",
     "parent_re": r".*",
     "child_re": r"(?i)sc\.exe$",
     "cmd_re": r"(?i)(\\\\.*\s+(create|start|config)\s)"},

    # ── Impacket / Cobalt Strike ──
    {"id": "PT-030", "name": "Impacket-style execution", "severity": "critical",
     "mitre": ["T1569.002"], "desc": "cmd.exe with echo/pipe pattern typical of Impacket remote execution.",
     "parent_re": r"(?i)(cmd|services)\.exe$",
     "child_re": r"(?i)cmd\.exe$",
     "cmd_re": r"(?i)(cmd\.exe\s+/q\s+/c|echo\s.*>\s*\\\\.*\\pipe\\|%comspec%\s+/q\s+/c)"},
]

# Compile all regex patterns once
for rule in PROCESS_RULES:
    rule["_parent_re"] = re.compile(rule["parent_re"])
    rule["_child_re"] = re.compile(rule["child_re"])
    rule["_cmd_re"] = re.compile(rule["cmd_re"]) if rule.get("cmd_re") else None


def _extract_process_name(full_path):
    """Extract just the filename from a full path."""
    if not full_path:
        return ""
    return full_path.replace("/", "\\").split("\\")[-1]


def _normalize_pid(pid_str):
    """Normalize PID from hex string (0xa0) or decimal string to consistent decimal string."""
    if not pid_str:
        return ""
    pid_str = str(pid_str).strip()
    try:
        if pid_str.startswith("0x") or pid_str.startswith("0X"):
            return str(int(pid_str, 16))
        return str(int(pid_str))
    except (ValueError, TypeError):
        return pid_str


# MandatoryLabel SID → integrity level mapping
_INTEGRITY_SIDS = {
    "s-1-16-0": "Untrusted",
    "s-1-16-4096": "Low",
    "s-1-16-8192": "Medium",
    "s-1-16-8448": "Medium",  # Medium Plus
    "s-1-16-12288": "High",
    "s-1-16-16384": "System",
}


def _parse_integrity(mandatory_label):
    """Parse integrity level from MandatoryLabel (handles SID and text formats)."""
    if not mandatory_label:
        return ""
    ml = mandatory_label.strip().lower()
    # Check SID format first (e.g., "S-1-16-16384")
    if ml.startswith("s-1-16-"):
        return _INTEGRITY_SIDS.get(ml, "")
    # Check text format (e.g., "Mandatory Label\High Mandatory Level")
    if "system" in ml or "16384" in ml:
        return "System"
    if "high" in ml or "12288" in ml:
        return "High"
    if "medium" in ml or "8192" in ml:
        return "Medium"
    if "low" in ml or "4096" in ml:
        return "Low"
    return ""


def build_process_tree(events: list[dict]) -> dict:
    """Build process tree from EID 1 (Sysmon) and EID 4688 (Security) events."""

    nodes = {}       # key -> node dict
    children = defaultdict(list)  # parent_key -> [child_keys]
    root_keys = []   # nodes with no parent found

    has_sysmon = any(str(e.get("event_id")) == "1" and "sysmon" in (e.get("provider") or "").lower() for e in events)

    for ev in events:
        eid = str(ev.get("event_id", ""))
        fields = ev.get("fields", {})
        if isinstance(fields, str):
            try:
                fields = json.loads(fields)
            except:
                fields = {}

        timestamp = ev.get("timestamp", "")
        computer = ev.get("computer", "")
        provider = (ev.get("provider") or "").lower()

        if eid == "1" and "sysmon" in provider:
            # Sysmon Process Create (provider must be Microsoft-Windows-Sysmon)
            proc_guid = fields.get("ProcessGuid", "")
            parent_guid = fields.get("ParentProcessGuid", "")
            pid = _normalize_pid(fields.get("ProcessId", ""))
            ppid = _normalize_pid(fields.get("ParentProcessId", ""))
            image = fields.get("Image", "")
            parent_image = fields.get("ParentImage", "")
            cmd_line = fields.get("CommandLine", "")
            parent_cmd = fields.get("ParentCommandLine", "")
            user = fields.get("User", "")
            integrity = fields.get("IntegrityLevel", "")
            hashes = fields.get("Hashes", "")

            key = proc_guid or f"pid-{pid}-{timestamp}"
            parent_key = parent_guid or f"pid-{ppid}" if ppid else ""

            nodes[key] = {
                "key": key,
                "pid": pid,
                "ppid": ppid,
                "image": image,
                "name": _extract_process_name(image),
                "cmd_line": cmd_line,
                "parent_image": parent_image,
                "parent_name": _extract_process_name(parent_image),
                "parent_cmd": parent_cmd,
                "user": user,
                "integrity": integrity,
                "timestamp": timestamp,
                "computer": computer,
                "hashes": hashes,
                "event_id": eid,
                "source": "sysmon",
                "parent_key": parent_key,
                "children": [],
                "depth": 0,
                "detections": [],
            }

        elif eid == "4688":
            # Security Process Creation
            pid_raw = fields.get("NewProcessId", fields.get("ProcessId", ""))
            ppid_raw = fields.get("ProcessId", fields.get("ParentProcessId", ""))
            image = fields.get("NewProcessName", "")
            parent_image = fields.get("ParentProcessName", "")
            cmd_line = fields.get("CommandLine", "")
            user = fields.get("SubjectUserName", fields.get("TargetUserName", ""))
            domain = fields.get("SubjectDomainName", fields.get("TargetDomainName", ""))
            token_elev = fields.get("TokenElevationType", "")
            mandatory_label = fields.get("MandatoryLabel", "")

            # Normalize hex PIDs to decimal for consistent matching
            pid = _normalize_pid(pid_raw)
            ppid = _normalize_pid(ppid_raw)

            # Filter noise: skip "-" users
            if user in ("-", ""):
                user = ""
            if domain in ("-", ""):
                domain = ""

            # Determine integrity from MandatoryLabel (handles both text and SID formats)
            integrity = _parse_integrity(mandatory_label)

            key = f"sec-{pid}-{timestamp}"
            parent_key = f"sec-{ppid}" if ppid else ""

            nodes[key] = {
                "key": key,
                "pid": pid,
                "ppid": ppid,
                "image": image,
                "name": _extract_process_name(image),
                "cmd_line": cmd_line,
                "parent_image": parent_image,
                "parent_name": _extract_process_name(parent_image),
                "parent_cmd": "",
                "user": f"{domain}\\{user}" if domain and domain != "-" else user,
                "integrity": integrity,
                "timestamp": timestamp,
                "computer": computer,
                "hashes": "",
                "event_id": eid,
                "source": "security",
                "parent_key": parent_key,
                "children": [],
                "depth": 0,
                "detections": [],
            }

    # ── Link parent-child ──
    # For Sysmon: use ProcessGuid/ParentProcessGuid (reliable)
    # For Security 4688: use PID matching (less reliable due to PID reuse)

    if has_sysmon:
        for key, node in nodes.items():
            pk = node["parent_key"]
            if pk and pk in nodes:
                children[pk].append(key)
            else:
                root_keys.append(key)
    else:
        # Security 4688 — match by PID (best effort)
        pid_to_keys = defaultdict(list)
        for key, node in nodes.items():
            if node["pid"]:
                pid_to_keys[node["pid"]].append(key)

        for key, node in nodes.items():
            ppid = node["ppid"]
            if ppid and ppid in pid_to_keys:
                # Find the most recent parent with this PID before this timestamp
                candidates = [k for k in pid_to_keys[ppid]
                              if nodes[k]["timestamp"] <= node["timestamp"]]
                if candidates:
                    parent_key = candidates[-1]  # most recent
                    children[parent_key].append(key)
                    node["parent_key"] = parent_key
                    continue
            root_keys.append(key)

    # Assign children lists and compute depth
    for parent_key, child_keys in children.items():
        if parent_key in nodes:
            nodes[parent_key]["children"] = child_keys

    def _set_depth(key, depth):
        if key in nodes:
            nodes[key]["depth"] = depth
            for ck in nodes[key]["children"]:
                _set_depth(ck, depth + 1)

    for rk in root_keys:
        _set_depth(rk, 0)

    return {"nodes": nodes, "roots": root_keys, "children": children}


def run_process_detections(tree: dict) -> list[dict]:
    """Run detection rules against all process chains in the tree."""
    findings = []
    nodes = tree["nodes"]

    for key, node in nodes.items():
        child_name = node["name"]
        child_image = node["image"]
        child_cmd = node["cmd_line"]
        parent_name = node["parent_name"]
        parent_image = node["parent_image"]

        if not child_name:
            continue

        for rule in PROCESS_RULES:
            # Check parent match
            parent_target = parent_image or parent_name
            if not rule["_parent_re"].search(parent_target or ""):
                continue

            # Check child match
            child_target = child_image or child_name
            if not rule["_child_re"].search(child_target):
                continue

            # Check command line match (if rule has cmd_re)
            if rule["_cmd_re"]:
                if not child_cmd or not rule["_cmd_re"].search(child_cmd):
                    continue

            # Match found
            node["detections"].append({
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "mitre": rule["mitre"],
                "desc": rule["desc"],
            })

            findings.append({
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "mitre": rule["mitre"],
                "desc": rule["desc"],
                "process_key": key,
                "parent": parent_name or parent_image,
                "child": child_name or child_image,
                "cmd_line": child_cmd[:300] if child_cmd else "",
                "user": node["user"],
                "timestamp": node["timestamp"],
                "computer": node["computer"],
            })

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 3), f["timestamp"]))
    return findings


def flatten_tree(tree: dict, max_nodes: int = 5000) -> list[dict]:
    """Flatten the tree into a list for frontend rendering (depth-first order)."""
    nodes = tree["nodes"]
    roots = tree["roots"]
    flat = []

    def _walk(key, depth):
        if len(flat) >= max_nodes:
            return
        if key not in nodes:
            return
        node = nodes[key]
        flat.append({
            "key": node["key"],
            "pid": node["pid"],
            "ppid": node["ppid"],
            "name": node["name"],
            "image": node["image"],
            "cmd_line": node["cmd_line"][:500] if node["cmd_line"] else "",
            "parent_name": node["parent_name"],
            "user": node["user"],
            "integrity": node["integrity"],
            "timestamp": node["timestamp"],
            "computer": node["computer"],
            "event_id": node["event_id"],
            "source": node["source"],
            "depth": depth,
            "child_count": len(node["children"]),
            "detections": node["detections"],
            "has_detection": len(node["detections"]) > 0,
        })
        for ck in sorted(node["children"], key=lambda k: nodes.get(k, {}).get("timestamp", "")):
            _walk(ck, depth + 1)

    for rk in sorted(roots, key=lambda k: nodes.get(k, {}).get("timestamp", "")):
        _walk(rk, 0)

    return flat


def analyze_process_tree(events: list[dict]) -> dict:
    """Full process tree analysis pipeline."""
    # Filter to process creation events only
    proc_events = [e for e in events if
                   (str(e.get("event_id", "")) == "4688") or
                   (str(e.get("event_id", "")) == "1" and "sysmon" in (e.get("provider") or "").lower())]

    if not proc_events:
        return {
            "status": "no_data",
            "tree": [],
            "findings": [],
            "summary": {
                "total_processes": 0,
                "sysmon_events": 0,
                "security_events": 0,
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
            }
        }

    tree = build_process_tree(proc_events)
    findings = run_process_detections(tree)
    flat = flatten_tree(tree)

    sysmon_count = sum(1 for e in proc_events if str(e.get("event_id")) == "1" and "sysmon" in (e.get("provider") or "").lower())
    security_count = sum(1 for e in proc_events if str(e.get("event_id")) == "4688")

    return {
        "status": "success",
        "tree": flat,
        "findings": findings,
        "summary": {
            "total_processes": len(flat),
            "sysmon_events": sysmon_count,
            "security_events": security_count,
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f["severity"] == "critical"),
            "high_count": sum(1 for f in findings if f["severity"] == "high"),
            "medium_count": sum(1 for f in findings if f["severity"] == "medium"),
            "root_processes": len(tree["roots"]),
        }
    }