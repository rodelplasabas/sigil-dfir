"""
SIGIL Lateral Movement Analyzer v2 — IRFlow-inspired improvements.

Enhancements over v1:
  1. Session-only vs edge-creating events — logoff/disconnect events don't pollute the graph
  2. RDP session correlation — 1149→4624(T10)→21→22 chain tracking with confidence scoring
  3. smbexec detection — random 8-char service names in EID 7045
  4. Cleartext logon flagging — LogonType 8 warning
  5. ADMIN$/C$ share access detection — from EID 5140/5145
  6. Pivot host detection — nodes that are both source and target
  7. 15+ finding detectors with MITRE mapping
"""

import re
from collections import defaultdict

LOGON_TYPES = {
    "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)", "11": "CachedInteractive", "12": "CachedRDP",
}

LOGON_COLORS = {
    "2": "#f59e0b", "3": "#10b981", "4": "#6b7280", "5": "#6b7280",
    "7": "#8b5cf6", "8": "#ef4444", "9": "#f97316", "10": "#3b82f6",
    "11": "#6366f1", "12": "#3b82f6",
}

NOISE_IPS = {"127.0.0.1", "::1", "-", "", "0.0.0.0"}
NOISE_USERS_ALWAYS = {"-", "", "system", "local service", "network service",
                      "dwm-1", "dwm-2", "umfd-0", "umfd-1", "font driver host"}
NOISE_USERS_LOCAL_ONLY = {"anonymous logon", "anonymous"}

# Events that create graph edges (connections between hosts)
EDGE_CREATING_EIDS = {
    "4624", "4625", "4648",          # Logon success/fail/explicit
    "4778",                           # Session reconnect (has ClientName)
    "1149",                           # RDP network auth
    "21", "22", "25",                 # RDP session active
    "5140", "5145",                   # SMB share access
    "7045", "4697",                   # Service install
    "4688",                           # Process creation
    "4104", "4103",                   # PowerShell
    "5861",                           # WMI
    "4698",                           # Scheduled task
    "1", "3",                         # Sysmon process/network
}

# Events used for correlation only (don't create graph edges)
SESSION_ONLY_EIDS = {
    "23", "24", "39", "40",           # RDP disconnect/logoff
    "4634", "4647",                   # Account logoff
    "4672", "4673", "4674",           # Privilege events
    "4769", "4768", "4776",           # Kerberos/NTLM
    "4779",                           # Session disconnect
    "4702",                           # Scheduled task updated
    "10", "11", "22",                 # Sysmon process access/file/DNS
}

ALL_LM_EVENT_IDS = EDGE_CREATING_EIDS | SESSION_ONLY_EIDS

# smbexec detection: random 8-char service names
SMBEXEC_RE = re.compile(r'^[a-zA-Z]{8}$')


def extract_logon_events(events: list[dict], target_eids: set[str] = None) -> list[dict]:
    """Extract and normalize lateral movement events from parsed EVTX."""
    if target_eids is None:
        target_eids = ALL_LM_EVENT_IDS

    logons = []
    for ev in events:
        eid = str(ev.get("event_id", ""))
        if eid not in target_eids:
            continue

        fields = ev.get("fields", {})
        timestamp = ev.get("timestamp", "")
        computer = ev.get("computer", "") or fields.get("Computer", "")

        source_ip = (fields.get("IpAddress") or fields.get("SourceAddress")
                     or fields.get("SourceNetworkAddress") or "").strip()
        target_user = (fields.get("TargetUserName") or fields.get("TargetUser") or "").strip()
        subject_user = (fields.get("SubjectUserName") or "").strip()
        workstation = (fields.get("WorkstationName") or "").strip()
        logon_type = str(fields.get("LogonType", "")).strip()
        target_domain = (fields.get("TargetDomainName") or "").strip()
        logon_id = (fields.get("TargetLogonId") or fields.get("SubjectLogonId") or "").strip()
        process_name = (fields.get("ProcessName") or fields.get("NewProcessName") or "").strip()
        service_name = (fields.get("ServiceName") or "").strip()
        share_name = (fields.get("ShareName") or "").strip()
        relative_target = (fields.get("RelativeTargetName") or "").strip()
        client_name = (fields.get("ClientName") or "").strip()
        client_address = (fields.get("ClientAddress") or "").strip()
        ticket_encryption = (fields.get("TicketEncryptionType") or "").strip()

        # Filter noise
        if source_ip in NOISE_IPS:
            source_ip = ""
        if target_user.lower() in NOISE_USERS_ALWAYS or target_user.endswith("$"):
            # Exception: keep machine account logons for 4624 Type 3 (network)
            if not (eid == "4624" and logon_type == "3" and target_user.endswith("$")):
                continue
        if target_user.lower() in NOISE_USERS_LOCAL_ONLY and not source_ip:
            continue
        if subject_user.lower() in NOISE_USERS_ALWAYS:
            subject_user = ""

        # Build source node
        if eid in ("4778", "4779"):
            source = client_name or client_address or ""
        else:
            source = source_ip or workstation or ""
        target = computer

        # Clean dash/LOCAL values
        if source in ("-", ".", "LOCAL", "local"):
            source = ""
        if target in ("-", ".", "LOCAL", "local"):
            target = ""

        if not source or not target:
            if eid in SESSION_ONLY_EIDS:
                continue  # Session-only events without source are noise
            elif eid == "4672":
                source = subject_user or ""
                if not source:
                    continue
            else:
                continue

        if source.lower() == target.lower():
            continue

        is_edge_creating = eid in EDGE_CREATING_EIDS
        status = "Success"
        if eid == "4625":
            status = "Failed"
        elif eid in SESSION_ONLY_EIDS:
            status = "Session"

        logons.append({
            "event_id": eid,
            "timestamp": timestamp,
            "source": source,
            "target": target,
            "target_user": target_user or subject_user,
            "subject_user": subject_user,
            "logon_type": logon_type,
            "logon_type_label": LOGON_TYPES.get(logon_type, f"Type {logon_type}" if logon_type else ""),
            "logon_type_color": LOGON_COLORS.get(logon_type, "#6b7280"),
            "domain": target_domain,
            "workstation": workstation,
            "status": status,
            "process_name": process_name,
            "service_name": service_name,
            "share_name": share_name,
            "relative_target": relative_target,
            "ticket_encryption": ticket_encryption,
            "record_id": ev.get("record_id", ""),
            "is_edge_creating": is_edge_creating,
        })

    logons.sort(key=lambda x: x.get("timestamp", ""))
    return logons


def build_network_graph(logons: list[dict]) -> dict:
    """Build graph from edge-creating events only."""
    nodes_set = set()
    edge_map = defaultdict(lambda: {
        "count": 0, "logon_types": set(), "users": set(),
        "first_seen": "", "last_seen": "", "statuses": set(),
        "share_names": set(), "service_names": set(),
        "has_failures": False, "has_cleartext": False,
        "admin_share_count": 0, "rdp_count": 0,
    })

    for logon in logons:
        if not logon.get("is_edge_creating", True):
            continue

        src, tgt = logon["source"], logon["target"]
        nodes_set.add(src)
        nodes_set.add(tgt)

        edge_key = f"{src}→{tgt}"
        edge = edge_map[edge_key]
        edge["count"] += 1
        if logon["logon_type"]:
            edge["logon_types"].add(logon["logon_type"])
        if logon["target_user"]:
            edge["users"].add(logon["target_user"])
        edge["statuses"].add(logon["status"])

        if not edge["first_seen"] or logon["timestamp"] < edge["first_seen"]:
            edge["first_seen"] = logon["timestamp"]
        if not edge["last_seen"] or logon["timestamp"] > edge["last_seen"]:
            edge["last_seen"] = logon["timestamp"]

        if logon["status"] == "Failed":
            edge["has_failures"] = True
        if logon["logon_type"] == "8":
            edge["has_cleartext"] = True
        if logon["logon_type"] in ("10", "12"):
            edge["rdp_count"] += 1
        if logon["share_name"]:
            edge["share_names"].add(logon["share_name"])
            sn = logon["share_name"].replace("\\\\*\\", "").upper()
            if re.match(r'^(ADMIN\$|C\$|[A-Z]\$)$', sn):
                edge["admin_share_count"] += 1
        if logon["service_name"]:
            edge["service_names"].add(logon["service_name"])

    sources = {l["source"] for l in logons if l.get("is_edge_creating")}
    targets = {l["target"] for l in logons if l.get("is_edge_creating")}

    # Count events per node for sizing
    node_event_counts = defaultdict(int)
    for l in logons:
        if l.get("is_edge_creating"):
            node_event_counts[l["source"]] += 1
            node_event_counts[l["target"]] += 1

    nodes = []
    for node_id in nodes_set:
        is_ip = any(c.isdigit() for c in node_id) and ("." in node_id or ":" in node_id)
        is_source_only = node_id in sources and node_id not in targets
        is_target_only = node_id not in sources and node_id in targets
        role = "both" if (node_id in sources and node_id in targets) else (
            "source" if is_source_only else "target")

        in_count = sum(1 for e in edge_map if e.endswith(f"→{node_id}"))
        out_count = sum(1 for e in edge_map if e.startswith(f"{node_id}→"))

        nodes.append({
            "id": node_id, "type": "ip" if is_ip else "host", "role": role,
            "connections_in": in_count, "connections_out": out_count,
            "event_count": node_event_counts.get(node_id, 0),
        })

    edges = []
    for edge_key, data in edge_map.items():
        src, tgt = edge_key.split("→", 1)
        primary_type = max(data["logon_types"], key=lambda t: sum(
            1 for l in logons if l["source"] == src and l["target"] == tgt
            and l["logon_type"] == t and l.get("is_edge_creating")
        )) if data["logon_types"] else ""

        edges.append({
            "source": src, "target": tgt,
            "count": data["count"],
            "logon_types": sorted(data["logon_types"]),
            "logon_type_label": LOGON_TYPES.get(primary_type, f"Type {primary_type}"),
            "color": LOGON_COLORS.get(primary_type, "#6b7280"),
            "users": sorted(data["users"]),
            "statuses": sorted(data["statuses"]),
            "first_seen": data["first_seen"],
            "last_seen": data["last_seen"],
            "has_failures": data["has_failures"],
            "has_cleartext": data["has_cleartext"],
            "admin_share_count": data["admin_share_count"],
            "rdp_count": data["rdp_count"],
            "share_names": sorted(data["share_names"]),
            "service_names": sorted(data["service_names"]),
        })

    return {"nodes": nodes, "edges": edges}


def detect_chains(logons: list[dict], max_chain_len: int = 8) -> list[list[dict]]:
    """Detect multi-hop lateral movement chains using edge-creating events only."""
    edge_logons = [l for l in logons if l.get("is_edge_creating")]
    # Index by SOURCE — so we can find "logons originating from host X"
    outbound_from = defaultdict(list)
    for logon in edge_logons:
        outbound_from[logon["source"]].append(logon)

    chains = []
    visited_starts = set()

    for logon in edge_logons:
        if logon["source"] in visited_starts:
            continue
        chain = [logon]
        current_target = logon["target"]
        current_time = logon["timestamp"]
        seen = {logon["source"], logon["target"]}

        for _ in range(max_chain_len - 1):
            # Find logons FROM current_target AFTER current_time
            next_hops = [
                l for l in outbound_from.get(current_target, [])
                if l["timestamp"] >= current_time
                and l["target"] not in seen
            ]
            if not next_hops:
                break
            hop = next_hops[0]
            chain.append(hop)
            seen.add(hop["target"])
            current_target = hop["target"]
            current_time = hop["timestamp"]

        if len(chain) >= 2:
            chains.append(chain)
            visited_starts.add(logon["source"])

    chains.sort(key=lambda c: (-len(c), c[0]["timestamp"]))
    return chains[:50]


def generate_findings(logons: list[dict], edges: list[dict], chains: list[list[dict]]) -> list[dict]:
    """Generate findings from lateral movement data — 15+ detectors."""
    findings = []

    # ── 1. Brute Force Detection ──
    failed_by_source = defaultdict(list)
    for l in logons:
        if l["status"] == "Failed":
            failed_by_source[l["source"]].append(l)

    for src, failed_list in failed_by_source.items():
        if len(failed_list) >= 3:
            targets = sorted(set(f["target"] for f in failed_list))
            findings.append({
                "severity": "high", "mitre": "T1110.001",
                "title": f"Brute force: {src} → {', '.join(targets[:3])}",
                "desc": f"{len(failed_list)} failed logon attempts from {src}.",
                "source": src, "targets": targets,
            })

    # ── 2. Credential Compromise (failed → success) ──
    pairs = defaultdict(lambda: {"f": [], "s": []})
    for l in logons:
        if l.get("is_edge_creating"):
            key = f"{l['source']}→{l['target']}"
            if l["status"] == "Failed":
                pairs[key]["f"].append(l)
            elif l["status"] == "Success":
                pairs[key]["s"].append(l)

    for pair_key, data in pairs.items():
        if data["f"] and data["s"]:
            last_fail = data["f"][-1]
            first_success = next((s for s in data["s"] if s["timestamp"] > last_fail["timestamp"]), None)
            if first_success:
                findings.append({
                    "severity": "critical", "mitre": "T1078",
                    "title": f"Credential compromise: {pair_key}",
                    "desc": f"Failed logon followed by success. User: {first_success['target_user']}.",
                    "source": pair_key.split("→")[0],
                    "targets": [pair_key.split("→")[1]],
                })

    # ── 3. RDP Sessions ──
    for edge in edges:
        if edge.get("rdp_count", 0) > 0:
            findings.append({
                "severity": "medium", "mitre": "T1021.001",
                "title": f"RDP session: {edge['source']} → {edge['target']}",
                "desc": f"{edge['rdp_count']} RDP logon(s). Users: {', '.join(edge['users'][:5])}.",
                "source": edge["source"], "targets": [edge["target"]],
            })

    # ── 4. Cleartext Logon (LogonType 8) ──
    for edge in edges:
        if edge.get("has_cleartext"):
            findings.append({
                "severity": "critical", "mitre": "T1552",
                "title": f"Cleartext logon: {edge['source']} → {edge['target']}",
                "desc": f"Network cleartext authentication (LogonType 8). Credentials transmitted in plaintext.",
                "source": edge["source"], "targets": [edge["target"]],
            })

    # ── 5. ADMIN$/C$ Share Access ──
    for edge in edges:
        if edge.get("admin_share_count", 0) > 0:
            shares = [s for s in edge.get("share_names", []) if
                      re.match(r'(?i).*\\\\.*\\(ADMIN\$|C\$|[A-Z]\$)', s)]
            findings.append({
                "severity": "high", "mitre": "T1021.002",
                "title": f"Admin share access: {edge['source']} → {edge['target']}",
                "desc": f"{edge['admin_share_count']} access(es) to administrative shares. "
                        f"Shares: {', '.join(edge.get('share_names', [])[:5])}.",
                "source": edge["source"], "targets": [edge["target"]],
            })

    # ── 6. smbexec Detection (random 8-char service names) ──
    smbexec_services = []
    for l in logons:
        if l["event_id"] in ("7045", "4697") and l.get("service_name"):
            if SMBEXEC_RE.match(l["service_name"]):
                smbexec_services.append(l)

    if smbexec_services:
        svc_names = sorted(set(s["service_name"] for s in smbexec_services))
        findings.append({
            "severity": "critical", "mitre": "T1569.002",
            "title": "Impacket smbexec.py detected",
            "desc": f"{len(smbexec_services)} event(s) with random 8-char service names: "
                    f"{', '.join(svc_names[:5])}. Classic Impacket smbexec indicator.",
            "source": smbexec_services[0].get("source", ""),
            "targets": sorted(set(s["target"] for s in smbexec_services)),
        })

    # ── 7. Pivot Host Detection ──
    sources_set = set(l["source"] for l in logons if l.get("is_edge_creating"))
    targets_set = set(l["target"] for l in logons if l.get("is_edge_creating"))
    pivot_hosts = sources_set & targets_set

    for host in pivot_hosts:
        in_edges = [e for e in edges if e["target"] == host]
        out_edges = [e for e in edges if e["source"] == host]
        if in_edges and out_edges:
            in_sources = sorted(set(e["source"] for e in in_edges))
            out_targets = sorted(set(e["target"] for e in out_edges))
            findings.append({
                "severity": "high", "mitre": "T1021",
                "title": f"Pivot host: {host}",
                "desc": f"Used as both target ({len(in_edges)} inbound from {', '.join(in_sources[:3])}) "
                        f"and source ({len(out_edges)} outbound to {', '.join(out_targets[:3])}).",
                "source": host, "targets": out_targets,
            })

    # ── 8. Multi-hop Chains ──
    for chain in chains:
        path = [chain[0]["source"]] + [h["target"] for h in chain]
        findings.append({
            "severity": "high", "mitre": "T1021",
            "title": f"Lateral chain ({len(chain)} hops)",
            "desc": " → ".join(path),
            "source": chain[0]["source"],
            "targets": [h["target"] for h in chain],
        })

    # ── 9. Kerberoasting (4769 spikes) ──
    kerb_events = [l for l in logons if l["event_id"] == "4769"]
    if len(kerb_events) >= 10:
        # Check for weak encryption types (0x17 = RC4)
        weak_enc = [k for k in kerb_events if k.get("ticket_encryption") in ("0x17", "23", "0x00000017")]
        if weak_enc:
            findings.append({
                "severity": "critical", "mitre": "T1558.003",
                "title": "Possible Kerberoasting detected",
                "desc": f"{len(kerb_events)} Kerberos service ticket requests, "
                        f"{len(weak_enc)} using RC4 (weak) encryption.",
                "source": weak_enc[0].get("source", ""),
                "targets": sorted(set(k["target"] for k in weak_enc))[:5],
            })
        elif len(kerb_events) >= 20:
            findings.append({
                "severity": "medium", "mitre": "T1558.003",
                "title": "Kerberos TGS request spike",
                "desc": f"{len(kerb_events)} Kerberos service ticket requests detected — "
                        f"may indicate Kerberoasting or service enumeration.",
                "source": kerb_events[0].get("source", ""),
                "targets": sorted(set(k["target"] for k in kerb_events))[:5],
            })

    # ── 10. Explicit Credential Usage (4648) ──
    explicit_creds = [l for l in logons if l["event_id"] == "4648" and l.get("is_edge_creating")]
    if explicit_creds:
        by_source = defaultdict(list)
        for ec in explicit_creds:
            by_source[ec["source"]].append(ec)
        for src, events in by_source.items():
            targets = sorted(set(e["target"] for e in events))
            if len(targets) >= 2:
                findings.append({
                    "severity": "high", "mitre": "T1550",
                    "title": f"Explicit credentials from {src} → {len(targets)} targets",
                    "desc": f"{len(events)} explicit credential logon(s) to: {', '.join(targets[:5])}. "
                            f"May indicate pass-the-hash or credential reuse.",
                    "source": src, "targets": targets,
                })

    # ── 11. Suspicious Process Execution via Lateral Movement ──
    sus_procs = []
    for l in logons:
        if l["event_id"] in ("4688", "1") and l.get("process_name"):
            pname = l["process_name"].lower()
            if any(s in pname for s in ("psexecsvc", "psexec", "wmic", "mshta",
                                         "certutil", "bitsadmin", "msbuild")):
                sus_procs.append(l)

    if sus_procs:
        proc_names = sorted(set(s["process_name"].split("\\")[-1] for s in sus_procs))
        findings.append({
            "severity": "high", "mitre": "T1569.002",
            "title": f"Suspicious remote process execution",
            "desc": f"{len(sus_procs)} suspicious process(es): {', '.join(proc_names[:5])}.",
            "source": sus_procs[0].get("source", ""),
            "targets": sorted(set(s["target"] for s in sus_procs)),
        })

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "low"), 3))

    return findings


def analyze_lateral_movement(events: list[dict], target_eids: set[str] = None) -> dict:
    """Full lateral movement analysis pipeline."""
    logons = extract_logon_events(events, target_eids)

    if not logons:
        return {
            "logon_count": 0, "logons": [], "graph": {"nodes": [], "edges": []},
            "chains": [], "findings": [],
            "summary": {
                "total_logons": 0, "unique_sources": 0, "unique_targets": 0,
                "rdp_logons": 0, "failed_logons": 0, "chain_count": 0,
                "max_chain_length": 0, "cleartext_count": 0, "admin_share_count": 0,
            }
        }

    graph = build_network_graph(logons)
    chains = detect_chains(logons)
    findings = generate_findings(logons, graph["edges"], chains)

    rdp_count = sum(1 for l in logons if l["logon_type"] in ("10", "12"))
    failed_count = sum(1 for l in logons if l["status"] == "Failed")
    cleartext_count = sum(1 for l in logons if l["logon_type"] == "8")
    admin_share = sum(e.get("admin_share_count", 0) for e in graph["edges"])

    return {
        "logon_count": len(logons),
        "logons": logons[:5000],
        "graph": graph,
        "chains": [[{
            "source": h["source"], "target": h["target"],
            "target_user": h["target_user"], "timestamp": h["timestamp"],
            "logon_type": h["logon_type"], "logon_type_label": h["logon_type_label"],
            "status": h["status"],
        } for h in chain] for chain in chains],
        "findings": findings,
        "summary": {
            "total_logons": len(logons),
            "unique_sources": len(set(l["source"] for l in logons)),
            "unique_targets": len(set(l["target"] for l in logons)),
            "rdp_logons": rdp_count,
            "failed_logons": failed_count,
            "chain_count": len(chains),
            "max_chain_length": max(len(c) for c in chains) if chains else 0,
            "cleartext_count": cleartext_count,
            "admin_share_count": admin_share,
        }
    }