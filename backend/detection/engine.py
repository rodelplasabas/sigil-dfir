"""
SIGIL Detection Engine — Runs detection rules against parsed log events.
Ported from the frontend JavaScript engine with provider filtering and evidence capture.
"""

import re
from typing import Optional


SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _calculate_confidence(match_count: int, keyword_hits: int, severity: str) -> int:
    score = 0
    if match_count >= 5:
        score += 40
    elif match_count >= 2:
        score += 30
    elif match_count >= 1:
        score += 20

    if keyword_hits >= 3:
        score += 30
    elif keyword_hits >= 2:
        score += 20
    elif keyword_hits >= 1:
        score += 10

    if severity == "critical":
        score += 20
    elif severity == "high":
        score += 15
    else:
        score += 10

    score += min(match_count * 2, 20)
    return min(score, 100)


def _compile_pattern(pattern_str: str) -> Optional[re.Pattern]:
    try:
        return re.compile(pattern_str, re.IGNORECASE)
    except re.error:
        return None


def run_detection(events: list[dict], log_type: str, rules: list[dict],
                  ioc_rules: Optional[list[dict]] = None) -> list[dict]:
    """
    Run detection rules against a list of parsed events.

    Args:
        events: List of parsed event dicts with 'content', 'timestamp', 'record_id', etc.
        log_type: One of 'windows_event_log', 'web_server_log', 'registry'
        rules: List of rule dicts for this log type
        ioc_rules: Optional additional IOC-based rules to inject

    Returns:
        List of finding dicts with matched evidence
    """
    all_rules = list(rules)
    if ioc_rules:
        all_rules.extend(ioc_rules)

    findings = []

    # Pre-build full content for keyword scanning
    full_content = "\n".join(e.get("content") or e.get("message", "") for e in events).lower()

    for rule in all_rules:
        main_re = _compile_pattern(rule["pattern"])
        if not main_re:
            continue

        alt_res = []
        for ap in rule.get("alt_patterns", []):
            compiled = _compile_pattern(ap)
            if compiled:
                alt_res.append(compiled)

        prov_filter = _compile_pattern(rule["provider_filter"]) if rule.get("provider_filter") else None
        prov_exclude = _compile_pattern(rule["provider_exclude"]) if rule.get("provider_exclude") else None

        match_count = 0
        matched_events = []
        match_excerpts = []

        for ev_idx, ev in enumerate(events):
            content = ev.get("content") or ev.get("message", "")
            if not content:
                continue

            # Provider filtering
            if prov_exclude and prov_exclude.search(content):
                continue
            if prov_filter and not prov_filter.search(content):
                continue

            line_matched = False

            # Test main pattern
            main_matches = main_re.findall(content)
            if main_matches:
                match_count += len(main_matches)
                match_excerpts.extend(main_matches[:2])
                line_matched = True

            # Test alt patterns
            for alt_re in alt_res:
                alt_matches = alt_re.findall(content)
                if alt_matches:
                    match_count += len(alt_matches)
                    match_excerpts.extend(alt_matches[:1])
                    line_matched = True

            if line_matched:
                # Capture context: up to 5 lines after the match
                context_lines = []
                for offset in range(1, 6):
                    if ev_idx + offset < len(events):
                        ctx = events[ev_idx + offset]
                        ctx_content = ctx.get("content") or ctx.get("message", "")
                        if ctx_content:
                            # Stop context at next registry key header or blank
                            if ctx_content.startswith("[HKEY_") or ctx_content.startswith("[HKLM") or ctx_content.startswith("[-"):
                                break
                            context_lines.append(ctx_content[:200])

                matched_events.append({
                    "timestamp": ev.get("timestamp"),
                    "event_id": ev.get("event_id"),
                    "record_id": ev.get("record_id"),
                    "content": content[:500] + "…" if len(content) > 500 else content,
                    "message": ev.get("message", ""),
                    "fields": ev.get("fields", {}),
                    "line_index": ev.get("line_index"),
                    "context": context_lines
                })

        # Check count threshold (for error-rate type rules)
        count_threshold = rule.get("count_threshold")
        if count_threshold and match_count < count_threshold:
            continue

        # Keyword scan against full content
        keyword_hits = 0
        for kw in rule.get("keywords", []):
            if kw.lower() in full_content:
                keyword_hits += 1

        # Require at least 1 pattern match
        if match_count == 0:
            continue

        confidence = _calculate_confidence(match_count, keyword_hits, rule.get("severity", "medium"))

        # Deduplicate matched events by record_id
        seen_records = set()
        unique_events = []
        for me in matched_events:
            rid = me.get("record_id")
            if rid:
                if rid in seen_records:
                    continue
                seen_records.add(rid)
            unique_events.append(me)

        # Sort by timestamp
        unique_events.sort(key=lambda e: e.get("timestamp") or "")

        findings.append({
            "id": rule["id"],
            "name": rule["name"],
            "description": rule.get("description", ""),
            "severity": rule.get("severity", "medium"),
            "mitre": rule.get("mitre", []),
            "match_count": match_count,
            "keyword_hits": keyword_hits,
            "confidence": confidence,
            "excerpts": list(set(str(e)[:80] for e in match_excerpts))[:5],
            "matched_events": unique_events,
            "next_steps": rule.get("next_steps", []),
            "is_ioc_rule": rule.get("is_ioc_rule", False)
        })

    # Sort by severity weight then confidence
    findings.sort(
        key=lambda f: (SEVERITY_WEIGHT.get(f["severity"], 0), f["confidence"]),
        reverse=True
    )

    return findings


def compute_overall_score(findings: list[dict]) -> dict:
    """Compute the overall CLEAN / SUSPICIOUS / COMPROMISED assessment."""
    if not findings:
        return {"label": "CLEAN", "color": "#10b981", "score": 0}

    crit_count = sum(1 for f in findings if f["severity"] == "critical")
    high_count = sum(1 for f in findings if f["severity"] == "high")
    total_weight = sum(
        SEVERITY_WEIGHT.get(f["severity"], 0) * f["confidence"]
        for f in findings
    )

    if crit_count >= 2 or total_weight > 500:
        return {"label": "COMPROMISED", "color": "#ef4444", "score": total_weight}
    if crit_count >= 1 or high_count >= 2 or total_weight > 200:
        return {"label": "SUSPICIOUS", "color": "#f59e0b", "score": total_weight}
    max_sev = max(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    if max_sev >= 2 or total_weight > 80:
        return {"label": "SUSPICIOUS", "color": "#f59e0b", "score": total_weight}

    return {"label": "CLEAN", "color": "#10b981", "score": total_weight}


def build_ioc_rules(ioc_list: list[dict]) -> list[dict]:
    """
    Build detection rules from a list of IOCs.
    ioc_list: [{"value": "1.2.3.4", "type": "ip"}, {"value": "evil.com", "type": "domain"}]
    """
    if not ioc_list:
        return []

    escaped = [re.escape(ioc["value"]) for ioc in ioc_list]
    rules = []
    chunk_size = 50

    ips = [i for i in ioc_list if i["type"] == "ip"]
    domains = [i for i in ioc_list if i["type"] == "domain"]

    for i in range(0, len(escaped), chunk_size):
        chunk = escaped[i:i + chunk_size]
        rule_num = len(rules) + 1
        parts = []
        if ips:
            parts.append(f"{len(ips)} IPs")
        if domains:
            parts.append(f"{len(domains)} domains")

        rules.append({
            "id": f"IOC-{rule_num:03d}",
            "name": f"IOC Match — {' + '.join(parts)}",
            "description": f"Matches against user-provided Indicators of Compromise. {len(ioc_list)} IOCs loaded.",
            "severity": "critical",
            "mitre": ["T1071", "T1105"],
            "pattern": "|".join(chunk),
            "alt_patterns": [],
            "keywords": [],
            "provider_filter": None,
            "provider_exclude": None,
            "next_steps": [
                "CRITICAL: Matched IOC indicates known malicious infrastructure",
                "Identify the full context — what process/request communicated with this IOC",
                "Check for data exfiltration or C2 beacon patterns",
                "Block the IOC at firewall/proxy and search for additional related IOCs",
                "Pivot on the matched IOC in threat intelligence platforms"
            ],
            "is_ioc_rule": True
        })

    return rules