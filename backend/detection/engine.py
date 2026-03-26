"""
SIGIL Detection Engine v2 — Optimized with Hayabusa-inspired architecture.

Key optimizations over v1:
  1. Event ID pre-routing — rules declare which EventIDs they target; events are
     matched to only the relevant rules via a lookup table (not brute-force N×M).
  2. Provider fast-skip — uses string `in` instead of regex for provider filtering.
  3. Field-level matching — for EVTX events, checks specific fields (event_id,
     provider, channel) before falling back to full content regex.
  4. re.search() instead of re.findall() — stops at first match per event.
  5. Pre-compiled patterns — compiled once at engine init, not per-call.
  6. No full_content join — keyword scanning is done per-event incrementally.
"""

import re
import time
from typing import Optional


SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ── Pattern Cache ─────────────────────────────────────────────────────────────
_pattern_cache: dict[str, Optional[re.Pattern]] = {}


def _compile_pattern(pattern_str: str) -> Optional[re.Pattern]:
    """Compile and cache a regex pattern."""
    if not pattern_str:
        return None
    if pattern_str not in _pattern_cache:
        try:
            _pattern_cache[pattern_str] = re.compile(pattern_str, re.IGNORECASE)
        except re.error:
            _pattern_cache[pattern_str] = None
    return _pattern_cache[pattern_str]


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


# ── Event ID Extraction from Rule Patterns ────────────────────────────────────

_EVENTID_RE = re.compile(r'EventID\[?:?\\?s?\]?\*?(?:4625|7045|4697|1102|1100|4720|4732|4728|4624|1149|4698|5025|5001|4104|4103|53504|\d{4,5})', re.IGNORECASE)
_EVENTID_EXTRACT = re.compile(r'(\d{4,5})')


def _extract_event_ids_from_pattern(pattern: str) -> set[str]:
    """Extract EventID numbers that a rule targets from its pattern string."""
    ids = set()
    # Match patterns like: EventID[:\s]*4625, EventID[:\s]*(?:7045|4697), event_id:4625
    for m in re.finditer(r'(?:EventID|event_id)[^0-9]*?((?:\d{3,5})(?:\|(?:\d{3,5}))*)', pattern, re.IGNORECASE):
        for eid in m.group(1).split("|"):
            eid = eid.strip()
            if eid.isdigit():
                ids.add(eid)
    return ids


def _extract_providers_from_filter(provider_filter: str) -> set[str]:
    """Extract provider name substrings from a provider_filter pattern."""
    if not provider_filter:
        return set()
    # Split on | and clean up regex artifacts
    parts = provider_filter.split("|")
    providers = set()
    for p in parts:
        cleaned = re.sub(r'[\\().*+?^\[\]{}]', '', p).strip().lower()
        if cleaned and len(cleaned) > 2 and not cleaned.isdigit():
            providers.add(cleaned)
    return providers


# ── Pre-process Rules ─────────────────────────────────────────────────────────

def _prepare_rules(rules: list[dict]) -> list[dict]:
    """Pre-compile patterns and extract routing metadata for each rule."""
    prepared = []
    for rule in rules:
        main_re = _compile_pattern(rule.get("pattern", ""))
        if not main_re:
            continue

        alt_res = []
        for ap in rule.get("alt_patterns", []):
            compiled = _compile_pattern(ap)
            if compiled:
                alt_res.append(compiled)

        # Extract EventIDs this rule targets (for EVTX routing)
        target_event_ids = _extract_event_ids_from_pattern(rule.get("pattern", ""))
        for ap in rule.get("alt_patterns", []):
            target_event_ids.update(_extract_event_ids_from_pattern(ap))

        # Extract provider filter as fast string set
        provider_include = _extract_providers_from_filter(rule.get("provider_filter", ""))
        provider_exclude = _extract_providers_from_filter(rule.get("provider_exclude", ""))

        # Keywords as lowercase set for fast scanning
        keywords_lower = [kw.lower() for kw in rule.get("keywords", []) if kw]

        prepared.append({
            **rule,
            "_main_re": main_re,
            "_alt_res": alt_res,
            "_target_event_ids": target_event_ids,
            "_provider_include": provider_include,
            "_provider_exclude": provider_exclude,
            "_keywords_lower": keywords_lower,
        })

    return prepared


# ── Main Detection Loop ──────────────────────────────────────────────────────

def run_detection(events: list[dict], log_type: str, rules: list[dict],
                  ioc_rules: Optional[list[dict]] = None) -> list[dict]:
    """
    Run detection rules against parsed events.
    Uses field-level pre-filtering for EVTX events (Hayabusa-style).
    """
    start_time = time.time()

    all_rules = list(rules)
    if ioc_rules:
        all_rules.extend(ioc_rules)

    prepared = _prepare_rules(all_rules)
    if not prepared:
        return []

    is_evtx = log_type == "windows_event_log"

    # Build EventID → rules index for EVTX fast routing
    eid_rule_index: dict[str, list[int]] = {}  # event_id -> [rule indices]
    generic_rules: list[int] = []  # rules without specific EventID targets

    for idx, rule in enumerate(prepared):
        if is_evtx and rule["_target_event_ids"]:
            for eid in rule["_target_event_ids"]:
                if eid not in eid_rule_index:
                    eid_rule_index[eid] = []
                eid_rule_index[eid].append(idx)
        else:
            generic_rules.append(idx)

    # Per-rule accumulators
    rule_matches = [{
        "match_count": 0,
        "matched_events": [],
        "keyword_hits_set": set(),
    } for _ in prepared]

    events_scanned = 0
    regex_checks = 0

    for ev_idx, ev in enumerate(events):
        content = ev.get("content") or ev.get("message", "")
        if not content:
            continue

        events_scanned += 1
        content_lower = content.lower()

        # Determine which rules to check for this event
        if is_evtx:
            ev_event_id = str(ev.get("event_id", ""))
            ev_provider = (ev.get("provider") or "").lower()

            # Get rules that target this EventID + generic rules
            candidate_indices = list(generic_rules)
            if ev_event_id in eid_rule_index:
                candidate_indices.extend(eid_rule_index[ev_event_id])
        else:
            # Non-EVTX: all rules are candidates
            candidate_indices = list(range(len(prepared)))

        for rule_idx in candidate_indices:
            rule = prepared[rule_idx]
            accum = rule_matches[rule_idx]

            # Fast provider filtering (string match, not regex)
            if is_evtx:
                if rule["_provider_exclude"]:
                    if any(exc in ev_provider for exc in rule["_provider_exclude"]):
                        continue
                if rule["_provider_include"]:
                    if not any(inc in ev_provider for inc in rule["_provider_include"]):
                        continue

            # Pattern matching — use search() not findall()
            line_matched = False
            regex_checks += 1

            if rule["_main_re"].search(content):
                accum["match_count"] += 1
                line_matched = True

            if not line_matched:
                for alt_re in rule["_alt_res"]:
                    regex_checks += 1
                    if alt_re.search(content):
                        accum["match_count"] += 1
                        line_matched = True
                        break  # One alt match is enough

            if line_matched:
                # Capture context: up to 5 lines after the match (registry only)
                context_lines = []
                if log_type == "registry":
                    for offset in range(1, 6):
                        if ev_idx + offset < len(events):
                            ctx = events[ev_idx + offset]
                            ctx_content = ctx.get("content") or ctx.get("message", "")
                            if ctx_content:
                                if ctx_content.startswith("[HKEY_") or ctx_content.startswith("[HKLM") or ctx_content.startswith("[-"):
                                    break
                                context_lines.append(ctx_content[:200])

                accum["matched_events"].append({
                    "timestamp": ev.get("timestamp"),
                    "event_id": ev.get("event_id"),
                    "record_id": ev.get("record_id"),
                    "content": content[:500] + "…" if len(content) > 500 else content,
                    "message": ev.get("message", ""),
                    "fields": ev.get("fields", {}),
                    "line_index": ev.get("line_index"),
                    "context": context_lines,
                    "event_data_xml": ev.get("event_data_xml", ""),
                })

            # Incremental keyword scanning (no giant full_content string)
            for kw in rule["_keywords_lower"]:
                if kw in content_lower:
                    accum["keyword_hits_set"].add(kw)

    # ── Build findings from accumulators ──────────────────────────────────
    findings = []

    for idx, rule in enumerate(prepared):
        accum = rule_matches[idx]
        match_count = accum["match_count"]

        # Check count threshold
        count_threshold = rule.get("count_threshold")
        if count_threshold and match_count < count_threshold:
            continue

        if match_count == 0:
            continue

        keyword_hits = len(accum["keyword_hits_set"])
        confidence = _calculate_confidence(match_count, keyword_hits, rule.get("severity", "medium"))

        # Deduplicate matched events by record_id
        seen_records = set()
        unique_events = []
        for me in accum["matched_events"]:
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
            "excerpts": [],
            "matched_events": unique_events,
            "next_steps": rule.get("next_steps", []),
            "is_ioc_rule": rule.get("is_ioc_rule", False),
        })

    # Sort by severity weight then confidence
    findings.sort(
        key=lambda f: (SEVERITY_WEIGHT.get(f["severity"], 0), f["confidence"]),
        reverse=True
    )

    elapsed = time.time() - start_time
    print(f"[SIGIL] Detection: {len(findings)} findings from {events_scanned} events, "
          f"{regex_checks} regex checks, {len(prepared)} rules in {elapsed:.2f}s")

    return findings


# ── Score & IOC helpers (unchanged) ───────────────────────────────────────────

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
    """Build detection rules from a list of IOCs."""
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