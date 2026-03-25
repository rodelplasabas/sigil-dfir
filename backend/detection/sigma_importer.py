"""
SIGIL Sigma Importer — Converts Sigma YAML rules to SIGIL detection rules.
Handles field-value pairs, keyword lists, modifiers, and MITRE tag extraction.
"""

import re
from typing import Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def _mini_yaml_parse(text: str) -> dict:
    """Fallback lightweight YAML parser if PyYAML is not installed."""
    result = {}
    lines = text.split("\n")
    stack = [{"obj": result, "indent": -1}]
    last_key = None

    for line in lines:
        raw = line
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        trimmed = raw.strip()

        while len(stack) > 1 and indent <= stack[-1]["indent"]:
            stack.pop()
        parent = stack[-1]["obj"]

        if trimmed.startswith("- "):
            val = trimmed[2:].strip().strip("'\"")
            if last_key and last_key in parent:
                if not isinstance(parent[last_key], list):
                    parent[last_key] = [parent[last_key]] if parent[last_key] else []
                parent[last_key].append(val)
            elif last_key:
                # Key exists but value was {} (empty dict from no-value key)
                parent[last_key] = [val]
        elif ":" in trimmed:
            colon_idx = trimmed.index(":")
            key = trimmed[:colon_idx].strip()  # Keep FULL key including |contains
            value = trimmed[colon_idx + 1:].strip().strip("'\"")
            last_key = key

            if value in ("", "|", ">"):
                parent[key] = {}
                stack.append({"obj": parent[key], "indent": indent})
            else:
                parent[key] = value

    return result


def parse_yaml(text: str) -> list[dict]:
    """Parse YAML text, handling multi-document files."""
    if HAS_YAML:
        try:
            docs = list(yaml.safe_load_all(text))
            result = [d for d in docs if d and isinstance(d, dict)]
            if result:
                print(f"[SIGIL] Sigma import: parsed with PyYAML ({len(result)} docs)")
                return result
        except yaml.YAMLError as e:
            print(f"[SIGIL] PyYAML parse failed: {e}, falling back to mini parser")
    else:
        print("[SIGIL] WARNING: PyYAML not installed! Using fallback mini parser. Install with: pip install pyyaml")

    # Fallback to mini parser
    raw_docs = text.split("\n---")
    results = []
    for doc in raw_docs:
        doc = doc.strip()
        if not doc:
            continue
        parsed = _mini_yaml_parse(doc)
        if parsed:
            results.append(parsed)
    return results


def _level_to_severity(level: str) -> str:
    return {
        "critical": "critical", "high": "high", "medium": "medium",
        "low": "low", "informational": "low"
    }.get((level or "medium").lower(), "medium")


def _logsource_to_type(logsource: dict) -> str:
    if not logsource or not isinstance(logsource, dict):
        return "windows_event_log"
    product = str(logsource.get("product", "")).lower()
    category = str(logsource.get("category", "")).lower()
    service = str(logsource.get("service", "")).lower()

    # Check specific categories first (before generic product match)
    if "registry" in category or "registry" in service:
        return "registry"
    if "webserver" in category or "proxy" in category or category == "web":
        return "web_server_log"
    if product == "linux" and service in ("apache", "nginx", "iis"):
        return "web_server_log"
    if product == "windows" or service in ("security", "system", "powershell", "sysmon"):
        return "windows_event_log"
    return "windows_event_log"


def _extract_mitre_tags(tags) -> list[str]:
    """Extract MITRE ATT&CK technique IDs from Sigma tags."""
    mitre = []
    if not tags:
        return mitre

    tag_list = tags if isinstance(tags, list) else [tags]
    for tag in tag_list:
        tag_str = str(tag)
        match = re.search(r"attack\.t(\d{4}(?:\.\d{3})?)", tag_str, re.IGNORECASE)
        if match:
            mitre.append("T" + match.group(1).upper())
    return list(set(mitre))


def _sigma_value_to_regex(value: str, modifier: str = "") -> str:
    """
    Convert a Sigma field value to a regex pattern string.
    Handles Sigma wildcards (*) and modifiers (contains, startswith, endswith, re).
    
    YAML parses backslashes in quoted strings as literal characters.
    re.escape() handles all special chars correctly for regex matching.
    """
    if "re" in modifier:
        return value  # Raw regex, no escaping

    # Split on Sigma wildcard *, escape each segment, rejoin with .*
    segments = value.split("*")
    escaped_segments = [re.escape(seg) for seg in segments]
    result = ".*".join(escaped_segments)

    if "startswith" in modifier:
        result = result + ".*"
    elif "endswith" in modifier:
        result = ".*" + result

    return result


def _process_field_values(field: str, field_val, patterns: list, keywords: list):
    """Process a single field's values from a Sigma detection selection."""
    clean_field = field.split("|")[0]
    modifier = "|".join(field.split("|")[1:]) if "|" in field else ""

    # If field_val is a nested dict, recurse into it
    if isinstance(field_val, dict):
        for sub_field, sub_val in field_val.items():
            _process_field_values(sub_field, sub_val, patterns, keywords)
        return

    values = field_val if isinstance(field_val, list) else [field_val]

    for v in values:
        if v is None:
            continue
        # Skip dicts/lists that somehow ended up as values
        if isinstance(v, (dict, list)):
            continue
        str_val = str(v).strip()
        if not str_val:
            continue

        keywords.append(str_val)
        pattern_str = _sigma_value_to_regex(str_val, modifier)

        if clean_field.lower() == "eventid":
            patterns.append(f"EventID[:\\s]*{pattern_str}\\b")
        elif modifier and ("contains" in modifier or "startswith" in modifier or "endswith" in modifier or "re" in modifier):
            patterns.append(pattern_str)
        else:
            patterns.append(f"(?:{_sigma_value_to_regex(clean_field)}[:\\s=\"]*{pattern_str}|{pattern_str})")


def _detection_to_patterns(detection: dict) -> dict:
    """Convert Sigma detection section to regex patterns and keywords."""
    if not detection or not isinstance(detection, dict):
        return {"pattern": ".", "alt_patterns": [], "keywords": []}

    patterns = []
    keywords = []

    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue

        if isinstance(value, str):
            keywords.append(value)

        elif isinstance(value, list):
            for item in value:
                if isinstance(item, (dict, list)):
                    continue
                item_str = str(item).strip()
                if not item_str:
                    continue
                keywords.append(item_str)
                patterns.append(_sigma_value_to_regex(item_str))

        elif isinstance(value, dict):
            # This could be a selection group (selection_payload, empire, etc.)
            # which contains field|modifier keys
            for field, field_val in value.items():
                _process_field_values(field, field_val, patterns, keywords)

    primary = patterns[0] if patterns else "."
    alt = patterns[1:] if len(patterns) > 1 else []
    unique_kw = list(dict.fromkeys(kw for kw in keywords if kw))[:20]

    return {"pattern": primary, "alt_patterns": alt, "keywords": unique_kw}


def convert_sigma_to_rules(yaml_text: str, filename: str = "unknown.yml") -> list[dict]:
    """
    Convert Sigma YAML text to a list of SIGIL rule dicts.
    Handles multi-document YAML files.

    Returns list of rule dicts ready for rule_store.create_rule().
    """
    docs = parse_yaml(yaml_text)
    rules = []

    for sigma in docs:
        if not sigma.get("title") and not sigma.get("detection"):
            continue

        log_type = _logsource_to_type(sigma.get("logsource", {}))
        severity = _level_to_severity(sigma.get("level"))
        detection_result = _detection_to_patterns(sigma.get("detection", {}))
        mitre = _extract_mitre_tags(sigma.get("tags"))

        # Build next_steps from falsepositives and references
        next_steps = []
        fps = sigma.get("falsepositives")
        if fps:
            fp_list = fps if isinstance(fps, list) else [fps]
            next_steps.append(f"False positives: {', '.join(str(f) for f in fp_list)}")
        next_steps.append("Correlate with other findings in the timeline")
        refs = sigma.get("references")
        if refs:
            ref_list = refs if isinstance(refs, list) else [refs]
            for ref in ref_list[:3]:
                next_steps.append(f"Reference: {ref}")
        if not next_steps:
            next_steps = ["Review matched events for context", "Check SigmaHQ for rule updates"]

        sigma_source = {
            "sigma_id": str(sigma.get("id", "")),
            "author": str(sigma.get("author", "")),
            "status": str(sigma.get("status", "")),
            "level": str(sigma.get("level", "")),
            "filename": filename,
            "date": str(sigma.get("date", "")),
        }

        rules.append({
            "name": sigma.get("title", "Imported Sigma Rule"),
            "description": str(sigma.get("description", ""))[:1000],
            "severity": severity,
            "log_type": log_type,
            "mitre": mitre,
            "pattern": detection_result["pattern"],
            "alt_patterns": detection_result["alt_patterns"],
            "keywords": detection_result["keywords"],
            "next_steps": next_steps,
            "provider_filter": None,
            "provider_exclude": None,
            "sigma_source": sigma_source,
        })

    return rules