"""
Web Access Log Parser — Apache/Nginx Combined + IIS W3C
Parses raw log content into structured events with timestamps, IPs, methods, URIs, status codes.
"""

import re
from datetime import datetime

MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"
}

# Apache/Nginx Combined Log Format
APACHE_RE = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+'
    r'\[([^\]]+)\]\s+'
    r'"(\S+)\s+([^\s"]+)\s*([^"]*)"\s+'
    r'(\d{3})\s+(\S+)'
    r'(?:\s+"([^"]*)")?'
    r'(?:\s+"([^"]*)")?'
)

APACHE_DATE_RE = re.compile(
    r'(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})\s*([+-]\d{4})?'
)

# IIS W3C fixed-field fallback
IIS_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+'
    r'(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+'
    r'(\S+)\s+(\S+)\s+(\S+)\s+(\d{3})\b'
)

IIS_DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+')


def _apache_date_to_iso(date_str: str) -> str:
    m = APACHE_DATE_RE.match(date_str)
    if not m:
        return date_str
    day, mon_str, year, time_part, tz = m.groups()
    month = MONTHS.get(mon_str, "01")
    tz_formatted = ""
    if tz:
        tz_formatted = f"{tz[:3]}:{tz[3:]}"
    else:
        tz_formatted = "+00:00"
    return f"{year}-{month}-{day}T{time_part}{tz_formatted}"


def _detect_iis(lines: list[str]) -> bool:
    for line in lines[:50]:
        if line.startswith("#Fields:"):
            return True
        if IIS_DATE_RE.match(line):
            return True
    return False


def _parse_iis_fields_header(lines: list[str]) -> list[str] | None:
    for line in lines:
        if line.startswith("#Fields:"):
            return line[8:].strip().split()
    return None


def parse_web_logs(raw_content: str, max_events: int = 50000) -> dict:
    """
    Parse web access logs into structured events.
    Returns dict with format, event_count, and events list.
    """
    lines = raw_content.split("\n")
    events = []
    is_iis = _detect_iis(lines)
    iis_fields = _parse_iis_fields_header(lines) if is_iis else None
    detected_format = "Unknown"

    for i, raw_line in enumerate(lines):
        if len(events) >= max_events:
            break

        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parsed = None

        # Try IIS W3C
        if is_iis:
            if iis_fields:
                parts = line.split()
                if len(parts) >= len(iis_fields) - 1:
                    field_map = {}
                    for idx, field_name in enumerate(iis_fields):
                        if idx < len(parts):
                            field_map[field_name] = parts[idx]

                    date_str = field_map.get("date", "")
                    time_str = field_map.get("time", "")
                    query = field_map.get("cs-uri-query", "-")

                    parsed = {
                        "ip": field_map.get("c-ip") or field_map.get("s-ip", "-"),
                        "timestamp": f"{date_str}T{time_str}Z" if date_str and time_str else date_str,
                        "method": field_map.get("cs-method", "-"),
                        "uri": field_map.get("cs-uri-stem", "-"),
                        "query": query if query != "-" else "",
                        "status": field_map.get("sc-status", "-"),
                        "size": field_map.get("sc-bytes", "-"),
                        "referer": field_map.get("cs(Referer)", "-"),
                        "user_agent": field_map.get("cs(User-Agent)", "-"),
                        "server_ip": field_map.get("s-ip", "-"),
                        "port": field_map.get("s-port", "-"),
                        "format": "IIS"
                    }
                    detected_format = "IIS"
            else:
                m = IIS_RE.match(line)
                if m:
                    parsed = {
                        "ip": m.group(9) or m.group(3),
                        "timestamp": f"{m.group(1)}T{m.group(2)}Z",
                        "method": m.group(4),
                        "uri": m.group(5),
                        "query": m.group(6) if m.group(6) != "-" else "",
                        "status": m.group(11),
                        "size": "-",
                        "referer": "-",
                        "user_agent": m.group(10) or "-",
                        "server_ip": m.group(3),
                        "port": m.group(7),
                        "format": "IIS"
                    }
                    detected_format = "IIS"

        # Try Apache/Nginx
        if not parsed:
            m = APACHE_RE.match(line)
            if m:
                iso_ts = _apache_date_to_iso(m.group(4))
                parsed = {
                    "ip": m.group(1),
                    "user": m.group(3) if m.group(3) != "-" else None,
                    "timestamp": iso_ts,
                    "method": m.group(5),
                    "uri": m.group(6),
                    "query": "",
                    "protocol": m.group(7),
                    "status": m.group(8),
                    "size": m.group(9),
                    "referer": m.group(10) or "-",
                    "user_agent": m.group(11) or "-",
                    "format": "Apache/Nginx"
                }
                detected_format = "Apache/Nginx"

        if parsed:
            full_uri = parsed["uri"]
            if parsed.get("query"):
                full_uri += f"?{parsed['query']}"

            # Build structured content line for detection matching
            parts = [
                f"Timestamp: {parsed['timestamp']}",
                f"IP: {parsed['ip']}",
                f"Method: {parsed['method']}",
                f"URI: {full_uri}",
                f"Status: {parsed['status']}",
                f"Size: {parsed.get('size', '-')}",
            ]
            if parsed.get("referer") and parsed["referer"] != "-":
                parts.append(f"Referer: {parsed['referer']}")
            if parsed.get("user_agent") and parsed["user_agent"] != "-":
                parts.append(f"UserAgent: {parsed['user_agent']}")
            parts.append(line)  # raw line for pattern matching
            content_line = " ".join(parts)

            fields = {
                "ip": parsed["ip"],
                "method": parsed["method"],
                "uri": full_uri,
                "status": parsed["status"],
                "size": parsed.get("size", "-"),
                "referer": parsed.get("referer", "-"),
                "userAgent": parsed.get("user_agent", "-"),
                "format": parsed["format"],
            }
            if parsed.get("server_ip"):
                fields["serverIp"] = parsed["server_ip"]
            if parsed.get("port"):
                fields["port"] = parsed["port"]
            if parsed.get("user"):
                fields["user"] = parsed["user"]

            events.append({
                "line_index": i,
                "timestamp": parsed["timestamp"],
                "event_id": parsed["status"],
                "record_id": str(i + 1),
                "message": line,
                "content": content_line,
                "fields": fields
            })

    return {
        "format": detected_format,
        "event_count": len(events),
        "events": events
    }