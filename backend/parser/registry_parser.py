"""
Registry Export Parser — Parses Windows .reg file exports into structured events.
"""


def parse_registry(raw_content: str, max_events: int = 50000) -> dict:
    """Parse .reg file content into structured line events."""
    lines = raw_content.split("\n")
    events = []

    for i, raw_line in enumerate(lines):
        if len(events) >= max_events:
            break

        line = raw_line.strip()
        if not line or line.startswith("Windows Registry Editor"):
            continue

        events.append({
            "line_index": i,
            "timestamp": None,
            "event_id": None,
            "record_id": str(i + 1),
            "message": line,
            "content": line,
            "fields": {}
        })

    return {
        "format": "Registry",
        "event_count": len(events),
        "events": events
    }