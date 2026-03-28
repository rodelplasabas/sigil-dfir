"""
EVTX Parser — Uses evtx_dump (Rust binary) for 100-650x faster parsing.
Falls back to python-evtx if evtx_dump is not found.

Setup:
  1. Download evtx_dump from https://github.com/omerbenamram/evtx/releases
  2. Place evtx_dump.exe in the sigil-backend/ directory (or anywhere in PATH)
  3. SIGIL will auto-detect and use it

Without evtx_dump, falls back to python-evtx (much slower).
"""

import subprocess
import json
import os
import sys
import shutil
import xml.etree.ElementTree as ET
import time


def _find_evtx_dump():
    """Find evtx_dump binary — check local dir, then PATH."""
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    local_names = ["evtx_dump.exe", "evtx_dump"] if sys.platform == "win32" else ["evtx_dump"]
    for name in local_names:
        local_path = os.path.join(backend_dir, name)
        if os.path.isfile(local_path):
            return local_path
    for name in local_names:
        tools_path = os.path.join(backend_dir, "tools", name)
        if os.path.isfile(tools_path):
            return tools_path
    found = shutil.which("evtx_dump")
    return found


def parse_evtx_fast(file_path, max_records=0):
    """Parse EVTX using evtx_dump (Rust). Returns list of event dicts or None if unavailable."""
    evtx_dump = _find_evtx_dump()
    if not evtx_dump:
        return None

    basename = os.path.basename(file_path)
    start = time.time()
    events = []

    try:
        cmd = [evtx_dump, "-o", "jsonl", file_path]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1048576,
        )

        parse_errors = 0
        line_num = 0
        for line in proc.stdout:
            if max_records > 0 and len(events) >= max_records:
                break

            line = line.strip()
            if not line:
                continue
            line_num += 1

            try:
                record = json.loads(line)
                event = _parse_jsonl_record(record)
                if event:
                    events.append(event)
            except Exception as e:
                parse_errors += 1
                if parse_errors <= 3:
                    # Show the problematic JSON snippet
                    snippet = line[:200].decode("utf-8", errors="replace") if isinstance(line, bytes) else str(line)[:200]
                    print(f"[SIGIL] evtx_dump parse error in {basename} line {line_num}: {type(e).__name__}: {e}")
                    print(f"[SIGIL]   JSON snippet: {snippet}")
                continue

        proc.stdout.close()
        stderr_out = proc.stderr.read().decode("utf-8", errors="replace").strip()
        proc.wait()

        if stderr_out and len(events) == 0:
            print(f"[SIGIL] evtx_dump stderr for {basename}: {stderr_out[:300]}")

        elapsed = time.time() - start
        rate = len(events) / max(elapsed, 0.001)
        err_msg = f" ({parse_errors} parse errors)" if parse_errors else ""
        print(f"[SIGIL] evtx_dump: {basename}: {len(events)} events in {elapsed:.1f}s ({rate:.0f} events/sec){err_msg}")
        return events

    except Exception as e:
        import traceback
        print(f"[SIGIL] evtx_dump FATAL for {basename}: {type(e).__name__}: {e}")
        print(f"[SIGIL] traceback: {traceback.format_exc()}")
        return None


def _safe_str(value):
    """Safely convert any value to a string — handles dicts, lists, None."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("#text", json.dumps(value, default=str))
    if isinstance(value, list):
        return ", ".join(_safe_str(v) for v in value)
    return str(value)


def _parse_jsonl_record(record):
    """Convert an evtx_dump JSONL record to SIGIL's event format."""
    event = record.get("Event", record)
    system = event.get("System", {})

    # Provider
    provider_data = system.get("Provider", {})
    if isinstance(provider_data, dict):
        provider = provider_data.get("#attributes", {}).get("Name", "")
    else:
        provider = str(provider_data)

    # EventID
    event_id_data = system.get("EventID", "")
    if isinstance(event_id_data, dict):
        event_id = str(event_id_data.get("#text", event_id_data.get("value", "")))
    else:
        event_id = str(event_id_data)

    # Timestamp
    time_created = system.get("TimeCreated", {})
    timestamp = ""
    if isinstance(time_created, dict):
        attrs = time_created.get("#attributes", {})
        timestamp = attrs.get("SystemTime", "")

    computer = system.get("Computer", "")
    channel = system.get("Channel", "")
    record_id = str(system.get("EventRecordID", ""))

    # EventData
    event_data = event.get("EventData", {})
    event_data_fields = {}
    message_parts = []

    if isinstance(event_data, dict):
        for key, value in event_data.items():
            if key.startswith("#") or key == "xmlns":
                continue
            val = _safe_str(value)
            event_data_fields[key] = val
            if val:
                message_parts.append(val)
    elif isinstance(event_data, list):
        for i, item in enumerate(event_data):
            val = _safe_str(item)
            event_data_fields[f"Data_{i}"] = val
            if val:
                message_parts.append(val)
    elif event_data:
        val = _safe_str(event_data)
        event_data_fields["Data"] = val
        message_parts.append(val)

    # UserData fallback
    user_data = event.get("UserData", {})
    user_data_fields = {}
    if isinstance(user_data, dict) and not event_data_fields:
        for key, value in user_data.items():
            if key.startswith("#") or key == "xmlns":
                continue
            if isinstance(value, dict):
                for k2, v2 in value.items():
                    if k2.startswith("#"):
                        continue
                    val = _safe_str(v2)
                    event_data_fields[k2] = val
                    user_data_fields[k2] = val
                    if val:
                        message_parts.append(val)
            else:
                val = _safe_str(value)
                event_data_fields[key] = val
                user_data_fields[key] = val
                if val:
                    message_parts.append(val)

    event_data_xml = _build_full_event_xml(system, event_data_fields, user_data_fields)

    # Defensive: ensure all message_parts are strings
    message_parts = [str(p) for p in message_parts if p]

    content = f"EventID: {event_id} Provider: {provider} Channel: {channel} "
    content += f"Timestamp: {timestamp} EventRecordID: {record_id} "
    content += " ".join(message_parts)

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "provider": provider,
        "computer": computer,
        "channel": channel,
        "record_id": record_id,
        "message": " ".join(message_parts),
        "content": content,
        "fields": event_data_fields,
        "event_data_xml": event_data_xml,
    }


def _build_full_event_xml(system, event_data_fields, user_data_fields=None):
    """Reconstruct full Event XML from parsed System and EventData fields."""
    parts = ['<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">']

    # System section
    parts.append('  <System>')

    provider_data = system.get("Provider", {})
    if isinstance(provider_data, dict):
        attrs = provider_data.get("#attributes", {})
        prov_name = attrs.get("Name", "")
        prov_guid = attrs.get("Guid", "")
        if prov_guid:
            parts.append(f'    <Provider Name="{prov_name}" Guid="{prov_guid}"/>')
        else:
            parts.append(f'    <Provider Name="{prov_name}"/>')

    event_id_data = system.get("EventID", "")
    if isinstance(event_id_data, dict):
        eid = str(event_id_data.get("#text", event_id_data.get("value", "")))
    else:
        eid = str(event_id_data)
    parts.append(f'    <EventID>{eid}</EventID>')

    for tag in ["Version", "Level", "Task", "Opcode"]:
        val = system.get(tag)
        if val is not None:
            parts.append(f'    <{tag}>{val}</{tag}>')

    keywords = system.get("Keywords")
    if keywords is not None:
        parts.append(f'    <Keywords>{keywords}</Keywords>')

    time_created = system.get("TimeCreated", {})
    if isinstance(time_created, dict):
        st = time_created.get("#attributes", {}).get("SystemTime", "")
        if st:
            parts.append(f'    <TimeCreated SystemTime="{st}"/>')

    record_id = system.get("EventRecordID", "")
    if record_id:
        parts.append(f'    <EventRecordID>{record_id}</EventRecordID>')

    correlation = system.get("Correlation", {})
    if isinstance(correlation, dict):
        corr_attrs = correlation.get("#attributes", {})
        activity_id = corr_attrs.get("ActivityID", "")
        if activity_id:
            parts.append(f'    <Correlation ActivityID="{activity_id}"/>')
        else:
            parts.append('    <Correlation/>')
    else:
        parts.append('    <Correlation/>')

    execution = system.get("Execution", {})
    if isinstance(execution, dict):
        exec_attrs = execution.get("#attributes", {})
        pid = exec_attrs.get("ProcessID", "")
        tid = exec_attrs.get("ThreadID", "")
        if pid or tid:
            parts.append(f'    <Execution ProcessID="{pid}" ThreadID="{tid}"/>')

    channel = system.get("Channel", "")
    if channel:
        parts.append(f'    <Channel>{channel}</Channel>')

    computer = system.get("Computer", "")
    if computer:
        parts.append(f'    <Computer>{computer}</Computer>')

    security = system.get("Security", {})
    if isinstance(security, dict):
        sec_attrs = security.get("#attributes", {})
        user_id = sec_attrs.get("UserID", "")
        if user_id:
            parts.append(f'    <Security UserID="{user_id}"/>')
        else:
            parts.append('    <Security/>')

    parts.append('  </System>')

    # EventData section
    if event_data_fields:
        parts.append('  <EventData>')
        for name, value in event_data_fields.items():
            escaped = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            parts.append(f'    <Data Name="{name}">{escaped}</Data>')
        parts.append('  </EventData>')

    # UserData section (if no EventData)
    if user_data_fields and not event_data_fields:
        parts.append('  <UserData>')
        for name, value in user_data_fields.items():
            escaped = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            parts.append(f'    <Data Name="{name}">{escaped}</Data>')
        parts.append('  </UserData>')

    parts.append('</Event>')
    return "\n".join(parts)
    return "\n".join(parts)


# ── Fallback: python-evtx ────────────────────────────────────────────────────

def parse_evtx_legacy(file_path, max_records=0):
    """Parse EVTX using python-evtx (pure Python, slow fallback)."""
    from Evtx.Evtx import Evtx

    NAMESPACE = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    events = []
    start = time.time()

    with Evtx(file_path) as log:
        for i, record in enumerate(log.records()):
            if max_records > 0 and i >= max_records:
                break
            try:
                xml = record.xml()
                root = ET.fromstring(xml)
                system = root.find("ns:System", NAMESPACE)

                event_id = timestamp = provider = computer = channel = record_id = None

                if system is not None:
                    eid_elem = system.find("ns:EventID", NAMESPACE)
                    if eid_elem is not None:
                        event_id = eid_elem.text
                    time_elem = system.find("ns:TimeCreated", NAMESPACE)
                    if time_elem is not None:
                        timestamp = time_elem.attrib.get("SystemTime")
                    prov_elem = system.find("ns:Provider", NAMESPACE)
                    if prov_elem is not None:
                        provider = prov_elem.attrib.get("Name")
                    comp_elem = system.find("ns:Computer", NAMESPACE)
                    if comp_elem is not None:
                        computer = comp_elem.text
                    chan_elem = system.find("ns:Channel", NAMESPACE)
                    if chan_elem is not None:
                        channel = chan_elem.text
                    rid_elem = system.find("ns:EventRecordID", NAMESPACE)
                    if rid_elem is not None:
                        record_id = rid_elem.text

                message = ""
                event_data_fields = {}
                event_data_xml = xml  # Store the full event XML

                eventdata = root.find("ns:EventData", NAMESPACE)
                if eventdata is not None:
                    for data in eventdata:
                        name = data.attrib.get("Name", "")
                        value = data.text or ""
                        if name:
                            event_data_fields[name] = value
                        if value:
                            message += f"{value} "

                userdata = root.find("ns:UserData", NAMESPACE)
                if userdata is not None:
                    for elem in userdata.iter():
                        if elem.text and elem.text.strip():
                            message += f"{elem.text.strip()} "

                events.append({
                    "timestamp": timestamp,
                    "event_id": event_id,
                    "provider": provider,
                    "computer": computer,
                    "channel": channel,
                    "record_id": record_id,
                    "message": message.strip(),
                    "fields": event_data_fields,
                    "event_data_xml": event_data_xml,
                })
            except Exception:
                continue

    elapsed = time.time() - start
    rate = len(events) / max(elapsed, 0.001)
    print(f"[SIGIL] python-evtx: {len(events)} events in {elapsed:.1f}s ({rate:.0f} events/sec)")
    return events


# ── Public API ────────────────────────────────────────────────────────────────

def parse_evtx(file_path, max_records=0):
    """Parse EVTX — tries evtx_dump (fast) first, falls back to python-evtx."""
    events = parse_evtx_fast(file_path, max_records)
    if events is not None:
        return events

    print("[SIGIL] evtx_dump not found — using python-evtx (much slower)")
    print("[SIGIL] Download evtx_dump from: https://github.com/omerbenamram/evtx/releases")
    return parse_evtx_legacy(file_path, max_records)