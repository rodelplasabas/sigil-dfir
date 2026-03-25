"""
SIGIL Backend — DFIR Compromise Assessment Tool API
Handles file parsing, detection rule execution, and IOC matching.
"""

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import tempfile
import os
import json

from parser.evtx_parser import parse_evtx
from parser.web_log_parser import parse_web_logs
from parser.registry_parser import parse_registry
from detection.engine import run_detection, compute_overall_score, build_ioc_rules
from detection.rules import DETECTION_RULES

app = FastAPI(title="SIGIL DFIR Backend", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Models ───────────────────────────────────────────────────────────────────

class IOCItem(BaseModel):
    value: str
    type: str  # "ip" or "domain"


class AnalyzeRequest(BaseModel):
    ioc_list: Optional[list[IOCItem]] = None
    ioc_enabled: Optional[bool] = True
    custom_rules: Optional[dict] = None  # Override rules (future use)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def detect_log_type(content: str, filename: str) -> str:
    """Auto-detect log type from content and filename."""
    fn = filename.lower()

    # Filename hints
    if fn.endswith(".evtx") or fn.endswith(".evt"):
        return "windows_event_log"
    if fn.endswith(".reg"):
        return "registry"

    lower = content[:5000].lower()

    # Content-based detection
    win_signals = ["eventid", "event_id", "logon type", "security audit",
                   "microsoft-windows", "event record id"]
    web_signals = ["get /", "post /", "http/1.", "http/2", "mozilla/5.0",
                   "#fields:", "cs-method"]
    reg_signals = ["hklm\\", "hkcu\\", "hkey_local_machine", "hkey_current_user",
                   "reg_sz", "reg_dword", "[hkey_"]

    win_score = sum(1 for s in win_signals if s in lower)
    web_score = sum(1 for s in web_signals if s in lower)
    reg_score = sum(1 for s in reg_signals if s in lower)

    if fn.endswith((".log", ".txt")):
        # Filename hints for web logs
        if any(x in fn for x in ["access", "error", "iis", "apache", "nginx", "httpd"]):
            web_score += 3

    best = max(win_score, web_score, reg_score)
    if best == 0:
        return "unknown"
    if win_score == best:
        return "windows_event_log"
    if web_score == best:
        return "web_server_log"
    return "registry"


def parse_file(content: str, log_type: str, file_path: Optional[str] = None,
               filename: str = "") -> dict:
    """Parse file content based on detected log type."""
    if log_type == "windows_event_log" and file_path and filename.lower().endswith((".evtx", ".evt")):
        # Binary EVTX — use python-evtx parser
        events = parse_evtx(file_path)
        # Build content lines for each event
        for ev in events:
            parts = [
                f"EventID: {ev.get('event_id', '')}",
                f"Provider: {ev.get('provider', '')}" if ev.get("provider") else "",
                f"Channel: {ev.get('channel', '')}" if ev.get("channel") else "",
                f"Timestamp: {ev.get('timestamp', '')}" if ev.get("timestamp") else "",
                f"EventRecordID: {ev.get('record_id', '')}" if ev.get("record_id") else "",
                ev.get("message", ""),
            ]
            if ev.get("fields"):
                for k, v in ev["fields"].items():
                    parts.append(f"{k}: {v}")
            ev["content"] = " ".join(p for p in parts if p)
        return {
            "log_type": log_type,
            "format": "EVTX",
            "event_count": len(events),
            "events": events
        }

    elif log_type == "web_server_log":
        result = parse_web_logs(content)
        return {
            "log_type": log_type,
            "format": result["format"],
            "event_count": result["event_count"],
            "events": result["events"]
        }

    elif log_type == "registry":
        result = parse_registry(content)
        return {
            "log_type": log_type,
            "format": "Registry",
            "event_count": result["event_count"],
            "events": result["events"]
        }

    else:
        # Unknown/generic — split into lines as events
        lines = content.split("\n")
        events = []
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
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
            "log_type": log_type,
            "format": "Text",
            "event_count": len(events),
            "events": events
        }


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "sigil-dfir-backend",
        "version": "2.0.0",
        "rules_count": sum(len(v) for v in DETECTION_RULES.values()),
        "capabilities": ["evtx", "web_logs", "registry", "detection", "ioc_matching"]
    }


@app.post("/upload-evtx/")
async def upload_evtx(file: UploadFile = File(...)):
    """Legacy EVTX-only endpoint (backward compatible)."""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name

        events = parse_evtx(tmp_path)
        os.remove(tmp_path)

        return {
            "status": "success",
            "filename": file.filename,
            "event_count": len(events),
            "events": events[:5000]
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/parse")
async def parse_artifact(file: UploadFile = File(...)):
    """
    Parse any supported artifact file and return structured events.
    Does NOT run detection — just parsing.
    """
    try:
        raw = await file.read()
        filename = file.filename or "unknown"
        tmp_path = None

        # For EVTX files, save to disk for binary parsing
        if filename.lower().endswith((".evtx", ".evt")):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as tmp:
                tmp.write(raw)
                tmp_path = tmp.name
            content = ""
        else:
            content = raw.decode("utf-8", errors="replace")

        log_type = detect_log_type(content, filename)
        result = parse_file(content, log_type, tmp_path, filename)

        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

        return {
            "status": "success",
            "filename": filename,
            **result
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/analyze")
async def analyze_artifact(
    file: UploadFile = File(...),
    ioc_list: Optional[str] = Form(None),
    ioc_enabled: Optional[bool] = Form(True)
):
    """
    Parse + Detect in one call.
    Upload a file, get back parsed events AND detection findings.
    IOC list is passed as JSON string via form field.
    """
    try:
        raw = await file.read()
        filename = file.filename or "unknown"
        tmp_path = None

        if filename.lower().endswith((".evtx", ".evt")):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as tmp:
                tmp.write(raw)
                tmp_path = tmp.name
            content = ""
        else:
            content = raw.decode("utf-8", errors="replace")

        # 1. Detect log type
        log_type = detect_log_type(content, filename)

        # 2. Parse
        parsed = parse_file(content, log_type, tmp_path, filename)

        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

        events = parsed["events"]

        # 3. Get rules for this log type
        rules = DETECTION_RULES.get(log_type, [])

        # 4. Build IOC rules if provided
        ioc_rules = None
        if ioc_enabled and ioc_list:
            try:
                iocs = json.loads(ioc_list)
                if iocs:
                    ioc_rules = build_ioc_rules(iocs)
            except (json.JSONDecodeError, TypeError):
                pass

        # 5. Run detection
        findings = run_detection(events, log_type, rules, ioc_rules)

        # 6. Compute overall score
        overall_score = compute_overall_score(findings)

        return {
            "status": "success",
            "filename": filename,
            "log_type": log_type,
            "format": parsed["format"],
            "event_count": parsed["event_count"],
            "events": events[:10000],  # Cap for response size
            "findings": findings,
            "overall_score": overall_score,
            "rules_applied": len(rules) + (len(ioc_rules) if ioc_rules else 0)
        }
    except Exception as e:
        import traceback
        return {"status": "error", "message": str(e), "trace": traceback.format_exc()}


@app.post("/detect")
async def detect_only(
    events: str = Form(...),
    log_type: str = Form("windows_event_log"),
    ioc_list: Optional[str] = Form(None),
    ioc_enabled: Optional[bool] = Form(True)
):
    """
    Run detection on pre-parsed events (JSON string).
    Useful when events are already parsed client-side.
    """
    try:
        parsed_events = json.loads(events)
        rules = DETECTION_RULES.get(log_type, [])

        ioc_rules = None
        if ioc_enabled and ioc_list:
            try:
                iocs = json.loads(ioc_list)
                if iocs:
                    ioc_rules = build_ioc_rules(iocs)
            except (json.JSONDecodeError, TypeError):
                pass

        findings = run_detection(parsed_events, log_type, rules, ioc_rules)
        overall_score = compute_overall_score(findings)

        return {
            "status": "success",
            "findings": findings,
            "overall_score": overall_score,
            "rules_applied": len(rules) + (len(ioc_rules) if ioc_rules else 0)
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}