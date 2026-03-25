"""
SIGIL Backend v3.0 — DFIR Compromise Assessment Tool API
Handles file parsing, detection rule execution, IOC matching, and rule management.
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
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
from detection.rule_store import (
    init_db, get_all_rules, get_rules_by_type, get_rules_grouped,
    get_rule, create_rule, update_rule, delete_rule, toggle_rule,
    reset_to_defaults, get_stats
)
from detection.sigma_importer import convert_sigma_to_rules

app = FastAPI(title="SIGIL DFIR Backend", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()


class RuleCreate(BaseModel):
    id: Optional[str] = None
    name: str
    description: Optional[str] = ""
    severity: Optional[str] = "medium"
    log_type: Optional[str] = "windows_event_log"
    mitre: Optional[list[str]] = []
    pattern: str
    alt_patterns: Optional[list[str]] = []
    keywords: Optional[list[str]] = []
    next_steps: Optional[list[str]] = []
    provider_filter: Optional[str] = None
    provider_exclude: Optional[str] = None
    count_threshold: Optional[int] = None

class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    log_type: Optional[str] = None
    mitre: Optional[list[str]] = None
    pattern: Optional[str] = None
    alt_patterns: Optional[list[str]] = None
    keywords: Optional[list[str]] = None
    next_steps: Optional[list[str]] = None
    provider_filter: Optional[str] = None
    provider_exclude: Optional[str] = None
    count_threshold: Optional[int] = None
    is_enabled: Optional[bool] = None


def detect_log_type(content: str, filename: str) -> str:
    fn = filename.lower()
    if fn.endswith(".evtx") or fn.endswith(".evt"):
        return "windows_event_log"
    if fn.endswith(".reg"):
        return "registry"
    lower = content[:5000].lower()
    win_signals = ["eventid", "event_id", "logon type", "security audit", "microsoft-windows", "event record id"]
    web_signals = ["get /", "post /", "http/1.", "http/2", "mozilla/5.0", "#fields:", "cs-method"]
    reg_signals = ["hklm\\", "hkcu\\", "hkey_local_machine", "hkey_current_user", "reg_sz", "reg_dword", "[hkey_"]
    win_score = sum(1 for s in win_signals if s in lower)
    web_score = sum(1 for s in web_signals if s in lower)
    reg_score = sum(1 for s in reg_signals if s in lower)
    if fn.endswith((".log", ".txt")):
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


def parse_file(content, log_type, file_path=None, filename=""):
    if log_type == "windows_event_log" and file_path and filename.lower().endswith((".evtx", ".evt")):
        events = parse_evtx(file_path)
        for ev in events:
            parts = [f"EventID: {ev.get('event_id', '')}",
                     f"Provider: {ev.get('provider', '')}" if ev.get("provider") else "",
                     f"Channel: {ev.get('channel', '')}" if ev.get("channel") else "",
                     f"Timestamp: {ev.get('timestamp', '')}" if ev.get("timestamp") else "",
                     f"EventRecordID: {ev.get('record_id', '')}" if ev.get("record_id") else "",
                     ev.get("message", "")]
            if ev.get("fields"):
                for k, v in ev["fields"].items():
                    parts.append(f"{k}: {v}")
            ev["content"] = " ".join(p for p in parts if p)
        return {"log_type": log_type, "format": "EVTX", "event_count": len(events), "events": events}
    elif log_type == "web_server_log":
        result = parse_web_logs(content)
        return {"log_type": log_type, "format": result["format"], "event_count": result["event_count"], "events": result["events"]}
    elif log_type == "registry":
        result = parse_registry(content)
        return {"log_type": log_type, "format": "Registry", "event_count": result["event_count"], "events": result["events"]}
    else:
        lines = content.split("\n")
        events = [{"line_index": i, "timestamp": None, "event_id": None, "record_id": str(i+1),
                    "message": l.strip(), "content": l.strip(), "fields": {}}
                   for i, l in enumerate(lines) if l.strip()]
        return {"log_type": log_type, "format": "Text", "event_count": len(events), "events": events}


# ═══ HEALTH ═══

@app.get("/health")
async def health():
    stats = get_stats()
    return {"status": "ok", "service": "sigil-dfir-backend", "version": "3.0.0",
            "rules": stats, "capabilities": ["evtx", "web_logs", "registry", "detection",
                                              "ioc_matching", "rule_management", "sigma_import"]}


# ═══ RULE MANAGEMENT ═══

@app.get("/rules")
async def list_rules(log_type: Optional[str] = None, grouped: bool = False):
    if grouped:
        return {"status": "success", "rules": get_rules_grouped()}
    if log_type:
        return {"status": "success", "rules": get_rules_by_type(log_type)}
    return {"status": "success", "rules": get_all_rules()}

@app.get("/rules/stats")
async def rules_stats():
    return {"status": "success", "stats": get_stats()}

@app.get("/rules/{rule_id}")
async def get_single_rule(rule_id: str):
    rule = get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return {"status": "success", "rule": rule}

@app.post("/rules")
async def create_new_rule(rule: RuleCreate):
    try:
        created = create_rule(rule.model_dump())
        return {"status": "success", "rule": created}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.put("/rules/{rule_id}")
async def update_existing_rule(rule_id: str, updates: RuleUpdate):
    updated = update_rule(rule_id, {k: v for k, v in updates.model_dump().items() if v is not None})
    if not updated:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return {"status": "success", "rule": updated}

@app.delete("/rules/{rule_id}")
async def delete_existing_rule(rule_id: str):
    if delete_rule(rule_id):
        return {"status": "success", "message": f"Rule {rule_id} deleted"}
    raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

@app.post("/rules/{rule_id}/toggle")
async def toggle_existing_rule(rule_id: str, enabled: bool = True):
    result = toggle_rule(rule_id, enabled)
    if not result:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return {"status": "success", "rule": result}

@app.post("/rules/reset")
async def reset_rules_endpoint():
    rules = reset_to_defaults()
    return {"status": "success", "message": "Rules reset to defaults", "rule_count": len(rules)}

@app.post("/rules/import-sigma")
async def import_sigma(file: UploadFile = File(...)):
    try:
        content = (await file.read()).decode("utf-8", errors="replace")
        filename = file.filename or "unknown.yml"
        sigma_rules = convert_sigma_to_rules(content, filename)
        created = []
        duplicates = []
        errors = []
        for rule_data in sigma_rules:
            try:
                result = create_rule(rule_data)
                created.append(result)
            except ValueError as ve:
                if "Duplicate" in str(ve):
                    duplicates.append(str(ve))
                else:
                    errors.append(str(ve))
            except Exception as e:
                errors.append(str(e))
        return {"status": "success", "imported": len(created), "duplicates": len(duplicates),
                "duplicate_details": duplicates, "errors": len(errors),
                "total_in_file": len(sigma_rules), "filename": filename, "rules": created}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/rules/import-sigma-batch")
async def import_sigma_batch(files: list[UploadFile] = File(...)):
    total_imported = 0
    total_duplicates = 0
    total_errors = 0
    all_rules = []
    duplicate_details = []
    for file in files:
        try:
            content = (await file.read()).decode("utf-8", errors="replace")
            filename = file.filename or "unknown.yml"
            sigma_rules = convert_sigma_to_rules(content, filename)
            for rule_data in sigma_rules:
                try:
                    result = create_rule(rule_data)
                    all_rules.append(result)
                    total_imported += 1
                except ValueError as ve:
                    if "Duplicate" in str(ve):
                        total_duplicates += 1
                        duplicate_details.append(str(ve))
                    else:
                        total_errors += 1
                except Exception:
                    total_errors += 1
        except Exception:
            total_errors += 1
    return {"status": "success", "imported": total_imported, "duplicates": total_duplicates,
            "duplicate_details": duplicate_details, "errors": total_errors, "rules": all_rules}


# ═══ FILE PARSING & DETECTION ═══

@app.post("/upload-evtx/")
async def upload_evtx(file: UploadFile = File(...)):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name
        events = parse_evtx(tmp_path)
        os.remove(tmp_path)
        return {"status": "success", "filename": file.filename, "event_count": len(events), "events": events}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/parse")
async def parse_artifact(file: UploadFile = File(...)):
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
        log_type = detect_log_type(content, filename)
        result = parse_file(content, log_type, tmp_path, filename)
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        return {"status": "success", "filename": filename, **result}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/analyze")
async def analyze_artifact(
    file: UploadFile = File(...),
    ioc_list: Optional[str] = Form(None),
    ioc_enabled: Optional[bool] = Form(True)
):
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
        log_type = detect_log_type(content, filename)
        parsed = parse_file(content, log_type, tmp_path, filename)
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        events = parsed["events"]
        # Rules from database
        rules = get_rules_by_type(log_type)
        ioc_rules = None
        if ioc_enabled and ioc_list:
            try:
                iocs = json.loads(ioc_list)
                if iocs:
                    ioc_rules = build_ioc_rules(iocs)
                    print(f"[SIGIL] /analyze IOC: {len(ioc_rules)} rules from {len(iocs)} IOCs, pattern: {ioc_rules[0]['pattern'][:60] if ioc_rules else 'N/A'}")
            except (json.JSONDecodeError, TypeError) as e:
                print(f"[SIGIL] /analyze IOC parse error: {e}")
        findings = run_detection(events, log_type, rules, ioc_rules)
        ioc_findings = [f for f in findings if f.get("is_ioc_rule")]
        print(f"[SIGIL] /analyze result: {len(findings)} findings ({len(ioc_findings)} IOC), {len(events)} events, log_type={log_type}")
        overall_score = compute_overall_score(findings)
        return {"status": "success", "filename": filename, "log_type": log_type,
                "format": parsed["format"], "event_count": parsed["event_count"],
                "events": events,  # No cap; all events returned for evidence viewer
                "findings": findings,
                "overall_score": overall_score,
                "rules_applied": len(rules) + (len(ioc_rules) if ioc_rules else 0)}
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
    try:
        parsed_events = json.loads(events)
        rules = get_rules_by_type(log_type)
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
        return {"status": "success", "findings": findings, "overall_score": overall_score,
                "rules_applied": len(rules) + (len(ioc_rules) if ioc_rules else 0)}
    except Exception as e:
        return {"status": "error", "message": str(e)}