# SIGIL — Changelog

## v2.2.0 — April 1, 2026, 12:41 PM (GMT+8)
### Changed
- **Revamped Timeline Explorer** — timeline will now show all events collated from all process artifacts.

## v2.1.2 — March 30, 2026, 1:27 PM (GMT+8)
### Changed
- **Merged duplicate findings** — findings with the same rule ID across multiple artifacts (e.g., WEB-002 from `access.log` and `access.log.1`) are now merged into a single finding with combined matched events; each event tagged with its source artifact filename
- **Source moved to evidence table** — removed Source from Detection Details box and Evidence modal header; added Source as a new column in the Evidence table (both EVTX and web log modes) so examiners can see which artifact each event came from
- **Evidence search includes source** — filtering in the Evidence modal now matches against the source filename
- **Removed "Type: Unknown"** — the log type label in Detection Details was never populated from the API; removed the orphaned display line

## v2.1.1 — March 30, 2026, 12:24 PM (GMT+8)
### Fixed
- **Finding source not displayed** — evidence viewer modal showed empty "Source:" field; added `source` column to `findings` table, populated with artifact filename during analysis (e.g., `Security.evtx`, `access.log`); all three frontend finding mappings (analyze, case open, case recovery) now include `source`

## v2.1.0 — March 30, 2026, 12:03 PM (GMT+8)
### Added
- **Incremental threat hunt** — `/case/analyze` now only processes artifacts not yet analyzed; previously completed artifacts are skipped and their findings preserved; supports `force_reanalyze=true` for full re-analysis when needed
- **Cross-platform evtx_dump detection** — `_find_evtx_dump` now detects the examiner's OS and architecture (Windows, macOS Intel/ARM, Linux x64/ARM64) and selects the correct binary automatically; all platform binaries can be placed in `backend/tools/` and SIGIL picks the right one
- **Linux/macOS launcher** — `start-sigil.sh` added alongside `start-sigil.bat`; clears `__pycache__`, auto-sets execute permissions on `evtx_dump` binaries, traps `Ctrl+C` for clean shutdown, kills processes by PID and port (`lsof`/`fuser` fallback)
 
### Changed
- **Analyze endpoint** — tracks artifact status (`parsed` → `complete`); skips artifacts already marked `complete`; recomputes overall score from all findings (existing + new) after each incremental run
- **Analyze logging** — prints incremental status showing new vs already-complete artifact counts (e.g., `Incremental analyze: 2 new artifact(s), 81 already complete`)
- **Empty artifact handling** — artifacts with 0 events or missing JSONL paths are now marked `complete` after analysis to prevent re-processing on subsequent runs
- **evtx_dump startup logging** — prints detected platform, binary path, and download instructions if not found
 
### Fixed
- **Web server logs parsed as single dict** — `parse_web_logs()` returns `{"format":..., "event_count":N, "events":[...]}` but `parse_file` was assigning the whole dict to `events` instead of extracting the list; same bug affected `parse_registry()`; caused JSONL files to contain one line (the serialized dict) instead of individual event lines, resulting in 0 parseable events during analysis

## v2.0.0 — March 28, 2026 (GMT+8)
### Added
- **Case-first architecture** — examiners must create a case before uploading files; all data persists in a SQLite database (`sigil.db`) inside the case folder
- **Case Gate screen** — new landing screen with "New Case" and "Open Existing Case" options; no file uploads until a case is active
- **New Case form** — Case Name, Examiner, Organization, Description, and Save Location (native folder picker via backend)
- **SQLite persistence layer** (`case_db.py`) — 10+ tables covering artifacts, findings, matched events, bookmarks, lateral movement data, and overall score; WAL mode with 64MB cache
- **JSONL event storage** — parsed events dumped to JSONL files in the case data folder for fast sequential reads during detection; avoids SQLite bottleneck on large EVTX files
- **Self-contained finding evidence** — `finding_events` table stores matched event data directly (record_id, event_id, timestamp, content, fields, EventData XML, context) instead of FK references to an events table
- **Crash/refresh recovery** — frontend calls `GET /case/info` on mount; if backend has an active case, all state (artifacts, findings, bookmarks, LM results, overall score) is restored instantly
- **Case folder portability** — uploaded files copied into case folder; reports saved to `case/reports/`; entire folder can be shared between examiners
- **12 new `/case/*` API endpoints** — create, open, close, browse-folder, browse-file, upload, analyze, bookmark, lateral-movement, report, info, test-lateral-movement
- **Lateral Movement Tracker** — dedicated tab with EventID config screen, draggable SVG network graph, click-to-highlight, timeline, chain detection, and auto-generated findings
- **Lateral movement persistence** — LM results (logons, graph nodes/edges, chains, findings, summary) saved to SQLite and restored on case open
- **IRFlow-inspired LM detections** — 11 detectors including smbexec (random 8-char service names), cleartext logon (LogonType 8), ADMIN$/C$ share access, pivot host detection, RDP session correlation, Kerberoasting, and explicit credential abuse
- **Process Inspector tab** — process tree visualization from Sysmon Event ID 1 data
- **3 new detection rules** — WIN-012 Anonymous/NTLM Logon from Remote IP, WIN-013 Pass-the-Hash/Explicit Credential Logon, WIN-014 Special Privileges Assigned to New Logon
- **Unique finding identifiers** — each finding gets a `uid` field combining rule ID and database ID (e.g., `WIN-003_7`) for correct expand/collapse and bookmarking when the same rule triggers across multiple artifacts
- **Full Event XML in evidence viewer** — "Show more" now displays the complete `<Event>` XML (System + EventData) instead of just the `<EventData>` fragment; matches Windows Event Viewer XML output
- **`GET /health` endpoint** — returns backend status, version, and active case state
 
### Changed
- **Architecture: case-first workflow** — all endpoints migrated from stateless `/parse`, `/analyze`, `/lateral-movement` to case-scoped `/case/*` equivalents
- **Event storage: JSONL over SQLite** — events written to JSONL files during upload for speed; SQLite used only for metadata, findings, and LM data
- **Finding↔event linkage** — replaced FK junction table (`finding_events` → `events`) with self-contained matched event storage; detection engine output written directly to `finding_events` with full event data
- **Report generation** — `/case/report` now uses frontend-provided pre-filtered data (respects Bookmarked Only, Critical & High, Critical Only selections) instead of re-querying SQLite
- **Bookmark scope** — bookmark keys use `uid:recordId` format instead of `ruleId:recordId`, preventing cross-finding bookmark collisions when duplicate rules exist
- **Close case cleanup** — resets all UI state including `activeTab`, `processTree`, `lateralMovement`, `lmNodePositions`, `lmSelectedNode`, findings, artifacts, bookmarks, and overall score
- **EVTX parser XML output** — `_build_event_data_xml` replaced with `_build_full_event_xml` reconstructing complete Event XML with System metadata (Provider, EventID, Level, Task, Keywords, TimeCreated, Execution, Channel, Computer, Security); legacy parser stores raw `record.xml()` directly
- **Version bumped** to v2.0.0
- **`start-sigil.bat`** — clears `__pycache__` on startup; uses `cmd /c` instead of `cmd /k`; kills processes by port PID with `/T` (tree kill) for reliable shutdown; verifies ports are freed before exiting
 
### Fixed
- **Evidence viewer showing 0 events** — `insert_finding` was looking up `record_id` in an empty `events` table; fixed by storing matched event data directly in `finding_events`
- **Duplicate findings expanding together** — all findings with the same rule ID (e.g., three "Event Log Cleared" WIN-003) shared the same expand/collapse key; fixed with unique `uid` per finding
- **Bookmarks bleeding across duplicate findings** — bookmarking an event in one "Event Log Cleared" showed stars on all three; fixed by scoping bookmark keys to `uid`
- **Report generation 404** — frontend was hitting `/report` instead of `/case/report`
- **Report generation `'int' object is not iterable`** — `generate_report()` was called with a single dict instead of separate arguments; DB column names (`rule_id`, `rule_name`) didn't match expected field names (`id`, `name`)
- **Report ignoring Bookmarked Only filter** — backend was re-querying all findings from SQLite instead of using the frontend's pre-filtered payload
- **Process Inspector stale state** — closing a case didn't clear `processTree`, so results from the previous case persisted
- **Lateral Movement empty graph on case open** — node positions weren't initialized when restoring LM data from SQLite; graph SVG rendered with undefined coordinates
- **Lateral Movement stale panel after close** — `activeTab` wasn't reset on case close, leaving the LM tab visible with empty/stale data in the new case
- **`limit=None` SQLite datatype mismatch** — `get_events_by_artifact(limit=None)` passed `None` to SQL `LIMIT` clause; fixed with conditional query
- **Slow finding insertion** — per-event `SELECT` queries replaced with batch `IN` lookup
- **Missing `/health` endpoint** — backend connectivity check returned 404
- **`final` variable reference error** — stale `final.length` reference in analyze flow caused silent crash; replaced with `allFindings.length`

## v1.4.0 — March 27, 2026 (GMT+8)
### Added
- **evtx_dump integration** — replaced python-evtx with Rust-based evtx_dump binary (omerbenamram/evtx) for EVTX parsing; auto-detects binary in backend directory or PATH; falls back to python-evtx if not found
- **Enhanced detection engine** — EventID pre-routing, provider fast-skip, field-level matching, pre-compiled pattern cache, incremental keyword scanning
- **Event-level bookmarking** — star individual events within a finding (not the whole finding), allowing examiners to separate true positives from false positives
- **Event Data XML display** — EVTX evidence viewer shows raw EventData XML in a collapsible, scrollable block
- **Structured field display** — EVTX evidence shows key-value pairs (ScriptBlockText, Path, etc.) instead of raw flattened content
- **Web log structured evidence in reports** — DOCX report uses 6-column table (Line, IP, Method, Status, Timestamp, URI) for web log findings
- **EVTX structured evidence in reports** — DOCX report shows ScriptBlockText, Path, and other fields for PowerShell/EVTX findings instead of raw content dump
- **Report scope for bookmarked mode** — shows "Bookmarked Evidence (N events)" with all bookmarked events included (no 5-event cap)
- **Context lines included in bookmarked reports** — registry context and EVTX context appended to evidence in DOCX output
- **Detection diagnostics** — engine logs findings count, events scanned, regex checks, and elapsed time per analysis run
- **evtx_dump per-file logging** — shows filename, event count, parse rate, and error count for each EVTX file
 
### Changed
- **Overall: 44x faster** — full analysis of 188 EVTX files dropped from 01:16:48 to 00:01:44
- Bookmarking moved from finding-level to event-level (`bookmarkedFindings` → `bookmarkedEvents` using `findingId:recordId` composite keys)
- Evidence viewer state (`expandedRows`, `searchFilter`) hoisted to parent component to survive re-renders
- Report payload sends structured `fields` for each matched event
- Content slice in report payload increased from 300 to 1,000 characters
- Context lines hidden for EVTX events (redundant when Event Data XML is shown)
 
### Fixed
- Evidence viewer scroll reset on bookmark click — scroll position preserved via ref
- Evidence viewer scroll reset on row expand — scroll position preserved via ref
- evtx_dump `--dont-show-record-number` flag removed (redundant with `-o jsonl`)
- evtx_dump JSONL parse errors handled per-record (bad records skipped, not entire file)
- EventData list values in EVTX JSONL handled via `_safe_str()` recursive converter
- `context` field now passed through from backend to frontend matched events mapping
- Backward compatibility for old case files with `bookmarkedFindings` format

## v1.3.0 — March 26, 2026, 6:50 PM (GMT+8)
### Added
- Bookmark feature — star individual findings for selective report generation
- Report generation options — All Findings, Bookmarked Only, Critical & High, Critical Only
- Evidence context lines — expand matched events to see surrounding lines (registry values, log entries)
- UTF-16LE encoding support — Windows Registry Editor exports (.reg) now parsed correctly
- Bookmark count indicator in Findings heading
- Bookmarks persist in case save/restore files

### Fixed
- Removed parser max lines limit — all parsers now process entire files without caps
- Fixed registry parser UTF-8 decoding — auto-detects UTF-16 BOM and UTF-16LE encoding
- Fixed browser crash on large .reg files — events no longer stored in browser memory

## v1.2.0 — March 26, 2026, 6:57 AM (GMT+8)
### Added
- DOCX report generation with professional formatting
- File hash calculation (MD5, SHA1, SHA256) on upload, included in reports
- Report scope label on title page (Full Report, Bookmarked, Critical & High, etc.)
- Artifacts table with hash details in generated reports

### Fixed
- Fixed SIGMA YAML import — proper `re.escape()` for backslash-heavy registry paths
- Fixed `_mini_yaml_parse` fallback — preserves `|contains` modifier in field keys
- Fixed `datetime.date` serialization from PyYAML — wrapped in `str()`
- Fixed logsource priority — `category: registry_event` now correctly maps to `registry` type
- Fixed duplicate Sigma rule prevention — dedicated `sigma_id` column with UNIQUE index
- Fixed `loadRulesFromBackend` field mapping — explicit snake_case → camelCase (no `...spread`)
- Fixed report payload size limit — switched from `Form` to `Request.json()`
- Fixed malformed web log entries — validates HTTP method before including in parsed events

## v1.1.0 — March 26, 2026, 5:45 AM (GMT+8)
### Added
- Frontend is now a thin API client (~1,000 lines of engine code removed)
- All file parsing routed through backend `/parse` endpoint
- All detection routed through backend `/analyze` endpoint
- Pasted content sent to backend as File blob
- Rule management API with SQLite persistence
- Rule CRUD endpoints (create, read, update, delete, toggle, reset)
- Sigma YAML import via backend (`POST /rules/import-sigma`)
- Duplicate Sigma rule detection by `sigma_id`
- Rules persist across restarts in `sigil_rules.db`
- Detection engine moved to Python backend
- Web log parser (Apache/Nginx/IIS) ported to Python
- Registry parser ported to Python
- Detection engine with provider filtering and IOC matching
- 26+ built-in detection rules seeded on first startup

### Changed
- Frontend no longer contains detection rules, parsers, or engine code
- `runAnalysis` calls backend `/analyze` — no client-side fallback
- `handleFileRead` calls backend `/parse` for all file types
- Case files no longer store `customRules` — rules live in the database
- Parsing banner updated from "Parsing EVTX files" to "Parsing files"
- Backend error message updated for all file types

## v1.0.0 — March 25, 2026, 10:38 PM (GMT+8)
### Initial Release
- React frontend with dark theme UI
- Drag-and-drop artifact upload with auto log type detection
- 26+ built-in detection rules across Windows Event Logs, Web Server Logs, and Registry
- MITRE ATT&CK mapping for all rules
- Scoring system: CLEAN / SUSPICIOUS / COMPROMISED
- Evidence Viewer with matched event display
- Interactive Timeline with pagination and severity filters
- Case management (New Case, Save, Open)
- IOC hunting panel (IP + domain) with toggle
- Rule editor with live regex validation
- Sigma YAML import (client-side)
- Backend EVTX parser via FastAPI
- Export findings as JSON and Markdown