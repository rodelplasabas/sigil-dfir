# SIGIL — Changelog

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
- **Phase 3**: Frontend is now a thin API client (~1,000 lines of engine code removed)
- All file parsing routed through backend `/parse` endpoint
- All detection routed through backend `/analyze` endpoint
- Pasted content sent to backend as File blob
- **Phase 2**: Rule management API with SQLite persistence
- Rule CRUD endpoints (create, read, update, delete, toggle, reset)
- Sigma YAML import via backend (`POST /rules/import-sigma`)
- Duplicate Sigma rule detection by `sigma_id`
- Rules persist across restarts in `sigil_rules.db`
- **Phase 1**: Detection engine moved to Python backend
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