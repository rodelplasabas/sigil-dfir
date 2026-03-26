# SIGIL — Changelog

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