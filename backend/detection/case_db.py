"""
SIGIL Case Database — SQLite persistence for case-first workflow.

Creates and manages a sigil.db inside each case folder containing:
  - artifacts: uploaded file metadata with hashes
  - events: all parsed events (the big table)
  - findings: detection results
  - finding_events: links findings to matched events
  - bookmarks: event-level bookmarks
  - lm_logons: lateral movement logon events
  - lm_findings: lateral movement findings
  - overall_score: assessment result
"""

import sqlite3
import json
import os
from datetime import datetime


def create_case_db(db_path: str) -> sqlite3.Connection:
    """Create a new case database with full schema."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-64000")  # 64MB cache

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS artifacts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            filename    TEXT NOT NULL,
            file_path   TEXT,
            file_size   INTEGER,
            md5         TEXT,
            sha1        TEXT,
            sha256      TEXT NOT NULL,
            log_type    TEXT NOT NULL,
            format      TEXT,
            event_count INTEGER DEFAULT 0,
            parsed_at   TEXT,
            status      TEXT DEFAULT 'pending'
        );

        CREATE TABLE IF NOT EXISTS events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_id     INTEGER NOT NULL,
            record_id       TEXT,
            event_id        TEXT,
            provider        TEXT,
            channel         TEXT,
            computer        TEXT,
            timestamp       TEXT,
            content         TEXT,
            message         TEXT,
            fields_json     TEXT,
            event_data_xml  TEXT,
            line_index      INTEGER,
            FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
        );

        CREATE INDEX IF NOT EXISTS idx_events_artifact ON events(artifact_id);
        CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_record_id ON events(record_id);

        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id         TEXT NOT NULL,
            rule_name       TEXT NOT NULL,
            description     TEXT,
            severity        TEXT,
            mitre_json      TEXT,
            match_count     INTEGER DEFAULT 0,
            keyword_hits    INTEGER DEFAULT 0,
            confidence      INTEGER DEFAULT 0,
            next_steps_json TEXT,
            is_ioc_rule     BOOLEAN DEFAULT 0,
            source          TEXT,
            created_at      TEXT
        );

        CREATE TABLE IF NOT EXISTS finding_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id      INTEGER NOT NULL,
            record_id       TEXT,
            event_id_str    TEXT,
            timestamp       TEXT,
            content         TEXT,
            message         TEXT,
            fields_json     TEXT,
            event_data_xml  TEXT,
            line_index      INTEGER,
            context_json    TEXT,
            FOREIGN KEY (finding_id) REFERENCES findings(id)
        );
        CREATE INDEX IF NOT EXISTS idx_fe_finding ON finding_events(finding_id);
        CREATE INDEX IF NOT EXISTS idx_fe_record ON finding_events(record_id);

        CREATE TABLE IF NOT EXISTS bookmarks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id  INTEGER NOT NULL,
            event_id    INTEGER NOT NULL,
            created_at  TEXT,
            UNIQUE(finding_id, event_id)
        );

        CREATE TABLE IF NOT EXISTS lm_logons (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            event_db_id     INTEGER,
            event_id        TEXT,
            timestamp       TEXT,
            source          TEXT,
            target          TEXT,
            target_user     TEXT,
            logon_type      TEXT,
            logon_type_label TEXT,
            logon_type_color TEXT,
            status          TEXT,
            is_edge_creating BOOLEAN,
            domain          TEXT,
            workstation     TEXT,
            service_name    TEXT,
            share_name      TEXT,
            process_name    TEXT,
            record_id       TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_lm_eid ON lm_logons(event_id);
        CREATE INDEX IF NOT EXISTS idx_lm_ts ON lm_logons(timestamp);

        CREATE TABLE IF NOT EXISTS lm_findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            severity        TEXT,
            mitre           TEXT,
            title           TEXT,
            description     TEXT,
            source          TEXT,
            targets_json    TEXT
        );

        CREATE TABLE IF NOT EXISTS lm_graph_nodes (
            id              TEXT PRIMARY KEY,
            type            TEXT,
            role            TEXT,
            connections_in  INTEGER DEFAULT 0,
            connections_out INTEGER DEFAULT 0,
            event_count     INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS lm_graph_edges (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source          TEXT NOT NULL,
            target          TEXT NOT NULL,
            count           INTEGER DEFAULT 0,
            logon_types_json TEXT,
            logon_type_label TEXT,
            color           TEXT,
            users_json      TEXT,
            first_seen      TEXT,
            last_seen       TEXT,
            has_failures    BOOLEAN DEFAULT 0,
            has_cleartext   BOOLEAN DEFAULT 0,
            admin_share_count INTEGER DEFAULT 0,
            rdp_count       INTEGER DEFAULT 0,
            share_names_json TEXT,
            service_names_json TEXT
        );

        CREATE TABLE IF NOT EXISTS lm_chains (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_index     INTEGER,
            hop_index       INTEGER,
            source          TEXT,
            target          TEXT,
            target_user     TEXT,
            timestamp       TEXT,
            logon_type      TEXT,
            logon_type_label TEXT,
            status          TEXT
        );

        CREATE TABLE IF NOT EXISTS overall_score (
            id      INTEGER PRIMARY KEY CHECK (id = 1),
            label   TEXT,
            color   TEXT,
            score   INTEGER
        );

        CREATE TABLE IF NOT EXISTS lm_summary (
            id                  INTEGER PRIMARY KEY CHECK (id = 1),
            total_logons        INTEGER DEFAULT 0,
            unique_sources      INTEGER DEFAULT 0,
            unique_targets      INTEGER DEFAULT 0,
            rdp_logons          INTEGER DEFAULT 0,
            failed_logons       INTEGER DEFAULT 0,
            chain_count         INTEGER DEFAULT 0,
            max_chain_length    INTEGER DEFAULT 0,
            cleartext_count     INTEGER DEFAULT 0,
            admin_share_count   INTEGER DEFAULT 0,
            selected_eids_json  TEXT
        );
    """)
    conn.commit()
    return conn


def open_case_db(db_path: str) -> sqlite3.Connection:
    """Open an existing case database."""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database not found: {db_path}")
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    # Migrate finding_events table if it has the old schema (FK-based)
    try:
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(finding_events)").fetchall()]
        if "event_id_str" not in cols:
            print("[SIGIL] Migrating finding_events table to v2.0 schema...")
            conn.execute("DROP TABLE IF EXISTS finding_events")
            conn.execute("""
                CREATE TABLE finding_events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id      INTEGER NOT NULL,
                    record_id       TEXT,
                    event_id_str    TEXT,
                    timestamp       TEXT,
                    content         TEXT,
                    message         TEXT,
                    fields_json     TEXT,
                    event_data_xml  TEXT,
                    line_index      INTEGER,
                    context_json    TEXT,
                    FOREIGN KEY (finding_id) REFERENCES findings(id)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fe_finding ON finding_events(finding_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_fe_record ON finding_events(record_id)")
            # Clear old findings since they can't link to the new schema
            conn.execute("DELETE FROM findings")
            conn.commit()
            print("[SIGIL] Migration complete. Re-run threat hunt to regenerate findings.")
    except Exception as e:
        print(f"[SIGIL] Schema migration check: {e}")

    return conn


# ── Artifact Operations ───────────────────────────────────────────────────────

def insert_artifact(conn, filename, file_size, md5, sha1, sha256, log_type, fmt):
    """Insert artifact metadata, return artifact_id."""
    cur = conn.execute(
        "INSERT INTO artifacts (filename, file_size, md5, sha1, sha256, log_type, format, parsed_at, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'parsed')",
        (filename, file_size, md5, sha1, sha256, log_type, fmt, datetime.utcnow().isoformat())
    )
    conn.commit()
    return cur.lastrowid


def get_artifact_by_hash(conn, sha256):
    """Check if artifact already exists by SHA256."""
    row = conn.execute("SELECT * FROM artifacts WHERE sha256 = ?", (sha256,)).fetchone()
    return dict(row) if row else None


def get_all_artifacts(conn):
    """Get all artifacts in the case."""
    rows = conn.execute("SELECT * FROM artifacts ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def update_artifact_status(conn, artifact_id, status, event_count=None):
    """Update artifact status and optionally event count."""
    if event_count is not None:
        conn.execute("UPDATE artifacts SET status=?, event_count=? WHERE id=?",
                     (status, event_count, artifact_id))
    else:
        conn.execute("UPDATE artifacts SET status=? WHERE id=?", (status, artifact_id))
    conn.commit()


# ── Event Operations ──────────────────────────────────────────────────────────

def insert_events_batch(conn, artifact_id, events, batch_size=5000):
    """Batch insert parsed events into SQLite."""
    rows = []
    for ev in events:
        fields = ev.get("fields", {})
        rows.append((
            artifact_id,
            ev.get("record_id"),
            str(ev.get("event_id", "")),
            ev.get("provider", ""),
            ev.get("channel", ""),
            ev.get("computer", ""),
            ev.get("timestamp", ""),
            ev.get("content", ""),
            ev.get("message", ""),
            json.dumps(fields) if fields else "{}",
            ev.get("event_data_xml", ""),
            ev.get("line_index"),
        ))

    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        conn.executemany(
            "INSERT INTO events (artifact_id, record_id, event_id, provider, channel, "
            "computer, timestamp, content, message, fields_json, event_data_xml, line_index) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            batch
        )
    conn.commit()
    return len(rows)


def get_events_by_artifact(conn, artifact_id, limit=5000):
    """Get events for a specific artifact."""
    if limit:
        rows = conn.execute(
            "SELECT * FROM events WHERE artifact_id = ? ORDER BY timestamp LIMIT ?",
            (artifact_id, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM events WHERE artifact_id = ? ORDER BY timestamp",
            (artifact_id,)
        ).fetchall()
    return [_row_to_event(r) for r in rows]


def get_all_events(conn, event_ids=None, limit=None):
    """Get all events, optionally filtered by event_id list."""
    if event_ids:
        placeholders = ",".join("?" * len(event_ids))
        sql = f"SELECT * FROM events WHERE event_id IN ({placeholders}) ORDER BY timestamp"
        params = list(event_ids)
    else:
        sql = "SELECT * FROM events ORDER BY timestamp"
        params = []

    if limit:
        sql += f" LIMIT {limit}"

    rows = conn.execute(sql, params).fetchall()
    return [_row_to_event(r) for r in rows]


def get_event_count(conn, artifact_id=None):
    """Get total event count."""
    if artifact_id:
        row = conn.execute("SELECT COUNT(*) as cnt FROM events WHERE artifact_id = ?",
                           (artifact_id,)).fetchone()
    else:
        row = conn.execute("SELECT COUNT(*) as cnt FROM events").fetchone()
    return row["cnt"]


def _row_to_event(row):
    """Convert a SQLite Row to an event dict matching the parser output format."""
    d = dict(row)
    try:
        d["fields"] = json.loads(d.get("fields_json") or "{}")
    except (json.JSONDecodeError, TypeError):
        d["fields"] = {}
    d.pop("fields_json", None)
    return d


# ── Finding Operations ────────────────────────────────────────────────────────

def clear_findings(conn):
    """Clear all findings and finding_events (before re-analysis)."""
    conn.execute("DELETE FROM finding_events")
    conn.execute("DELETE FROM findings")
    conn.execute("DELETE FROM overall_score")
    conn.commit()


def insert_finding(conn, finding):
    """Insert a finding and its matched events. Returns finding_id."""
    cur = conn.execute(
        "INSERT INTO findings (rule_id, rule_name, description, severity, mitre_json, "
        "match_count, keyword_hits, confidence, next_steps_json, is_ioc_rule, source, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            finding["id"], finding["name"], finding.get("description", ""),
            finding.get("severity", "medium"),
            json.dumps(finding.get("mitre", [])),
            finding.get("match_count", 0),
            finding.get("keyword_hits", 0),
            finding.get("confidence", 0),
            json.dumps(finding.get("next_steps", [])),
            finding.get("is_ioc_rule", False),
            finding.get("source", ""),
            datetime.utcnow().isoformat(),
        )
    )
    finding_id = cur.lastrowid

    # Store matched events directly (no FK to events table needed)
    matched = finding.get("matched_events", [])
    if matched:
        rows = []
        for me in matched:
            fields = me.get("fields", {})
            rows.append((
                finding_id,
                me.get("record_id", ""),
                str(me.get("event_id", "")),
                me.get("timestamp", ""),
                me.get("content", ""),
                me.get("message", ""),
                json.dumps(fields) if fields else "{}",
                me.get("event_data_xml", ""),
                me.get("line_index"),
                json.dumps(me.get("context", [])),
            ))
        for i in range(0, len(rows), 500):
            conn.executemany(
                "INSERT INTO finding_events (finding_id, record_id, event_id_str, "
                "timestamp, content, message, fields_json, event_data_xml, line_index, context_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows[i:i + 500]
            )

    conn.commit()
    return finding_id


def insert_overall_score(conn, score):
    """Insert or replace overall score."""
    conn.execute(
        "INSERT OR REPLACE INTO overall_score (id, label, color, score) VALUES (1, ?, ?, ?)",
        (score["label"], score["color"], score["score"])
    )
    conn.commit()


def get_all_findings(conn):
    """Get all findings with their matched events. Merges findings with the same rule_id."""
    raw_findings = []
    rows = conn.execute("SELECT * FROM findings ORDER BY "
                        "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                        "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, "
                        "confidence DESC").fetchall()

    for row in rows:
        f = dict(row)
        f["mitre"] = json.loads(f.pop("mitre_json", "[]"))
        f["next_steps"] = json.loads(f.pop("next_steps_json", "[]"))
        source = f.get("source", "")

        # Get matched events stored directly in finding_events
        event_rows = conn.execute(
            "SELECT * FROM finding_events WHERE finding_id = ? ORDER BY timestamp",
            (f["id"],)
        ).fetchall()

        matched = []
        for er in event_rows:
            ev = dict(er)
            ev["event_id"] = ev.pop("event_id_str", "")
            try:
                ev["fields"] = json.loads(ev.pop("fields_json", "{}"))
            except (json.JSONDecodeError, TypeError):
                ev["fields"] = {}
            try:
                ev["context"] = json.loads(ev.pop("context_json", "[]"))
            except (json.JSONDecodeError, TypeError):
                ev["context"] = []
            # Tag each event with the source artifact
            ev["source"] = source
            matched.append(ev)

        f["matched_events"] = matched
        f["match_count"] = f.get("match_count", len(matched))

        # Check bookmarks
        bm_rows = conn.execute(
            "SELECT event_id FROM bookmarks WHERE finding_id = ?", (f["id"],)
        ).fetchall()
        f["bookmarked_event_ids"] = [r["event_id"] for r in bm_rows]

        raw_findings.append(f)

    # Merge findings with the same rule_id
    merged_map = {}
    for f in raw_findings:
        rule_id = f.get("rule_id", "")
        if rule_id in merged_map:
            m = merged_map[rule_id]
            # Combine matched events
            m["matched_events"].extend(f.get("matched_events", []))
            # Aggregate counts
            m["match_count"] = m.get("match_count", 0) + f.get("match_count", 0)
            m["keyword_hits"] = max(m.get("keyword_hits", 0), f.get("keyword_hits", 0))
            m["confidence"] = max(m.get("confidence", 0), f.get("confidence", 0))
            # Merge sources
            new_source = f.get("source", "")
            if new_source and new_source not in m.get("sources", []):
                m["sources"].append(new_source)
            # Merge bookmarks
            m["bookmarked_event_ids"].extend(f.get("bookmarked_event_ids", []))
            # Collect db IDs for bookmark operations
            m["db_ids"].append(f["id"])
        else:
            f["sources"] = [f.get("source", "")] if f.get("source") else []
            f["db_ids"] = [f["id"]]
            merged_map[rule_id] = f

    # Sort merged results and re-sort matched events by timestamp
    findings = list(merged_map.values())
    for f in findings:
        f["matched_events"].sort(key=lambda e: e.get("timestamp") or "")
        f["match_count"] = len(f["matched_events"])

    findings.sort(key=lambda f: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.get("severity", "medium"), 4),
        -(f.get("confidence", 0))
    ))

    return findings


def get_overall_score(conn):
    """Get the stored overall score."""
    row = conn.execute("SELECT * FROM overall_score WHERE id = 1").fetchone()
    return dict(row) if row else None


# ── Bookmark Operations ───────────────────────────────────────────────────────

def toggle_bookmark(conn, finding_id, event_id):
    """Toggle a bookmark. Returns True if added, False if removed."""
    existing = conn.execute(
        "SELECT id FROM bookmarks WHERE finding_id = ? AND event_id = ?",
        (finding_id, event_id)
    ).fetchone()

    if existing:
        conn.execute("DELETE FROM bookmarks WHERE id = ?", (existing["id"],))
        conn.commit()
        return False
    else:
        conn.execute(
            "INSERT INTO bookmarks (finding_id, event_id, created_at) VALUES (?, ?, ?)",
            (finding_id, event_id, datetime.utcnow().isoformat())
        )
        conn.commit()
        return True


def get_all_bookmarks(conn):
    """Get all bookmarks as set of 'finding_id:event_id' strings."""
    rows = conn.execute("SELECT finding_id, event_id FROM bookmarks").fetchall()
    return {f"{r['finding_id']}:{r['event_id']}" for r in rows}


# ── Lateral Movement Persistence ──────────────────────────────────────────────

def clear_lm_data(conn):
    """Clear all lateral movement data before re-analysis."""
    conn.execute("DELETE FROM lm_logons")
    conn.execute("DELETE FROM lm_findings")
    conn.execute("DELETE FROM lm_graph_nodes")
    conn.execute("DELETE FROM lm_graph_edges")
    conn.execute("DELETE FROM lm_chains")
    conn.execute("DELETE FROM lm_summary")
    conn.commit()


def save_lm_results(conn, result, selected_eids=None):
    """Save full lateral movement analysis results to SQLite."""
    clear_lm_data(conn)

    # Save logons
    logon_rows = []
    for l in result.get("logons", []):
        logon_rows.append((
            l.get("event_id"), l.get("timestamp"), l.get("source"), l.get("target"),
            l.get("target_user"), l.get("logon_type"), l.get("logon_type_label"),
            l.get("logon_type_color"), l.get("status"), l.get("is_edge_creating", True),
            l.get("domain"), l.get("workstation"), l.get("service_name"),
            l.get("share_name"), l.get("process_name"), l.get("record_id"),
        ))
    for i in range(0, len(logon_rows), 5000):
        conn.executemany(
            "INSERT INTO lm_logons (event_id, timestamp, source, target, target_user, "
            "logon_type, logon_type_label, logon_type_color, status, is_edge_creating, "
            "domain, workstation, service_name, share_name, process_name, record_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            logon_rows[i:i + 5000]
        )

    # Save graph nodes
    for n in result.get("graph", {}).get("nodes", []):
        conn.execute(
            "INSERT OR REPLACE INTO lm_graph_nodes (id, type, role, connections_in, connections_out, event_count) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (n["id"], n.get("type"), n.get("role"), n.get("connections_in", 0),
             n.get("connections_out", 0), n.get("event_count", 0))
        )

    # Save graph edges
    for e in result.get("graph", {}).get("edges", []):
        conn.execute(
            "INSERT INTO lm_graph_edges (source, target, count, logon_types_json, logon_type_label, "
            "color, users_json, first_seen, last_seen, has_failures, has_cleartext, "
            "admin_share_count, rdp_count, share_names_json, service_names_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (e["source"], e["target"], e["count"],
             json.dumps(e.get("logon_types", [])), e.get("logon_type_label"),
             e.get("color"), json.dumps(e.get("users", [])),
             e.get("first_seen"), e.get("last_seen"),
             e.get("has_failures", False), e.get("has_cleartext", False),
             e.get("admin_share_count", 0), e.get("rdp_count", 0),
             json.dumps(e.get("share_names", [])),
             json.dumps(e.get("service_names", [])))
        )

    # Save chains
    for ci, chain in enumerate(result.get("chains", [])):
        for hi, hop in enumerate(chain):
            conn.execute(
                "INSERT INTO lm_chains (chain_index, hop_index, source, target, target_user, "
                "timestamp, logon_type, logon_type_label, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ci, hi, hop.get("source"), hop.get("target"), hop.get("target_user"),
                 hop.get("timestamp"), hop.get("logon_type"), hop.get("logon_type_label"),
                 hop.get("status"))
            )

    # Save findings
    for f in result.get("findings", []):
        conn.execute(
            "INSERT INTO lm_findings (severity, mitre, title, description, source, targets_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (f.get("severity"), f.get("mitre"), f.get("title"),
             f.get("desc"), f.get("source"), json.dumps(f.get("targets", [])))
        )

    # Save summary
    summary = result.get("summary", {})
    conn.execute(
        "INSERT OR REPLACE INTO lm_summary (id, total_logons, unique_sources, unique_targets, "
        "rdp_logons, failed_logons, chain_count, max_chain_length, cleartext_count, "
        "admin_share_count, selected_eids_json) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (summary.get("total_logons", 0), summary.get("unique_sources", 0),
         summary.get("unique_targets", 0), summary.get("rdp_logons", 0),
         summary.get("failed_logons", 0), summary.get("chain_count", 0),
         summary.get("max_chain_length", 0), summary.get("cleartext_count", 0),
         summary.get("admin_share_count", 0),
         json.dumps(list(selected_eids)) if selected_eids else "[]")
    )

    conn.commit()


def get_lm_results(conn):
    """Load lateral movement results from SQLite."""
    summary_row = conn.execute("SELECT * FROM lm_summary WHERE id = 1").fetchone()
    if not summary_row or summary_row["total_logons"] == 0:
        return None

    logons = [dict(r) for r in conn.execute(
        "SELECT * FROM lm_logons ORDER BY timestamp LIMIT 5000").fetchall()]

    nodes = [dict(r) for r in conn.execute("SELECT * FROM lm_graph_nodes").fetchall()]

    edges = []
    for r in conn.execute("SELECT * FROM lm_graph_edges").fetchall():
        e = dict(r)
        e["logon_types"] = json.loads(e.pop("logon_types_json", "[]"))
        e["users"] = json.loads(e.pop("users_json", "[]"))
        e["share_names"] = json.loads(e.pop("share_names_json", "[]"))
        e["service_names"] = json.loads(e.pop("service_names_json", "[]"))
        edges.append(e)

    chains = []
    chain_rows = conn.execute("SELECT * FROM lm_chains ORDER BY chain_index, hop_index").fetchall()
    current_chain = []
    current_idx = -1
    for r in chain_rows:
        if r["chain_index"] != current_idx:
            if current_chain:
                chains.append(current_chain)
            current_chain = []
            current_idx = r["chain_index"]
        current_chain.append(dict(r))
    if current_chain:
        chains.append(current_chain)

    findings = []
    for r in conn.execute("SELECT * FROM lm_findings").fetchall():
        f = dict(r)
        f["targets"] = json.loads(f.pop("targets_json", "[]"))
        f["desc"] = f.pop("description", "")
        findings.append(f)

    summary = dict(summary_row)
    summary.pop("id", None)
    summary["selected_eids"] = json.loads(summary.pop("selected_eids_json", "[]"))

    return {
        "logons": logons, "graph": {"nodes": nodes, "edges": edges},
        "chains": chains, "findings": findings, "summary": summary,
    }