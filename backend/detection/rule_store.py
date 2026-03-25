"""
SIGIL Rule Store — SQLite-backed persistence for detection rules.
Handles CRUD operations, Sigma YAML import, and rule serialization.
"""

import sqlite3
import json
import os
import uuid
from typing import Optional
from detection.rules import DETECTION_RULES

DB_PATH = os.path.join(os.path.dirname(__file__), "sigil_rules.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Create tables and seed with default rules if empty."""
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            severity TEXT DEFAULT 'medium',
            log_type TEXT NOT NULL,
            mitre TEXT DEFAULT '[]',
            pattern TEXT NOT NULL,
            alt_patterns TEXT DEFAULT '[]',
            keywords TEXT DEFAULT '[]',
            next_steps TEXT DEFAULT '[]',
            provider_filter TEXT,
            provider_exclude TEXT,
            count_threshold INTEGER,
            is_builtin INTEGER DEFAULT 0,
            is_enabled INTEGER DEFAULT 1,
            sigma_source TEXT,
            sigma_id TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )
    """)
    # Add unique index on sigma_id for dedup
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sigma_id ON rules(sigma_id) WHERE sigma_id IS NOT NULL")
    conn.commit()

    # Migration: add sigma_id column if missing (for existing databases)
    try:
        conn.execute("ALTER TABLE rules ADD COLUMN sigma_id TEXT")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_sigma_id ON rules(sigma_id) WHERE sigma_id IS NOT NULL")
        conn.commit()
    except Exception:
        pass  # Column already exists

    # Seed with built-in rules if table is empty
    count = conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
    if count == 0:
        _seed_defaults(conn)

    conn.close()


def _seed_defaults(conn: sqlite3.Connection):
    """Insert all default detection rules from rules.py."""
    for log_type, rules in DETECTION_RULES.items():
        for rule in rules:
            conn.execute("""
                INSERT OR IGNORE INTO rules
                (id, name, description, severity, log_type, mitre, pattern,
                 alt_patterns, keywords, next_steps, provider_filter,
                 provider_exclude, count_threshold, is_builtin)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (
                rule["id"],
                rule["name"],
                rule.get("description", ""),
                rule.get("severity", "medium"),
                log_type,
                json.dumps(rule.get("mitre", [])),
                rule["pattern"],
                json.dumps(rule.get("alt_patterns", [])),
                json.dumps(rule.get("keywords", [])),
                json.dumps(rule.get("next_steps", [])),
                rule.get("provider_filter"),
                rule.get("provider_exclude"),
                rule.get("count_threshold"),
            ))
    conn.commit()


def _row_to_rule(row: sqlite3.Row) -> dict:
    """Convert a database row to a rule dict for the detection engine."""
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "severity": row["severity"],
        "log_type": row["log_type"],
        "mitre": json.loads(row["mitre"]),
        "pattern": row["pattern"],
        "alt_patterns": json.loads(row["alt_patterns"]),
        "keywords": json.loads(row["keywords"]),
        "next_steps": json.loads(row["next_steps"]),
        "provider_filter": row["provider_filter"],
        "provider_exclude": row["provider_exclude"],
        "count_threshold": row["count_threshold"],
        "is_builtin": bool(row["is_builtin"]),
        "is_enabled": bool(row["is_enabled"]),
        "sigma_source": json.loads(row["sigma_source"]) if row["sigma_source"] else None,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


# ─── CRUD ─────────────────────────────────────────────────────────────────────

def get_all_rules() -> list[dict]:
    """Get all enabled rules."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM rules WHERE is_enabled = 1 ORDER BY log_type, id"
    ).fetchall()
    conn.close()
    return [_row_to_rule(r) for r in rows]


def get_rules_by_type(log_type: str) -> list[dict]:
    """Get enabled rules for a specific log type."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM rules WHERE log_type = ? AND is_enabled = 1 ORDER BY id",
        (log_type,)
    ).fetchall()
    conn.close()
    return [_row_to_rule(r) for r in rows]


def get_rules_grouped() -> dict:
    """Get all rules grouped by log_type (for frontend sync)."""
    rules = get_all_rules()
    grouped = {}
    for r in rules:
        lt = r["log_type"]
        if lt not in grouped:
            grouped[lt] = []
        grouped[lt].append(r)
    return grouped


def get_rule(rule_id: str) -> Optional[dict]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    conn.close()
    return _row_to_rule(row) if row else None


def create_rule(rule: dict) -> dict:
    """Create a new rule. Auto-generates ID if not provided. Rejects duplicate Sigma rules."""
    conn = _get_conn()

    # Extract sigma_id from sigma_source
    sigma_source = rule.get("sigma_source")
    sigma_id = None
    if sigma_source:
        if isinstance(sigma_source, dict):
            sigma_id = sigma_source.get("sigma_id")
        elif isinstance(sigma_source, str):
            try:
                sigma_id = json.loads(sigma_source).get("sigma_id")
            except (json.JSONDecodeError, AttributeError):
                pass
        # Normalize
        if sigma_id in ("", "None", None):
            sigma_id = None

    # Check for duplicate Sigma rule by dedicated sigma_id column
    if sigma_id:
        existing = conn.execute(
            "SELECT id, name FROM rules WHERE sigma_id = ?",
            (sigma_id,)
        ).fetchone()
        if existing:
            conn.close()
            raise ValueError(f"Duplicate Sigma rule: '{existing['name']}' (ID: {existing['id']}) already has sigma_id {sigma_id}")

    rule_id = rule.get("id")
    if not rule_id:
        log_type = rule.get("log_type", "windows_event_log")
        prefix = {"windows_event_log": "CUS", "web_server_log": "CUW", "registry": "CUR"}.get(log_type, "CUS")
        existing = conn.execute(
            "SELECT id FROM rules WHERE id LIKE ? ORDER BY id DESC LIMIT 1",
            (f"{prefix}-%",)
        ).fetchone()
        if existing:
            num = int(existing["id"].split("-")[-1]) + 1
        else:
            num = 1
        rule_id = f"{prefix}-{num:03d}"

    conn.execute("""
        INSERT INTO rules
        (id, name, description, severity, log_type, mitre, pattern,
         alt_patterns, keywords, next_steps, provider_filter,
         provider_exclude, count_threshold, is_builtin, sigma_source, sigma_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
    """, (
        rule_id,
        rule["name"],
        rule.get("description", ""),
        rule.get("severity", "medium"),
        rule.get("log_type", "windows_event_log"),
        json.dumps(rule.get("mitre", [])),
        rule["pattern"],
        json.dumps(rule.get("alt_patterns", [])),
        json.dumps(rule.get("keywords", [])),
        json.dumps(rule.get("next_steps", [])),
        rule.get("provider_filter"),
        rule.get("provider_exclude"),
        rule.get("count_threshold"),
        json.dumps(rule.get("sigma_source")) if rule.get("sigma_source") else None,
        sigma_id,
    ))
    conn.commit()
    conn.close()
    return get_rule(rule_id)


def update_rule(rule_id: str, updates: dict) -> Optional[dict]:
    """Update an existing rule."""
    conn = _get_conn()
    existing = conn.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if not existing:
        conn.close()
        return None

    fields = []
    values = []
    for key in ["name", "description", "severity", "log_type", "pattern",
                "provider_filter", "provider_exclude", "count_threshold", "is_enabled"]:
        if key in updates:
            fields.append(f"{key} = ?")
            values.append(updates[key])

    for key in ["mitre", "alt_patterns", "keywords", "next_steps"]:
        if key in updates:
            fields.append(f"{key} = ?")
            values.append(json.dumps(updates[key]))

    if fields:
        fields.append("updated_at = datetime('now')")
        values.append(rule_id)
        conn.execute(f"UPDATE rules SET {', '.join(fields)} WHERE id = ?", values)
        conn.commit()

    conn.close()
    return get_rule(rule_id)


def delete_rule(rule_id: str) -> bool:
    conn = _get_conn()
    cursor = conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def toggle_rule(rule_id: str, enabled: bool) -> Optional[dict]:
    """Enable or disable a rule without deleting it."""
    return update_rule(rule_id, {"is_enabled": 1 if enabled else 0})


def reset_to_defaults():
    """Drop all rules and re-seed with defaults."""
    conn = _get_conn()
    conn.execute("DELETE FROM rules")
    _seed_defaults(conn)
    conn.close()
    return get_all_rules()


def get_stats() -> dict:
    """Get rule statistics."""
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
    enabled = conn.execute("SELECT COUNT(*) FROM rules WHERE is_enabled = 1").fetchone()[0]
    builtin = conn.execute("SELECT COUNT(*) FROM rules WHERE is_builtin = 1").fetchone()[0]
    custom = total - builtin
    by_type = {}
    for row in conn.execute("SELECT log_type, COUNT(*) as cnt FROM rules WHERE is_enabled = 1 GROUP BY log_type"):
        by_type[row["log_type"]] = row["cnt"]
    sigma_count = conn.execute("SELECT COUNT(*) FROM rules WHERE sigma_source IS NOT NULL").fetchone()[0]
    conn.close()
    return {
        "total": total, "enabled": enabled, "builtin": builtin,
        "custom": custom, "sigma_imported": sigma_count, "by_type": by_type
    }