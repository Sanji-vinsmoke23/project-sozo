"""Sozo Event Store - SQLite backbone (M-010)."""
import sqlite3
import os

DB_PATH = os.environ.get("SOZO_DB_PATH", "sozo.db")

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS http_events (
    event_id TEXT PRIMARY KEY,
    event_ts TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    method TEXT,
    uri_path TEXT,
    uri_query TEXT,
    status_code INTEGER,
    response_bytes INTEGER,
    user_agent TEXT,
    referer TEXT,
    session_hash TEXT,
    response_time_ms INTEGER,
    parse_status TEXT,
    raw_log_ref TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_http_ip_ts ON http_events(source_ip, event_ts);

CREATE TABLE IF NOT EXISTS detections (
    detection_id TEXT PRIMARY KEY,
    event_id TEXT,
    rule_id TEXT,
    attack_type TEXT,
    owasp_ref TEXT,
    mitre_ref TEXT,
    matched_field TEXT,
    matched_indicator TEXT,
    confidence REAL,
    severity TEXT,
    dedup_key TEXT,
    repeat_count INTEGER DEFAULT 1,
    ml_score REAL,
    action_level TEXT,
    action_id TEXT,
    false_positive_flag INTEGER DEFAULT 0,
    analyst_notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_det_rule ON detections(rule_id);
CREATE INDEX IF NOT EXISTS idx_det_dedup ON detections(dedup_key);

CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    detection_id TEXT,
    indicator TEXT,
    planned_level TEXT,
    planned_action TEXT,
    actor TEXT,
    executed_ts TEXT,
    result TEXT,
    verification TEXT,
    expiry_ts TEXT,
    released_ts TEXT,
    release_reason TEXT,
    review_verdict TEXT,
    reviewer TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_memory (
    indicator TEXT PRIMARY KEY,
    indicator_type TEXT,
    first_seen TEXT,
    last_seen TEXT,
    attack_type TEXT,
    confidence REAL,
    status TEXT,
    expiry_ts TEXT,
    reason TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mem_status ON threat_memory(status);

CREATE TABLE IF NOT EXISTS health_events (
    event_id TEXT PRIMARY KEY,
    component TEXT,
    status TEXT,
    message TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


def init_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    conn.close()
    return tables


if __name__ == "__main__":
    created = init_db()
    print(f"[DB] sozo.db initialized at {os.path.abspath(DB_PATH)}")
    print(f"[DB] tables: {', '.join(created)}")
