"""Sozo SOAR Orchestrator & Threat Memory (R-030 to R-036)."""
import os
import sys
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

DB_PATH = os.path.join(ROOT, "sozo.db")

# Safety Rails (from Safe Response Lifecycle doc)
DEFAULT_TTL_MINUTES = 30
ALLOWLIST_IPS = {"10.10.10.1", "127.0.0.1", "172.17.0.1"} # Docker gateway / host
DRY_RUN_MODE = True # Safety first!
DEMO_MODE = True

def get_conn():
    return sqlite3.connect(DB_PATH)

def get_unmitigated_detections(conn):
    cursor = conn.execute("""
        SELECT d.detection_id, d.event_id, d.rule_id, d.attack_type, 
               d.confidence, d.severity, d.action_level, d.dedup_key,
               e.source_ip
        FROM detections d
        JOIN http_events e ON d.event_id = e.event_id
        WHERE d.action_id IS NULL OR d.action_id = ''
    """)
    return cursor.fetchall()

def update_memory(conn, ip, attack_type, confidence, ttl_minutes):
    now = datetime.now(timezone.utc)
    expiry = (now + timedelta(minutes=ttl_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    cursor = conn.execute("SELECT first_seen FROM threat_memory WHERE indicator = ?", (ip,))
    if cursor.fetchone():
        conn.execute("""
            UPDATE threat_memory 
            SET last_seen = ?, attack_type = ?, confidence = MAX(confidence, ?), status = 'active', expiry_ts = ?
            WHERE indicator = ?
        """, (now_str, attack_type, confidence, expiry, ip))
    else:
        conn.execute("""
            INSERT INTO threat_memory (indicator, indicator_type, first_seen, last_seen, attack_type, confidence, status, expiry_ts, reason)
            VALUES (?, 'ip', ?, ?, ?, ?, 'active', ?, 'SOAR auto-mitigation')
        """, (ip, now_str, now_str, attack_type, confidence, expiry))

def decide_and_act(conn, det):
    det_id, event_id, rule_id, attack_type, conf, sev, planned_level, dedup_key, ip = det
    
    # 1. Allowlist Check
    if ip in ALLOWLIST_IPS and not DEMO_MODE:
        print(f"[SOAR] ALLOWLISTED: {ip} ({rule_id}). Logging and ignoring.")
        action_id = uuid.uuid4().hex
        conn.execute("""
            INSERT INTO actions (action_id, detection_id, indicator, planned_level, planned_action, actor, result, notes)
            VALUES (?, ?, ?, 'L0', 'allowlist_bypass', 'auto', 'skipped', 'IP in allowlist')
        """, (action_id, det_id, ip))
        conn.execute("UPDATE detections SET action_id = ? WHERE detection_id = ?", (action_id, det_id))
        return

    # 2. Memory Check
    mem = conn.execute("SELECT status FROM threat_memory WHERE indicator = ?", (ip,)).fetchone()
    if mem and mem[0] == 'active':
        print(f"[SOAR] MEMORY HIT: {ip} already isolated. Updating last_seen.")
        update_memory(conn, ip, attack_type, conf, DEFAULT_TTL_MINUTES)
        return

    # 3. Decision Matrix
    action_to_take = planned_level
    actual_result = "dry_run"
    
    if DRY_RUN_MODE:
        actual_result = "dry_run"
        action_to_take = f"{planned_level} (Dry-Run)"
    else:
        if conf >= 0.8 and sev == 'high':
            actual_result = "simulated_success" 
        else:
            actual_result = "logged_only"

    # 4. Execute and Audit
    action_id = uuid.uuid4().hex
    expiry_ts = (datetime.now(timezone.utc) + timedelta(minutes=DEFAULT_TTL_MINUTES)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    conn.execute("""
        INSERT INTO actions (action_id, detection_id, indicator, planned_level, planned_action, actor, executed_ts, result, expiry_ts)
        VALUES (?, ?, ?, ?, ?, 'auto', ?, ?, ?)
    """, (action_id, det_id, ip, planned_level, f"network_isolation_{attack_type}", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), actual_result, expiry_ts))
    
    conn.execute("UPDATE detections SET action_id = ? WHERE detection_id = ?", (action_id, det_id))
    update_memory(conn, ip, attack_type, conf, DEFAULT_TTL_MINUTES)
    
    print(f"[SOAR AUDIT] Action={action_to_take} | IP={ip} | Rule={rule_id} | Conf={conf} | Result={actual_result} | TTL={expiry_ts}")

def run_soar():
    conn = get_conn()
    detections = get_unmitigated_detections(conn)
    
    if not detections:
        print("[SOAR] No unmitigated detections found. System is quiet.")
        conn.close()
        return
        
    print(f"[SOAR] Processing {len(detections)} new detections...")
    for det in detections:
        decide_and_act(conn, det)
        
    conn.commit()
    conn.close()
    print("[SOAR] Orchestration cycle complete. Audit trail saved to sozo.db.")

if __name__ == "__main__":
    run_soar()
