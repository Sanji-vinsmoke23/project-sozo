"""Sozo Live Collector (M-006). Streams logs from Docker to the pipeline."""
import os
import sys
import time
import sqlite3
import docker

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from src.parser.parser import parse_line
from src.detection.engine import Engine

DB_PATH = os.path.join(ROOT, "sozo.db")

def flush_to_db(engine, events_batch):
    conn = sqlite3.connect(DB_PATH)
    for e in events_batch:
        conn.execute(
            "INSERT OR IGNORE INTO http_events (event_id,event_ts,source_ip,method,"
            "uri_path,uri_query,status_code,response_bytes,user_agent,referer,parse_status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (e["event_id"], e["event_ts"], e["source_ip"], e["method"], e["uri_path"],
             e["uri_query"], e["status_code"], e["response_bytes"], e["user_agent"],
             e["referer"], e["parse_status"]))
    for d in engine.detections:
        conn.execute(
            "INSERT OR IGNORE INTO detections (detection_id,event_id,rule_id,attack_type,"
            "owasp_ref,mitre_ref,matched_field,matched_indicator,confidence,severity,"
            "dedup_key,action_level) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (d["detection_id"], d["event_id"], d["rule_id"], d["attack_type"],
             d["owasp_ref"], d["mitre_ref"], d["matched_field"], d["matched_indicator"],
             d["confidence"], d["severity"], d["dedup_key"], d["action_level"]))
    conn.commit()
    conn.close()
    engine.detections = [] # Clear detections after flushing to DB

def run():
    print("[COLLECTOR] Connecting to Docker daemon...")
    try:
        client = docker.from_env()
        container = client.containers.get('sozo_victim')
    except Exception as e:
        print(f"[ERROR] Docker connection failed: {e}")
        print("Ensure Docker is running and 'sozo_victim' container is up.")
        return

    print("[COLLECTOR] Streaming logs from sozo_victim... (Ctrl+C to stop)")
    engine = Engine()
    batch = []
    last_flush = time.time()

    try:
        # stream=True, follow=True keeps the connection open for new logs
        for log in container.logs(stream=True, follow=True, tail=0):
            line = log.decode('utf-8').strip()
            if not line: continue
            
            ev = parse_line(line)
            if ev and ev['parse_status'] == 'ok':
                batch.append(ev)
                engine.evaluate(ev)
            
            # Flush every 2 seconds or 50 events
            if time.time() - last_flush > 2 or len(batch) > 50:
                if batch:
                    flush_to_db(engine, batch)
                    print(f"[COLLECTOR] Flushed {len(batch)} events | Active Detections: {len(engine.detections)}")
                    batch = []
                    last_flush = time.time()
                    
    except KeyboardInterrupt:
        print("\n[COLLECTOR] Stopping stream...")
        if batch: flush_to_db(engine, batch)

if __name__ == "__main__":
    run()
