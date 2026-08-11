"""SOZO Platform API v1.1 (Fixed schema & config integration)."""
import os
import sys
import sqlite3
from fastapi import FastAPI
from typing import Dict, Any, List

# Fix 1: Use our enterprise config system instead of hardcoded paths
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from src.core.config import load_config, db_path

app = FastAPI(title="SOZO Platform API", version="1.1.0")

def get_db_connection():
    cfg = load_config()
    conn = sqlite3.connect(db_path(cfg))
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/status")
def get_status() -> Dict[str, Any]:
    try:
        conn = get_db_connection()
        # Fix 2: Count http_events, not detections
        cursor = conn.execute("SELECT COUNT(*) FROM http_events")
        count = cursor.fetchone()[0]
        conn.close()
        return {"status": "active", "total_events": count}
    except Exception:
        return {"status": "active", "total_events": 0}

@app.get("/detections")
def get_detections() -> List[Dict[str, Any]]:
    try:
        conn = get_db_connection()
        # Fix 3: Use 'created_at' instead of 'timestamp'
        cursor = conn.execute("SELECT * FROM detections ORDER BY created_at DESC LIMIT 10")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception:
        return []

@app.get("/memory")
def get_memory() -> List[Dict[str, Any]]:
    try:
        conn = get_db_connection()
        # Fix 4: Use lowercase 'active'
        cursor = conn.execute("SELECT * FROM threat_memory WHERE status = 'active'")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception:
        return []
