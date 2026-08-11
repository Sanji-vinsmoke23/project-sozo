import sqlite3
from fastapi import FastAPI
from typing import Dict, Any, List
app = FastAPI(title="SOZO Platform API", version="1.0.0")
DB_PATH = "sozo.db"
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/status")
def get_status() -> Dict[str, Any]:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM detections")
        count = cursor.fetchone()[0]
        conn.close()
        return {"status": "active", "total_events": count}
    except Exception:
        return {"status": "active", "total_events": 0}

@app.get("/detections")
def get_detections() -> List[Dict[str, Any]]:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM detections ORDER BY timestamp DESC LIMIT 10")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception:
        return []
@app.get("/memory")
def get_memory() -> List[Dict[str, Any]]:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_memory WHERE status = 'ACTIVE'")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    except Exception:
        return []
