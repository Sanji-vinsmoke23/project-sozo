"""Sozo Real-Time SOC Dashboard (Phase 3 / M5)."""
import streamlit as st
import pandas as pd
import sqlite3
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(ROOT, "sozo.db")

st.set_page_config(page_title="Project Sozo: Autonomous Immune SOC", layout="wide", page_icon="🧬")

st.title("🧬 Project Sozo: Autonomous Immune SOC")
st.markdown("Real-time telemetry, threat memory, and SOAR audit trail.")
st.markdown("---")
import requests

def get_db_data():
    try:
        # Fetch from FastAPI instead of SQLite directly
        status_resp = requests.get("http://localhost:8000/status").json()
        events = status_resp.get("total_events", 0)
        
        alerts = requests.get("http://localhost:8000/detections").json()
        memory = requests.get("http://localhost:8000/memory").json()
        
        # Actions and Narratives still need direct DB access (not exposed in API yet)
        conn = sqlite3.connect(DB_PATH)
        actions = pd.read_sql_query("""
            SELECT indicator, planned_action, result, executed_ts 
            FROM actions ORDER BY executed_ts DESC LIMIT 10
        """, conn)
        narratives = pd.read_sql_query("""
            SELECT n.narrative, d.attack_type, d.confidence, n.model
            FROM narratives n JOIN detections d ON n.detection_id = d.detection_id
            ORDER BY n.created_at DESC LIMIT 5
        """, conn)
        conn.close()
        
        return events, pd.DataFrame(alerts), pd.DataFrame(memory), actions, narratives
        
    except Exception as e:
        st.error(f"API connection failed: {e}. Is uvicorn running?")
        return 0, pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
events, alerts, memory, actions, narratives = get_db_data()

# ... (keep the top metrics the same) ...

# Main Content
left_col, right_col = st.columns(2)

with left_col:
    st.subheader("🛡️ Active Threat Memory")
    if len(memory) > 0:
        st.dataframe(memory, use_container_width=True, hide_index=True)
    else:
        st.info("No active threats. The immune system is resting.")

    st.subheader("⚡ Recent SOAR Audit Trail")
    if len(actions) > 0:
        st.dataframe(actions, use_container_width=True, hide_index=True)
    else:
        st.info("No actions recorded yet.")

with right_col:
    # NEW: Narratives Section
    st.subheader("🗣️ AI Incident Summaries")
    if len(narratives) > 0:
        st.dataframe(narratives, use_container_width=True, hide_index=True)
    else:
        st.info("No narratives generated yet.")

    st.subheader("🚨 Live Detection Feed (Last 10)")
    if len(alerts) > 0:
        st.dataframe(alerts, use_container_width=True, hide_index=True)
    else:
        st.info("No attacks detected in the current window.")

# Auto-refresh every 3 seconds
time.sleep(3)
st.rerun()
