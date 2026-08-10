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

def get_db_data():
    conn = sqlite3.connect(DB_PATH)
    events = pd.read_sql_query("SELECT COUNT(*) as total FROM http_events", conn).iloc[0]['total']
    
    alerts = pd.read_sql_query("""
        SELECT attack_type, severity, confidence, created_at 
        FROM detections ORDER BY created_at DESC LIMIT 10
    """, conn)
    
    memory = pd.read_sql_query("""
        SELECT indicator, status, attack_type, expiry_ts 
        FROM threat_memory WHERE status='active' ORDER BY last_seen DESC
    """, conn)
    
    actions = pd.read_sql_query("""
        SELECT indicator, planned_action, result, executed_ts 
        FROM actions ORDER BY executed_ts DESC LIMIT 10
    """, conn)
    
    conn.close()
    return events, alerts, memory, actions

events, alerts, memory, actions = get_db_data()

# Top Metrics
col1, col2, col3 = st.columns(3)
col1.metric("Events Processed", events)
col2.metric("Active Threats in Memory", len(memory))
col3.metric("SOAR Actions Taken", len(actions))

st.markdown("---")

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
    st.subheader("🚨 Live Detection Feed (Last 10)")
    if len(alerts) > 0:
        # Color code severity for visual pop
        st.dataframe(alerts, use_container_width=True, hide_index=True)
    else:
        st.info("No attacks detected in the current window.")

# Auto-refresh every 3 seconds
time.sleep(3)
st.rerun()
