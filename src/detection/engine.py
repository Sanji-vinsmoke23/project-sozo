"""Sozo Detection Engine v2 (R-021). Rules: DET-SQLI-01, DET-BRUTE-01, DET-SCAN-01."""
import os
import re
import sys
import uuid
import sqlite3
from collections import defaultdict
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from src.parser.parser import parse_file

DB_PATH = os.path.join(ROOT, "sozo.db")

SQLI_PATTERNS = [
    (re.compile(r"(?i)\bunion\b[^&]*\bselect\b"), "union_select"),
    (re.compile(r"(?i)\b(or|and)\b\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+"), "tautology"),
    (re.compile(r"(?i)\b(sleep|benchmark)\s*\("), "time_based"),
    (re.compile(r"(?i)information_schema"), "schema_probe"),
    (re.compile(r"(?i)['\"]\s*;\s*(drop|delete|update|insert)\b"), "stacked_query"),
]

BRUTE_COUNT = 5
BRUTE_WINDOW = 300
SCAN_COUNT = 20
SCAN_WINDOW = 60


def ts_epoch(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").timestamp()


class Engine:
    def __init__(self):
        self.logins = defaultdict(list)
        self.not404 = defaultdict(list)
        self.detections = []

    def evaluate(self, ev):
        for key, value in ev["query_params"].items():
            for pat, family in SQLI_PATTERNS:
                if pat.search(value):
                    self._add(ev, "DET-SQLI-01", "sqli", "A03", "T1190",
                              f"query_params[{key}]", value, 0.8, "high", "L3")
                    break
        t = ts_epoch(ev["event_ts"])
        if ev["method"] == "POST" and ev["uri_path"] == "/login.php":
            self.logins[ev["source_ip"]].append(t)
            w = [x for x in self.logins[ev["source_ip"]] if t - x <= BRUTE_WINDOW]
            self.logins[ev["source_ip"]] = w
            if len(w) >= BRUTE_COUNT:
                self._add(ev, "DET-BRUTE-01", "brute_force", "A07", "T1110",
                          "login_rate", f"{len(w)} logins in {BRUTE_WINDOW}s", 0.7, "high", "L3")
                self.logins[ev["source_ip"]] = []
        if ev["status_code"] == 404:
            self.not404[ev["source_ip"]].append(t)
            w = [x for x in self.not404[ev["source_ip"]] if t - x <= SCAN_WINDOW]
            self.not404[ev["source_ip"]] = w
            if len(w) >= SCAN_COUNT:
                self._add(ev, "DET-SCAN-01", "scanner_recon", "A05", "T1595",
                          "404_rate", f"{len(w)} 404s in {SCAN_WINDOW}s", 0.6, "medium", "L2")
                self.not404[ev["source_ip"]] = []

    def _add(self, ev, rule, atype, owasp, mitre, field, indicator, conf, sev, level):
        self.detections.append({
            "detection_id": uuid.uuid4().hex, "event_id": ev["event_id"],
            "rule_id": rule, "attack_type": atype, "owasp_ref": owasp,
            "mitre_ref": mitre, "matched_field": field,
            "matched_indicator": indicator[:120], "confidence": conf,
            "severity": sev, "dedup_key": f"{ev['source_ip']}|{rule}",
            "action_level": level,
        })


def store(events, detections):
    conn = sqlite3.connect(DB_PATH)
    for e in events:
        conn.execute(
            "INSERT OR IGNORE INTO http_events (event_id,event_ts,source_ip,method,"
            "uri_path,uri_query,status_code,response_bytes,user_agent,referer,parse_status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (e["event_id"], e["event_ts"], e["source_ip"], e["method"], e["uri_path"],
             e["uri_query"], e["status_code"], e["response_bytes"], e["user_agent"],
             e["referer"], e["parse_status"]))
    for d in detections:
        conn.execute(
            "INSERT OR IGNORE INTO detections (detection_id,event_id,rule_id,attack_type,"
            "owasp_ref,mitre_ref,matched_field,matched_indicator,confidence,severity,"
            "dedup_key,action_level) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (d["detection_id"], d["event_id"], d["rule_id"], d["attack_type"],
             d["owasp_ref"], d["mitre_ref"], d["matched_field"], d["matched_indicator"],
             d["confidence"], d["severity"], d["dedup_key"], d["action_level"]))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    target = sys.argv[1]
    events, malformed = parse_file(target)
    eng = Engine()
    for ev in events:
        eng.evaluate(ev)
    store(events, eng.detections)
    print(f"[ENGINE] file={target}")
    print(f"[ENGINE] events_stored={len(events)} malformed_skipped={malformed} detections={len(eng.detections)}")
    for d in eng.detections:
        print(f"[ALERT] {d['rule_id']} {d['attack_type']} owasp={d['owasp_ref']} "
              f"conf={d['confidence']} level={d['action_level']} :: {d['matched_indicator'][:60]}")
