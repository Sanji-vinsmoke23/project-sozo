"""Sozo Detection Engine v2 (R-021 + E1 Config Integration)."""
import os
import sys

# CRITICAL: Project root must be added to sys.path BEFORE importing src.*
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

import re
import uuid
import sqlite3
from collections import defaultdict
from datetime import datetime

from src.parser.parser import parse_file
from src.core.config import load_config, db_path
from src.core.logger import get_logger

log = get_logger("engine")

SQLI_PATTERNS = [
    (re.compile(r"(?i)\bunion\b[^&]*\bselect\b"), "union_select"),
    (re.compile(r"(?i)\b(or|and)\b\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+"), "tautology"),
    (re.compile(r"(?i)\b(sleep|benchmark)\s*\("), "time_based"),
    (re.compile(r"(?i)information_schema"), "schema_probe"),
    (re.compile(r"(?i)['\"]\s*;\s*(drop|delete|update|insert)\b"), "stacked_query"),
]

def ts_epoch(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").timestamp()

class Engine:
    def __init__(self, cfg):
        self.d_sqli = cfg["detection"]["sqli"]["enabled"]
        self.d_brute = cfg["detection"]["brute_force"]["enabled"]
        self.d_scan = cfg["detection"]["scanner"]["enabled"]

        self.brute_count = cfg["detection"]["brute_force"]["count"]
        self.brute_window = cfg["detection"]["brute_force"]["window_seconds"]
        self.scan_count = cfg["detection"]["scanner"]["count"]
        self.scan_window = cfg["detection"]["scanner"]["window_seconds"]

        self.logins = defaultdict(list)
        self.not404 = defaultdict(list)
        self.detections = []

    def evaluate(self, ev):
        if self.d_sqli:
            for key, value in ev["query_params"].items():
                for pat, family in SQLI_PATTERNS:
                    if pat.search(value):
                        self._add(ev, "DET-SQLI-01", "sqli", "A03", "T1190",
                                  f"query_params[{key}]", value, 0.8, "high", "L3")
                        break
        
        t = ts_epoch(ev["event_ts"])
        
        if self.d_brute and ev["method"] == "POST" and ev["uri_path"] == "/login.php":
            self.logins[ev["source_ip"]].append(t)
            w = [x for x in self.logins[ev["source_ip"]] if t - x <= self.brute_window]
            self.logins[ev["source_ip"]] = w
            if len(w) >= self.brute_count:
                self._add(ev, "DET-BRUTE-01", "brute_force", "A07", "T1110",
                          "login_rate", f"{len(w)} logins in {self.brute_window}s", 0.7, "high", "L3")
                self.logins[ev["source_ip"]] = []
                
        if self.d_scan and ev["status_code"] == 404:
            self.not404[ev["source_ip"]].append(t)
            w = [x for x in self.not404[ev["source_ip"]] if t - x <= self.scan_window]
            self.not404[ev["source_ip"]] = w
            if len(w) >= self.scan_count:
                self._add(ev, "DET-SCAN-01", "scanner_recon", "A05", "T1595",
                          "404_rate", f"{len(w)} 404s in {self.scan_window}s", 0.6, "medium", "L2")
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

def store(events, detections, db_file):
    conn = sqlite3.connect(db_file)
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
    cfg = load_config()
    target = sys.argv[1] if len(sys.argv) > 1 else "data/benign_samples/benign_sample_01.log"
    
    log.info(f"Config loaded: brute={cfg['detection']['brute_force']['count']}, scan={cfg['detection']['scanner']['count']}")
    events, malformed = parse_file(target)
    eng = Engine(cfg)
    for ev in events:
        eng.evaluate(ev)
        
    store(events, eng.detections, db_path(cfg))
    log.info(f"Processed {target} | events={len(events)} malformed={malformed} detections={len(eng.detections)}")
    for d in eng.detections:
        log.warning(f"ALERT | {d['rule_id']} | {d['attack_type']} | conf={d['confidence']} | {d['matched_indicator'][:60]}")
