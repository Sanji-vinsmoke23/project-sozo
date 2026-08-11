import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.core.config import load_config
from src.detection.engine import Engine
from src.parser.parser import parse_file, parse_line

def make_engine(**det_overrides):
    cfg = load_config()
    for key, values in det_overrides.items():
        cfg["detection"][key].update(values)
    return Engine(cfg)

def run(events, engine):
    for ev in events:
        engine.evaluate(ev)
    return engine.detections

def test_benign_logs_zero_detections():
    eng = make_engine()
    dets = []
    for i in (1, 2, 3):
        events, _ = parse_file(f"data/benign_samples/benign_sample_0{i}.log")
        dets = run(events, eng)
    assert dets == []

def test_attack_log_exactly_four_detections():
    eng = make_engine()
    events, _ = parse_file("data/attack_samples/attack_sample_01.log")
    dets = run(events, eng)
    rules = sorted(d["rule_id"] for d in dets)
    assert rules == ["DET-BRUTE-01", "DET-SCAN-01", "DET-SQLI-01", "DET-SQLI-01"]

def test_obrien_no_false_positive():
    eng = make_engine()
    ev = parse_line('10.10.10.1 - - [09/Aug/2026:15:20:49 +0000] "GET /vulnerabilities/sqli/?id=O%27Brien&Submit=Submit HTTP/1.1" 200 506 "-" "Mozilla/5.0"')
    eng.evaluate(ev)
    assert eng.detections == []

def test_sqli_disabled_flag():
    eng = make_engine(sqli={"enabled": False})
    events, _ = parse_file("data/attack_samples/attack_sample_01.log")
    dets = run(events, eng)
    assert all(d["rule_id"] != "DET-SQLI-01" for d in dets)

def test_xss_detection():
    eng = make_engine()
    ev = parse_line('10.10.10.5 - - [10/Aug/2026:12:00:00 +0000] "GET /search/?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 500 "-" "Mozilla/5.0"')
    eng.evaluate(ev)
    assert len(eng.detections) == 1
    assert eng.detections[0]["rule_id"] == "DET-XSS-01"

def test_cmdi_detection():
    eng = make_engine()
    # URL encoded `; cat /etc/passwd` -> %3Bcat%20/etc/passwd
    ev = parse_line('10.10.10.5 - - [10/Aug/2026:12:00:00 +0000] "GET /ping/?ip=8.8.8.8%3Bcat%20/etc/passwd HTTP/1.1" 200 500 "-" "Mozilla/5.0"')
    eng.evaluate(ev)
    assert any(d["rule_id"] == "DET-CMDI-01" for d in eng.detections)

def test_fi_detection():
    eng = make_engine()
    # URL encoded `../../etc/passwd` -> ..%2F..%2Fetc%2Fpasswd
    ev = parse_line('10.10.10.5 - - [10/Aug/2026:12:00:00 +0000] "GET /view/?file=..%2F..%2Fetc%2Fpasswd HTTP/1.1" 200 500 "-" "Mozilla/5.0"')
    eng.evaluate(ev)
    assert any(d["rule_id"] == "DET-FI-01" for d in eng.detections)
