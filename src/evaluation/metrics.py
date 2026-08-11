"""Sozo Evaluation Metrics Pipeline."""
import os
import sys
import sqlite3

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from src.core.config import load_config, db_path
from src.parser.parser import parse_file
from src.detection.engine import Engine

def evaluate():
    cfg = load_config()
    db_file = db_path(cfg)
    
    # Reset DB for clean evaluation
    if os.path.exists(db_file):
        os.remove(db_file)
    
    from src.db.database import init_db
    init_db(db_file)
    
    print("[EVAL] Running evaluation on ground-truth datasets...")
    
    # 1. Benign Baseline (should produce 0 alerts)
    benign_events = []
    for i in (1, 2, 3):
        events, _ = parse_file(f"data/benign_samples/benign_sample_0{i}.log")
        benign_events.extend(events)
    
    eng_benign = Engine(cfg)
    for ev in benign_events:
        eng_benign.evaluate(ev)
    
    fp_count = len(eng_benign.detections)
    
    # 2. Attack Samples (should produce alerts)
    attack_events, _ = parse_file("data/attack_samples/attack_sample_01.log")
    eng_attack = Engine(cfg)
    for ev in attack_events:
        eng_attack.evaluate(ev)
    
    tp_count = len(eng_attack.detections)
    
    # 3. Calculate Metrics
    total_benign = len(benign_events)
    total_attack = len(attack_events)
    
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0
    fpr = fp_count / total_benign if total_benign > 0 else 0
    
    print(f"\n[RESULTS]")
    print(f"  Benign events processed: {total_benign}")
    print(f"  False Positives: {fp_count}")
    print(f"  Attack events processed: {total_attack}")
    print(f"  True Positives (detections): {tp_count}")
    print(f"\n  Precision: {precision:.2%}")
    print(f"  False Positive Rate: {fpr:.2%}")
    
    if fp_count == 0 and tp_count >= 4:
        print("\n✅ PASS: Zero false positives, all attacks detected!")
    else:
        print("\n⚠️  Needs tuning: Check thresholds in config/sozo.yaml")

if __name__ == "__main__":
    evaluate()
