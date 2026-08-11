"""Trains the IsolationForest anomaly detector on benign traffic."""
import os
import sys
import glob
import pickle

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from sklearn.ensemble import IsolationForest
from src.parser.parser import parse_file
from src.ml.features import extract_features

def train():
    X = []
    files = glob.glob("data/benign_samples/*.log")
    print(f"[ML] Found {len(files)} benign log files.")
    
    for f in files:
        events, _ = parse_file(f)
        for ev in events:
            X.append(extract_features(ev)[0])
            
    if not X:
        print("[ERROR] No events found to train on!")
        return

    print(f"[ML] Training IsolationForest on {len(X)} benign samples...")
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X)

    os.makedirs("models", exist_ok=True)
    with open("models/http_anomaly.pkl", "wb") as f:
        pickle.dump(model, f)
        
    print("[ML] Model trained and saved to models/http_anomaly.pkl")

if __name__ == "__main__":
    train()
