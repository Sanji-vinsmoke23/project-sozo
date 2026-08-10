import pandas as pd
import joblib
import os

def test_adaptive_core():
    model_path = 'adaptive_model.pkl'
    test_file = 'Bruteforce-Tuesday-no-metadata.parquet'

    # 1. Check if model exists
    if not os.path.exists(model_path):
        print("[-] Error: 'adaptive_model.pkl' not found! Make sure you trained the model.")
        return

    print("[*] Loading trained Isolation Forest model...")
    model = joblib.load(model_path)

    # 2. Check if Tuesday test dataset exists
    if not os.path.exists(test_file):
        print(f"[-] Error: '{test_file}' not found in current folder.")
        print("[!] Please download the Tuesday parquet file from your Drive into this folder.")
        return

    print(f"[*] Loading test dataset: {test_file}...")
    df = pd.read_parquet(test_file, engine='pyarrow')

    print("[*] Pre-processing test data...")
    # Clean features to match the exact format used during training
    if 'Label' in df.columns:
        df_features = df.drop(columns=['Label'])
    else:
        df_features = df.copy()

    numeric_df = df_features.select_dtypes(include=['float64', 'int64']).fillna(0)

    # 3. Sample 20,000 rows for fast testing
    sample_size = min(20000, len(numeric_df))
    print(f"[*] Running anomaly detection on {sample_size:,} flows from Tuesday's traffic...")
    test_data = numeric_df.sample(n=sample_size, random_state=42)

    # Predict: IsolationForest outputs 1 for normal (benign) and -1 for anomaly (attack)
    predictions = model.predict(test_data)

    normal_count = (predictions == 1).sum()
    anomaly_count = (predictions == -1).sum()
    anomaly_percentage = (anomaly_count / sample_size) * 100

    print("\n" + "="*50)
    print("📊 ADAPTIVE IMMUNE SYSTEM TEST RESULTS")
    print("="*50)
    print(f"Total Flows Evaluated: {sample_size:,}")
    print(f"✅ Flagged as Normal (Benign):  {normal_count:,}")
    print(f"🚨 Flagged as Anomalies/Attacks: {anomaly_count:,}")
    print(f"📈 Anomaly Detection Rate:      {anomaly_percentage:.2f}%")
    print("="*50)

if __name__ == "__main__":
