import pandas as pd
import joblib
import os

def test_adaptive_core():
    model_path = 'adaptive_model.pkl'
    test_file = 'Bruteforce-Tuesday-no-metadata.parquet'

    if not os.path.exists(model_path):
        print("[-] Error: 'adaptive_model.pkl' not found!")
        return

    print("[*] Loading trained Isolation Forest model...")
    model = joblib.load(model_path)

    if not os.path.exists(test_file):
        print(f"[-] Error: '{test_file}' not found.")
        return

    print(f"[*] Loading test dataset: {test_file}...")
    df = pd.read_parquet(test_file, engine='pyarrow')

    print("[*] Pre-processing test data to match training features...")
    if 'Label' in df.columns:
        df_features = df.drop(columns=['Label'])
    else:
        df_features = df.copy()

    numeric_df = df_features.select_dtypes(include=['float64', 'int64']).fillna(0)

    # ==== THE FIX: Aligning Tuesday's data to match Monday's model ====
    expected_columns = model.feature_names_in_
    
    # If Tuesday is missing a column Monday had, fill it with 0s
    for col in expected_columns:
        if col not in numeric_df.columns:
            numeric_df[col] = 0
            
    # Drop any extra columns Tuesday has, and enforce the exact order
    numeric_df = numeric_df[expected_columns]
    # ==================================================================

    sample_size = min(20000, len(numeric_df))
    print(f"[*] Running anomaly detection on {sample_size:,} flows from Tuesday's traffic...")
    test_data = numeric_df.sample(n=sample_size, random_state=42)

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
    test_adaptive_core()