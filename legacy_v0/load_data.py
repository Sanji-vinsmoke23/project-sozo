import gdown
import pandas as pd

def fetch_and_load_data():
    file_id = '1CghdAtADAY-ERTcQpD2oSb5XnDOlQMqf' 
    url = f'https://drive.google.com/uc?id={file_id}'
    output_file = 'Benign-Monday-no-metadata.parquet'

    print("[*] Downloading Parquet file from Google Drive...")
    gdown.download(url, output_file, quiet=False)

    print("[*] Loading data into Pandas DataFrame...")
    df = pd.read_parquet(output_file, engine='pyarrow')
    
    print("\n--- Data Snapshot ---")
    print(df.head())
    print(f"\nTotal rows and columns: {df.shape}")

if __name__ == "__main__":
    fetch_and_load_data()
