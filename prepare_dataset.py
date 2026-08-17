import os
import sys
import glob
import pandas as pd
import numpy as np
import json
import joblib
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
print(f"Project directory: {BASE_DIR}")

# SEARCH FOR ALL PARQUET FILES IN THE PROJECT DIRECTORY
parquet_files = glob.glob(os.path.join(BASE_DIR, "*.parquet"))

if not parquet_files:
    print("ERROR: No .parquet files found in the project directory!")
    sys.exit(1)

print(f"Found {len(parquet_files)} parquet file(s) to process.")

# READ AND CONCATENATE ALL FOUND PARQUET FILES
df_list = []
for file in parquet_files:
    print(f"Loading: {os.path.basename(file)}...")
    temp_df = pd.read_parquet(file)
    df_list.append(temp_df)

df = pd.concat(df_list, ignore_index=True)
print(f"Combined data dimensions: {df.shape}")

# CLEAN COLUMN NAMES
df.columns = df.columns.str.strip()

# EXACT MATCH TARGET FEATURES (37 FEATURES BASED ON YOUR DATASET)
TARGET_FEATURES = [
    'Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Fwd Packets Length Total', 'Bwd Packets Length Total', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Fwd IAT Total', 'Bwd IAT Total',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Packet Length Min', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Avg Packet Size', 'Fwd Seg Size Min'
]

# CHECK FOR MATCHED FEATURES
FOUND_FEATURES = [col for col in TARGET_FEATURES if col in df.columns]
print(f"\nSUCCESSFULLY MATCHED {len(FOUND_FEATURES)} / {len(TARGET_FEATURES)} FEATURES.")

if len(FOUND_FEATURES) == 0:
    print("ERROR: No matching features were found in the dataset.")
    sys.exit(1)

# 2- SAVE FEATURE SCHEMA
print("Saving feature_schema.json...")
schema_path = os.path.join(BASE_DIR, "feature_schema.json")
with open(schema_path, "w") as f:
    json.dump({"features": FOUND_FEATURES}, f, indent=4)

# 3- CLEANING PROCESS
print("CLEANING PROCESS: Converting to numeric and removing NaN / Infinity...")
df_selected = df[FOUND_FEATURES].copy()

# CONVERT ALL COLUMNS TO NUMERIC SAFELY
for col in FOUND_FEATURES:
    df_selected[col] = pd.to_numeric(df_selected[col], errors='coerce')

df_selected.replace([np.inf, -np.inf], np.nan, inplace=True)
df_cleaned = df_selected.dropna()
print(f"NUMBER OF CLEAN ROWS: {len(df_cleaned)}")

# 4- PREPROCESSING AND SCALING PIPELINE
print("Preprocessing and Scaling Pipeline...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df_cleaned)

# SAVE TRAINED SCALER
scaler_path = os.path.join(BASE_DIR, "scaler.joblib")
joblib.dump(scaler, scaler_path)

# 5- CSV EXPORT
print("EXPORTING clean_ids2018_processed.csv...")
df_processed = pd.DataFrame(X_scaled, columns=FOUND_FEATURES)

# SAMPLE UP TO 500,000 ROWS FOR OPTIMAL PERFORMANCE IF DATASET IS TOO LARGE
if len(df_processed) > 500000:
    df_processed = df_processed.sample(n=500000, random_state=42)

csv_path = os.path.join(BASE_DIR, "clean_ids2018_processed.csv")
df_processed.to_csv(csv_path, index=False)

print("\nALL DATASETS COMBINED AND PREPARED SUCCESSFULLY!")
print("FILES GENERATED:")
print(f" 1. {csv_path}")
print(f" 2. {schema_path}")
print(f" 3. {scaler_path}")
