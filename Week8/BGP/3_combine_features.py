import os
import glob
import pandas as pd

PROC_DIR = "data/processed"

files = glob.glob(os.path.join(PROC_DIR, "*_features.csv"))

all_dfs = []

for f in files:
    df = pd.read_csv(f)
    all_dfs.append(df)

combined = pd.concat(all_dfs, ignore_index=False)

output_path = os.path.join(PROC_DIR, "all_features_combined.csv")
combined.to_csv(output_path)

print("Saved:", output_path)
print("Total rows:", len(combined))