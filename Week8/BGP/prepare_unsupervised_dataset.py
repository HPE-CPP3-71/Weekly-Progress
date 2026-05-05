import os
import glob
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

PROC_DIR = "data/processed"

# ─────────────────────────────
# STEP 1: Load all processed files
# ─────────────────────────────

files = glob.glob(os.path.join(PROC_DIR, "*_features.csv"))

dfs = []
for f in files:
    df = pd.read_csv(f)
    dfs.append(df)

df = pd.concat(dfs, ignore_index=True)

print("Total rows:", len(df))


# ─────────────────────────────
# STEP 2: Feature Engineering (same as before)
# ─────────────────────────────
# log scaling (VERY IMPORTANT)
df["log_ann"] = np.log1p(df["num_announcements"])
df["log_wit"] = np.log1p(df["num_withdrawals"])

# ratios
df["ann_wit_ratio"] = df["num_announcements"] / (df["num_withdrawals"] + 1)

# temporal changes
df["ann_diff"] = df["num_announcements"].diff().fillna(0)
df["wit_diff"] = df["num_withdrawals"].diff().fillna(0)

# rolling stats (KEY)
df["ann_roll_mean"] = df["num_announcements"].rolling(5).mean().fillna(0)
df["wit_roll_mean"] = df["num_withdrawals"].rolling(5).mean().fillna(0)

df["ann_roll_std"] = df["num_announcements"].rolling(5).std().fillna(0)
df["wit_roll_std"] = df["num_withdrawals"].rolling(5).std().fillna(0)

# deviation from trend (VERY POWERFUL)
df["ann_dev"] = df["num_announcements"] - df["ann_roll_mean"]
df["wit_dev"] = df["num_withdrawals"] - df["wit_roll_mean"]

# ----------------------

# df["ann_wit_ratio"] = df["num_announcements"] / (df["num_withdrawals"] + 1)

# df["ann_diff"] = df["num_announcements"].diff().fillna(0)
# df["wit_diff"] = df["num_withdrawals"].diff().fillna(0)

# df["ann_roll_std"] = df["num_announcements"].rolling(3).std().fillna(0)
# df["wit_roll_std"] = df["num_withdrawals"].rolling(3).std().fillna(0)


# ─────────────────────────────
# STEP 3: Create label (ONLY for evaluation)
# ─────────────────────────────

df["label"] = (df["label_str"] == "anomalous").astype(int)


# ─────────────────────────────
# STEP 4: Split NORMAL data
# ─────────────────────────────

normal_df = df[df["label"] == 0]
anomaly_df = df[df["label"] == 1]

print("\nNormal:", len(normal_df))
print("Anomaly:", len(anomaly_df))


# ─────────────────────────────
# STEP 5: Split normal → train/test
# ─────────────────────────────

train_norm, test_norm = train_test_split(
    normal_df,
    test_size=0.3,   # 30% normal goes to test
    random_state=42
)

# ─────────────────────────────
# STEP 6: Final datasets
# ─────────────────────────────

train_df = train_norm.copy()

test_df = pd.concat([test_norm, anomaly_df]).sample(frac=1, random_state=42)

print("\nTrain size:", len(train_df))
print("Test size :", len(test_df))

print("\nTest distribution:")
print(test_df["label"].value_counts())


# ─────────────────────────────
# STEP 7: Save
# ─────────────────────────────

FEATURES = [
    "num_announcements",
    "num_withdrawals",
    "avg_as_path_length",
    "max_as_path_length",
    "std_as_path_length",
    "duplicate_withdrawals",
    "unique_withdrawn_prefixes",
    "total_records",
    "ann_wit_ratio",
    "ann_diff",
    "wit_diff",
    "ann_roll_std",
    "wit_roll_std"
]

train_df[FEATURES].to_csv("train_unsupervised.csv", index=False)

test_df[FEATURES + ["label"]].to_csv("test_unsupervised.csv", index=False)

print("\nSaved:")
print("train_unsupervised.csv")
print("test_unsupervised.csv")