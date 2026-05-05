"""
BGP PREPROCESSING + FEATURE EXTRACTION (FINAL)

✔ Processes one file at a time (memory safe)
✔ Correct 3-min resampling (no skipped windows)
✔ Fixed cubic spline (stable)
✔ Correct std calculation (ddof=0)
✔ Explicit memory cleanup after each file

Input:  data/raw/*.csv
Output: data/processed/*_features.csv
"""

import os
import glob
import gc
import pandas as pd
import numpy as np
from scipy.interpolate import CubicSpline


# PATH CONFIG 

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

RAW_DIR  = os.path.join(BASE_DIR, "data", "raw")
PROC_DIR = os.path.join(BASE_DIR, "data", "processed")

os.makedirs(PROC_DIR, exist_ok=True)

INTERVAL = "3min"

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def parse_as_path_length(as_path):
    if pd.isna(as_path) or as_path == "":
        return 0
    return len(str(as_path).split())


def compute_features(group):
    announcements = group[group["msg_type"] == "A"]
    withdrawals   = group[group["msg_type"] == "W"]

    ann_paths = announcements["as_path"].apply(parse_as_path_length)

    if not withdrawals.empty:
        w_counts = withdrawals["prefix"].value_counts()
        dup_w = int((w_counts > 1).sum())
        uniq_w = int(w_counts.shape[0])
    else:
        dup_w = 0
        uniq_w = 0

    return {
        "num_announcements": len(announcements),
        "num_withdrawals": len(withdrawals),
        "avg_as_path_length": float(ann_paths.mean()) if len(ann_paths) else 0.0,
        "max_as_path_length": float(ann_paths.max()) if len(ann_paths) else 0.0,
        "std_as_path_length": float(ann_paths.std(ddof=0)) if len(ann_paths) > 1 else 0.0,
        "duplicate_withdrawals": dup_w,
        "unique_withdrawn_prefixes": uniq_w,
        "total_records": len(group),
    }


# ─────────────────────────────────────────────
# SAFE CUBIC SPLINE (FIXED)
# ─────────────────────────────────────────────

def cubic_spline_fill(df):
    numeric_cols = df.select_dtypes(include=[np.number]).columns

    for col in numeric_cols:
        series = df[col]

        if series.isna().sum() == 0:
            continue

        valid = series.dropna()

        if len(valid) < 2:
            df[col] = series.fillna(0)
            continue

        # SAFE indexing (NOT timestamp-based)
        x_valid = np.arange(len(valid))
        x_all   = np.arange(len(series))

        try:
            cs = CubicSpline(x_valid, valid.values, extrapolate=True)
            filled = cs(x_all)

            mask = series.isna()
            df.loc[mask, col] = np.clip(filled[mask], 0, None)

        except Exception:
            df[col] = series.fillna(0)

    return df


# ─────────────────────────────────────────────
# MAIN PROCESSING
# ─────────────────────────────────────────────

def preprocess_file(path):
    print(f"\nProcessing: {os.path.basename(path)}")

    # Load CSV
    df = pd.read_csv(path, low_memory=False)

    if df.empty:
        print("  → Skipped (empty)")
        return None

    # Timestamp conversion
    df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s", utc=True)
    df = df.set_index("timestamp").sort_index()

    # ─────────────────────────────────────────
    # RESAMPLING (NO SKIPPING EMPTY WINDOWS)
    # ─────────────────────────────────────────

    resampled = []

    for window_start, group in df.resample(INTERVAL):
        feat = compute_features(group)
        feat["timestamp"] = window_start
        resampled.append(feat)

    feat_df = pd.DataFrame(resampled).set_index("timestamp")

    # Full index (continuous time)
    full_idx = pd.date_range(
        feat_df.index.min(),
        feat_df.index.max(),
        freq=INTERVAL,
        tz="UTC"
    )

    feat_df = feat_df.reindex(full_idx)

    # Fill missing
    feat_df = cubic_spline_fill(feat_df)

    return feat_df


# ─────────────────────────────────────────────
# PROCESS ALL FILES (MEMORY SAFE)
# ─────────────────────────────────────────────

def preprocess_all():
    files = sorted(glob.glob(os.path.join(RAW_DIR, "*.csv")))

    if not files:
        print("No raw files found!")
        return

    for path in files:

        try:
            basename = os.path.splitext(os.path.basename(path))[0]

            parts = basename.split("_", 2)
            collector = parts[0]
            event     = parts[1]
            label_str = parts[2]

            feat_df = preprocess_file(path)

            if feat_df is None or feat_df.empty:
                continue

            # Add metadata
            feat_df["collector"] = collector
            feat_df["event"] = event
            feat_df["label_str"] = label_str
            feat_df["label"] = 1 if "anomalous" in label_str else 0

            # Save
            out_path = os.path.join(PROC_DIR, f"{basename}_features.csv")
            feat_df.to_csv(out_path)

            print(f"  → Saved: {out_path} ({len(feat_df)} rows)")

        except Exception as e:
            print(f"  ERROR: {e}")

        finally:
            # 🔥 MEMORY CLEANUP
            del feat_df
            gc.collect()


# ─────────────────────────────────────────────

if __name__ == "__main__":
    preprocess_all()