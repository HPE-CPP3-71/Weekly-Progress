"""
PART 3 — MAD ANOMALY DETECTION (FINAL CORRECTED)

✔ Uses ONLY normal data to compute baseline (critical fix)
✔ Stable MAD handling (no division by zero)
✔ Efficient persistence (rolling window)
✔ Dynamic threshold optimization

Output:
    data/processed/labelled_dataset.csv
"""

import os
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score

PROC_DIR = os.path.join(os.path.dirname(__file__), "data", "processed")

N_SAMPLES    = 200        # reduced for speed (500 also OK)
N_MIN, N_MAX = 1.0, 5.0
T_PERSIST    = 6          # minutes
INTERVAL_MIN = 3          # minutes


# ─────────────────────────────────────────────
# MAD helpers
# ─────────────────────────────────────────────

def compute_mad(series):
    m = float(series.median())
    mad = float((series - m).abs().median())
    mad = max(mad, 1e-9)   # avoid zero MAD issue
    return m, mad


def apply_mad(series, median, mad, n):
    return (series - median).abs() > (n * mad)


def persistence_filter(series):
    # 6 minutes with 3-min bins → 2 consecutive bins
    min_bins = max(1, T_PERSIST // INTERVAL_MIN)

    return (
        series.astype(int)
              .rolling(window=min_bins)
              .sum()
              .ge(min_bins)
              .astype(int)
    )


def mad_label(df, n, baseline_df):
    # compute baseline ONLY on normal data
    m_ann, mad_ann = compute_mad(baseline_df["num_announcements"])
    m_wit, mad_wit = compute_mad(baseline_df["num_withdrawals"])

    ann_flag = apply_mad(df["num_announcements"], m_ann, mad_ann, n)
    wit_flag = apply_mad(df["num_withdrawals"],   m_wit, mad_wit, n)

    combined = ann_flag & wit_flag

    return persistence_filter(combined)


# ─────────────────────────────────────────────
# Dynamic threshold optimization
# ─────────────────────────────────────────────

def find_best_n(df, true_labels):
    candidates = np.linspace(N_MIN, N_MAX, N_SAMPLES)

    best_n = candidates[0]
    best_score = -1
    best_metrics = {}

    baseline_df = df[df["occurrence_label"] == 0]

    for n in candidates:
        y_pred = mad_label(df, n, baseline_df).values

        if len(np.unique(y_pred)) < 2:
            continue

        f1 = f1_score(true_labels, y_pred, zero_division=0)
        prec = precision_score(true_labels, y_pred, zero_division=0)

        score = 0.6 * f1 + 0.4 * prec

        if score > best_score:
            best_score = score
            best_n = n
            best_metrics = {
                "f1": f1,
                "precision": prec,
                "score": score
            }

    return best_n, best_metrics


# ─────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────

def run_mad(input_csv):
    df = pd.read_csv(input_csv, index_col=0, parse_dates=True)

    # create occurrence label
    df["occurrence_label"] = (df["label_str"] == "anomalous").astype(int)

    print("\nOptimizing threshold n...")

    best_n, metrics = find_best_n(df, df["occurrence_label"].values)

    print(f"\nBest n: {best_n:.4f}")
    print(f"F1: {metrics['f1']:.4f} | Precision: {metrics['precision']:.4f}")

    baseline_df = df[df["occurrence_label"] == 0]

    df["mad_label"] = mad_label(df, best_n, baseline_df)
    df["optimal_n"] = best_n

    out_path = os.path.join(PROC_DIR, "labelled_dataset.csv")
    df.to_csv(out_path)

    print(f"\nSaved labelled dataset → {out_path}")

    return df


if __name__ == "__main__":
    input_csv = os.path.join(PROC_DIR, "all_features_combined.csv")

    if not os.path.exists(input_csv):
        print("Run preprocessing first.")
    else:
        run_mad(input_csv)