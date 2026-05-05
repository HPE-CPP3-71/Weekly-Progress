import os
import glob
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score

PROC_DIR = "data/processed"

N_SAMPLES = 200
N_MIN, N_MAX = 1.0, 5.0

T_PERSIST = 6
INTERVAL_MIN = 3


# ─────────────────────────────────────────────
# MAD helpers
# ─────────────────────────────────────────────

def compute_mad(series):
    m = float(series.median())
    mad = float((series - m).abs().median())
    mad = max(mad, 1e-9)
    return m, mad


def apply_mad(series, median, mad, n):
    return (series - median).abs() > (n * mad)


def persistence_filter(series):
    min_bins = max(1, T_PERSIST // INTERVAL_MIN)
    return (
        series.astype(int)
              .rolling(window=min_bins)
              .sum()
              .ge(min_bins)
              .astype(int)
    )


def mad_label(df, n, baseline_df):
    m_ann, mad_ann = compute_mad(baseline_df["num_announcements"])
    m_wit, mad_wit = compute_mad(baseline_df["num_withdrawals"])

    ann_flag = apply_mad(df["num_announcements"], m_ann, mad_ann, n)
    wit_flag = apply_mad(df["num_withdrawals"],   m_wit, mad_wit, n)

    combined = ann_flag & wit_flag
    return persistence_filter(combined)


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
            best_metrics = {"f1": f1, "precision": prec, "score": score}

    return best_n, best_metrics


# ─────────────────────────────────────────────
# PER-EVENT PROCESSING
# ─────────────────────────────────────────────

def process_event(event_name):
    print(f"\nProcessing event: {event_name}")

    files = glob.glob(os.path.join(PROC_DIR, f"*_{event_name}_*_features.csv"))

    dfs = []
    for f in files:
        df = pd.read_csv(f, index_col=0)
        dfs.append(df)

    df = pd.concat(dfs)

    # label creation
    df["occurrence_label"] = (df["label_str"] == "anomalous").astype(int)

    best_n, metrics = find_best_n(df, df["occurrence_label"].values)

    print(f"  Best n: {best_n:.3f} | F1: {metrics['f1']:.3f}")

    baseline_df = df[df["occurrence_label"] == 0]

    df["mad_label"] = mad_label(df, best_n, baseline_df)
    df["optimal_n"] = best_n
    df["event_group"] = event_name

    return df


def run_all_events():
    events = ["codered", "slammer", "nimda", "moscow_blackout", "tmnet"]

    all_results = []

    for event in events:
        df_event = process_event(event)
        all_results.append(df_event)

    final_df = pd.concat(all_results)

    out_path = os.path.join(PROC_DIR, "labelled_dataset.csv")
    final_df.to_csv(out_path)

    print(f"\nSaved final dataset → {out_path}")
    print("\nFinal distribution:")
    print(final_df["mad_label"].value_counts())

    return final_df


if __name__ == "__main__":
    run_all_events()