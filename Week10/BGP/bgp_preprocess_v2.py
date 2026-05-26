"""
BGP Novel Approach — Local Preprocessor
========================================
Reads the 20 raw CSVs (exact format from your download script) and
produces ONE consolidated feature CSV ready for Colab.

Input columns expected:
    timestamp, collector, event, label, msg_type, prefix, as_path

Output (data/ready_for_colab/bgp_all_features.csv):
    One row per 3-minute window per (collector, event, label) combination.
    ~40 engineered features + label columns.

Usage:
    python bgp_preprocess_v2.py
    python bgp_preprocess_v2.py --data-dir "D:/HPE/BGP/Project/data" --window-sec 180

Author: Novel Extension Pipeline
"""

import os
import re
import argparse
import warnings
import numpy as np
import pandas as pd
from pathlib import Path
from scipy.stats import median_abs_deviation

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

COLLECTORS   = ["rrc00", "rrc04"]
EVENTS       = ["codered", "slammer", "nimda", "moscow_blackout", "tmnet"]
LABELS       = ["anomalous", "normal"]
WINDOW_SEC   = 180   # 3-minute windows (matches paper)

ANOMALY_CLASS = {
    "codered":          "worm",
    "slammer":          "worm",
    "nimda":            "worm",
    "moscow_blackout":  "infrastructure",
    "tmnet":            "misconfiguration",
}

# ─────────────────────────────────────────────────────────────────────────────
# AS-PATH UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def parse_as_path(as_path_str):
    """
    Parse an AS_PATH string like '3333 1234 5678' or '{1234,5678} 9999'
    into a clean list of integer ASNs.
    Returns [] on empty / NaN input.
    """
    if pd.isna(as_path_str) or str(as_path_str).strip() == "":
        return []
    tokens = str(as_path_str).strip().split()
    asns = []
    for t in tokens:
        t = re.sub(r"[{}]", "", t)          # strip AS_SET braces
        for part in t.split(","):
            try:
                asns.append(int(part))
            except ValueError:
                pass
    return asns


def has_loop(asns):
    """True if any ASN appears more than once (routing loop)."""
    return len(asns) != len(set(asns))


def get_origin(asns):
    """Last ASN in the path = origin AS."""
    return asns[-1] if asns else None


def get_peer(asns):
    """First ASN in the path = advertising peer (proxy for peer_asn)."""
    return asns[0] if asns else None


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1  Build global AS-link baseline from ALL normal data
# ─────────────────────────────────────────────────────────────────────────────

def build_known_links(raw_dir):
    """
    Collect every AS-AS adjacency ever seen in normal-period data.
    Used to compute #new_links (unseen adjacencies) — a hijack signal.
    """
    print("\n[Step 1] Building AS-link baseline from normal data ...")
    known = set()
    for col in COLLECTORS:
        for ev in EVENTS:
            fpath = Path(raw_dir) / f"{col}_{ev}_normal.csv"
            if not fpath.exists():
                print(f"  ⚠  Not found: {fpath.name}")
                continue
            df = pd.read_csv(fpath, usecols=["as_path"], dtype=str)
            for path_str in df["as_path"].dropna():
                asns = parse_as_path(path_str)
                for i in range(len(asns) - 1):
                    known.add((asns[i], asns[i + 1]))
            print(f"  ✓  {fpath.name:50s}  baseline size={len(known):,}")
    print(f"  → Total known adjacencies: {len(known):,}")
    return known


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2  Window-level feature extraction for one raw CSV
# ─────────────────────────────────────────────────────────────────────────────

def featurise_file(fpath, known_links, window_sec):
    """
    Read one raw CSV and return a DataFrame with one row per window.

    Features computed
    -----------------
    Volume:
        n_ann, n_wit, n_total, awr,
        n_unique_prefixes, n_unique_peer_asns

    AS-path (paper + extensions):
        path_len_avg, path_len_max, path_len_std, path_len_min,
        n_loops, n_origin_asns

    Hijack signals:
        n_moas, n_new_links, n_dup_ann,
        n_withdrawn_unique_pfx  (paper feature)

    Temporal / rolling (computed later across windows):
        placeholders filled by add_temporal_features()
    """

    df = pd.read_csv(fpath, dtype={
        "timestamp": float,
        "msg_type":  str,
        "prefix":    str,
        "as_path":   str,
    })

    # ── Normalise timestamp to integer Unix seconds ───────────────────────────
    if df["timestamp"].dtype == object:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True).astype(np.int64) // 1_000_000_000
    df["timestamp"] = df["timestamp"].astype(np.int64)

    # ── Normalise msg_type ────────────────────────────────────────────────────
    df["msg_type"] = df["msg_type"].str.strip().str.upper().replace(
        {"ANNOUNCEMENT": "A", "WITHDRAWAL": "W",
         "ANNOUNCE":     "A", "WITHDRAW":   "W"}
    )

    t_min = df["timestamp"].min()
    t_max = df["timestamp"].max()

    # Pre-parse all AS paths (expensive — do once)
    print(f"    Parsing AS paths ({len(df):,} rows) ...", end=" ", flush=True)
    df["_asns"]   = df["as_path"].apply(parse_as_path)
    df["_origin"] = df["_asns"].apply(get_origin)
    df["_peer"]   = df["_asns"].apply(get_peer)
    df["_pathlen"]= df["_asns"].apply(len)
    df["_loop"]   = df["_asns"].apply(has_loop)
    print("done")

    rows = []
    t = t_min
    while t < t_max:
        t_end = t + window_sec
        mask = (df["timestamp"] >= t) & (df["timestamp"] < t_end)
        w = df[mask]

        ann = w[w["msg_type"] == "A"]
        wit = w[w["msg_type"] == "W"]

        n_ann = len(ann)
        n_wit = len(wit)
        n_tot = n_ann + n_wit
        awr   = n_ann / max(n_wit, 1)

        # Unique prefixes (announcements)
        ann_pfx = ann["prefix"].dropna()
        n_unique_pfx = ann_pfx.nunique()

        # Withdrawn unique prefixes (paper feature)
        wit_pfx = wit["prefix"].dropna()
        n_wit_unique_pfx = wit_pfx.nunique()

        # AS-path length stats (announcements only — withdrawals have no path)
        path_lens = ann["_pathlen"].values
        if len(path_lens) > 0:
            pl_avg = float(np.mean(path_lens))
            pl_max = int(np.max(path_lens))
            pl_std = float(np.std(path_lens))
            pl_min = int(np.min(path_lens))
        else:
            pl_avg = pl_max = pl_std = pl_min = 0.0

        # Duplicate announcements: same prefix announced > 1× in window
        n_dup_ann = int((ann_pfx.value_counts() > 1).sum()) if n_ann > 0 else 0

        # MOAS: same prefix, different origin ASN
        moas_count = 0
        if n_ann > 0:
            pfx_origins = {}
            for pfx, orig in zip(ann["prefix"], ann["_origin"]):
                if pd.notna(pfx) and orig is not None:
                    pfx_origins.setdefault(pfx, set()).add(orig)
            moas_count = sum(1 for s in pfx_origins.values() if len(s) > 1)

        # New / unseen AS-AS links
        new_links = 0
        for asns in ann["_asns"]:
            for i in range(len(asns) - 1):
                edge = (asns[i], asns[i + 1])
                if edge not in known_links and (edge[1], edge[0]) not in known_links:
                    new_links += 1

        # Loop count
        n_loops = int(ann["_loop"].sum()) if n_ann > 0 else 0

        # Unique origin ASNs
        n_origin_asns = ann["_origin"].dropna().nunique() if n_ann > 0 else 0

        # Unique peer ASNs (proxy)
        n_peer_asns = ann["_peer"].dropna().nunique() if n_ann > 0 else 0

        rows.append({
            "window_start":       t,
            "window_end":         t_end,
            # ── Volume ──
            "n_ann":              n_ann,
            "n_wit":              n_wit,
            "n_total":            n_tot,
            "awr":                round(awr, 4),
            "n_unique_pfx":       n_unique_pfx,
            "n_wit_unique_pfx":   n_wit_unique_pfx,    # paper feature
            "n_unique_peer_asns": n_peer_asns,
            # ── AS-path ──
            "path_len_avg":       round(pl_avg, 4),    # paper feature
            "path_len_max":       pl_max,              # paper feature
            "path_len_std":       round(pl_std, 4),    # paper feature
            "path_len_min":       pl_min,
            # ── Hijack / anomaly signals ──
            "n_moas":             moas_count,
            "n_new_links":        new_links,
            "n_dup_ann":          n_dup_ann,
            "n_loops":            n_loops,
            "n_origin_asns":      n_origin_asns,
            # ── Silence ──
            "is_silent":          int(n_tot == 0),
        })
        t = t_end

    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3  Rolling temporal features (requires sorted windows within a group)
# ─────────────────────────────────────────────────────────────────────────────

def _mad_score_rolling(series, window=10):
    """Rolling robust Z-score using MAD."""
    def _score(arr):
        med = np.median(arr)
        mad = median_abs_deviation(arr, scale="normal")
        return abs(arr[-1] - med) / mad if mad > 0 else 0.0
    return series.rolling(window, min_periods=3).apply(_score, raw=True)


def add_temporal_features(df):
    """
    Add rolling and lag features. df must be sorted by window_start
    and belong to a single (collector, event, label) group.
    """
    df = df.sort_values("window_start").reset_index(drop=True)

    for col in ["n_ann", "n_wit", "n_total"]:
        if col not in df.columns:
            continue
        s = df[col]
        df[f"{col}_roll3_mean"] = s.rolling(3,  min_periods=1).mean()
        df[f"{col}_roll6_mean"] = s.rolling(6,  min_periods=1).mean()
        df[f"{col}_roll12_mean"]= s.rolling(12, min_periods=1).mean()
        df[f"{col}_roll3_std"]  = s.rolling(3,  min_periods=1).std().fillna(0)
        df[f"{col}_roll6_std"]  = s.rolling(6,  min_periods=1).std().fillna(0)
        df[f"{col}_delta"]      = s.diff().fillna(0)
        df[f"{col}_pct_change"] = s.pct_change().replace([np.inf, -np.inf], 0).fillna(0)
        df[f"{col}_mad_score"]  = _mad_score_rolling(s, window=10).fillna(0)

    # Lag features (t-1, t-2)
    for col in ["n_ann", "n_wit"]:
        if col in df.columns:
            df[f"{col}_lag1"] = df[col].shift(1).fillna(0)
            df[f"{col}_lag2"] = df[col].shift(2).fillna(0)

    # Autocorrelation lag-1 (rolling 12 windows = 36 min)
    if "n_ann" in df.columns:
        df["ann_autocorr_lag1"] = df["n_ann"].rolling(12, min_periods=4).apply(
            lambda x: pd.Series(x).autocorr(lag=1) if len(x) >= 4 else 0.0,
            raw=True
        ).fillna(0)

    return df


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4  Global MAD anomaly score (cross-normalised per event)
# ─────────────────────────────────────────────────────────────────────────────

def add_global_mad_score(df_all, k_values=(1, 2, 3, 3.5, 4, 5)):
    """
    For each (collector, event) pair, compute how many MADs the
    announcement and withdrawal counts deviate from the normal-period
    distribution.

    Also implements the paper's dynamic threshold selection:
        Combined Score = 0.6 * F1 + 0.4 * Precision
    to find the best k per event (stored in best_k_per_event).
    """
    print("\n[Step 4] Computing global MAD scores and dynamic thresholds ...")

    scores = np.zeros(len(df_all))

    for event in df_all["event"].unique():
        for collector in df_all["collector"].unique():
            m_normal = (df_all["event"] == event) & \
                       (df_all["collector"] == collector) & \
                       (df_all["label_int"] == 0)
            m_all    = (df_all["event"] == event) & \
                       (df_all["collector"] == collector)

            for col in ["n_ann", "n_wit"]:
                if col not in df_all.columns:
                    continue
                normal_vals = df_all.loc[m_normal, col].dropna().values
                if len(normal_vals) < 3:
                    continue
                med = np.median(normal_vals)
                mad = median_abs_deviation(normal_vals, scale="normal")
                if mad == 0:
                    mad = 1.0
                idx = df_all.index[m_all]
                z   = np.abs(df_all.loc[m_all, col].values - med) / mad
                scores[idx] += z

    df_all["mad_score_global"] = scores

    # ── Dynamic threshold: paper formula 0.6*F1 + 0.4*Prec ──────────────────
    y_true = df_all["label_int"].values
    best_k    = 3.5
    best_cs   = -1.0

    from sklearn.metrics import f1_score, precision_score

    for k in k_values:
        y_pred = (scores > k).astype(int)
        if y_pred.sum() == 0:
            continue
        f1   = f1_score(y_true, y_pred, zero_division=0)
        prec = precision_score(y_true, y_pred, zero_division=0)
        cs   = 0.6 * f1 + 0.4 * prec
        if cs > best_cs:
            best_cs = cs
            best_k  = k

    print(f"  → Best dynamic threshold k={best_k}  "
          f"(Combined Score={best_cs:.4f})")
    df_all["mad_flag"] = (scores > best_k).astype(int)
    df_all["best_k"]   = best_k

    flagged = df_all["mad_flag"].sum()
    print(f"  → MAD flagged {flagged}/{len(df_all)} windows "
          f"({flagged/len(df_all)*100:.1f}%)")
    return df_all, best_k


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5  Build the THREE datasets the paper uses + the full dataset
# ─────────────────────────────────────────────────────────────────────────────

def build_datasets(df_all, out_dir):
    """
    Paper creates 3 label strategies:

    1. Occurrence Dataset  — all windows inside the anomalous event
       time range are labelled 1 (label_int column from raw data).

    2. MAD Anomalous Dataset — only windows flagged by MAD are labelled 1;
       all other windows (including unflagged anomalous ones) are labelled 0.

    3. Normal Dataset — only the normal-period windows, all labelled 0.

    For ML training the paper combines:
        - (Occurrence  + Normal) → "occurrence_dataset.csv"
        - (MAD-flagged + Normal) → "mad_dataset.csv"

    We also export a FULL dataset (all windows, original labels) for the
    novel extension models (GNN, LSTM, stacking).
    """
    normal_df     = df_all[df_all["label_int"] == 0].copy()
    anomalous_df  = df_all[df_all["label_int"] == 1].copy()
    mad_df        = df_all[df_all["mad_flag"]   == 1].copy()

    # Re-label MAD dataset: only MAD-flagged → 1, everything else → 0
    mad_combined = pd.concat([
        mad_df.assign(ml_label=1),
        normal_df.assign(ml_label=0),
    ], ignore_index=True)

    occurrence_combined = pd.concat([
        anomalous_df.assign(ml_label=1),
        normal_df.assign(ml_label=0),
    ], ignore_index=True)

    # Full dataset for novel extension
    df_all = df_all.copy()
    df_all["ml_label"] = df_all["label_int"]

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "mad_dataset":        out_dir / "bgp_mad_dataset.csv",
        "occurrence_dataset": out_dir / "bgp_occurrence_dataset.csv",
        "full_dataset":       out_dir / "bgp_all_features.csv",
    }

    mad_combined.to_csv(paths["mad_dataset"], index=False)
    occurrence_combined.to_csv(paths["occurrence_dataset"], index=False)
    df_all.to_csv(paths["full_dataset"], index=False)

    print("\n[Step 5] Saved datasets:")
    for name, path in paths.items():
        size_mb = path.stat().st_size / 1024 / 1024
        print(f"  {name:25s}: {path.name}  ({size_mb:.1f} MB,  {len(pd.read_csv(path)):,} rows)")

    return paths


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main(data_dir, window_sec):
    raw_dir = Path(data_dir) / "raw"
    out_dir = Path(data_dir) / "ready_for_colab"

    # ── Step 1: baseline links ────────────────────────────────────────────────
    known_links = build_known_links(raw_dir)

    # ── Step 2+3: featurise every file ───────────────────────────────────────
    print("\n[Step 2+3] Featurising raw files ...")
    all_dfs = []

    for collector in COLLECTORS:
        for event in EVENTS:
            for label in LABELS:
                fpath = raw_dir / f"{collector}_{event}_{label}.csv"
                if not fpath.exists():
                    print(f"  ⚠  Missing: {fpath.name}")
                    continue

                print(f"\n  ── {collector} | {event} | {label}")
                try:
                    df_win = featurise_file(fpath, known_links, window_sec)
                    df_win = add_temporal_features(df_win)

                    # Attach metadata
                    df_win["collector"]     = collector
                    df_win["event"]         = event
                    df_win["label"]         = label
                    df_win["label_int"]     = 1 if label == "anomalous" else 0
                    df_win["anomaly_class"] = ANOMALY_CLASS[event] \
                                             if label == "anomalous" else "normal"

                    print(f"    → {len(df_win):,} windows, "
                          f"{df_win.shape[1]} columns")
                    all_dfs.append(df_win)

                except Exception as e:
                    import traceback
                    print(f"  ✗  FAILED on {fpath.name}: {e}")
                    traceback.print_exc()

    if not all_dfs:
        raise RuntimeError("No data was loaded. Check --data-dir path.")

    df_all = pd.concat(all_dfs, ignore_index=True)

    # ── Step 4: MAD score + dynamic threshold ─────────────────────────────────
    df_all, best_k = add_global_mad_score(df_all)

    # ── Fill NaN ──────────────────────────────────────────────────────────────
    num_cols = df_all.select_dtypes(include=[np.number]).columns
    df_all[num_cols] = df_all[num_cols].fillna(0)

    # ── Step 5: Save the three datasets ───────────────────────────────────────
    paths = build_datasets(df_all, out_dir)

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("PREPROCESSING COMPLETE")
    print(f"  Output directory : {out_dir}")
    print(f"  Full dataset     : {df_all.shape}")
    print(f"  Features         : {[c for c in df_all.columns if c not in ['collector','event','label','label_int','anomaly_class','ml_label','best_k']]}")
    print(f"\n  Class distribution (full):")
    print(df_all.groupby(["anomaly_class", "label_int"]).size()
              .rename("count").reset_index().to_string(index=False))
    print(f"\n  Best MAD threshold k = {best_k}")
    print("=" * 65)
    print("\nUpload bgp_all_features.csv to Colab for the novel extension models.")
    print("Upload bgp_mad_dataset.csv and bgp_occurrence_dataset.csv if you")
    print("want to replicate the paper's ML comparison as a baseline.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BGP Novel Approach Preprocessor")
    parser.add_argument(
        "--data-dir",
        default=r"D:\HPE\BGP\Project\data",
        help="Root data dir containing raw/ subdirectory"
    )
    parser.add_argument(
        "--window-sec",
        type=int,
        default=180,
        help="Window size in seconds (default: 180 = 3 min)"
    )
    args = parser.parse_args()
    main(args.data_dir, args.window_sec)
