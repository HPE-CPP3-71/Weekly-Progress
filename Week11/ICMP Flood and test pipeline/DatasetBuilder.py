#!/usr/bin/env python3
"""
ICMP Flood Dataset Builder
===========================
Combines attack flows (fl1 + fl2) and benign flows into one
balanced training-ready CSV.

  Attack  55% = 268,889 rows  (split across 6 variations)
  Benign  45% = 220,000 rows  (all flows kept)
  Total        488,889 rows

Usage:
    python build_dataset.py \
        --fl1   icmpfl1_labeled.csv \
        --fl2   icmpfl2_labeled.csv \
        --benign benign_labeled.csv \
        --output icmp_dataset_final.csv

    # Preview counts without saving:
    python build_dataset.py --fl1 ... --fl2 ... --benign ... --dry-run
"""

import pandas as pd
import argparse
import sys

RANDOM_SEED = 42

# ── Target samples per variation ─────────────────────────────────────────────
#
# Logic: split attack budget equally between two tool groups, then
#        equally within each group (rare variants kept whole).
#
# Group A — Scapy (custom Python, variable payload 32-1400B, rand src)
#   scapy_slow       : 1,989   keep ALL  — low-rate attack, only 1,989 exist
#   scapy_fast_run1  : 66,227  — high-rate scapy, run 1
#   scapy_fast_run2  : 66,227  — high-rate scapy, run 2 (same params, diff flows)
#
# Group B — System tools (ping + hping3, network-layer floods)
#   ping_flood_64B   : 1       keep ALL  — fixed-src, only 1 flow exists
#   hping3_rand_src  : 67,222  — hping3 rand-source, standard 28-byte payload
#   hping3_rand_large: 67,222  — hping3 rand-source, 1200-byte payload
#
VARIATION_TARGETS = {
    "scapy_slow"       : 1_989,   # keep all — only 1,989 available
    "scapy_fast_run1"  : 66_227,
    "scapy_fast_run2"  : 66_227,
    "ping_flood_64B"   : 1,       # keep all — only 1 available
    "hping3_rand_src"  : 67_222,
    "hping3_rand_large": 67_222,
}

BENIGN_TARGET = 220_000   # all benign flows


def load_and_check(path, label):
    print(f"  Loading {path}...")
    df = pd.read_csv(path)
    print(f"    {len(df):>10,} rows  |  columns: {df.shape[1]}")
    if "Label" not in df.columns:
        print(f"    ERROR: 'Label' column missing in {path}")
        sys.exit(1)
    if "variation" not in df.columns:
        print(f"    WARNING: 'variation' column missing — adding as '{label}'")
        df["variation"] = label
    return df


def sample_attacks(fl1, fl2):
    combined = pd.concat([fl1, fl2], ignore_index=True)
    print(f"\n  Combined attack rows available: {len(combined):,}")

    sampled_parts = []
    print(f"\n  {'Variation':<22} {'Available':>12} {'Sampled':>10}")
    print(f"  {'-'*46}")

    for var, target in VARIATION_TARGETS.items():
        pool = combined[combined["variation"] == var]
        available = len(pool)
        if available == 0:
            print(f"  {var:<22} {'MISSING':>12} {'0':>10}  ⚠ not found in data")
            continue
        n = min(target, available)
        sampled = pool.sample(n=n, random_state=RANDOM_SEED)
        sampled_parts.append(sampled)
        print(f"  {var:<22} {available:>12,} {n:>10,}")

    print(f"  {'-'*46}")
    result = pd.concat(sampled_parts, ignore_index=True)
    print(f"  {'TOTAL':<22} {len(combined):>12,} {len(result):>10,}")
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fl1",     required=True, help="icmpfl1_labeled.csv")
    ap.add_argument("--fl2",     required=True, help="icmpfl2_labeled.csv")
    ap.add_argument("--benign",  required=True, help="benign_labeled.csv")
    ap.add_argument("--output",  default="icmp_dataset_final.csv")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print counts only, don't save")
    args = ap.parse_args()

    print("\n── Loading files ─────────────────────────────────────────")
    fl1    = load_and_check(args.fl1,    "ICMP_FLOOD")
    fl2    = load_and_check(args.fl2,    "ICMP_FLOOD")
    benign = load_and_check(args.benign, "BENIGN")

    print("\n── Sampling attack variations ────────────────────────────")
    attack_df = sample_attacks(fl1, fl2)

    print("\n── Preparing benign class ────────────────────────────────")
    if len(benign) < BENIGN_TARGET:
        print(f"  WARNING: only {len(benign):,} benign rows available, "
              f"need {BENIGN_TARGET:,}. Using all.")
        benign_df = benign.copy()
    else:
        benign_df = benign.sample(n=BENIGN_TARGET, random_state=RANDOM_SEED)
    print(f"  Benign rows: {len(benign_df):,}")

    print("\n── Building final dataset ────────────────────────────────")
    final = pd.concat([attack_df, benign_df], ignore_index=True)
    final = final.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    total   = len(final)
    n_atk   = (final["Label"] == "ICMP_FLOOD").sum()
    n_ben   = (final["Label"] == "BENIGN").sum()

    print(f"\n  Total rows  : {total:,}")
    print(f"  ICMP_FLOOD  : {n_atk:,}  ({100*n_atk/total:.1f}%)")
    print(f"  BENIGN      : {n_ben:,}  ({100*n_ben/total:.1f}%)")

    print(f"\n  Attack variation breakdown:")
    atk_sub = final[final["Label"] == "ICMP_FLOOD"]
    for var, cnt in atk_sub["variation"].value_counts().items():
        print(f"    {var:<22}: {cnt:>8,}  ({100*cnt/n_atk:.1f}% of attack)")

    if args.dry_run:
        print("\n  [Dry run — nothing saved]")
        return

    # Drop variation column before saving (metadata, not a training feature)
    final.drop(columns=["variation"], inplace=True)

    final.to_csv(args.output, index=False)
    print(f"\n  Saved → {args.output}")
    print(f"  Shape  : {final.shape}")


if __name__ == "__main__":
    main()