"""
══════════════════════════════════════════════════════════════════════════════
Capture timeline :
  22:00 - 22:27  →  BENIGN          (no attacker traffic)
  22:28 - 22:43  →  PortScan        (Kali hits 192.168.56.105 across many ports)
  22:44 - 23:05  →  BENIGN break    (only stray DHCP pings - not an attack)
  23:06 - 23:16  →  SSH-BruteForce  (Kali → port 22 on 192.168.56.105)
  23:17 - 23:31  →  FTP-BruteForce  (Kali → port 21 on 192.168.56.105)

Network layout:
  Attacker  : 192.168.56.106  (Kali VM)
  Victim    : 192.168.56.105  (Ubuntu, enp0s8)
══════════════════════════════════════════════════════════════════════════════
"""

import argparse
import sys
import pandas as pd
import numpy as np
from datetime import datetime

# ─── CONFIG ──────────────────────────────────────────────────────────────────
INPUT_FILE  = "port_brutepcap_Flow.csv"
OUTPUT_FILE = "port_brute_labeled.csv"

ATTACKER_IP = "192.168.56.106"
VICTIM_IP   = "192.168.56.105"

TIMESTAMP_FORMAT = "%d/%m/%Y %I:%M:%S %p"

PORTSCAN_START  = "2026-04-09 22:27:55"
PORTSCAN_END    = "2026-04-09 22:44:05"

SSH_BRUTE_START = "2026-04-09 23:05:55"
SSH_BRUTE_END   = "2026-04-09 23:16:59"

FTP_BRUTE_START = "2026-04-09 23:16:55"
FTP_BRUTE_END   = "2026-04-09 23:32:00"
SSH_PORT = 22
FTP_PORT = 21

def load_data(path: str) -> pd.DataFrame:
    """Load the CICFlowMeter CSV and parse timestamps robustly."""
    try:
        df = pd.read_csv(path)
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: '{path}'")
        print("        Pass the correct path with --input <path/to/file.csv>")
        sys.exit(1)

    df.columns = df.columns.str.strip()

    # Try the known format first; fall back to pandas auto-inference
    try:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], format=TIMESTAMP_FORMAT)
    except (ValueError, KeyError):
        print("[WARN] Primary timestamp format failed — trying auto-inference.")
        try:
            df["Timestamp"] = pd.to_datetime(df["Timestamp"], infer_datetime_format=True)
        except Exception as e:
            print(f"[ERROR] Could not parse 'Timestamp' column: {e}")
            sys.exit(1)

    print(f"[+] Loaded {len(df):,} rows  |  "
          f"{df['Timestamp'].min()} → {df['Timestamp'].max()}")
    return df


def label_flows(df: pd.DataFrame) -> pd.DataFrame:
    """Apply time-window + IP/port rules to assign a Label to every flow."""
    df = df.copy()

    ts    = df["Timestamp"]
    src   = df["Src IP"]
    dst   = df["Dst IP"]
    dport = df["Dst Port"]

    # ── Boolean masks ─────────────────────────────────────────────────────────
    kali_involved = (src == ATTACKER_IP) | (dst == ATTACKER_IP)
    kali_is_src   = (src == ATTACKER_IP)
    hits_victim   = (dst == VICTIM_IP)   | (src == VICTIM_IP)

    scan_window = (ts >= PORTSCAN_START)   & (ts <= PORTSCAN_END)
    ssh_window  = (ts >= SSH_BRUTE_START)  & (ts <= SSH_BRUTE_END)
    ftp_window  = (ts >= FTP_BRUTE_START)  & (ts <= FTP_BRUTE_END)

    # Rule 1 – FTP Brute Force
    ftp_mask = ftp_window & kali_is_src & (dport == FTP_PORT) & hits_victim

    # Rule 2 – SSH Brute Force
    ssh_mask = ssh_window & kali_is_src & (dport == SSH_PORT) & hits_victim

    # Rule 3 – Port Scan  (any port; both flow directions)
    scan_mask = scan_window & kali_involved & hits_victim

    # Rule 4 – Benign (default)
    df["Label"] = "BENIGN"
    df.loc[scan_mask, "Label"] = "PortScan"
    df.loc[ssh_mask,  "Label"] = "SSH-BruteForce"
    df.loc[ftp_mask,  "Label"] = "FTP-BruteForce"

    return df


def verify(df_labeled: pd.DataFrame):
    """Print a breakdown and sanity checks — no file is written."""
    print("\n" + "═" * 65)
    print("  LABEL DISTRIBUTION")
    print("═" * 65)
    dist = df_labeled["Label"].value_counts()
    for label, count in dist.items():
        pct = count / len(df_labeled) * 100
        print(f"  {label:<20} {count:>8,}  ({pct:5.1f}%)")
    print(f"  {'TOTAL':<20} {len(df_labeled):>8,}")

    print("\n" + "═" * 65)
    print("  PER-MINUTE BREAKDOWN (attack labels only)")
    print("═" * 65)
    df_labeled = df_labeled.copy()
    df_labeled["minute"] = df_labeled["Timestamp"].dt.floor("1min")
    attack_df = df_labeled[df_labeled["Label"] != "BENIGN"]
    if attack_df.empty:
        print("  (no attack flows found — check time windows and IPs)")
    else:
        pivot = (
            attack_df
            .groupby(["minute", "Label"])
            .size()
            .unstack(fill_value=0)
        )
        print(pivot.to_string())

    print("\n" + "═" * 65)
    print("  BOUNDARY CHECK — first / last flow per attack class")
    print("═" * 65)
    for label in ["PortScan", "SSH-BruteForce", "FTP-BruteForce"]:
        subset = df_labeled[df_labeled["Label"] == label]["Timestamp"]
        if len(subset):
            print(f"  {label:<18}  first={subset.min()}  last={subset.max()}")
        else:
            print(f"  {label:<18}  (no flows found)")

    # ── Sanity checks ─────────────────────────────────────────────────────────
    print("\n" + "═" * 65)
    print("  SANITY CHECKS")
    print("═" * 65)

    wrong_ssh  = df_labeled[(df_labeled["Label"] == "SSH-BruteForce") & (df_labeled["Src IP"] != ATTACKER_IP)]
    wrong_ftp  = df_labeled[(df_labeled["Label"] == "FTP-BruteForce") & (df_labeled["Src IP"] != ATTACKER_IP)]
    wrong_scan = df_labeled[
        (df_labeled["Label"] == "PortScan")
        & ~((df_labeled["Src IP"] == ATTACKER_IP) | (df_labeled["Dst IP"] == ATTACKER_IP))
    ]
    overlap_ssh_ftp = df_labeled[(df_labeled["Label"] == "SSH-BruteForce") & (df_labeled["Dst Port"] == FTP_PORT)]
    overlap_ftp_ssh = df_labeled[(df_labeled["Label"] == "FTP-BruteForce") & (df_labeled["Dst Port"] == SSH_PORT)]

    print(f"  SSH-BruteForce rows with wrong Src IP  : {len(wrong_ssh)}")
    print(f"  FTP-BruteForce rows with wrong Src IP  : {len(wrong_ftp)}")
    print(f"  PortScan rows with no Kali IP           : {len(wrong_scan)}")
    print(f"  SSH window rows going to port 21        : {len(overlap_ssh_ftp)}")
    print(f"  FTP window rows going to port 22        : {len(overlap_ftp_ssh)}")

    all_good = all(len(x) == 0 for x in [wrong_ssh, wrong_ftp, wrong_scan,
                                          overlap_ssh_ftp, overlap_ftp_ssh])
    print("\nAll checks passed — labels look clean." if all_good
          else "\nSome checks flagged — review output above.")


def main():
    parser = argparse.ArgumentParser(
        description="Label a CICFlowMeter CSV with attack / benign classes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python label_flows.py\n"
            "  python label_flows.py --input captures/my.csv --output labeled.csv\n"
            "  python label_flows.py --verify\n"
        )
    )
    parser.add_argument("--input",  default=INPUT_FILE,
                        help=f"Path to raw CICFlowMeter CSV (default: {INPUT_FILE})")
    parser.add_argument("--output", default=OUTPUT_FILE,
                        help=f"Path for labeled output CSV  (default: {OUTPUT_FILE})")
    parser.add_argument("--verify", action="store_true",
                        help="Print stats and sanity checks only — no file is written")
    args = parser.parse_args()

    df         = load_data(args.input)
    df_labeled = label_flows(df)
    verify(df_labeled)

    if not args.verify:
        df_out = df_labeled.drop(columns=["minute"], errors="ignore")
        df_out.to_csv(args.output, index=False)
        print(f"\n[+] Saved labeled CSV → {args.output}")
    else:
        print("\n[--verify mode] No file written.")


if __name__ == "__main__":
    main()