"""
BGP DATA COLLECTION SCRIPT (Paper Reproduction)

- Source: RIPE RIS (via PyBGPStream)
- Collectors: rrc00, rrc04
- Events:
    CodeRed v2
    Slammer
    Nimda
    Moscow Blackout
    TMnet

Output:
    data/raw/{collector}_{event}_{label}.csv

Author: Reproducibility Pipeline
"""

import pybgpstream
import csv
import os
from datetime import datetime, timezone

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

COLLECTORS = ["rrc00", "rrc04"]
OUTPUT_DIR = "data/raw"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─────────────────────────────────────────────
# EXACT TIMESTAMPS (from paper)
# ─────────────────────────────────────────────

ANOMALOUS_PERIODS = {
    "codered": ("2001-07-19 13:20:00", "2001-07-20 00:00:00"),
    "slammer": ("2003-01-25 05:31:00", "2003-01-25 19:59:00"),
    "nimda": ("2001-09-18 13:19:00", "2001-09-19 10:59:00"),
    "moscow_blackout": ("2005-05-25 04:00:00", "2005-05-25 10:30:00"),
    "tmnet": ("2015-06-12 08:43:00", "2015-06-12 11:53:00"),
}

NORMAL_PERIODS = {
    "codered": ("2001-07-05 19:09:00", "2001-07-20 05:42:00"),
    "slammer": ("2003-01-05 04:30:00", "2003-01-05 08:57:00"),
    "nimda": ("2001-08-25 19:09:00", "2001-08-26 16:42:00"),
    "moscow_blackout": ("2005-05-27 13:06:00", "2005-05-27 18:54:00"),
    "tmnet": ("2015-06-12 20:51:00", "2015-06-12 23:54:00"),
}

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def to_epoch(ts_str):
    """Convert UTC timestamp string to epoch"""
    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def extract_updates(event, start, end, label, collector):
    """Extract BGP UPDATE messages"""

    start_epoch = to_epoch(start)
    end_epoch = to_epoch(end)

    output_file = os.path.join(
        OUTPUT_DIR,
        f"{collector}_{event}_{label}.csv"
    )

    print(f"\n[{collector}] {event.upper()} ({label})")
    print(f"{start} → {end}")
    print(f"Saving to: {output_file}")

    stream = pybgpstream.BGPStream(
        from_time=start_epoch,
        until_time=end_epoch,
        collectors=[collector],
        record_type="updates",
    )

    count = 0

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "timestamp",
            "collector",
            "event",
            "label",
            "msg_type",
            "prefix",
            "as_path"
        ])

        for rec in stream.records():
            for elem in rec:

                if elem.type not in ("A", "W"):
                    continue

                writer.writerow([
                    elem.time,
                    collector,
                    event,
                    label,
                    elem.type,
                    elem.fields.get("prefix", ""),
                    elem.fields.get("as-path", "")
                ])

                count += 1

                # progress print every 100k rows
                if count % 100000 == 0:
                    print(f"  Processed: {count:,}")

    print(f"Finished → {count:,} records")


# ─────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────

def run_collection():

    for collector in COLLECTORS:

        # Anomalous periods
        for event, (start, end) in ANOMALOUS_PERIODS.items():
            extract_updates(event, start, end, "anomalous", collector)

        # Normal periods
        for event, (start, end) in NORMAL_PERIODS.items():
            extract_updates(event, start, end, "normal", collector)


if __name__ == "__main__":
    run_collection()