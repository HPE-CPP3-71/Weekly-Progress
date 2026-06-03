import numpy as np
import pandas as pd
import joblib
from nfstream import NFPlugin, NFStreamer
from datetime import datetime

# ── Load saved artifacts ──────────────────────────────────────────────────────
model        = joblib.load("xgb_icmp_flood.pkl")
le           = joblib.load("label_encoder.pkl")
feature_cols = joblib.load("feature_columns.pkl")

print(f"Model loaded. Expecting {len(feature_cols)} features.")
print(f"Classes: {list(le.classes_)}\n")

# ── Re-use your exact plugins from training ───────────────────────────────────
# Paste BulkPlugin, HeaderLenPlugin, InitWindowPlugin,
# ExtraFeaturesPlugin, ActiveIdlePlugin here (same code as nfsflowmeter.py)
# ... (copy them in)

# ── Prediction plugin ─────────────────────────────────────────────────────────
class ICMPFloodDetector(NFPlugin):

    def on_init(self, packet, flow):
        flow.udps.prediction  = "PENDING"
        flow.udps.confidence  = 0.0

    def on_expire(self, flow):
        try:
            duration_sec = flow.bidirectional_duration_ms / 1000.0

            # ── Build the same post-processed features from training ──────────
            row = {
                # NFStream built-in fields
                "bidirectional_duration_ms"  : flow.bidirectional_duration_ms,
                "bidirectional_packets"      : flow.bidirectional_packets,
                "bidirectional_bytes"        : flow.bidirectional_bytes,
                "src2dst_duration_ms"        : flow.src2dst_duration_ms,
                "src2dst_packets"            : flow.src2dst_packets,
                "src2dst_bytes"              : flow.src2dst_bytes,
                "bidirectional_min_ps"       : flow.bidirectional_min_ps,
                "bidirectional_mean_ps"      : flow.bidirectional_mean_ps,
                "bidirectional_stddev_ps"    : flow.bidirectional_stddev_ps,
                "bidirectional_max_ps"       : flow.bidirectional_max_ps,
                "src2dst_min_ps"             : flow.src2dst_min_ps,
                "src2dst_mean_ps"            : flow.src2dst_mean_ps,
                "src2dst_stddev_ps"          : flow.src2dst_stddev_ps,
                "src2dst_max_ps"             : flow.src2dst_max_ps,
                "bidirectional_min_piat_ms"  : flow.bidirectional_min_piat_ms,
                "bidirectional_mean_piat_ms" : flow.bidirectional_mean_piat_ms,
                "bidirectional_stddev_piat_ms": flow.bidirectional_stddev_piat_ms,
                "bidirectional_max_piat_ms"  : flow.bidirectional_max_piat_ms,
                "src2dst_min_piat_ms"        : flow.src2dst_min_piat_ms,
                "src2dst_mean_piat_ms"       : flow.src2dst_mean_piat_ms,
                "src2dst_stddev_piat_ms"     : flow.src2dst_stddev_piat_ms,
                "src2dst_max_piat_ms"        : flow.src2dst_max_piat_ms,

                # Custom plugin outputs
                "udps.fwd_byts_b_avg"  : flow.udps.fwd_byts_b_avg,
                "udps.fwd_pkts_b_avg"  : flow.udps.fwd_pkts_b_avg,
                "udps.fwd_blk_rate_avg": flow.udps.fwd_blk_rate_avg,
                "udps.fwd_header_len"  : flow.udps.fwd_header_len,
                "udps.fwd_act_data_pkts": flow.udps.fwd_act_data_pkts,
                "udps.active_mean"     : flow.udps.active_mean,
                "udps.active_max"      : flow.udps.active_max,
                "udps.active_min"      : flow.udps.active_min,
                "udps.idle_mean"       : flow.udps.idle_mean,
                "udps.idle_std"        : flow.udps.idle_std,
                "udps.idle_max"        : flow.udps.idle_max,
                "udps.idle_min"        : flow.udps.idle_min,

                # Post-processed derived features (same as post_process_cicflowmeter)
                "Flow Byts/s"    : flow.bidirectional_bytes   / duration_sec if duration_sec > 0 else 0,
                "Flow Pkts/s"    : flow.bidirectional_packets / duration_sec if duration_sec > 0 else 0,
                "Fwd Pkts/s"     : flow.src2dst_packets       / duration_sec if duration_sec > 0 else 0,
                "Pkt Len Var"    : flow.bidirectional_stddev_ps ** 2,
                "Fwd Seg Size Avg": flow.src2dst_bytes / flow.src2dst_packets if flow.src2dst_packets > 0 else 0,
                "Fwd IAT Tot"    : flow.src2dst_duration_ms,
            }

            # Align to exact training column order, fill any missing with 0
            X_live = pd.DataFrame([row]).reindex(columns=feature_cols, fill_value=0)

            # Replace inf
            X_live.replace([np.inf, -np.inf], 0, inplace=True)
            X_live.fillna(0, inplace=True)

            proba      = self.model.predict_proba(X_live)[0]
            pred_idx   = np.argmax(proba)
            label      = self.le.inverse_transform([pred_idx])[0]
            confidence = proba[pred_idx]

            flow.udps.prediction = label
            flow.udps.confidence = round(float(confidence), 4)

        except Exception as e:
            flow.udps.prediction = f"ERROR: {e}"
            flow.udps.confidence = 0.0


# ── Find your Windows interface ───────────────────────────────────────────────
# Run this block first to see available interfaces, then pick the right one
import psutil
print("Available interfaces:")
for name, stats in psutil.net_if_stats().items():
    if stats.isup:
        print(f"  {name}")

# ── Start live capture ────────────────────────────────────────────────────────
INTERFACE = "Ethernet"   # ← change to your interface name from above
                         # Common values: "Ethernet", "Wi-Fi", "vEthernet (WSL)"

print(f"\nStarting live ICMP detection on [{INTERFACE}]")
print("Send normal ping or flood from Kali → this machine\n")
print(f"{'Time':<10} {'Src IP':<18} {'Dst IP':<18} {'Pkts':>6} "
      f"{'Bytes':>8} {'Prediction':<12} {'Confidence':>10}")
print("-" * 85)

streamer = NFStreamer(
    source             = INTERFACE,
    statistical_analysis = True,
    splt_analysis      = 0,
    accounting_mode    = 3,
    idle_timeout       = 10,      # expire flows faster for demo (10s idle)
    active_timeout     = 60,
    udps=[
        BulkPlugin(),
        HeaderLenPlugin(),
        InitWindowPlugin(),
        ExtraFeaturesPlugin(),
        ActiveIdlePlugin(idle_threshold_ms=5000),
        ICMPFloodDetector(model=model, le=le),
    ]
)

for flow in streamer:
    if flow.protocol != 1:       # ICMP only
        continue
    ts = datetime.now().strftime("%H:%M:%S")
    color = "\033[91m" if flow.udps.prediction == "ICMP_FLOOD" else "\033[92m"
    reset = "\033[0m"
    print(f"{ts:<10} {flow.src_ip:<18} {flow.dst_ip:<18} "
          f"{flow.bidirectional_packets:>6} {flow.bidirectional_bytes:>8} "
          f"{color}{flow.udps.prediction:<12}{reset} {flow.udps.confidence:>10.4f}")