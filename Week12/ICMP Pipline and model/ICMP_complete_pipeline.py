import numpy as np
import pandas as pd
import joblib
import math
from nfstream import NFPlugin, NFStreamer
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# PLUGINS  (unchanged from v1 — same feature extraction logic)
# ─────────────────────────────────────────────────────────────────────────────

class BulkPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.fwd_helper_count      = 0
        flow.udps.fwd_helper_bytes      = 0
        flow.udps.fwd_helper_start_ts   = 0
        flow.udps.fwd_last_payload_ts   = 0
        flow.udps.fwd_bulk_state_count  = 0
        flow.udps.fwd_bulk_packet_count = 0
        flow.udps.fwd_bulk_size_total   = 0
        flow.udps.fwd_bulk_duration_ms  = 0

        flow.udps.bwd_helper_count      = 0
        flow.udps.bwd_helper_bytes      = 0
        flow.udps.bwd_helper_start_ts   = 0
        flow.udps.bwd_last_payload_ts   = 0
        flow.udps.bwd_bulk_state_count  = 0
        flow.udps.bwd_bulk_packet_count = 0
        flow.udps.bwd_bulk_size_total   = 0
        flow.udps.bwd_bulk_duration_ms  = 0

        flow.udps.fwd_byts_b_avg   = 0.0
        flow.udps.fwd_pkts_b_avg   = 0.0
        flow.udps.fwd_blk_rate_avg = 0.0
        flow.udps.bwd_byts_b_avg   = 0.0
        flow.udps.bwd_pkts_b_avg   = 0.0
        flow.udps.bwd_blk_rate_avg = 0.0
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if packet.payload_size == 0:
            return

        if packet.direction == 0:
            if flow.udps.fwd_helper_count > 0:
                time_exceeded  = (packet.time - flow.udps.fwd_last_payload_ts) > 1000
                opp_interrupted = flow.udps.bwd_last_payload_ts > flow.udps.fwd_helper_start_ts
                if time_exceeded or opp_interrupted:
                    flow.udps.fwd_helper_count = 0
                    flow.udps.fwd_helper_bytes = 0
            if flow.udps.fwd_helper_count == 0:
                flow.udps.fwd_helper_start_ts = packet.time
            prev_ts = flow.udps.fwd_last_payload_ts
            flow.udps.fwd_helper_count += 1
            flow.udps.fwd_helper_bytes += packet.payload_size
            flow.udps.fwd_last_payload_ts = packet.time
            if flow.udps.fwd_helper_count == 4:
                flow.udps.fwd_bulk_state_count  += 1
                flow.udps.fwd_bulk_packet_count += 4
                flow.udps.fwd_bulk_size_total   += flow.udps.fwd_helper_bytes
                flow.udps.fwd_bulk_duration_ms  += (packet.time - flow.udps.fwd_helper_start_ts)
            elif flow.udps.fwd_helper_count > 4:
                flow.udps.fwd_bulk_packet_count += 1
                flow.udps.fwd_bulk_size_total   += packet.payload_size
                flow.udps.fwd_bulk_duration_ms  += (packet.time - prev_ts)
        else:
            if flow.udps.bwd_helper_count > 0:
                time_exceeded   = (packet.time - flow.udps.bwd_last_payload_ts) > 1000
                opp_interrupted = flow.udps.fwd_last_payload_ts > flow.udps.bwd_helper_start_ts
                if time_exceeded or opp_interrupted:
                    flow.udps.bwd_helper_count = 0
                    flow.udps.bwd_helper_bytes = 0
            if flow.udps.bwd_helper_count == 0:
                flow.udps.bwd_helper_start_ts = packet.time
            prev_ts = flow.udps.bwd_last_payload_ts
            flow.udps.bwd_helper_count += 1
            flow.udps.bwd_helper_bytes += packet.payload_size
            flow.udps.bwd_last_payload_ts = packet.time
            if flow.udps.bwd_helper_count == 4:
                flow.udps.bwd_bulk_state_count  += 1
                flow.udps.bwd_bulk_packet_count += 4
                flow.udps.bwd_bulk_size_total   += flow.udps.bwd_helper_bytes
                flow.udps.bwd_bulk_duration_ms  += (packet.time - flow.udps.bwd_helper_start_ts)
            elif flow.udps.bwd_helper_count > 4:
                flow.udps.bwd_bulk_packet_count += 1
                flow.udps.bwd_bulk_size_total   += packet.payload_size
                flow.udps.bwd_bulk_duration_ms  += (packet.time - prev_ts)

    def on_expire(self, flow):
        if flow.udps.fwd_bulk_state_count > 0:
            flow.udps.fwd_byts_b_avg = flow.udps.fwd_bulk_size_total / flow.udps.fwd_bulk_state_count
            flow.udps.fwd_pkts_b_avg = flow.udps.fwd_bulk_packet_count / flow.udps.fwd_bulk_state_count
        fwd_dur_sec = flow.udps.fwd_bulk_duration_ms / 1000.0
        if fwd_dur_sec > 0:
            flow.udps.fwd_blk_rate_avg = flow.udps.fwd_bulk_size_total / fwd_dur_sec
        if flow.udps.bwd_bulk_state_count > 0:
            flow.udps.bwd_byts_b_avg = flow.udps.bwd_bulk_size_total / flow.udps.bwd_bulk_state_count
            flow.udps.bwd_pkts_b_avg = flow.udps.bwd_bulk_packet_count / flow.udps.bwd_bulk_state_count
        bwd_dur_sec = flow.udps.bwd_bulk_duration_ms / 1000.0
        if bwd_dur_sec > 0:
            flow.udps.bwd_blk_rate_avg = flow.udps.bwd_bulk_size_total / bwd_dur_sec


class HeaderLenPlugin(NFPlugin):
    def on_init(self, packet, flow):
        if packet.ip_version not in [4, 6]:
            flow.udps.fwd_header_len = 0
            flow.udps.bwd_header_len = 0
            return
        header_bytes = packet.ip_size - packet.payload_size
        if packet.direction == 0:
            flow.udps.fwd_header_len = header_bytes
            flow.udps.bwd_header_len = 0
        else:
            flow.udps.fwd_header_len = 0
            flow.udps.bwd_header_len = header_bytes

    def on_update(self, packet, flow):
        if packet.ip_version not in [4, 6]:
            return
        header_bytes = packet.ip_size - packet.payload_size
        if packet.direction == 0:
            flow.udps.fwd_header_len += header_bytes
        else:
            flow.udps.bwd_header_len += header_bytes


class InitWindowPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.init_fwd_win = -1
        flow.udps.init_bwd_win = -1
        if packet.protocol == 6:
            is_syn     = packet.syn and not packet.ack
            is_syn_ack = packet.syn and packet.ack
            if is_syn:
                flow.udps.init_fwd_win = self._extract_tcp_window(packet)
            elif is_syn_ack:
                flow.udps.init_bwd_win = self._extract_tcp_window(packet)

    def on_update(self, packet, flow):
        if packet.protocol != 6:
            return
        is_syn     = packet.syn and not packet.ack
        is_syn_ack = packet.syn and packet.ack
        if is_syn and flow.udps.init_fwd_win == -1:
            flow.udps.init_fwd_win = self._extract_tcp_window(packet)
        elif is_syn_ack and flow.udps.init_bwd_win == -1:
            flow.udps.init_bwd_win = self._extract_tcp_window(packet)

    def _extract_tcp_window(self, packet):
        try:
            raw_bytes = packet.ip_packet
            ip_hl = (raw_bytes[0] & 0x0F) * 4 if packet.ip_version == 4 else 40
            return (raw_bytes[ip_hl + 14] << 8) | raw_bytes[ip_hl + 15]
        except IndexError:
            return -1


class ExtraFeaturesPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.fwd_act_data_pkts = 0
        flow.udps.fwd_seg_size_min  = -1
        self._update_features(packet, flow)

    def on_update(self, packet, flow):
        self._update_features(packet, flow)

    def _update_features(self, packet, flow):
        if packet.ip_version not in [4, 6]:
            return
        if packet.direction == 0:
            if packet.payload_size > 0:
                flow.udps.fwd_act_data_pkts += 1
            header_length = packet.ip_size - packet.payload_size
            if flow.udps.fwd_seg_size_min == -1 or header_length < flow.udps.fwd_seg_size_min:
                flow.udps.fwd_seg_size_min = header_length


class ActiveIdlePlugin(NFPlugin):
    def __init__(self, idle_threshold_ms=5000, **kwargs):
        super().__init__(**kwargs)
        self.idle_threshold_ms = idle_threshold_ms

    def on_init(self, packet, flow):
        flow.udps._start_active_time = packet.time
        flow.udps._end_active_time   = packet.time
        flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2 = 0, 0.0, 0.0
        flow.udps._act_max, flow.udps._act_min = 0.0, -1.0
        flow.udps._idle_n, flow.udps._idle_mean, flow.udps._idle_M2 = 0, 0.0, 0.0
        flow.udps._idle_max, flow.udps._idle_min = 0.0, -1.0
        flow.udps.active_mean = flow.udps.active_std = flow.udps.active_max = flow.udps.active_min = 0.0
        flow.udps.idle_mean   = flow.udps.idle_std  = flow.udps.idle_max   = flow.udps.idle_min   = 0.0

    @staticmethod
    def _welford(n, mean, M2, new_val):
        n    += 1
        delta = new_val - mean
        mean += delta / n
        M2   += delta * (new_val - mean)
        return n, mean, M2

    def on_update(self, packet, flow):
        current_time = packet.time
        gap = current_time - flow.udps._end_active_time
        if gap > self.idle_threshold_ms:
            active_dur = flow.udps._end_active_time - flow.udps._start_active_time
            if active_dur > 0:
                n, m, M2 = self._welford(flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2, active_dur)
                flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2 = n, m, M2
                if active_dur > flow.udps._act_max: flow.udps._act_max = active_dur
                if flow.udps._act_min == -1.0 or active_dur < flow.udps._act_min: flow.udps._act_min = active_dur
            n, m, M2 = self._welford(flow.udps._idle_n, flow.udps._idle_mean, flow.udps._idle_M2, gap)
            flow.udps._idle_n, flow.udps._idle_mean, flow.udps._idle_M2 = n, m, M2
            if gap > flow.udps._idle_max: flow.udps._idle_max = gap
            if flow.udps._idle_min == -1.0 or gap < flow.udps._idle_min: flow.udps._idle_min = gap
            flow.udps._start_active_time = current_time
            flow.udps._end_active_time   = current_time
        else:
            flow.udps._end_active_time = current_time

    def on_expire(self, flow):
        active_dur = flow.udps._end_active_time - flow.udps._start_active_time
        if active_dur > 0:
            n, m, M2 = self._welford(flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2, active_dur)
            flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2 = n, m, M2
            if active_dur > flow.udps._act_max: flow.udps._act_max = active_dur
            if flow.udps._act_min == -1.0 or active_dur < flow.udps._act_min: flow.udps._act_min = active_dur

        n = flow.udps._act_n
        flow.udps.active_mean = flow.udps._act_mean if n > 0 else 0.0
        flow.udps.active_std  = math.sqrt(flow.udps._act_M2 / (n - 1)) if n > 1 else 0.0
        flow.udps.active_max  = flow.udps._act_max if n > 0 else 0.0
        flow.udps.active_min  = flow.udps._act_min if flow.udps._act_min != -1.0 else 0.0

        n = flow.udps._idle_n
        flow.udps.idle_mean = flow.udps._idle_mean if n > 0 else 0.0
        flow.udps.idle_std  = math.sqrt(flow.udps._idle_M2 / (n - 1)) if n > 1 else 0.0
        flow.udps.idle_max  = flow.udps._idle_max if n > 0 else 0.0
        flow.udps.idle_min  = flow.udps._idle_min if flow.udps._idle_min != -1.0 else 0.0


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':

    # 1. Load updated ML assets (v2)
    model        = joblib.load("/home/phani-madhav/detection/xgboost_model3.pkl")
    le           = joblib.load("/home/phani-madhav/detection/label_encoder3.pkl")
    feature_cols = joblib.load("/home/phani-madhav/detection/feature_columns3.pkl")

    print(f"Model loaded. Expecting {len(feature_cols)} features.")
    print(f"Classes: {list(le.classes_)}\n")

    INTERFACE = "enp0s8"

    print(f"Starting live ICMP detection on [{INTERFACE}]")
    print("Send normal ping or flood from Kali → this machine\n")
    print(f"{'Time':<10} {'Src IP':<18} {'Dst IP':<18} {'Pkts':>6} "
          f"{'Bytes':>8} {'Prediction':<12} {'Confidence':>10}")
    print("-" * 85)

    streamer = NFStreamer(
        source               = INTERFACE,
        statistical_analysis = True,
        splt_analysis        = 0,
        accounting_mode      = 3,
        idle_timeout         = 2,
        active_timeout       = 5,
        udps=[
            BulkPlugin(),
            HeaderLenPlugin(),
            InitWindowPlugin(),
            ExtraFeaturesPlugin(),
            ActiveIdlePlugin(idle_threshold_ms=5000),
        ]
    )

    print("Pipeline ready. Waiting for network traffic...")

    for flow in streamer:

        if flow.protocol != 1:
            print("--skipped non icmp packet--")
            continue

        ts = datetime.now().strftime("%H:%M:%S")

        print("\n--- udps debug ---")
        udps_fields = [
            'fwd_byts_b_avg', 'fwd_pkts_b_avg', 'fwd_blk_rate_avg',
            'fwd_header_len', 'fwd_act_data_pkts',
            'active_mean', 'active_max', 'active_min',
            'idle_mean', 'idle_std', 'idle_max', 'idle_min',
        ]
        
        for field in udps_fields:
            val = getattr(flow.udps, field, "MISSING")
            status = "⚠ MISSING" if val == "MISSING" else ("✓" if val != 0 else "zero")
            print(f"  {field:<25} = {val}  {status}")
        print("------------------\n")
                
        # ── Heuristic gate ────────────────────────────────────────────────────
        # A real flood produces many fragments quickly from the same source.
        if flow.bidirectional_packets < 5 and flow.bidirectional_duration_ms < 10:
            prediction = "BENIGN"
            confidence = 1.999#Kept for testing if gate is working
            color, reset = "\033[92m", "\033[0m"
            print(f"{ts:<10} {flow.src_ip:<18} {flow.dst_ip:<18} "
                  f"{flow.bidirectional_packets:>6} {flow.bidirectional_bytes:>8} "
                  f"{color}{prediction:<12}{reset} {confidence:>10.4f}  [gate]")
            continue
        # ─────────────────────────────────────────────────────────────────────

        try:
            duration_sec = max(flow.bidirectional_duration_ms / 1000.0, 0.5) 

            row = {
                "bidirectional_duration_ms"    : flow.bidirectional_duration_ms,
                "bidirectional_packets"        : flow.bidirectional_packets,
                "bidirectional_bytes"          : flow.bidirectional_bytes,
                "src2dst_duration_ms"          : flow.src2dst_duration_ms,
                "src2dst_packets"              : flow.src2dst_packets,
                "src2dst_bytes"                : flow.src2dst_bytes,
                "bidirectional_min_ps"         : flow.bidirectional_min_ps,
                "bidirectional_mean_ps"        : flow.bidirectional_mean_ps,
                "bidirectional_stddev_ps"      : flow.bidirectional_stddev_ps,
                "bidirectional_max_ps"         : flow.bidirectional_max_ps,
                "src2dst_min_ps"               : flow.src2dst_min_ps,
                "src2dst_mean_ps"              : flow.src2dst_mean_ps,
                "src2dst_stddev_ps"            : flow.src2dst_stddev_ps,
                "src2dst_max_ps"               : flow.src2dst_max_ps,
                "bidirectional_min_piat_ms"    : flow.bidirectional_min_piat_ms,
                "bidirectional_mean_piat_ms"   : flow.bidirectional_mean_piat_ms,
                "bidirectional_stddev_piat_ms" : flow.bidirectional_stddev_piat_ms,
                "bidirectional_max_piat_ms"    : flow.bidirectional_max_piat_ms,
                "src2dst_min_piat_ms"          : flow.src2dst_min_piat_ms,
                "src2dst_mean_piat_ms"         : flow.src2dst_mean_piat_ms,
                "src2dst_stddev_piat_ms"       : flow.src2dst_stddev_piat_ms,
                "src2dst_max_piat_ms"          : flow.src2dst_max_piat_ms,
                "dst2src_packets"              : flow.dst2src_packets,
                "dst2src_bytes"                : flow.dst2src_bytes,
                "dst2src_duration_ms"          : flow.dst2src_duration_ms,
                "dst2src_mean_ps"              : flow.dst2src_mean_ps,

                "udps.fwd_byts_b_avg"   : getattr(flow.udps, 'fwd_byts_b_avg',    0.0),
                "udps.fwd_pkts_b_avg"   : getattr(flow.udps, 'fwd_pkts_b_avg',    0.0),
                "udps.fwd_blk_rate_avg" : getattr(flow.udps, 'fwd_blk_rate_avg',  0.0),
                "udps.fwd_header_len"   : getattr(flow.udps, 'fwd_header_len',    0.0),
                "udps.fwd_act_data_pkts": getattr(flow.udps, 'fwd_act_data_pkts', 0),
                "udps.active_mean"      : getattr(flow.udps, 'active_mean',       0.0),
                "udps.active_max"       : getattr(flow.udps, 'active_max',        0.0),
                "udps.active_min"       : getattr(flow.udps, 'active_min',        0.0),
                "udps.idle_mean"        : getattr(flow.udps, 'idle_mean',         0.0),
                "udps.idle_std"         : getattr(flow.udps, 'idle_std',          0.0),
                "udps.idle_max"         : getattr(flow.udps, 'idle_max',          0.0),
                "udps.idle_min"         : getattr(flow.udps, 'idle_min',          0.0),

                "Flow Byts/s"     : flow.bidirectional_bytes   / duration_sec,
                "Flow Pkts/s"     : flow.bidirectional_packets / duration_sec,
                "Fwd Pkts/s"      : flow.src2dst_packets       / duration_sec,
                "Pkt Len Var"     : flow.bidirectional_stddev_ps ** 2,
                "Fwd Seg Size Avg": flow.src2dst_bytes / flow.src2dst_packets if flow.src2dst_packets > 0 else 0,
                "Fwd IAT Tot"     : flow.src2dst_duration_ms,
                "Bwd Pkts/s"      : flow.dst2src_packets / duration_sec,
                "Bwd Seg Size Avg": flow.dst2src_bytes / flow.dst2src_packets if flow.dst2src_packets > 0 else 0,
                "Down/Up Ratio"   : flow.dst2src_packets // flow.src2dst_packets if flow.src2dst_packets > 0 else 0,
                "Bwd IAT Tot"     : flow.dst2src_duration_ms,
                
            }

            X_live = pd.DataFrame([row]).reindex(columns=feature_cols, fill_value=0)
            X_live.replace([np.inf, -np.inf], 0, inplace=True)
            X_live.fillna(0, inplace=True)

            proba      = model.predict_proba(X_live)[0]
            pred_idx   = np.argmax(proba)
            prediction = le.inverse_transform([pred_idx])[0]
            confidence = proba[pred_idx]

        except Exception as e:
            prediction = f"ERR: {e}"
            confidence = 0.0

        if prediction == "ICMP_FLOOD":
            color = "\033[91m"    # red
        elif prediction == "ICMP_Tunnel":
            color = "\033[93m"    # yellow
        else:
            color = "\033[92m"    # green      
             
        reset = "\033[0m"
        
        print(f"{ts:<10} {flow.src_ip:<18} {flow.dst_ip:<18} "
              f"{flow.bidirectional_packets:>6} {flow.bidirectional_bytes:>8} "
              f"{color}{prediction:<12}{reset} {confidence:>10.4f}")
