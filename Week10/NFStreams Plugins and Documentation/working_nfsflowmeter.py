import math
import numpy as np
import pandas as pd
from nfstream import NFPlugin, NFStreamer
import time

class BulkPlugin(NFPlugin):
    def on_init(self, packet, flow):
        # --- FORWARD STATE ---
        flow.udps.fwd_helper_count = 0
        flow.udps.fwd_helper_bytes = 0
        flow.udps.fwd_helper_start_ts = 0
        flow.udps.fwd_last_payload_ts = 0
        
        # Valid Bulk Totals
        flow.udps.fwd_bulk_state_count = 0
        flow.udps.fwd_bulk_packet_count = 0
        flow.udps.fwd_bulk_size_total = 0
        flow.udps.fwd_bulk_duration_ms = 0
        
        # --- BACKWARD STATE ---
        flow.udps.bwd_helper_count = 0
        flow.udps.bwd_helper_bytes = 0
        flow.udps.bwd_helper_start_ts = 0
        flow.udps.bwd_last_payload_ts = 0
        
        # Valid Bulk Totals
        flow.udps.bwd_bulk_state_count = 0
        flow.udps.bwd_bulk_packet_count = 0
        flow.udps.bwd_bulk_size_total = 0
        flow.udps.bwd_bulk_duration_ms = 0
        
        # --- FINAL OUTPUT FEATURES ---
        flow.udps.fwd_byts_b_avg = 0.0
        flow.udps.fwd_pkts_b_avg = 0.0
        flow.udps.fwd_blk_rate_avg = 0.0
        flow.udps.bwd_byts_b_avg = 0.0
        flow.udps.bwd_pkts_b_avg = 0.0
        flow.udps.bwd_blk_rate_avg = 0.0
        self.on_update(packet, flow)
        
    def on_update(self, packet, flow):
        # RULE 1: If there is no payload, ignore it completely. 
        # It does not break the sequence.
        if packet.payload_size == 0:
            return 

        if packet.direction == 0:  # FORWARD PACKET
            # RULE 2 & 3: Check interruptions (Time > 1s OR Opposite direction sent payload)
            if flow.udps.fwd_helper_count > 0:
                time_exceeded = (packet.time - flow.udps.fwd_last_payload_ts) > 1000
                opp_interrupted = flow.udps.bwd_last_payload_ts > flow.udps.fwd_helper_start_ts
                
                if time_exceeded or opp_interrupted:
                    # Reset the helper waiting room
                    flow.udps.fwd_helper_count = 0
                    flow.udps.fwd_helper_bytes = 0
            
            # Start a new potential bulk if waiting room is empty
            if flow.udps.fwd_helper_count == 0:
                flow.udps.fwd_helper_start_ts = packet.time
            
            # Add to helper variables
            prev_ts = flow.udps.fwd_last_payload_ts
            flow.udps.fwd_helper_count += 1
            flow.udps.fwd_helper_bytes += packet.payload_size
            flow.udps.fwd_last_payload_ts = packet.time
            
            # RULE 4: The 4-Packet Threshold
            if flow.udps.fwd_helper_count == 4:
                # We officially have a bulk! Commit the helper totals.
                flow.udps.fwd_bulk_state_count += 1
                flow.udps.fwd_bulk_packet_count += 4
                flow.udps.fwd_bulk_size_total += flow.udps.fwd_helper_bytes
                flow.udps.fwd_bulk_duration_ms += (packet.time - flow.udps.fwd_helper_start_ts)
                
            elif flow.udps.fwd_helper_count > 4:
                # Continuing an existing bulk. Just append current packet's stats.
                flow.udps.fwd_bulk_packet_count += 1
                flow.udps.fwd_bulk_size_total += packet.payload_size
                flow.udps.fwd_bulk_duration_ms += (packet.time - prev_ts)

        else:  # BACKWARD PACKET (Mirrored Logic)
            if flow.udps.bwd_helper_count > 0:
                time_exceeded = (packet.time - flow.udps.bwd_last_payload_ts) > 1000
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
                flow.udps.bwd_bulk_state_count += 1
                flow.udps.bwd_bulk_packet_count += 4
                flow.udps.bwd_bulk_size_total += flow.udps.bwd_helper_bytes
                flow.udps.bwd_bulk_duration_ms += (packet.time - flow.udps.bwd_helper_start_ts)
                
            elif flow.udps.bwd_helper_count > 4:
                flow.udps.bwd_bulk_packet_count += 1
                flow.udps.bwd_bulk_size_total += packet.payload_size
                flow.udps.bwd_bulk_duration_ms += (packet.time - prev_ts)

    def on_expire(self, flow):
        # Calculate Final Forward Averages
        if flow.udps.fwd_bulk_state_count > 0:
            flow.udps.fwd_byts_b_avg = flow.udps.fwd_bulk_size_total / flow.udps.fwd_bulk_state_count
            flow.udps.fwd_pkts_b_avg = flow.udps.fwd_bulk_packet_count / flow.udps.fwd_bulk_state_count
        
        fwd_dur_sec = flow.udps.fwd_bulk_duration_ms / 1000.0
        if fwd_dur_sec > 0:
            flow.udps.fwd_blk_rate_avg = flow.udps.fwd_bulk_size_total / fwd_dur_sec

        # Calculate Final Backward Averages
        if flow.udps.bwd_bulk_state_count > 0:
            flow.udps.bwd_byts_b_avg = flow.udps.bwd_bulk_size_total / flow.udps.bwd_bulk_state_count
            flow.udps.bwd_pkts_b_avg = flow.udps.bwd_bulk_packet_count / flow.udps.bwd_bulk_state_count
        
        bwd_dur_sec = flow.udps.bwd_bulk_duration_ms / 1000.0
        if bwd_dur_sec > 0:
            flow.udps.bwd_blk_rate_avg = flow.udps.bwd_bulk_size_total / bwd_dur_sec

class HeaderLenPlugin(NFPlugin):
    def on_init(self, packet, flow):
        # Calculate the header for the very first packet
        header_bytes = packet.ip_size - packet.payload_size
        
        if packet.direction == 0:
            flow.udps.fwd_header_len = header_bytes
            flow.udps.bwd_header_len = 0
        else:
            flow.udps.fwd_header_len = 0
            flow.udps.bwd_header_len = header_bytes

    def on_update(self, packet, flow):
        # Calculate for packet #2 and onwards
        header_bytes = packet.ip_size - packet.payload_size
        
        if packet.direction == 0:
            flow.udps.fwd_header_len += header_bytes
        else:
            flow.udps.bwd_header_len += header_bytes

class InitWindowPlugin(NFPlugin):
    def on_init(self, packet, flow):
        # Initialize default values
        flow.udps.init_fwd_win = -1
        flow.udps.init_bwd_win = -1
        
        # Check the VERY FIRST packet (Usually the client SYN)
        if packet.protocol == 6:
            is_syn = packet.syn and not packet.ack
            is_syn_ack = packet.syn and packet.ack
            
            if is_syn:
                flow.udps.init_fwd_win = self._extract_tcp_window(packet)
            elif is_syn_ack: # Just in case capture started mid-handshake
                flow.udps.init_bwd_win = self._extract_tcp_window(packet)

    def on_update(self, packet, flow):
        # Check packet #2 and onwards
        if packet.protocol != 6:
            return

        is_syn = packet.syn and not packet.ack
        is_syn_ack = packet.syn and packet.ack

        if is_syn and flow.udps.init_fwd_win == -1:
            flow.udps.init_fwd_win = self._extract_tcp_window(packet)
            
        elif is_syn_ack and flow.udps.init_bwd_win == -1:
            flow.udps.init_bwd_win = self._extract_tcp_window(packet)

    def _extract_tcp_window(self, packet):
        """Helper function to parse the raw byte array for the TCP window size."""
        try:
            raw_bytes = packet.ip_packet
            
            # Determine IP header length to know where TCP header starts
            if packet.ip_version == 4:
                ip_hl = (raw_bytes[0] & 0x0F) * 4
            elif packet.ip_version == 6:
                ip_hl = 40
            else:
                return -1

            # The TCP window size is 2 bytes, located at offset 14 of the TCP header
            window_size = (raw_bytes[ip_hl + 14] << 8) | raw_bytes[ip_hl + 15]
            return window_size
            
        except IndexError:
            return -1


class ExtraFeaturesPlugin(NFPlugin):
    """
    Captures Fwd Act Data Pkts (count of forward packets with payload)
    and Fwd Seg Size Min (minimum header length in the forward direction).
    """
    def on_init(self, packet, flow):
        flow.udps.fwd_act_data_pkts = 0
        flow.udps.fwd_seg_size_min = -1 
        
        self._update_features(packet, flow)

    def on_update(self, packet, flow):
        self._update_features(packet, flow)

    def _update_features(self, packet, flow):
        # We only care about the Forward direction (0)
        if packet.direction == 0:
            
            # 1. Forward Active Data Packets
            if packet.payload_size > 0:
                flow.udps.fwd_act_data_pkts += 1
                
            # 2. Forward Minimum Segment Size (Header Length)
            header_length = packet.ip_size - packet.payload_size
            
            if flow.udps.fwd_seg_size_min == -1 or header_length < flow.udps.fwd_seg_size_min:
                flow.udps.fwd_seg_size_min = header_length

class ActiveIdlePlugin(NFPlugin):
    def __init__(self, idle_threshold_ms=5000, **kwargs):
        """
        Allows passing the threshold dynamically when creating the plugin.
        Default is 5000ms (5 seconds) matching CICFlowMeter.
        """
        super().__init__(**kwargs)
        self.idle_threshold_ms = idle_threshold_ms

    def on_init(self, packet, flow):
        flow.udps._start_active_time = packet.time
        flow.udps._end_active_time = packet.time
        
        # Active period running stats 
        flow.udps._act_n = 0
        flow.udps._act_mean = 0.0
        flow.udps._act_M2 = 0.0
        flow.udps._act_max = 0.0
        flow.udps._act_min = -1.0 
        
        # Idle period running stats 
        flow.udps._idle_n = 0
        flow.udps._idle_mean = 0.0
        flow.udps._idle_M2 = 0.0
        flow.udps._idle_max = 0.0
        flow.udps._idle_min = -1.0
        
        # Final output fields
        flow.udps.active_mean = 0.0
        flow.udps.active_std = 0.0
        flow.udps.active_max = 0.0
        flow.udps.active_min = 0.0
        flow.udps.idle_mean = 0.0
        flow.udps.idle_std = 0.0
        flow.udps.idle_max = 0.0
        flow.udps.idle_min = 0.0

    @staticmethod
    def _welford(n, mean, M2, new_val):
        """Returns updated (n, mean, M2) using Welford's online algorithm."""
        n += 1
        delta = new_val - mean
        mean += delta / n
        M2 += delta * (new_val - mean)
        return n, mean, M2

    def on_update(self, packet, flow):
        current_time = packet.time
        gap = current_time - flow.udps._end_active_time
        
        if gap > self.idle_threshold_ms:
            # --- 1. An Idle state has occurred ---
            
            # Record Active Time
            active_dur = flow.udps._end_active_time - flow.udps._start_active_time
            if active_dur > 0:
                n, m, M2 = self._welford(flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2, active_dur)
                flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2 = n, m, M2
                
                if active_dur > flow.udps._act_max:
                    flow.udps._act_max = active_dur
                if flow.udps._act_min == -1.0 or active_dur < flow.udps._act_min:
                    flow.udps._act_min = active_dur
            
            # Record Idle Time (the gap)
            n, m, M2 = self._welford(flow.udps._idle_n, flow.udps._idle_mean, flow.udps._idle_M2, gap)
            flow.udps._idle_n, flow.udps._idle_mean, flow.udps._idle_M2 = n, m, M2
            
            if gap > flow.udps._idle_max:
                flow.udps._idle_max = gap
            if flow.udps._idle_min == -1.0 or gap < flow.udps._idle_min:
                flow.udps._idle_min = gap
            
            # Reset for a brand-new Active phase
            flow.udps._start_active_time = current_time
            flow.udps._end_active_time = current_time
            
        else:
            # --- 2. Still in continuous communication ---
            flow.udps._end_active_time = current_time

    def on_expire(self, flow):
        # --- 3. Wrapping up the Flow ---
        # Add the final active phase that was cut off by flow termination
        active_dur = flow.udps._end_active_time - flow.udps._start_active_time
        if active_dur > 0:
            n, m, M2 = self._welford(flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2, active_dur)
            flow.udps._act_n, flow.udps._act_mean, flow.udps._act_M2 = n, m, M2
            if active_dur > flow.udps._act_max:
                flow.udps._act_max = active_dur
            if flow.udps._act_min == -1.0 or active_dur < flow.udps._act_min:
                flow.udps._act_min = active_dur

        # --- 4. Generating Final Metrics ---
        # Calculate Final Active Averages
        n = flow.udps._act_n
        flow.udps.active_mean = flow.udps._act_mean if n > 0 else 0.0
        flow.udps.active_std = math.sqrt(flow.udps._act_M2 / (n - 1)) if n > 1 else 0.0
        flow.udps.active_max = flow.udps._act_max if n > 0 else 0.0
        flow.udps.active_min = flow.udps._act_min if flow.udps._act_min != -1.0 else 0.0

        # Calculate Final Idle Averages
        n = flow.udps._idle_n
        flow.udps.idle_mean = flow.udps._idle_mean if n > 0 else 0.0
        flow.udps.idle_std = math.sqrt(flow.udps._idle_M2 / (n - 1)) if n > 1 else 0.0
        flow.udps.idle_max = flow.udps._idle_max if n > 0 else 0.0
        flow.udps.idle_min = flow.udps._idle_min if flow.udps._idle_min != -1.0 else 0.0

def post_process_cicflowmeter(csv_path, output_path):
    print(f"Loading {csv_path} for post-processing...")
    df = pd.read_csv(csv_path)

    # Flow Duration in Seconds
    duration_sec = df['bidirectional_duration_ms'] / 1000.0

    new_features = {
        'Flow Byts/s': np.where(duration_sec > 0, df['bidirectional_bytes'] / duration_sec, 0),
        'Flow Pkts/s': np.where(duration_sec > 0, df['bidirectional_packets'] / duration_sec, 0),
        'Fwd Pkts/s': np.where(duration_sec > 0, df['src2dst_packets'] / duration_sec, 0),
        'Bwd Pkts/s': np.where(duration_sec > 0, df['dst2src_packets'] / duration_sec, 0),
        'Down/Up Ratio': np.where(df['src2dst_packets'] > 0, df['dst2src_packets'] // df['src2dst_packets'], 0),
        'Pkt Len Var': df['bidirectional_stddev_ps'] ** 2,
        'Fwd Seg Size Avg': np.where(df['src2dst_packets'] > 0, df['src2dst_bytes'] / df['src2dst_packets'], 0),
        'Bwd Seg Size Avg': np.where(df['dst2src_packets'] > 0, df['dst2src_bytes'] / df['dst2src_packets'], 0),
        'Fwd IAT Tot': df['src2dst_duration_ms'],
        'Bwd IAT Tot': df['dst2src_duration_ms']
    }

    df = pd.concat([df, pd.DataFrame(new_features, index=df.index)], axis=1)
    
    # NOTE: Next iteration rename all columns names to CICFlowmeter exact
    df.rename(columns={
        'bidirectional_fin_packets': 'FIN Flag Cnt',
        'bidirectional_syn_packets': 'SYN Flag Cnt',
        'bidirectional_rst_packets': 'RST Flag Cnt',
        'bidirectional_psh_packets': 'PSH Flag Cnt',
        'bidirectional_ack_packets': 'ACK Flag Cnt',
        'bidirectional_urg_packets': 'URG Flag Cnt',
        'bidirectional_cwr_packets': 'CWE Flag Count',
        'bidirectional_ece_packets': 'ECE Flag Cnt'
    }, inplace=True)

    #CLEANUP: Drop Internal State Columns
    cols_to_drop = [col for col in df.columns if any(keyword in col for keyword in [
        '_act_n', '_act_mean', '_act_M2', '_act_max', '_act_min',
        '_idle_n', '_idle_mean', '_idle_M2', '_idle_max', '_idle_min',
        '_active_time', 'helper', 'last_payload_ts', 
        'bulk_state_count', 'bulk_packet_count', 'bulk_size_total', 'bulk_duration_ms',
        'in_bulk'
    ])]
    
    df.drop(columns=cols_to_drop, inplace=True, errors='ignore')

    df.to_csv(output_path, index=False)
    print(f"Post-processing complete. Dropped {len(cols_to_drop)} internal columns.")
    print(f"Saved fully featured ML-ready dataset to {output_path}")
    return df

        
if __name__ == '__main__':
    print("Starting NFStream processing...")
    t0 = time.time()

    streamer = NFStreamer(
        source="test.pcap",  
        statistical_analysis=True,
        splt_analysis=0,
        accounting_mode=3,           
        udps=[BulkPlugin(),HeaderLenPlugin(),InitWindowPlugin(),ExtraFeaturesPlugin(),ActiveIdlePlugin(idle_threshold_ms=5000)]   
    )

    output_filename = "testfile8.csv"
    total_flows = streamer.to_csv(path=output_filename) 

    print(f"Streamer done in {(time.time()-t0)/60:.1f} min — {total_flows:,} flows captured")
    
    final_filename = "final_testfile.csv"
    final_df = post_process_cicflowmeter(output_filename, final_filename)