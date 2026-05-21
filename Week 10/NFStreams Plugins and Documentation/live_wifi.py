import pandas as pd
from nfstream import NFStreamer

# --- CONFIGURATION ---
TARGET_INTERFACE = r"\Device\NPF_{93D028A2-DCBD-4B3C-BE5E-91BE06132F19}"

def main():
    print(f"🚀 Starting live capture on interface: {TARGET_INTERFACE}...")

    # Initialize the streamer with aggressive timeouts
    streamer = NFStreamer(
        source=TARGET_INTERFACE,
        statistical_analysis=True,
        promiscuous_mode=False,
        active_timeout=10, 
        idle_timeout=5      
    )

    MAX_FLOWS = 10
    captured_data = []

    for flow in streamer:
        protocol = flow.application_name
        print(f"Captured: {flow.src_ip}:{flow.src_port} --> {flow.dst_ip}:{flow.dst_port} [Protocol: {protocol}]")
        flow_dict = {
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'application_name': flow.application_name,
            'bidirectional_packets': flow.bidirectional_packets,
            'bidirectional_bytes': flow.bidirectional_bytes
        }
        
        captured_data.append(flow_dict)
        
        if len(captured_data) >= MAX_FLOWS:
            print(f"\n✅ Reached {MAX_FLOWS} flows. Stopping capture.")
            break

    df = pd.DataFrame(captured_data)

    if df.empty:
        print("\n⚠️ No traffic captured. Check your interface ID!")
        return

    print("\n--- Preview of your DataFrame ---")
    print(df.head())

    df.to_csv("live_wifi_traffic.csv", index=False)
    print("\n💾 Data successfully saved to live_wifi_traffic.csv!")

if __name__ == '__main__':
    from multiprocessing import freeze_support
    freeze_support()
    main()