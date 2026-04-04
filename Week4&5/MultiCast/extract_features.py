from scapy.all import *
from scapy.contrib.igmp import IGMP
from scapy.layers.inet6 import _ICMPv6 as ICMPv6, ICMPv6MLReport2, ICMPv6MLQuery
load_layer("inet6")
import pandas as pd, math, os, glob

def get_group_entropy(group_addr):
    if not group_addr or group_addr == '0.0.0.0':
        return 0.0
    octets = [int(x) for x in group_addr.split('.')]
    total = sum(octets) or 1
    probs = [o/total for o in octets if o > 0]
    return -sum(p * math.log2(p) for p in probs)

def extract(pcap_file, label):
    print(f"Processing {pcap_file}...")
    packets = rdpcap(pcap_file)
    rows = []
    prev_time = None

    for i, pkt in enumerate(packets):
        row = {}

        # ── Timing features ──────────────────────────────
        cur_time = float(pkt.time)
        row['frame_time_relative'] = cur_time - float(packets[0].time)
        row['frame_time_delta']    = cur_time - prev_time if prev_time else 0.0
        prev_time = cur_time

        # ── Frame features ───────────────────────────────
        row['frame_len']      = len(pkt)
        row['frame_number']   = i + 1

        # ── IP features ──────────────────────────────────
        if IP in pkt:
            ip = pkt[IP]
            row['ip_proto']    = ip.proto
            row['ip_ttl']      = ip.ttl
            row['ip_hdr_len']  = ip.ihl * 4
            row['ip_len']      = ip.len
            row['ip_flags']    = int(ip.flags)
            row['ip_frag']     = ip.frag
            row['ip_src_oct4'] = int(ip.src.split('.')[-1])
            row['ip_dst_oct4'] = int(ip.dst.split('.')[-1])
            # Is destination multicast?
            row['dst_is_multicast'] = 1 if ip.dst.startswith('22') or ip.dst.startswith('23') else 0
            row['src_is_spoofed']   = 1 if ip.src.startswith('192.168.2') else 0
        else:
            row.update({'ip_proto':0,'ip_ttl':0,'ip_hdr_len':0,'ip_len':0,
                        'ip_flags':0,'ip_frag':0,'ip_src_oct4':0,'ip_dst_oct4':0,
                        'dst_is_multicast':0,'src_is_spoofed':0})

        # ── IPv6 features ────────────────────────────────
        if IPv6 in pkt:
            ip6 = pkt[IPv6]
            row['ipv6_hlim']    = ip6.hlim
            row['ipv6_plen']    = ip6.plen
            row['is_ipv6']      = 1
        else:
            row.update({'ipv6_hlim':0,'ipv6_plen':0,'is_ipv6':0})

        # ── IGMP features ────────────────────────────────
        if IGMP in pkt:
            igmp = pkt[IGMP]
            row['igmp_type']         = igmp.type
            row['igmp_mrtime']       = getattr(igmp, 'mrtime', 0)
            row['igmp_gaddr_oct3']   = int(str(igmp.gaddr).split('.')[2]) if igmp.gaddr else 0
            row['igmp_gaddr_oct4']   = int(str(igmp.gaddr).split('.')[3]) if igmp.gaddr else 0
            row['igmp_group_entropy']= get_group_entropy(str(igmp.gaddr))
            row['igmp_is_join']      = 1 if igmp.type == 0x16 else 0
            row['igmp_is_leave']     = 1 if igmp.type == 0x17 else 0
            row['igmp_is_query']     = 1 if igmp.type == 0x11 else 0
            row['is_igmp']           = 1
        else:
            row.update({'igmp_type':0,'igmp_mrtime':0,'igmp_gaddr_oct3':0,
                        'igmp_gaddr_oct4':0,'igmp_group_entropy':0.0,
                        'igmp_is_join':0,'igmp_is_leave':0,'igmp_is_query':0,'is_igmp':0})

        # ── ICMPv6 / MLD features ────────────────────────
        if ICMPv6MLReport2 in pkt or ICMPv6MLQuery in pkt:
            row['is_mld']      = 1
            row['icmpv6_type'] = pkt[ICMPv6MLReport2].type if ICMPv6MLReport2 in pkt else 130
        elif ICMPv6 in pkt:
            row['is_mld']      = 0
            row['icmpv6_type'] = pkt[ICMPv6].type
        else:
            row['is_mld']      = 0
            row['icmpv6_type'] = 0

        # ── PIM features ─────────────────────────────────
        if IP in pkt and pkt[IP].proto == 103:
            row['is_pim'] = 1
            payload = bytes(pkt[IP].payload)
            row['pim_type'] = (payload[0] & 0x0F) if payload else 0
        else:
            row['is_pim']  = 0
            row['pim_type']= 0

        # ── ICMP features ────────────────────────────────
        if ICMP in pkt:
            row['icmp_type'] = pkt[ICMP].type
            row['icmp_code'] = pkt[ICMP].code
            row['is_icmp']   = 1
        else:
            row['icmp_type'] = 0
            row['icmp_code'] = 0
            row['is_icmp']   = 0

        # ── Windowed rate features (last 10 packets) ─────
        window = rows[-10:] if len(rows) >= 10 else rows
        if window:
            times = [r['frame_time_relative'] for r in window]
            sizes = [r['frame_len'] for r in window]
            span  = (times[-1] - times[0]) or 0.001
            row['pkt_rate_10']  = len(window) / span
            row['avg_size_10']  = sum(sizes) / len(sizes)
            row['std_size_10']  = pd.Series(sizes).std() or 0.0
            igmp_recent = sum(1 for r in window if r['is_igmp'] == 1)
            row['igmp_ratio_10']= igmp_recent / len(window)
        else:
            row.update({'pkt_rate_10':0,'avg_size_10':0,
                        'std_size_10':0,'igmp_ratio_10':0})

        row['Label'] = label
        rows.append(row)

    return pd.DataFrame(rows)

# ── Process all PCAPs ─────────────────────────────────────
label_map = {
    'class0_benign':        0,
    'class1_igmp_flood':    1,
    'class2_igmp_spoof':    2,
    'class3_mld_flood':     3,
    'class4_pim_manip':     4,
    'class5_amplification': 5,
    'class6_group_scan':    6
}


# 1. Define the absolute base directory
base_dir = r'C:\Users\pmjpr\OneDrive\Desktop\HPE_project\pcaps'
all_dfs = []
for key, label in label_map.items():
    # 2. Join the base directory with the filename
    pcap = os.path.join(base_dir, f'{key}.pcap')
    if os.path.exists(pcap):
        df = extract(pcap, label)
        all_dfs.append(df)
        print(f"  {key}: {len(df)} rows, {len(df.columns)} features")
    else:
        print(f"  MISSING: {pcap}")


final = pd.concat(all_dfs, ignore_index=True)
final.fillna(0, inplace=True)
final.to_csv('multicast_dataset.csv', index=False)
print(f"\nDataset saved: {final.shape}")
print(final['Label'].value_counts().sort_index())
print(f"\nFeatures: {list(final.columns)}")




