from scapy.all import sniff, IP
from scapy.contrib.igmp import IGMP  # Required to parse IGMP fields
from scapy.contrib.igmpv3 import IGMPv3mr, IGMPv3gr  # Need the v3 specific modules

# --- STATE MEMORY ---
last_general_query_time = 0
leave_tracker = {}  # Tracks the last time a group was left. Format: {'239.1.1.1': timestamp}

def is_igmp_leave(packet):
    """
    Evaluates a packet to determine if it is an IGMP Leave, 
    supporting both IGMPv2 and IGMPv3.
    """
    # Check for IGMPv2 explicit Leave (Type 0x17)
    if packet.haslayer(IGMP) and packet[IGMP].type == 0x17:
        return True, packet[IGMP].gaddr
        
    # Check for IGMPv3 "Empty Source List" Leave (Inside a Type 0x22 Report)
    elif packet.haslayer(IGMPv3mr):
        # A v3 report can contain multiple group records, we must check them all
        for group_record in packet[IGMPv3mr].records:
            # Record Type 3 is "CHANGE_TO_INCLUDE_MODE"
            # If they change to include mode and provide 0 sources, it is a leave.
            if group_record.rtype == 3 and group_record.numsrc == 0:
                return True, group_record.maddr
                
    return False, None

def detect_igmp_state_attacks(packet):
    global last_general_query_time, leave_tracker

    # When reading a PCAP, we MUST use packet.time to get the historical timestamp
    current_time = float(packet.time) 

    # ---------------------------------------------------------
    # LOGIC 1: Tracking Host Leave Packets (v2 and v3)
    # ---------------------------------------------------------
    is_leave, leave_group_ip = is_igmp_leave(packet)
    
    if is_leave:
        leave_tracker[leave_group_ip] = current_time
        # Silently remember this. We expect a Group-Specific Query soon.
        return  # Exit early since we successfully processed the leave

    # ---------------------------------------------------------
    # LOGIC 2: Checking Queries (Type 0x11 / 17)
    # ---------------------------------------------------------
    # Both v2 and v3 use Type 0x11 for Queries.
    if packet.haslayer(IGMP) and packet[IGMP].type == 0x11:
        group_ip = packet[IGMP].gaddr
        
        # SCENARIO A: General Query (Target IP is always 0.0.0.0)
        if group_ip == "0.0.0.0":
            if last_general_query_time != 0:
                iat = current_time - last_general_query_time
                
                # If it's less than 120, it's considered an attack based on your threshold.
                if iat < 120:
                    print(f"[TIME: {current_time}] 🚨 ATTACK: IGMP General Query Flood! IAT was only {iat:.2f}s")
            
            # Update memory
            last_general_query_time = current_time

        # SCENARIO B: Group-Specific Query (Target IP is a multicast group)
        else:
            last_leave_time = leave_tracker.get(group_ip, 0)
            time_since_leave = current_time - last_leave_time

            # If no leave packet was ever seen, or it was seen more than 5 seconds ago
            if last_leave_time == 0 or time_since_leave > 5:
                print(f"[TIME: {current_time}] 🚨 ATTACK: Illegal Group-Specific Query for {group_ip}! No Leave packet seen in last 5s.")
            else:
                # Normal behavior. The query is legally verifying the Leave packet.
                pass

if __name__ == "__main__":
    # Change this to the exact name of the PCAP file you generated in GNS3
    pcap_filename = r"C:\Users\pmjpr\OneDrive\Desktop\gns3 pcaps\switch-multicast - Copy\class 6  (Group Scanning)\r2-sw1_final0.pcap"
    
    print(f"Starting offline analysis on: {pcap_filename}...")
    print("-" * 50)
    
    try:
        # store=0 ensures Scapy doesn't keep all packets in RAM, preventing memory crashes
        sniff(offline=pcap_filename, prn=detect_igmp_state_attacks, store=0)
        print("-" * 50)
        print("Analysis complete.")
    except FileNotFoundError:
        print(f"Error: Could not find the file '{pcap_filename}'. Please ensure it is in the same directory as this script.")
