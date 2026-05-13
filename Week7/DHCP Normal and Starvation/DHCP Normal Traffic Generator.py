from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import random
import time

conf.checkIPaddr = False

# -----------------------------
# CONFIG
# -----------------------------
iface = "wlp0s20f3"

# -----------------------------
# RANDOM MAC GENERATOR
# -----------------------------
def random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

# -----------------------------
# DHCP CLIENT
# -----------------------------
def dhcp_client():

    print("[*] DHCP Client Started")
    print("[*] Press CTRL+C to stop\n")

    try:
        while True:

            client_mac = random_mac()
            xid = random.randint(1, 0xFFFFFFFF)

            mac_bytes = bytes.fromhex(client_mac.replace(":", ""))

            delay = random.randint(10, 17)

            print(f"[+] New Client")
            print(f"    MAC   : {client_mac}")
            print(f"    XID   : {hex(xid)}")

            # -----------------------------------
            # DHCP DISCOVER
            # -----------------------------------
            discover = (
                Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac_bytes, xid=xid) /
                DHCP(options=[
                    ("message-type", "discover"),
                    ("hostname", f"client-{random.randint(1000,9999)}"),
                    ("param_req_list", [1,3,6,15,51,58,59]),
                    "end"
                ])
            )

            print("[*] Sending DHCP Discover...")
            sendp(discover, iface=iface, verbose=False)

            # -----------------------------------
            # WAIT FOR OFFER
            # -----------------------------------
            print("[*] Waiting for DHCP Offer...")

            offer = sniff(
                iface=iface,
                filter="udp and (port 67 or 68)",
                timeout=5,
                count=1,
                lfilter=lambda p:
                    p.haslayer(DHCP) and
                    p[BOOTP].xid == xid and
                    p[DHCP].options[0][1] == 2
            )

            if not offer:
                print("[!] No DHCP Offer received\n")
                time.sleep(delay)
                continue

            offer = offer[0]

            offered_ip = offer[BOOTP].yiaddr
            server_ip = offer[IP].src

            print(f"[+] OFFER Received")
            print(f"    Offered IP : {offered_ip}")
            print(f"    DHCP Server: {server_ip}")

            # -----------------------------------
            # DHCP REQUEST
            # -----------------------------------
            request = (
                Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac_bytes, xid=xid) /
                DHCP(options=[
                    ("message-type", "request"),
                    ("requested_addr", offered_ip),
                    ("server_id", server_ip),
                    ("hostname", f"client-{random.randint(1000,9999)}"),
                    "end"
                ])
            )

            print("[*] Sending DHCP Request...")
            sendp(request, iface=iface, verbose=False)

            # -----------------------------------
            # WAIT FOR ACK
            # -----------------------------------
            print("[*] Waiting for DHCP ACK...")

            ack = sniff(
                iface=iface,
                filter="udp and (port 67 or 68)",
                timeout=5,
                count=1,
                lfilter=lambda p:
                    p.haslayer(DHCP) and
                    p[BOOTP].xid == xid and
                    p[DHCP].options[0][1] == 5
            )

            if ack:
                print(f"[+] DHCP ACK Received -> IP Assigned: {offered_ip}\n")
            else:
                print("[!] No DHCP ACK received\n")

            print(f"[*] Waiting {delay} seconds before next client...\n")
            time.sleep(delay)

    except KeyboardInterrupt:
        print("\n[!] Stopped by user")


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    dhcp_client()
