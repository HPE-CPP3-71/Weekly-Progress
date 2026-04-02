import pandas as pd
import numpy as np
import random

OUTPUT_FILE = "dhcp_flowmon_dataset.csv"
NUM_RECORDS = 50000

packet_counter = 1

def get_packet_no():
    global packet_counter
    val = packet_counter
    packet_counter += 1
    return val


def random_mac():
    return ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])

def random_ip():
    return f"192.168.1.{random.randint(2, 254)}"


# ==============================
# NORMAL DHCP FLOW
# ==============================
def normal_flow():
    mac = random_mac()
    ip = random_ip()
    xid = random.randint(1, 100000)

    return [
        ("DISCOVER", mac, "0.0.0.0"),
        ("OFFER", "server", ip),
        ("REQUEST", mac, "0.0.0.0"),
        ("ACK", "server", ip)
    ], xid, "NONE", "BENIGN"


# ==============================
# DHCP STARVATION
# ==============================
def starvation():
    packets = []
    xid = random.randint(1, 100000)

    for _ in range(10):  # burst traffic
        packets.append(("DISCOVER", random_mac(), "0.0.0.0"))

    return packets, xid, "DHCP_STARVATION", "ATTACK"


# ==============================
# ROGUE DHCP
# ==============================
def rogue():
    mac = random_mac()
    xid = random.randint(1, 100000)

    return [
        ("DISCOVER", mac, "0.0.0.0"),
        ("OFFER", "rogue_server", "10.0.0.5"),
        ("OFFER", "server", random_ip())  # conflicting offers
    ], xid, "ROGUE_DHCP", "ATTACK"


# ==============================
# DHCP SPOOFING
# ==============================
def spoofing():
    mac = random_mac()
    xid = random.randint(1, 100000)

    return [
        ("OFFER", "attacker", "111.111.111.1"),
        ("ACK", "attacker", "111.111.111.1")
    ], xid, "DHCP_SPOOFING", "ATTACK"


# ==============================
# DUPLICATE IP
# ==============================
def duplicate_ip():
    ip = random_ip()
    xid = random.randint(1, 100000)

    return [
        ("ACK", random_mac(), ip),
        ("ACK", random_mac(), ip)
    ], xid, "DUPLICATE_IP", "ATTACK"


# ==============================
# ABNORMAL RENEWAL
# ==============================
def renewal():
    mac = random_mac()
    xid = random.randint(1, 100000)

    packets = []
    for _ in range(6):  # repeated requests
        packets.append(("REQUEST", mac, random_ip()))

    return packets, xid, "ABNORMAL_RENEWAL", "ATTACK"


# ==============================
# RELAY ANOMALY
# ==============================
def relay():
    mac = random_mac()
    xid = random.randint(1, 100000)

    return [
        ("DISCOVER", mac, "0.0.0.0"),
        ("OFFER", "server", random_ip())
    ], xid, "RELAY_ANOMALY", "ATTACK"


# ==============================
# MAIN
# ==============================
def main():

    dataset = []

    attack_functions = [
        starvation,
        rogue,
        spoofing,
        duplicate_ip,
        renewal,
        relay
    ]

    for _ in range(NUM_RECORDS):

        # 70% normal, 30% attack
        if random.random() < 0.7:
            packets, xid, attack_type, label = normal_flow()
        else:
            func = random.choice(attack_functions)
            packets, xid, attack_type, label = func()

        for msg, mac, ip in packets:
            dataset.append({
                "packet_no": get_packet_no(),
                "msg_type": msg,
                "src_mac": mac,
                "src_ip": ip,
                "xid": xid,
                "lease_time": random.randint(10, 86400),
                "relay_ip": "0.0.0.0" if attack_type != "RELAY_ANOMALY"
                            else f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
                "dns": "8.8.8.8" if label == "BENIGN" else "123.123.123.123",
                "gateway": "192.168.1.1" if label == "BENIGN" else "111.111.111.1",
                "label": label,
                "attack_type": attack_type
            })

    df = pd.DataFrame(dataset)

    # Shuffle + fix packet_no
    df = df.sample(frac=1).reset_index(drop=True)
    df["packet_no"] = np.arange(1, len(df) + 1)

    df.to_csv(OUTPUT_FILE, index=False)

    print("Dataset Generated:", df.shape)
    print(df["attack_type"].value_counts())


if __name__ == "__main__":
    main()
