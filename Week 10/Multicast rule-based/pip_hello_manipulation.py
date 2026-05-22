from collections import defaultdict, deque
from typing import Dict, Any, Set, List

from scapy.all import rdpcap, IP
from scapy.contrib.pim import PIMv2Hdr


class PIMHelloManipulationDetector:
    """
    Detects:

    1. PIM Hello Flood
    2. Fake Neighbor Injection
    3. Neighbor Explosion
    4. DR Priority Hijacking
    5. Holdtime Manipulation
    6. Distributed Spoofed Neighbor Attack
    7. Invalid TTL
    8. Invalid PIM Version
    9. PIM on Access Port
    """

    def __init__(self):

        # =====================================================
        # CONFIGURATION
        # =====================================================

        self.NORMAL_HELLO_INTERVAL = 30

        self.MIN_HELLO_INTERVAL = 5

        self.WINDOW_SEC = 30

        self.MAX_HELLO_COUNT = 10

        self.MIN_HOLDTIME = 60

        self.MAX_DR_PRIORITY = 1000

        self.MAX_NEIGHBORS = 20

        self.NEIGHBOR_TIMEOUT = 105

        self.ROUTER_MATURITY_SEC = 60

        # Distributed fake neighbor detection

        self.NEW_NEIGHBOR_WINDOW = 10

        self.MAX_NEW_NEIGHBORS = 5

        # =====================================================
        # STATE
        # =====================================================

        # Current active neighbors

        self.last_seen = {}

        # First observed timestamp

        self.first_seen = {}

        # Stable trusted neighbors

        self.known_neighbors: Set[str] = set()

        # Hello timestamps per source

        self.hello_history = defaultdict(deque)

        # DR priority history

        self.dr_priority_history = defaultdict(deque)

        # New neighbor creation history

        self.new_neighbor_history = deque()

        # Alerts

        self.alerts = []

    # =========================================================
    # CLEANUP
    # =========================================================

    def cleanup_old_entries(
        self,
        current_time
    ):

        # -------------------------------------------------
        # Cleanup hello histories
        # -------------------------------------------------

        for src in list(self.hello_history.keys()):

            q = self.hello_history[src]

            while (
                q
                and
                current_time - q[0] > self.WINDOW_SEC
            ):
                q.popleft()

            if not q:
                del self.hello_history[src]

        # -------------------------------------------------
        # Cleanup DR priority histories
        # -------------------------------------------------

        for src in list(self.dr_priority_history.keys()):

            q = self.dr_priority_history[src]

            while (
                q
                and
                current_time - q[0][0]
                > self.WINDOW_SEC * 2
            ):
                q.popleft()

            if not q:
                del self.dr_priority_history[src]

        # -------------------------------------------------
        # Cleanup expired neighbors
        # -------------------------------------------------

        expired = []

        for nbr, last_ts in self.last_seen.items():

            if (
                current_time - last_ts
                > self.NEIGHBOR_TIMEOUT
            ):

                expired.append(nbr)

        for nbr in expired:

            self.last_seen.pop(nbr, None)

            self.first_seen.pop(nbr, None)

            self.known_neighbors.discard(nbr)

        # -------------------------------------------------
        # Cleanup new neighbor history
        # -------------------------------------------------

        cutoff = (
            current_time
            - self.NEW_NEIGHBOR_WINDOW
        )

        while (
            self.new_neighbor_history
            and
            self.new_neighbor_history[0] < cutoff
        ):
            self.new_neighbor_history.popleft()

    # =========================================================
    # TRACK NEW NEIGHBORS
    # =========================================================

    def record_new_neighbor(
        self,
        ts,
        src_ip
    ):

        if src_ip not in self.first_seen:

            self.first_seen[src_ip] = ts

            self.new_neighbor_history.append(ts)

    # =========================================================
    # UPDATE NEIGHBOR STATE
    # =========================================================

    def update_neighbor_state(
        self,
        ts,
        src_ip,
        dr_priority
    ):

        self.last_seen[src_ip] = ts

        self.hello_history[src_ip].append(ts)

        self.dr_priority_history[src_ip].append(
            (ts, dr_priority)
        )

        # Mature trusted neighbor

        if (
            ts - self.first_seen[src_ip]
            >= self.ROUTER_MATURITY_SEC
        ):

            self.known_neighbors.add(src_ip)

    # =========================================================
    # HELLO FLOOD
    # =========================================================

    def is_excessive_hello_count(
        self,
        src_ip
    ):

        return (
            len(self.hello_history[src_ip])
            > self.MAX_HELLO_COUNT
        )

    # =========================================================
    # SHORT HELLO INTERVAL
    # =========================================================

    def is_short_hello_interval(
        self,
        src_ip
    ):

        q = self.hello_history[src_ip]

        if len(q) < 2:
            return False

        iat = q[-1] - q[-2]

        return iat < self.MIN_HELLO_INTERVAL

    # =========================================================
    # DR PRIORITY HIJACK
    # =========================================================

    def is_dr_priority_suspicious(
        self,
        src_ip
    ):

        q = self.dr_priority_history[src_ip]

        if not q:
            return False

        latest_priority = q[-1][1]

        return (
            latest_priority
            > self.MAX_DR_PRIORITY
        )

    # =========================================================
    # NEIGHBOR EXPLOSION
    # =========================================================

    def is_neighbor_explosion(self):

        return (
            len(self.last_seen)
            > self.MAX_NEIGHBORS
        )

    # =========================================================
    # DISTRIBUTED FAKE NEIGHBOR ATTACK
    # =========================================================

    def is_distributed_neighbor_attack(self):

        return (
            len(self.new_neighbor_history)
            > self.MAX_NEW_NEIGHBORS
        )

    # =========================================================
    # ACCESS PORT CHECK
    # =========================================================

    def is_access_port(
        self,
        interface
    ):

        return interface.startswith("access")

    # =========================================================
    # PROCESS PACKET
    # =========================================================

    def process_packet(
        self,
        pkt: Dict[str, Any]
    ):

        ts = pkt["timestamp"]

        src_ip = pkt["src_ip"]

        ttl = pkt["ttl"]

        pim_version = pkt["pim_version"]

        pim_type = pkt["pim_type"]

        holdtime = pkt["holdtime"]

        dr_priority = pkt["dr_priority"]

        interface = pkt.get(
            "interface",
            "unknown"
        )

        # -------------------------------------------------
        # Cleanup
        # -------------------------------------------------

        self.cleanup_old_entries(ts)

        # -------------------------------------------------
        # Only Hello packets
        # -------------------------------------------------

        # PIM Hello = Type 0

        if pim_type != 0:
            return

        # -------------------------------------------------
        # Track new neighbors
        # -------------------------------------------------

        self.record_new_neighbor(
            ts,
            src_ip
        )

        # -------------------------------------------------
        # Update state
        # -------------------------------------------------

        self.update_neighbor_state(
            ts,
            src_ip,
            dr_priority
        )

        suspicion = 0

        reasons = []

        # =================================================
        # RULE 1 — INVALID TTL
        # =================================================

        if ttl != 1:

            suspicion += 1

            reasons.append(
                f"Invalid TTL={ttl}"
            )

        # =================================================
        # RULE 2 — INVALID PIM VERSION
        # =================================================

        if pim_version != 2:

            suspicion += 1

            reasons.append(
                f"Unexpected PIM version={pim_version}"
            )

        # =================================================
        # RULE 3 — HELLO FLOOD
        # =================================================

        if self.is_excessive_hello_count(src_ip):

            suspicion += 1

            reasons.append(
                f"Excessive Hellos="
                f"{len(self.hello_history[src_ip])}"
            )

        # =================================================
        # RULE 4 — VERY SHORT HELLO INTERVAL
        # =================================================

        if self.is_short_hello_interval(src_ip):

            q = self.hello_history[src_ip]

            iat = q[-1] - q[-2]

            suspicion += 1

            reasons.append(
                f"Very short hello interval="
                f"{iat:.2f}s"
            )

        # =================================================
        # RULE 5 — LOW HOLDTIME
        # =================================================

        if holdtime < self.MIN_HOLDTIME:

            suspicion += 1

            reasons.append(
                f"Low holdtime={holdtime}"
            )

        # =================================================
        # RULE 6 — DR HIJACK
        # =================================================

        if self.is_dr_priority_suspicious(src_ip):

            suspicion += 1

            reasons.append(
                f"High DR priority="
                f"{dr_priority}"
            )

        # =================================================
        # RULE 7 — NEIGHBOR EXPLOSION
        # =================================================

        if self.is_neighbor_explosion():

            suspicion += 1

            reasons.append(
                f"Neighbor explosion="
                f"{len(self.last_seen)}"
            )

        # =================================================
        # RULE 8 — DISTRIBUTED FAKE NEIGHBOR ATTACK
        # =================================================

        if self.is_distributed_neighbor_attack():

            suspicion += 2

            reasons.append(
                "Rapid fake neighbor creation"
            )

        # =================================================
        # RULE 9 — ACCESS PORT PIM
        # =================================================

        if self.is_access_port(interface):

            suspicion += 1

            reasons.append(
                "PIM seen on access port"
            )

        # =================================================
        # RULE 10 — UNKNOWN ROUTER BURST
        # =================================================

        if src_ip not in self.known_neighbors:

            if self.is_excessive_hello_count(src_ip):

                suspicion += 1

                reasons.append(
                    "Unknown router burst"
                )

        # =================================================
        # FINAL DECISION
        # =================================================

        if suspicion >= 2:

            alert = {

                "timestamp": ts,

                "alert": "PIM Hello Manipulation",

                "source": src_ip,

                "holdtime": holdtime,

                "dr_priority": dr_priority,

                "suspicion_score": suspicion,

                "reasons": reasons
            }

            self.alerts.append(alert)

            print("\n=================================")
            print("PIM HELLO ALERT")
            print("=================================")

            print(f"Time: {ts:.3f}")

            print(f"Source: {src_ip}")

            print(f"Holdtime: {holdtime}")

            print(f"DR Priority: {dr_priority}")

            for r in reasons:
                print(f" - {r}")

    # =========================================================
    # GET ALERTS
    # =========================================================

    def get_alerts(self):

        return self.alerts


# =============================================================
# PCAP DETECTION
# =============================================================

def detect_pim_hello_attacks_in_pcap(
    pcap_path
):

    detector = PIMHelloManipulationDetector()

    packets = rdpcap(pcap_path)

    for pkt in packets:

        try:

            if IP not in pkt:
                continue

            ip_pkt = pkt[IP]

            # PIM protocol number
            if ip_pkt.proto != 103:
                continue

            if not pkt.haslayer(PIMv2Hdr):
                continue

            pim = pkt[PIMv2Hdr]

            processed_pkt = {

                "timestamp": float(pkt.time),

                "src_ip": ip_pkt.src,

                "ttl": ip_pkt.ttl,

                "pim_version": pim.version,

                "pim_type": pim.type,

                # default values
                "holdtime": 105,

                "dr_priority": 1,

                "interface": "router-link"
            }

            detector.process_packet(
                processed_pkt
            )

        except Exception:
            continue

    return detector.get_alerts()


# =============================================================
# EXAMPLE
# =============================================================


alerts = detect_pim_hello_attacks_in_pcap(
    "/content/r2-sw1_5.pcap"
)

print(alerts)
