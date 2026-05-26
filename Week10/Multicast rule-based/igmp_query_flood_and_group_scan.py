# IGMP query flood / Group Scanning

from collections import defaultdict, Counter, deque
from typing import Dict, List, Any, Optional
from scapy.all import rdpcap, IP


class IGMPAnomalyDetector:
    """
    Detects:

    1) IGMP General Query Flood
    2) IGMP Group-Specific Query Flood
    3) IGMP Group Scanning
    4) Unknown Querier Behavior
    5) TTL Violations

    Protocol-aware IGMP anomaly detector.
    """

    def __init__(self):

        # =========================================================
        # CONFIGURATION
        # =========================================================

        # General Query timing
        self.GENERAL_QUERY_IAT_THRESHOLD = 100
        self.GENERAL_QUERY_BURST_THRESHOLD = 3
        self.GENERAL_QUERY_WINDOW = 300

        # Group Query Flood
        self.GROUP_QUERY_BURST_THRESHOLD = 5
        self.GROUP_QUERY_WINDOW = 30

        # Membership correlation
        self.MAX_RECENT_MEMBER_EVENT_SEC = 10

        # Group scanning
        self.GROUP_SCAN_WINDOW = 30
        self.MAX_UNIQUE_GROUPS = 10

        # Querier maturity
        self.QUERIER_MATURITY_SEC = 300

        # TTL validation
        self.REQUIRE_TTL_1 = True

        # =========================================================
        # STATE
        # =========================================================

        # -----------------------------
        # General Query tracking
        # -----------------------------

        self.last_general_query_time = None

        self.general_query_history = deque()

        # -----------------------------
        # Membership events
        # -----------------------------

        self.member_event_history = defaultdict(deque)

        # -----------------------------
        # Group query tracking
        # -----------------------------

        self.group_query_history = defaultdict(deque)

        # -----------------------------
        # Group scan tracking
        # -----------------------------

        # src_ip -> {group -> ts}
        self.group_scan_groups = defaultdict(dict)

        # -----------------------------
        # Querier tracking
        # -----------------------------

        self.querier_first_seen = {}

        self.known_queriers = set()

        # -----------------------------
        # Alerts
        # -----------------------------

        self.alerts = []

    # =============================================================
    # VERSION CLASSIFICATION
    # =============================================================

    def classify_igmp_version(
        self,
        igmp_type,
        version_hint=None
    ):

        if version_hint is not None:
            return version_hint

        if igmp_type == 0x12:
            return 1

        if igmp_type == 0x17:
            return 2

        if igmp_type == 0x22:
            return 3

        return 2

    # =============================================================
    # QUERY TYPE
    # =============================================================

    def is_general_query(
        self,
        igmp_type,
        group
    ):

        return (
            igmp_type == 0x11
            and group == "0.0.0.0"
        )

    def is_group_specific_query(
        self,
        igmp_type,
        group
    ):

        return (
            igmp_type == 0x11
            and group != "0.0.0.0"
        )

    # =============================================================
    # QUERIER MATURITY
    # =============================================================

    def update_querier_state(
        self,
        ts,
        src_ip
    ):

        if src_ip not in self.querier_first_seen:

            self.querier_first_seen[src_ip] = ts

        if (
            ts - self.querier_first_seen[src_ip]
            >= self.QUERIER_MATURITY_SEC
        ):

            self.known_queriers.add(src_ip)

    # =============================================================
    # CLEANUP FUNCTIONS
    # =============================================================

    def cleanup_deque(
        self,
        q,
        current_time,
        window
    ):

        cutoff = current_time - window

        while q and q[0] < cutoff:
            q.popleft()

    # =============================================================
    # MEMBER EVENTS
    # =============================================================

    def record_member_event(
        self,
        ts,
        group
    ):

        q = self.member_event_history[group]

        q.append(ts)

        self.cleanup_deque(
            q,
            ts,
            self.MAX_RECENT_MEMBER_EVENT_SEC
        )

    def has_recent_member_event(
        self,
        ts,
        group
    ):

        q = self.member_event_history[group]

        self.cleanup_deque(
            q,
            ts,
            self.MAX_RECENT_MEMBER_EVENT_SEC
        )

        return len(q) > 0

    # =============================================================
    # GENERAL QUERY TRACKING
    # =============================================================

    def record_general_query(
        self,
        ts
    ):

        self.general_query_history.append(ts)

        self.cleanup_deque(
            self.general_query_history,
            ts,
            self.GENERAL_QUERY_WINDOW
        )

    # =============================================================
    # GROUP QUERY TRACKING
    # =============================================================

    def record_group_query(
        self,
        ts,
        group
    ):

        q = self.group_query_history[group]

        q.append(ts)

        self.cleanup_deque(
            q,
            ts,
            self.GROUP_QUERY_WINDOW
        )

    def is_group_query_flood(
        self,
        group
    ):

        return (
            len(self.group_query_history[group])
            >= self.GROUP_QUERY_BURST_THRESHOLD
        )

    # =============================================================
    # GROUP SCAN TRACKING
    # =============================================================

    def record_group_scan(
        self,
        src_ip,
        ts,
        group
    ):

        self.group_scan_groups[src_ip][group] = ts

        cutoff = ts - self.GROUP_SCAN_WINDOW

        expired = []

        for g, last_ts in self.group_scan_groups[src_ip].items():

            if last_ts < cutoff:
                expired.append(g)

        for g in expired:
            del self.group_scan_groups[src_ip][g]

    def is_group_scan(
        self,
        src_ip
    ):

        return (
            len(self.group_scan_groups[src_ip])
            >= self.MAX_UNIQUE_GROUPS
        )

    # =============================================================
    # PROCESS PACKET
    # =============================================================

    def process_packet(
        self,
        pkt: Dict[str, Any]
    ):

        ts = pkt["timestamp"]

        igmp_type = pkt["igmp_type"]

        src_ip = pkt["src_ip"]

        ttl = pkt["ttl"]

        group = pkt["group_addr"]

        igmp_version = self.classify_igmp_version(
            igmp_type,
            pkt.get("igmp_version")
        )

        # =========================================================
        # MEMBER EVENTS
        # =========================================================

        # IGMPv2 Leave
        if igmp_type == 0x17:

            self.record_member_event(
                ts,
                group
            )

        # IGMPv3 Report
        elif igmp_type == 0x22:

            self.record_member_event(
                ts,
                group
            )

        # =========================================================
        # ONLY HANDLE QUERIES
        # =========================================================

        if igmp_type != 0x11:
            return

        # =========================================================
        # UPDATE QUERIER STATE
        # =========================================================

        self.update_querier_state(
            ts,
            src_ip
        )

        suspicion = 0

        reasons = []

        # =========================================================
        # GENERAL QUERY FLOOD
        # =========================================================

        if self.is_general_query(
            igmp_type,
            group
        ):

            if self.last_general_query_time is not None:

                iat = ts - self.last_general_query_time

                if (
                    iat
                    < self.GENERAL_QUERY_IAT_THRESHOLD
                ):

                    self.record_general_query(ts)

                    if (
                        len(self.general_query_history)
                        >= self.GENERAL_QUERY_BURST_THRESHOLD
                    ):

                        suspicion += 1

                        reasons.append(
                            "General Query Flood"
                        )

            self.last_general_query_time = ts

        # =========================================================
        # GROUP-SPECIFIC QUERY
        # =========================================================

        elif self.is_group_specific_query(
            igmp_type,
            group
        ):

            # ---------------------------------------------
            # Group query flood tracking
            # ---------------------------------------------

            self.record_group_query(
                ts,
                group
            )

            # ---------------------------------------------
            # Group scan tracking
            # ---------------------------------------------

            self.record_group_scan(
                src_ip,
                ts,
                group
            )

            # ---------------------------------------------
            # Flood detection
            # ---------------------------------------------

            if (
                self.is_group_query_flood(group)
                and
                not self.has_recent_member_event(
                    ts,
                    group
                )
            ):

                suspicion += 1

                reasons.append(
                    "Group Query Flood"
                )

            # ---------------------------------------------
            # Group scan detection
            # ---------------------------------------------

            if self.is_group_scan(src_ip):

                suspicion += 1

                reasons.append(
                    "Multicast Group Scan"
                )

        # =========================================================
        # TTL CHECK
        # =========================================================

        if self.REQUIRE_TTL_1 and ttl != 1:

            suspicion += 1

            reasons.append(
                f"Invalid TTL={ttl}"
            )

        # =========================================================
        # UNKNOWN QUERIER
        # =========================================================

        if src_ip not in self.known_queriers:

            suspicion += 1

            reasons.append(
                "Unknown Querier"
            )

        # =========================================================
        # FINAL ALERT
        # =========================================================

        if suspicion >= 2:

            alert = {

                "timestamp": ts,

                "alert": "IGMP Anomaly",

                "source": src_ip,

                "group": group,

                "igmp_version": igmp_version,

                "reasons": reasons,

                "suspicion_score": suspicion,

                "unique_groups": len(
                    self.group_scan_groups[src_ip]
                )
            }

            self.alerts.append(alert)

            print("\n===================================")
            print("IGMP ALERT")
            print("===================================")

            print(f"Time: {ts:.3f}")

            print(f"Source: {src_ip}")

            print(f"Group: {group}")

            for r in reasons:
                print(f" - {r}")

    # =============================================================
    # GET ALERTS
    # =============================================================

    def get_alerts(self):

        return self.alerts

    # =============================================================
    # RESET
    # =============================================================

    def reset_state(self):

        self.last_general_query_time = None

        self.general_query_history.clear()

        self.member_event_history.clear()

        self.group_query_history.clear()

        self.group_scan_groups.clear()

        self.querier_first_seen.clear()

        self.known_queriers.clear()

        self.alerts.clear()


# =================================================================
# PCAP DETECTION FUNCTION
# =================================================================

def detect_igmp_attacks_in_pcap(
    pcap_path
):

    detector = IGMPAnomalyDetector()

    packets = rdpcap(pcap_path)

    for pkt in packets:

        try:

            if IP not in pkt:
                continue

            ip_pkt = pkt[IP]

            # IGMP = protocol number 2
            if ip_pkt.proto != 2:
                continue

            raw = bytes(ip_pkt.payload)

            if len(raw) < 8:
                continue

            igmp_type = raw[0]

            group_bytes = raw[4:8]

            group_addr = ".".join(
                str(x)
                for x in group_bytes
            )

            processed_pkt = {

                "timestamp": float(pkt.time),

                "igmp_type": igmp_type,

                "src_ip": ip_pkt.src,

                "ttl": ip_pkt.ttl,

                "group_addr": group_addr,

                "igmp_version": None
            }

            detector.process_packet(
                processed_pkt
            )

        except Exception:
            continue

    return detector.get_alerts()


# =================================================================
# EXAMPLE USAGE
# =================================================================


alerts = detect_igmp_attacks_in_pcap(
    "/content/r2-sw1_5.pcap"
)

print(alerts)
