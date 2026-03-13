from __future__ import annotations

from prometheus_client import Counter, Gauge


PACKETS_TOTAL = Counter(
    "threatd_packets_total",
    "Total packets processed by the backend worker",
)

BYTES_TOTAL = Counter(
    "threatd_bytes_total",
    "Total bytes processed by the backend worker",
)

PACKET_RATE_PPS = Gauge(
    "threatd_packet_rate_pps",
    "Estimated packet rate (packets per second)",
)

DETECTED_ATTACKS_TOTAL = Counter(
    "threatd_detected_attacks_total",
    "Total detected attacks / alerts emitted",
    labelnames=("attack_type",),
)

BLOCKED_IP_EVENTS_TOTAL = Counter(
    "threatd_blocked_ip_events_total",
    "Total times an IP was blocked by automated response",
)

BLOCKLIST_SIZE = Gauge(
    "threatd_blocklist_size",
    "Current number of blocked IPs in Redis set",
)
