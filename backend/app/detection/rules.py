from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..schemas import AlertCreate, Severity


@dataclass
class RuleHit:
    alert: AlertCreate
    reason: str


def severity_for_score(score: float) -> Severity:
    if score >= 0.95:
        return "CRITICAL"
    if score >= 0.85:
        return "HIGH"
    if score >= 0.7:
        return "MEDIUM"
    return "LOW"


def detect_rules(features: dict) -> list[RuleHit]:
    """Rule-based detection for MVP.

    Inputs: flow feature dict from RollingWindowState.features_for().
    """

    hits: list[RuleHit] = []
    ts = datetime.fromisoformat(features["ts"])

    src_ip = features["src_ip"]
    dst_ip = features.get("dst_ip")
    dst_port = features.get("dst_port")

    conn_count = int(features.get("connection_count_10s", 0))
    distinct_ports = int(features.get("distinct_dst_ports_10s", 0))
    syn_count = int(features.get("syn_count_10s", 0))
    total_packets = int(features.get("total_packets", 0))
    avg_size = float(features.get("avg_packet_size", 0))

    # Port scanning: many distinct destination ports in 10s
    if distinct_ports >= 18:
        score = min(1.0, distinct_ports / 30)
        sev: Severity = severity_for_score(score)
        hits.append(
            RuleHit(
                alert=AlertCreate(
                    ts=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    attack_type="Port Scan",
                    severity=sev,
                    details={
                        "rule": "port_scan",
                        "distinct_dst_ports_10s": distinct_ports,
                        "connection_count_10s": conn_count,
                    },
                ),
                reason="High destination port fan-out",
            )
        )

    # Brute force attempts: repeated connections to common auth ports
    auth_ports = {22, 3389, 445, 80, 443}
    if dst_port in auth_ports and syn_count >= 35 and conn_count >= 25:
        score = min(1.0, (syn_count + conn_count) / 120)
        sev = severity_for_score(score)
        hits.append(
            RuleHit(
                alert=AlertCreate(
                    ts=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    attack_type="Brute Force",
                    severity=sev,
                    details={
                        "rule": "bruteforce",
                        "syn_count_10s": syn_count,
                        "connection_count_10s": conn_count,
                        "dst_port": dst_port,
                    },
                ),
                reason="Repeated connection attempts to auth/service port",
            )
        )

    # Suspicious traffic spike: high packet count with larger sizes
    if total_packets >= 120 or (total_packets >= 80 and avg_size >= 900):
        score = min(1.0, total_packets / 220)
        sev = severity_for_score(score)
        hits.append(
            RuleHit(
                alert=AlertCreate(
                    ts=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    attack_type="Suspicious Spike",
                    severity=sev,
                    details={
                        "rule": "traffic_spike",
                        "total_packets": total_packets,
                        "avg_packet_size": avg_size,
                    },
                ),
                reason="Burst of packets in a short time window",
            )
        )

    return hits
