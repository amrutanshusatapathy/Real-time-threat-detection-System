from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

ThreatType = Literal["DDoS", "Port Scan", "SQL Injection", "XSS", "Brute Force", "Suspicious Spike", "Anomaly"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Protocol = Literal["TCP", "UDP", "ICMP", "OTHER"]


class PacketEvent(BaseModel):
    ts: datetime
    src_ip: str
    dst_ip: str
    protocol: Protocol
    size: int

    src_port: int | None = None
    dst_port: int | None = None

    tcp_flags: str | None = None


class FlowFeatures(BaseModel):
    ts: datetime

    src_ip: str
    dst_ip: str
    protocol: Protocol
    src_port: int | None = None
    dst_port: int | None = None

    flow_duration_s: float
    total_packets: int
    avg_packet_size: float

    connection_count_10s: int
    distinct_dst_ports_10s: int

    syn_count_10s: int
    rst_count_10s: int


class AlertCreate(BaseModel):
    ts: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str
    dst_ip: str | None = None
    dst_port: int | None = None

    attack_type: ThreatType
    severity: Severity

    details: dict = Field(default_factory=dict)
    anomaly_score: float | None = None


class AlertOut(AlertCreate):
    id: int
    blocked: bool = False


class NetworkStatsOut(BaseModel):
    ts: datetime
    packets_per_second: int
    bandwidth_mbps: float
    active_connections: int


class BlockedIpOut(BaseModel):
    ip: str
    blocked_at: datetime
    reason: str | None = None
