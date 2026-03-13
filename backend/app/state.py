from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime

from .schemas import PacketEvent, Protocol


@dataclass
class FlowKey:
    src_ip: str
    dst_ip: str
    protocol: Protocol
    src_port: int | None
    dst_port: int | None


@dataclass
class FlowState:
    first_ts: float
    last_ts: float
    total_packets: int
    total_size: int

    syn_count: int
    rst_count: int


class RollingWindowState:
    """In-memory rolling state for feature engineering.

    For a hackathon MVP, this is intentionally in-memory.
    If you need horizontal scaling, move these counters to Redis.
    """

    def __init__(self) -> None:
        self.flow_map: dict[FlowKey, FlowState] = {}

        # Per src_ip recent activity (timestamps)
        self.ip_packets: dict[str, deque[float]] = defaultdict(deque)
        self.ip_connections: dict[str, deque[float]] = defaultdict(deque)
        self.ip_dst_ports: dict[str, deque[tuple[float, int]]] = defaultdict(deque)

    def _expire(self, now: float) -> None:
        # expire old activity beyond 10s
        cutoff = now - 10.0
        for ip, q in list(self.ip_packets.items()):
            while q and q[0] < cutoff:
                q.popleft()
            if not q:
                self.ip_packets.pop(ip, None)

        for ip, q in list(self.ip_connections.items()):
            while q and q[0] < cutoff:
                q.popleft()
            if not q:
                self.ip_connections.pop(ip, None)

        for ip, q in list(self.ip_dst_ports.items()):
            while q and q[0][0] < cutoff:
                q.popleft()
            if not q:
                self.ip_dst_ports.pop(ip, None)

        # flows expire beyond 2 minutes of inactivity
        flow_cutoff = now - 120.0
        for key, st in list(self.flow_map.items()):
            if st.last_ts < flow_cutoff:
                self.flow_map.pop(key, None)

    def update(self, pkt: PacketEvent) -> None:
        now = pkt.ts.timestamp()
        self._expire(now)

        key = FlowKey(pkt.src_ip, pkt.dst_ip, pkt.protocol, pkt.src_port, pkt.dst_port)
        st = self.flow_map.get(key)

        syn = 1 if (pkt.tcp_flags or "").upper().find("S") >= 0 else 0
        rst = 1 if (pkt.tcp_flags or "").upper().find("R") >= 0 else 0

        if st is None:
            self.flow_map[key] = FlowState(
                first_ts=now,
                last_ts=now,
                total_packets=1,
                total_size=pkt.size,
                syn_count=syn,
                rst_count=rst,
            )
            self.ip_connections[pkt.src_ip].append(now)
        else:
            st.last_ts = now
            st.total_packets += 1
            st.total_size += pkt.size
            st.syn_count += syn
            st.rst_count += rst

        self.ip_packets[pkt.src_ip].append(now)
        if pkt.dst_port is not None:
            self.ip_dst_ports[pkt.src_ip].append((now, pkt.dst_port))

    def get_flow_state(self, pkt: PacketEvent) -> FlowState:
        key = FlowKey(pkt.src_ip, pkt.dst_ip, pkt.protocol, pkt.src_port, pkt.dst_port)
        st = self.flow_map.get(key)
        if st is None:
            # Should not happen if update() called first
            st = FlowState(
                first_ts=pkt.ts.timestamp(),
                last_ts=pkt.ts.timestamp(),
                total_packets=1,
                total_size=pkt.size,
                syn_count=0,
                rst_count=0,
            )
            self.flow_map[key] = st
        return st

    def features_for(self, pkt: PacketEvent) -> dict:
        st = self.get_flow_state(pkt)
        duration = max(0.001, st.last_ts - st.first_ts)
        avg_size = st.total_size / max(1, st.total_packets)

        now = pkt.ts.timestamp()
        cutoff = now - 10.0

        conn_count = sum(1 for t in self.ip_connections.get(pkt.src_ip, []) if t >= cutoff)
        dst_ports = {p for t, p in self.ip_dst_ports.get(pkt.src_ip, []) if t >= cutoff}

        return {
            "ts": pkt.ts.isoformat(),
            "src_ip": pkt.src_ip,
            "dst_ip": pkt.dst_ip,
            "protocol": pkt.protocol,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "flow_duration_s": float(duration),
            "total_packets": int(st.total_packets),
            "total_bytes": int(st.total_size),
            "avg_packet_size": float(avg_size),
            "connection_count_10s": int(conn_count),
            "distinct_dst_ports_10s": int(len(dst_ports)),
            "syn_count_10s": int(st.syn_count),
            "rst_count_10s": int(st.rst_count),
        }

    def active_connections(self) -> int:
        # Approximate: number of currently tracked flows
        return len(self.flow_map)


def now_utc() -> datetime:
    return datetime.utcnow()
