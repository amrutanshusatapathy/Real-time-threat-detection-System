from __future__ import annotations

import threading
from datetime import datetime
from typing import Any

from scapy.all import IP, TCP, UDP, ICMP, sniff  # type: ignore

from ..config import settings
from ..redis_client import get_redis
from ..streaming import xadd_packet


def _protocol(pkt: Any) -> str:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def _extract(pkt: Any) -> dict[str, Any] | None:
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    proto = _protocol(pkt)

    src_port: int | None = None
    dst_port: int | None = None
    flags: str | None = None

    if proto == "TCP":
        tcp = pkt[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        flags = str(tcp.flags)
    elif proto == "UDP":
        udp = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)

    size = int(len(pkt))

    return {
        "ts": datetime.utcnow().isoformat(),
        "src_ip": str(ip.src),
        "dst_ip": str(ip.dst),
        "protocol": proto,
        "size": size,
        "src_port": src_port,
        "dst_port": dst_port,
        "tcp_flags": flags,
    }


def start_capture_thread() -> threading.Thread | None:
    if not settings.capture_enabled:
        return None

    redis = get_redis()

    def on_packet(pkt: Any) -> None:
        event = _extract(pkt)
        if not event:
            return
        try:
            xadd_packet(redis, event)
        except Exception:
            # Avoid crashing sniff loop during demos
            return

    iface = settings.capture_iface

    thread = threading.Thread(
        target=lambda: sniff(prn=on_packet, store=False, iface=iface),
        name="scapy-sniffer",
        daemon=True,
    )
    thread.start()
    return thread
