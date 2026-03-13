from __future__ import annotations

import argparse
import time
from datetime import datetime

from ..config import settings
from ..redis_client import get_redis
from ..streaming import xadd_packet
from .traffic_generator import brute_force, mixed_scenario, normal_traffic, port_scan, traffic_spike


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulated traffic generator")
    parser.add_argument(
        "--mode",
        choices=["normal", "scan", "bruteforce", "spike", "mixed"],
        default="mixed",
    )
    parser.add_argument("--rate", type=float, default=1.0, help="ticks per second")
    parser.add_argument("--target", type=str, default="10.0.0.10")
    args = parser.parse_args()

    redis = get_redis()

    print(f"[sim] redis={settings.redis_url} stream={settings.stream_packets} mode={args.mode}")

    attacker = "203.0.113.42"

    while True:
        now = datetime.utcnow()

        if args.mode == "normal":
            packets = normal_traffic(now, 30)
        elif args.mode == "scan":
            packets = port_scan(now, attacker, args.target, ports=list(range(20, 60)))
        elif args.mode == "bruteforce":
            packets = brute_force(now, attacker, args.target, service_port=22, attempts=60)
        elif args.mode == "spike":
            packets = traffic_spike(now, attacker, args.target, seconds=2, pps=60)
        else:
            packets = mixed_scenario(now)

        for p in packets:
            xadd_packet(
                redis,
                {
                    "ts": p.ts.isoformat(),
                    "src_ip": p.src_ip,
                    "dst_ip": p.dst_ip,
                    "protocol": p.protocol,
                    "size": p.size,
                    "src_port": p.src_port,
                    "dst_port": p.dst_port,
                    "tcp_flags": p.tcp_flags,
                },
            )

        time.sleep(max(0.05, 1.0 / max(0.1, args.rate)))


if __name__ == "__main__":
    main()
