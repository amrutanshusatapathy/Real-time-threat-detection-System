from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class GeneratedPacket:
    ts: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    size: int
    src_port: int | None
    dst_port: int | None
    tcp_flags: str | None


ATTACK_TYPES = ["DDoS", "Port Scan", "SQL Injection", "XSS", "Brute Force"]


def _random_ip() -> str:
    a = random.choice([23, 31, 45, 58, 77, 89, 103, 109, 141, 176, 185, 203])
    return f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def normal_traffic(now: datetime, count: int) -> list[GeneratedPacket]:
    out: list[GeneratedPacket] = []
    for _ in range(count):
        proto = random.choices(["TCP", "UDP"], weights=[0.75, 0.25])[0]
        dst_port = random.choice([53, 80, 443, 8080, 22, 3389])
        size = int(max(60, random.gauss(600, 220)))
        out.append(
            GeneratedPacket(
                ts=now,
                src_ip=_random_ip(),
                dst_ip="10.0.0.10",
                protocol=proto,
                size=size,
                src_port=random.randint(20000, 65000),
                dst_port=dst_port,
                tcp_flags="S" if proto == "TCP" and random.random() < 0.4 else None,
            )
        )
    return out


def port_scan(now: datetime, attacker_ip: str, target_ip: str, ports: list[int]) -> list[GeneratedPacket]:
    out: list[GeneratedPacket] = []
    for p in ports:
        out.append(
            GeneratedPacket(
                ts=now,
                src_ip=attacker_ip,
                dst_ip=target_ip,
                protocol="TCP",
                size=random.randint(60, 120),
                src_port=random.randint(20000, 65000),
                dst_port=p,
                tcp_flags="S",
            )
        )
    return out


def brute_force(now: datetime, attacker_ip: str, target_ip: str, service_port: int, attempts: int) -> list[GeneratedPacket]:
    out: list[GeneratedPacket] = []
    for i in range(attempts):
        out.append(
            GeneratedPacket(
                ts=now + timedelta(milliseconds=i * 25),
                src_ip=attacker_ip,
                dst_ip=target_ip,
                protocol="TCP",
                size=random.randint(90, 260),
                src_port=random.randint(20000, 65000),
                dst_port=service_port,
                tcp_flags="S",
            )
        )
    return out


def traffic_spike(now: datetime, attacker_ip: str, target_ip: str, seconds: int, pps: int) -> list[GeneratedPacket]:
    out: list[GeneratedPacket] = []
    total = seconds * pps
    for i in range(total):
        out.append(
            GeneratedPacket(
                ts=now + timedelta(milliseconds=int(i * (1000 / max(1, pps)))),
                src_ip=attacker_ip,
                dst_ip=target_ip,
                protocol=random.choice(["UDP", "TCP"]),
                size=random.randint(200, 1400),
                src_port=random.randint(20000, 65000),
                dst_port=random.choice([53, 80, 443, 123, 1900, 8080]),
                tcp_flags="S" if random.random() < 0.2 else None,
            )
        )
    return out


def mixed_scenario(now: datetime) -> list[GeneratedPacket]:
    attacker = _random_ip()
    target = "10.0.0.10"

    packets: list[GeneratedPacket] = []
    packets.extend(normal_traffic(now, 25))

    if random.random() < 0.35:
        packets.extend(port_scan(now, attacker, target, ports=random.sample(range(20, 1024), 18)))

    if random.random() < 0.35:
        packets.extend(brute_force(now, attacker, target, service_port=random.choice([22, 3389, 80, 443]), attempts=30))

    if random.random() < 0.22:
        packets.extend(traffic_spike(now, attacker, target, seconds=2, pps=45))

    return packets
