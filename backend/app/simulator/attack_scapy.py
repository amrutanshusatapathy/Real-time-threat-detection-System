from __future__ import annotations

import argparse
import random
import time
from dataclasses import dataclass
from typing import Iterable

from scapy.all import IP, TCP, UDP, ICMP, Raw, conf, send  # type: ignore


@dataclass
class SimConfig:
    target_ip: str
    seconds: float
    pps: int
    base_dst_port: int
    port_scan_min: int
    port_scan_max: int
    brute_force_port: int
    ddos_port: int
    payload_size: int
    spoof_src: bool


def _rand_private_ip() -> str:
    # Bias towards RFC1918 ranges for demos.
    ranges = [
        ("10", 1, 254, 1, 254),
        ("172", 16, 31, 1, 254),
        ("192", 168, 168, 1, 254),
    ]
    a, b1, b2, c1, c2 = random.choice(ranges)
    if a == "10":
        return f"10.{random.randint(b1, b2)}.{random.randint(c1, c2)}.{random.randint(1, 254)}"
    if a == "172":
        return f"172.{random.randint(b1, b2)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _src_ip(spoof: bool) -> str | None:
    return _rand_private_ip() if spoof else None


def _log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def _pace_loop(total_packets: int, pps: int) -> Iterable[int]:
    # Yields packet indices, pacing to approximate pps.
    if pps <= 0:
        for i in range(total_packets):
            yield i
        return

    interval = 1.0 / float(pps)
    start = time.perf_counter()

    for i in range(total_packets):
        target_t = start + (i * interval)
        now = time.perf_counter()
        if target_t > now:
            time.sleep(target_t - now)
        yield i


def _send(pkt) -> None:
    send(pkt, verbose=False)


def simulate_normal(cfg: SimConfig) -> None:
    _log(f"NORMAL traffic: target={cfg.target_ip} seconds={cfg.seconds} pps={cfg.pps}")
    total = max(1, int(cfg.seconds * cfg.pps))

    for i in _pace_loop(total, cfg.pps):
        sip = _src_ip(cfg.spoof_src)

        # Low-noise mix of TCP/UDP/ICMP
        choice = i % 10
        if choice in (0, 1):
            # ICMP ping-ish
            pkt = IP(dst=cfg.target_ip, src=sip) / ICMP() / Raw(load=b"ping")
        elif choice in (2, 3, 4):
            # UDP small payload
            pkt = (
                IP(dst=cfg.target_ip, src=sip)
                / UDP(sport=random.randint(1024, 65535), dport=cfg.base_dst_port)
                / Raw(load=b"x" * max(20, cfg.payload_size // 8))
            )
        else:
            # TCP ACK-ish small payload (no handshake needed for demo capture)
            pkt = (
                IP(dst=cfg.target_ip, src=sip)
                / TCP(sport=random.randint(1024, 65535), dport=cfg.base_dst_port, flags="A")
                / Raw(load=b"hello")
            )

        _send(pkt)

        if (i + 1) % max(1, cfg.pps) == 0:
            _log(f"NORMAL sent {i + 1}/{total}")


def simulate_port_scan(cfg: SimConfig) -> None:
    _log(
        "PORT SCAN: "
        f"target={cfg.target_ip} ports={cfg.port_scan_min}-{cfg.port_scan_max} "
        f"seconds={cfg.seconds} pps={cfg.pps}"
    )

    ports = list(range(cfg.port_scan_min, cfg.port_scan_max + 1))
    random.shuffle(ports)

    total = max(1, int(cfg.seconds * cfg.pps))

    for i in _pace_loop(total, cfg.pps):
        sip = _src_ip(cfg.spoof_src)
        dport = ports[i % len(ports)]

        pkt = IP(dst=cfg.target_ip, src=sip) / TCP(
            sport=random.randint(1024, 65535),
            dport=int(dport),
            flags="S",
            seq=random.randint(0, 2**32 - 1),
        )
        _send(pkt)

        if (i + 1) % max(1, cfg.pps) == 0:
            _log(f"PORT SCAN sent {i + 1}/{total} (last dport={dport})")


def simulate_brute_force(cfg: SimConfig) -> None:
    _log(
        "BRUTE FORCE attempts: "
        f"target={cfg.target_ip} dport={cfg.brute_force_port} seconds={cfg.seconds} pps={cfg.pps}"
    )

    total = max(1, int(cfg.seconds * cfg.pps))

    for i in _pace_loop(total, cfg.pps):
        sip = _src_ip(cfg.spoof_src)

        # SYN flood to a common auth port approximates repeated login attempts.
        pkt = IP(dst=cfg.target_ip, src=sip) / TCP(
            sport=random.randint(1024, 65535),
            dport=int(cfg.brute_force_port),
            flags="S",
            seq=random.randint(0, 2**32 - 1),
        )
        _send(pkt)

        if (i + 1) % max(1, cfg.pps) == 0:
            _log(f"BRUTE FORCE sent {i + 1}/{total}")


def simulate_ddos(cfg: SimConfig) -> None:
    _log(
        "DDoS burst: "
        f"target={cfg.target_ip} dport={cfg.ddos_port} seconds={cfg.seconds} pps={cfg.pps} payload={cfg.payload_size}B"
    )

    total = max(1, int(cfg.seconds * cfg.pps))
    payload = b"D" * max(1, cfg.payload_size)

    for i in _pace_loop(total, cfg.pps):
        sip = _src_ip(cfg.spoof_src)

        # UDP burst with larger payload
        pkt = (
            IP(dst=cfg.target_ip, src=sip)
            / UDP(sport=random.randint(1024, 65535), dport=int(cfg.ddos_port))
            / Raw(load=payload)
        )
        _send(pkt)

        if (i + 1) % max(1, cfg.pps) == 0:
            _log(f"DDoS sent {i + 1}/{total}")


def simulate_mixed(cfg: SimConfig) -> None:
    # Short, punchy sequence that reliably triggers rules:
    # - Normal warmup
    # - Port scan
    # - Brute force
    # - DDoS
    secs = max(1.0, cfg.seconds)
    chunk = secs / 4.0

    _log("MIXED demo starting")

    simulate_normal(
        SimConfig(
            **{**cfg.__dict__, "seconds": chunk, "pps": max(5, cfg.pps // 6), "payload_size": max(64, cfg.payload_size // 4)}
        )
    )
    simulate_port_scan(SimConfig(**{**cfg.__dict__, "seconds": chunk, "pps": max(20, cfg.pps)}))
    simulate_brute_force(SimConfig(**{**cfg.__dict__, "seconds": chunk, "pps": max(30, cfg.pps)}))
    simulate_ddos(SimConfig(**{**cfg.__dict__, "seconds": chunk, "pps": max(80, cfg.pps * 2)}))

    _log("MIXED demo finished")


def main() -> None:
    conf.verb = 0

    parser = argparse.ArgumentParser(description="Scapy cyber-attack simulator for hackathon demos")
    parser.add_argument(
        "--mode",
        choices=["normal", "portscan", "bruteforce", "ddos", "mixed"],
        default="mixed",
        help="Traffic pattern to simulate",
    )
    parser.add_argument("--target", required=True, help="Target IP to send packets to")
    parser.add_argument("--seconds", type=float, default=12.0, help="Duration to run")
    parser.add_argument("--pps", type=int, default=120, help="Packets per second (approx)")

    parser.add_argument("--base-dst-port", type=int, default=443, help="Base destination port for normal traffic")
    parser.add_argument("--port-scan-min", type=int, default=1, help="Port scan start port")
    parser.add_argument("--port-scan-max", type=int, default=120, help="Port scan end port")

    parser.add_argument("--brute-force-port", type=int, default=22, help="Auth port to target")
    parser.add_argument("--ddos-port", type=int, default=9999, help="UDP port for DDoS burst")
    parser.add_argument("--payload-size", type=int, default=900, help="UDP payload size in bytes")

    parser.add_argument(
        "--spoof-src",
        action="store_true",
        help="Spoof random private source IPs (for demo visualization); may not work on all networks",
    )

    args = parser.parse_args()

    cfg = SimConfig(
        target_ip=args.target,
        seconds=float(args.seconds),
        pps=int(args.pps),
        base_dst_port=int(args.base_dst_port),
        port_scan_min=int(args.port_scan_min),
        port_scan_max=int(args.port_scan_max),
        brute_force_port=int(args.brute_force_port),
        ddos_port=int(args.ddos_port),
        payload_size=int(args.payload_size),
        spoof_src=bool(args.spoof_src),
    )

    _log("NOTE: Raw packet sending/sniffing may require Administrator/Npcap on Windows")

    if args.mode == "normal":
        simulate_normal(cfg)
    elif args.mode == "portscan":
        simulate_port_scan(cfg)
    elif args.mode == "bruteforce":
        simulate_brute_force(cfg)
    elif args.mode == "ddos":
        simulate_ddos(cfg)
    else:
        simulate_mixed(cfg)


if __name__ == "__main__":
    main()
