from __future__ import annotations

import argparse
import os
import random
import socket
import time


def _rand_payload(size: int) -> bytes:
    return os.urandom(max(1, size))


def udp_flood(target_host: str, target_port: int, seconds: int, pps: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    deadline = time.time() + seconds
    interval = 1.0 / max(1, pps)
    sent = 0

    while time.time() < deadline:
        sock.sendto(_rand_payload(random.randint(300, 1400)), (target_host, target_port))
        sent += 1
        time.sleep(interval)

    print(f"[socket] UDP flood sent={sent}")


def tcp_connect_burst(target_host: str, target_port: int, attempts: int) -> None:
    ok = 0
    for _ in range(attempts):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            s.connect((target_host, target_port))
            ok += 1
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    print(f"[socket] TCP connect attempts={attempts} connected={ok}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Socket-based traffic sender (optional)")
    parser.add_argument("--mode", choices=["udp", "tcp"], default="udp")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)

    parser.add_argument("--seconds", type=int, default=3)
    parser.add_argument("--pps", type=int, default=150)
    parser.add_argument("--attempts", type=int, default=120)
    args = parser.parse_args()

    if args.mode == "udp":
        udp_flood(args.host, args.port, seconds=args.seconds, pps=args.pps)
    else:
        tcp_connect_burst(args.host, args.port, attempts=args.attempts)


if __name__ == "__main__":
    main()
