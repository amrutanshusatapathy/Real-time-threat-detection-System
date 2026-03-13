from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime

from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError

from .config import settings
from .db import db_session
from .detection.ml_models import load_or_train
from .detection.pipeline import run_detection
from .redis_client import get_redis
from .repository import create_alert, create_incident, upsert_blocked_ip
from .schemas import AlertCreate, PacketEvent
from .state import RollingWindowState
from .streaming import parse_stream_entries, publish_live_alert, read_stream, xadd_alert
from .metrics import (
    BLOCKED_IP_EVENTS_TOTAL,
    BLOCKLIST_SIZE,
    BYTES_TOTAL,
    DETECTED_ATTACKS_TOTAL,
    PACKETS_TOTAL,
    PACKET_RATE_PPS,
)


@dataclass
class WorkerState:
    last_id: str = "$"


def _parse_packet(obj: dict) -> PacketEvent | None:
    try:
        return PacketEvent.model_validate(obj)
    except Exception:
        return None


def _severity_rank(sev: str) -> int:
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(sev, 0)


def _automated_response(redis: Redis, alert: AlertCreate) -> bool:
    # High severity -> block
    if _severity_rank(alert.severity) < 2:
        return False

    reason = f"auto-response: {alert.attack_type} ({alert.severity})"
    redis.sadd(settings.blocklist_set, alert.src_ip)
    BLOCKED_IP_EVENTS_TOTAL.inc()
    with db_session() as session:
        upsert_blocked_ip(session, alert.src_ip, reason=reason)
        create_incident(
            session,
            src_ip=alert.src_ip,
            severity=alert.severity,
            summary=f"{alert.attack_type} detected; IP added to blocklist",
            context={"alert": alert.model_dump()},
        )
    return True


def run_worker_loop() -> None:
    redis = get_redis()

    models = load_or_train()
    rolling = RollingWindowState()
    state = WorkerState(last_id="0-0")

    # rolling network stats window (approx)
    last_stats_t = time.time()
    pkt_count = 0
    byte_count = 0

    print(
        f"[worker] redis={settings.redis_url} stream={settings.stream_packets} alerts={settings.stream_alerts}"
    )

    while True:
        try:
            entries = read_stream(
                redis,
                settings.stream_packets,
                last_id=state.last_id,
                count=settings.worker_batch_count,
                block_ms=settings.worker_poll_block_ms,
            )
        except RedisConnectionError:
            # Redis not available yet; retry until it comes up.
            time.sleep(1.5)
            redis = get_redis()
            continue

        if not entries:
            continue

        state.last_id = entries[-1][0]
        packets = parse_stream_entries(entries)

        for obj in packets:
            pkt = _parse_packet(obj)
            if not pkt:
                continue

            pkt_count += 1
            byte_count += int(pkt.size)
            PACKETS_TOTAL.inc()
            BYTES_TOTAL.inc(int(pkt.size))

            rolling.update(pkt)
            feats = rolling.features_for(pkt)

            results = run_detection(models, feats)

            for res in results:
                if not res.alert:
                    continue

                blocked = _automated_response(redis, res.alert)

                DETECTED_ATTACKS_TOTAL.labels(attack_type=res.alert.attack_type).inc()

                with db_session() as session:
                    db_alert = create_alert(session, res.alert, blocked=blocked)

                payload = {
                    "id": db_alert.id,
                    **res.alert.model_dump(),
                    "blocked": blocked,
                    "layer": res.layer,
                    "notes": res.notes,
                }

                xadd_alert(redis, payload)
                publish_live_alert(redis, payload)

        # Update simple network stats once per second
        now_t = time.time()
        if now_t - last_stats_t >= 1.0:
            elapsed = max(0.2, now_t - last_stats_t)
            pps = int(pkt_count / elapsed)
            mbps = float((byte_count * 8.0) / (elapsed * 1_000_000.0))
            active = int(rolling.active_connections())

            PACKET_RATE_PPS.set(pps)
            try:
                BLOCKLIST_SIZE.set(int(redis.scard(settings.blocklist_set) or 0))
            except Exception:
                # Keep worker resilient if Redis hiccups
                pass

            # Short TTL keeps it self-healing
            redis.set("net:pps", pps, ex=3)
            redis.set("net:bw_mbps", f"{mbps:.2f}", ex=3)
            redis.set("net:active_conns", active, ex=3)

            last_stats_t = now_t
            pkt_count = 0
            byte_count = 0

        # light yield
        time.sleep(0.001)
