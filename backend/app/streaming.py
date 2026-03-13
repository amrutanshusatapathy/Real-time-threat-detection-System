from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Iterable

from redis import Redis

from .config import settings


def xadd_packet(redis: Redis, packet: dict[str, Any]) -> str:
    payload = {"ts": packet.get("ts") or datetime.utcnow().isoformat(), "data": json.dumps(packet)}
    return redis.xadd(settings.stream_packets, payload, maxlen=5000, approximate=True)


def xadd_alert(redis: Redis, alert: dict[str, Any]) -> str:
    payload = {"ts": alert.get("ts") or datetime.utcnow().isoformat(), "data": json.dumps(alert)}
    return redis.xadd(settings.stream_alerts, payload, maxlen=5000, approximate=True)


def publish_live_alert(redis: Redis, alert: dict[str, Any]) -> None:
    redis.publish(settings.channel_live_alerts, json.dumps(alert))


def read_stream(
    redis: Redis,
    stream: str,
    last_id: str,
    count: int,
    block_ms: int,
) -> list[tuple[str, dict[str, str]]]:
    # Returns list of (id, fields)
    resp = redis.xread({stream: last_id}, count=count, block=block_ms)
    if not resp:
        return []
    _, entries = resp[0]
    return [(entry_id, fields) for entry_id, fields in entries]


def parse_stream_entries(entries: Iterable[tuple[str, dict[str, str]]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for _, fields in entries:
        raw = fields.get("data")
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out
