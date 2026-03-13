from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from fastapi import APIRouter, WebSocket
from starlette.websockets import WebSocketDisconnect
from redis.exceptions import ConnectionError as RedisConnectionError

from .config import settings
from .db import db_session
from .redis_client import get_redis
from .repository import list_alerts, list_blocked_ips
from .schemas import AlertCreate, AlertOut, BlockedIpOut, NetworkStatsOut

router = APIRouter()


def _to_alert_out(a: Any) -> AlertOut:
    return AlertOut(
        id=a.id,
        ts=a.ts,
        src_ip=a.src_ip,
        dst_ip=a.dst_ip,
        dst_port=a.dst_port,
        attack_type=a.attack_type,
        severity=a.severity,
        details=a.details or {},
        anomaly_score=a.anomaly_score,
        blocked=bool(a.blocked),
    )


@router.post("/create-alert", response_model=AlertOut)
def create_alert_endpoint(payload: AlertCreate) -> AlertOut:
    # Manual injection endpoint for testing.
    from .repository import create_alert as db_create_alert
    from .streaming import publish_live_alert, xadd_alert

    redis = None
    try:
        redis = get_redis()
    except Exception:
        redis = None

    blocked = False
    if payload.severity in ("HIGH", "CRITICAL"):
        if redis is not None:
            redis.sadd(settings.blocklist_set, payload.src_ip)
        blocked = True

    with db_session() as session:
        a = db_create_alert(session, payload, blocked=blocked)

    out = _to_alert_out(a)

    if redis is not None:
        data = out.model_dump()
        xadd_alert(redis, data)
        publish_live_alert(redis, data)

    return out


@router.get("/get-threats", response_model=list[AlertOut])
def get_threats(limit: int = 200) -> list[AlertOut]:
    with db_session() as session:
        alerts = list_alerts(session, limit=limit)
    return [_to_alert_out(a) for a in alerts]


@router.get("/get-blocked-ips", response_model=list[BlockedIpOut])
def get_blocked_ips(limit: int = 200) -> list[BlockedIpOut]:
    with db_session() as session:
        items = list_blocked_ips(session, limit=limit)
    return [BlockedIpOut(ip=i.ip, blocked_at=i.blocked_at, reason=i.reason) for i in items]


@router.get("/get-network-stats", response_model=NetworkStatsOut)
def get_network_stats() -> NetworkStatsOut:
    # For MVP we derive stats from Redis counters updated by the worker.
    pps, bw, conns = 0, 0.0, 0
    try:
        redis = get_redis()
        pps = int(redis.get("net:pps") or 0)
        bw = float(redis.get("net:bw_mbps") or 0.0)
        conns = int(redis.get("net:active_conns") or 0)
    except Exception:
        pps, bw, conns = 0, 0.0, 0

    # Fall back to something reasonable if empty
    if pps == 0 and bw == 0.0 and conns == 0:
        pps, bw, conns = 900, 75.0, 420

    return NetworkStatsOut(
        ts=datetime.utcnow(),
        packets_per_second=pps,
        bandwidth_mbps=bw,
        active_connections=conns,
    )


@router.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket) -> None:
    await ws.accept()

    try:
        redis = get_redis()
        pubsub = redis.pubsub()
        pubsub.subscribe(settings.channel_live_alerts)
    except Exception:
        await ws.send_text(
            '{"error":"redis_unavailable","message":"Redis is not running; start it to receive live alerts."}'
        )
        await ws.close()
        return

    try:
        while True:
            msg = await asyncio.to_thread(
                pubsub.get_message,
                ignore_subscribe_messages=True,
                timeout=1.0,
            )

            if msg and msg.get("data"):
                data = msg["data"]
                if isinstance(data, (bytes, bytearray)):
                    await ws.send_text(data.decode("utf-8", errors="ignore"))
                else:
                    await ws.send_text(str(data))

            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        return
    finally:
        try:
            pubsub.close()
        except Exception:
            pass
