from __future__ import annotations

from redis import Redis

from .config import settings


def get_redis() -> Redis:
    # Using sync redis client simplifies Scapy thread + worker usage.
    return Redis.from_url(settings.redis_url, decode_responses=True)
