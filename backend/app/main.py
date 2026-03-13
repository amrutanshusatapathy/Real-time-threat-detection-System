from __future__ import annotations

import threading

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from .api import router
from .capture.scapy_capture import start_capture_thread
from .config import settings
from .init_db import init_db
from .worker import run_worker_loop

app = FastAPI(title=settings.app_name)


def _parse_cors_origins(value: str) -> list[str]:
    raw = (value or "").strip()
    if not raw or raw == "*":
        return ["*"]
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def _parse_cors_list(value: str) -> list[str]:
    raw = (value or "").strip()
    if not raw:
        return ["*"]
    if raw == "*":
        return ["*"]
    return [item.strip() for item in raw.split(",") if item.strip()]


_cors_origins = _parse_cors_origins(settings.cors_allow_origins)
_cors_allow_credentials = bool(settings.cors_allow_credentials) and _cors_origins != ["*"]

# Demo-friendly default: if we're not using credentials/cookies, allow any Origin.
# This avoids common deployment footguns where the frontend domain changes (Vercel previews, etc.).
_cors_allow_origin_regex = None
if not _cors_allow_credentials:
    _cors_allow_origin_regex = ".*"

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_origin_regex=_cors_allow_origin_regex,
    allow_credentials=_cors_allow_credentials,
    allow_methods=_parse_cors_list(settings.cors_allow_methods),
    allow_headers=_parse_cors_list(settings.cors_allow_headers),
)

app.include_router(router)

_worker_thread: threading.Thread | None = None
_capture_thread: threading.Thread | None = None


@app.on_event("startup")
def on_startup() -> None:
    global _worker_thread, _capture_thread

    init_db()

    if _worker_thread is None or not _worker_thread.is_alive():
        _worker_thread = threading.Thread(
            target=run_worker_loop,
            name="threat-worker",
            daemon=True,
        )
        _worker_thread.start()

    if settings.capture_enabled:
        _capture_thread = start_capture_thread()


@app.get("/")
def root() -> dict:
    return {
        "name": settings.app_name,
        "redis": settings.redis_url,
        "capture_enabled": settings.capture_enabled,
        "capture_iface": settings.capture_iface,
        "endpoints": [
            "/create-alert",
            "/get-threats",
            "/get-network-stats",
            "/get-blocked-ips",
            "/ws/alerts",
        ],
    }


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
