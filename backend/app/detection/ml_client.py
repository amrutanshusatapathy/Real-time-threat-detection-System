from __future__ import annotations

import json
import urllib.request
from typing import Any

from ..config import settings


def predict(features: dict[str, Any], timeout_s: float = 2.0) -> tuple[float, str]:
    """Call the standalone ML service for a single flow prediction.

    Expects ML_SERVICE_URL to be configured (e.g. http://ml:9000).
    Returns (anomaly_score, attack_type).
    """

    if not settings.ml_service_url:
        raise RuntimeError("ML service is not configured (ml_service_url is empty)")

    url = settings.ml_service_url.rstrip("/") + "/predict"
    body = json.dumps({"features": features}).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # nosec - controlled URL
        payload = json.loads(resp.read().decode("utf-8"))

    return float(payload.get("anomaly_score", 0.0)), str(payload.get("attack_type", "Anomaly"))
