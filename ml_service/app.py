from __future__ import annotations

import os
from typing import Any, Dict

import joblib
import numpy as np
from fastapi import FastAPI
from fastapi.responses import Response
from pydantic import BaseModel
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest


FEATURE_COLUMNS = [
    "flow_duration_s",
    "total_packets",
    "total_bytes",
    "avg_packet_size",
    "protocol_code",
    "connection_count_10s",
    "distinct_dst_ports_10s",
    "syn_count_10s",
    "rst_count_10s",
]

ATTACK_LABELS = [
    "Normal Traffic",
    "DDoS",
    "Port Scan",
    "SQL Injection",
    "Brute Force",
    "Botnet",
]


PREDICTIONS_TOTAL = Counter(
    "ml_predictions_total",
    "Total predictions served by the ML service",
)


def _protocol_code(value: object) -> float:
    if value is None:
        return 3.0

    if isinstance(value, (int, float, np.integer, np.floating)):
        iv = int(value)
        if iv == 6:
            return 0.0
        if iv == 17:
            return 1.0
        if iv == 1:
            return 2.0
        return 3.0

    s = str(value).strip().upper()
    if s == "TCP":
        return 0.0
    if s == "UDP":
        return 1.0
    if s == "ICMP":
        return 2.0
    return 3.0


def _vectorize(features: Dict[str, Any]) -> np.ndarray:
    out: list[float] = []
    for c in FEATURE_COLUMNS:
        if c == "protocol_code":
            out.append(_protocol_code(features.get("protocol_code", features.get("protocol"))))
        else:
            out.append(float(features.get(c, 0.0)))
    return np.array(out, dtype=np.float32)


class PredictRequest(BaseModel):
    features: Dict[str, Any]


class PredictResponse(BaseModel):
    anomaly_score: float
    attack_type: str


def _load_models() -> tuple[object, object]:
    models_dir = os.getenv("MODELS_DIR", "/models")
    iso_path = os.path.join(models_dir, "isolation_forest.joblib")
    clf_path = os.path.join(models_dir, "random_forest.joblib")

    if not os.path.exists(iso_path) or not os.path.exists(clf_path):
        raise FileNotFoundError(
            f"Missing model files in {models_dir}. Expected {iso_path} and {clf_path}."
        )

    iso = joblib.load(iso_path)
    clf = joblib.load(clf_path)
    return iso, clf


app = FastAPI(title="Threat Detection ML Service")

_iso: object | None = None
_clf: object | None = None


@app.on_event("startup")
def _startup() -> None:
    global _iso, _clf
    _iso, _clf = _load_models()


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest) -> PredictResponse:
    global _iso, _clf
    if _iso is None or _clf is None:
        _iso, _clf = _load_models()

    x = _vectorize(req.features).reshape(1, -1)

    # IsolationForest: higher score => more normal. We'll invert to anomaly.
    iso = _iso
    if hasattr(iso, "score_samples"):
        normal_score = float(iso.score_samples(x)[0])
    elif hasattr(iso, "named_steps") and "model" in iso.named_steps:
        x_t = x
        if "imputer" in iso.named_steps:
            x_t = iso.named_steps["imputer"].transform(x_t)
        if "scaler" in iso.named_steps:
            x_t = iso.named_steps["scaler"].transform(x_t)
        normal_score = float(iso.named_steps["model"].score_samples(x_t)[0])
    else:
        raise TypeError("Unsupported IsolationForest model type")

    anomaly_score = float(1.0 / (1.0 + np.exp(2.5 * normal_score)))

    pred_idx = int(_clf.predict(x)[0])
    attack_type = ATTACK_LABELS[pred_idx] if 0 <= pred_idx < len(ATTACK_LABELS) else "Anomaly"

    PREDICTIONS_TOTAL.inc()

    return PredictResponse(anomaly_score=anomaly_score, attack_type=attack_type)
