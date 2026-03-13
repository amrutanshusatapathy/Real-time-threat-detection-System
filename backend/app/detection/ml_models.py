from __future__ import annotations

import os
from dataclasses import dataclass

import joblib
import numpy as np
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import IsolationForest

from ..config import settings
from . import ml_client


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


# Ordered list of attack/traffic classes used by the classifier.
# Keep this in sync with the CICIDS2018 training pipeline.
ATTACK_LABELS = [
    "Normal Traffic",
    "DDoS",
    "Port Scan",
    "SQL Injection",
    "Brute Force",
    "Botnet",
]


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _protocol_code(value: object) -> float:
    """Encode protocol into a small numeric space.

    Accepts common strings (TCP/UDP/ICMP/OTHER) or IANA protocol numbers
    (6/17/1). Unknowns map to 3 (OTHER).
    """

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


def vectorize(features: dict) -> np.ndarray:
    out: list[float] = []
    for c in FEATURE_COLUMNS:
        if c == "protocol_code":
            out.append(_protocol_code(features.get("protocol_code", features.get("protocol"))))
        else:
            out.append(float(features.get(c, 0.0)))
    return np.array(out, dtype=np.float32)


def build_training_set() -> tuple[np.ndarray, np.ndarray]:
    """Synthetic labeled training set for hackathon demos.

    RandomForest needs labels; we generate a simple dataset that separates classes.
    """

    rng = np.random.default_rng(7)

    rows: list[list[float]] = []
    labels: list[int] = []

    def add(n: int, label: int, base: list[float], noise: list[float]) -> None:
        for _ in range(n):
            row = [max(0.0, b + float(rng.normal(0, s))) for b, s in zip(base, noise)]
            rows.append(row)
            labels.append(label)

    # Columns:
    # duration, total_packets, total_bytes, avg_size, protocol_code, conn, distinct_ports, syn, rst

    # DDoS: many packets/bytes, larger sizes, higher conn count (mostly UDP)
    add(
        700,
        1,
        [0.4, 180, 180 * 950, 950, 1, 45, 6, 18, 2],
        [0.25, 45, 60_000, 240, 0.2, 14, 3, 8, 2],
    )

    # Port Scan: high distinct ports + syn (TCP)
    add(
        700,
        2,
        [0.8, 45, 45 * 120, 120, 0, 30, 28, 38, 3],
        [0.5, 15, 3_000, 50, 0.2, 10, 6, 10, 2],
    )

    # SQLi: fewer packets but moderate size (proxy for app payload) + connections
    add(
        700,
        3,
        [1.8, 28, 28 * 700, 700, 0, 18, 4, 10, 2],
        [0.8, 10, 6_000, 180, 0.2, 6, 3, 6, 2],
    )

    # Brute Force: high syn and connections to a single port (distinct_ports low)
    add(
        700,
        4,
        [1.2, 60, 60 * 180, 180, 0, 34, 2, 44, 6],
        [0.6, 18, 4_000, 80, 0.2, 10, 1.5, 14, 4],
    )

    # Botnet: moderate bursts, mixed protocol (OTHER)
    add(
        700,
        5,
        [2.2, 75, 75 * 420, 420, 3, 22, 5, 12, 4],
        [0.9, 25, 10_000, 160, 0.4, 8, 3, 6, 3],
    )

    # Normal Traffic
    add(
        900,
        0,
        [1.4, 18, 18 * 320, 320, 0, 6, 2, 3, 1],
        [0.9, 10, 3_000, 150, 0.2, 4, 1.5, 3, 1.5],
    )

    X = np.array(rows, dtype=np.float32)
    y = np.array(labels, dtype=np.int64)
    return X, y


@dataclass
class Models:
    # These may be raw sklearn estimators or sklearn Pipelines.
    iso: object
    clf: object


def load_or_train() -> Models:
    _ensure_dir(settings.models_dir)

    iso_path = os.path.join(settings.models_dir, "isolation_forest.joblib")
    clf_path = os.path.join(settings.models_dir, "random_forest.joblib")

    iso: object
    clf: object

    if os.path.exists(iso_path):
        iso = joblib.load(iso_path)
    else:
        # Train IsolationForest on synthetic "normal" distribution near low counts
        rng = np.random.default_rng(3)
        X_norm = np.stack(
            [
                rng.uniform(0.1, 3.0, 3000),
                rng.integers(1, 35, 3000),
                rng.integers(500, 40_000, 3000),
                rng.uniform(60, 800, 3000),
                rng.choice([0.0, 1.0, 2.0, 3.0], 3000, p=[0.6, 0.25, 0.05, 0.1]),
                rng.integers(1, 18, 3000),
                rng.integers(1, 8, 3000),
                rng.integers(0, 20, 3000),
                rng.integers(0, 6, 3000),
            ],
            axis=1,
        ).astype(np.float32)

        iso = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
                (
                    "model",
                    IsolationForest(
                        n_estimators=220,
                        contamination=0.04,
                        random_state=7,
                    ),
                ),
            ]
        )
        iso.fit(X_norm)
        joblib.dump(iso, iso_path)

    if os.path.exists(clf_path):
        clf = joblib.load(clf_path)
    else:
        X, y = build_training_set()
        clf = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
                (
                    "model",
                    RandomForestClassifier(
                        n_estimators=220,
                        random_state=7,
                        class_weight="balanced",
                    ),
                ),
            ]
        )
        clf.fit(X, y)
        joblib.dump(clf, clf_path)

    return Models(iso=iso, clf=clf)


def anomaly_score(models: Models, features: dict) -> float:
    x = vectorize(features).reshape(1, -1)
    iso = models.iso

    # IsolationForest: higher score => more normal. We'll invert to anomaly.
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

    # map roughly into [0,1]
    return float(1.0 / (1.0 + np.exp(2.5 * normal_score)))


def classify_attack(models: Models, features: dict) -> str:
    x = vectorize(features).reshape(1, -1)
    pred = int(models.clf.predict(x)[0])
    return ATTACK_LABELS[pred] if 0 <= pred < len(ATTACK_LABELS) else "Anomaly"


def predict(models: Models, features: dict) -> tuple[float, str]:
    """Return (anomaly_score, attack_type) for a flow.

    If `settings.ml_service_url` is set, uses the standalone ML service.
    Otherwise uses locally loaded sklearn models.
    """

    if settings.ml_service_url:
        return ml_client.predict(features)

    score = anomaly_score(models, features)
    attack = classify_attack(models, features)
    return score, attack
