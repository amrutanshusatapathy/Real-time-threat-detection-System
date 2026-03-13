from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..schemas import AlertCreate, Severity
from .ml_models import Models, predict
from .rules import RuleHit, detect_rules


@dataclass
class DetectionResult:
    alert: AlertCreate | None
    layer: str
    notes: str


def _sev_from_anomaly(score: float) -> Severity:
    if score >= 0.92:
        return "CRITICAL"
    if score >= 0.85:
        return "HIGH"
    if score >= 0.75:
        return "MEDIUM"
    return "LOW"


def run_detection(models: Models, features: dict) -> list[DetectionResult]:
    """Runs 3 layers and returns 0..N alerts.

    - Layer 1: rules
    - Layer 2: IsolationForest anomaly score
    - Layer 3: RandomForest attack classification
    """

    results: list[DetectionResult] = []

    # Layer 1
    rule_hits: list[RuleHit] = detect_rules(features)
    for h in rule_hits:
        results.append(DetectionResult(alert=h.alert, layer="rules", notes=h.reason))

    # Layer 2
    score, attack = predict(models, features)
    if score >= 0.82:
        ts = datetime.fromisoformat(features["ts"])
        results.append(
            DetectionResult(
                alert=AlertCreate(
                    ts=ts,
                    src_ip=features["src_ip"],
                    dst_ip=features.get("dst_ip"),
                    dst_port=features.get("dst_port"),
                    attack_type="Anomaly",
                    severity=_sev_from_anomaly(score),
                    anomaly_score=score,
                    details={"layer": "isolation_forest", "score": score, "features": features},
                ),
                layer="anomaly",
                notes="IsolationForest score crossed threshold",
            )
        )

    # Layer 3 (only if something looks suspicious)
    if rule_hits or score >= 0.78:
        ts = datetime.fromisoformat(features["ts"])

        # Promote to a classification alert only if it's not purely normal
        if attack != "Normal Traffic":
            results.append(
                DetectionResult(
                    alert=AlertCreate(
                        ts=ts,
                        src_ip=features["src_ip"],
                        dst_ip=features.get("dst_ip"),
                        dst_port=features.get("dst_port"),
                        attack_type=attack,
                        severity="HIGH" if (score >= 0.85 or rule_hits) else "MEDIUM",
                        anomaly_score=score,
                        details={"layer": "random_forest", "predicted": attack, "score": score},
                    ),
                    layer="classification",
                    notes="RandomForest classified suspicious flow",
                )
            )

    # Only return unique attack_type per src_ip per tick-ish (dedupe lightly)
    dedup: dict[tuple[str, str], DetectionResult] = {}
    for r in results:
        if not r.alert:
            continue
        key = (r.alert.src_ip, r.alert.attack_type)
        dedup[key] = r

    return list(dedup.values())
