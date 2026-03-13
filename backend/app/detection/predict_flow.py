from __future__ import annotations

import argparse
import json
from typing import Any, Dict

from .ml_models import Models, anomaly_score, classify_attack, load_or_train


def _load_features(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Input JSON must be a single object with feature keys")
    return data


def predict(features: Dict[str, Any], models: Models | None = None) -> Dict[str, Any]:
    if models is None:
        models = load_or_train()

    score = anomaly_score(models, features)
    attack = classify_attack(models, features)

    return {
        "anomaly_score": float(score),
        "attack_type": str(attack),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Predict anomaly score and attack type for a single "
            "network flow feature vector using trained models."
        )
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help=(
            "Path to JSON file containing a feature dict with keys "
            "matching the online feature names (e.g. flow_duration_s, "
            "total_packets, avg_packet_size, connection_count_10s, "
            "distinct_dst_ports_10s, syn_count_10s, rst_count_10s)."
        ),
    )

    args = parser.parse_args()

    features = _load_features(args.input)
    models = load_or_train()
    result = predict(features, models)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
