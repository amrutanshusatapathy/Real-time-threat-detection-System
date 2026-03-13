from __future__ import annotations

import argparse
import os
from typing import Iterable, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ..config import settings
from .ml_models import FEATURE_COLUMNS, ATTACK_LABELS


RAW_LABEL_COL = "Label"
TIMESTAMP_COL = "Timestamp"


def _load_dataset(paths: Iterable[str]) -> pd.DataFrame:
    frames: list[pd.DataFrame] = []
    for p in paths:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Dataset file not found: {p}")
        df = pd.read_csv(p)
        frames.append(df)
    if not frames:
        raise RuntimeError("No dataset files loaded")
    df_all = pd.concat(frames, ignore_index=True)
    return df_all


def _map_attack_label(raw: str) -> str:
    if raw is None:
        return "Normal Traffic"
    s = str(raw).strip().lower()

    # Normal / benign traffic
    if "benign" in s or "normal" in s:
        return "Normal Traffic"

    # DDoS / DoS-style attacks
    if "ddos" in s or "dos" in s:
        return "DDoS"

    # Port scans
    if "portscan" in s or "port scan" in s:
        return "Port Scan"

    # SQL injection
    if "sql" in s:
        return "SQL Injection"

    # Brute force
    if "brute force" in s or "bruteforce" in s:
        return "Brute Force"

    # Botnet / bots
    if "bot" in s:
        return "Botnet"

    # Fallback to normal if unknown
    return "Normal Traffic"


def _preprocess(df: pd.DataFrame) -> pd.DataFrame:
    # Basic cleaning
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=[RAW_LABEL_COL])

    # Parse timestamp if present
    if TIMESTAMP_COL in df.columns:
        df[TIMESTAMP_COL] = pd.to_datetime(df[TIMESTAMP_COL], errors="coerce")
    else:
        # Some CICIDS2018 releases use different column names; try a few fallbacks.
        for alt in ["Timestamp", "Flow Start Time", "StartTime"]:
            if alt in df.columns:
                df.rename(columns={alt: TIMESTAMP_COL}, inplace=True)
                df[TIMESTAMP_COL] = pd.to_datetime(df[TIMESTAMP_COL], errors="coerce")
                break

    # Feature engineering to match online features used by RollingWindowState
    # These rely on standard CICIDS2018 column names; adjust if your CSV differs.
    # Flow duration in seconds
    if "Flow Duration" in df.columns:
        df["flow_duration_s"] = df["Flow Duration"].astype(float) / 1_000_000.0
    else:
        df["flow_duration_s"] = 0.0

    # Packet counts and sizes
    tot_fwd = df.get("Tot Fwd Pkts", pd.Series(0, index=df.index)).astype(float)
    tot_bwd = df.get("Tot Bwd Pkts", pd.Series(0, index=df.index)).astype(float)
    df["total_packets"] = (tot_fwd + tot_bwd).astype(float)

    len_fwd = df.get("TotLen Fwd Pkts", pd.Series(0, index=df.index)).astype(float)
    len_bwd = df.get("TotLen Bwd Pkts", pd.Series(0, index=df.index)).astype(float)
    df["total_bytes"] = (len_fwd + len_bwd).astype(float)
    df["avg_packet_size"] = df["total_bytes"] / df["total_packets"].clip(lower=1.0)

    # Protocol encoding (categorical -> numeric code)
    # CICIDS typically provides IANA protocol numbers: TCP=6, UDP=17, ICMP=1
    proto_col = None
    for cand in ["Protocol", "protocol"]:
        if cand in df.columns:
            proto_col = cand
            break
    if proto_col is None:
        df["protocol_code"] = 3.0
    else:
        def _encode_proto(v: object) -> float:
            if pd.isna(v):
                return 3.0
            if isinstance(v, (int, float, np.integer, np.floating)):
                iv = int(v)
                if iv == 6:
                    return 0.0
                if iv == 17:
                    return 1.0
                if iv == 1:
                    return 2.0
                return 3.0
            s = str(v).strip().upper()
            if s == "TCP":
                return 0.0
            if s == "UDP":
                return 1.0
            if s == "ICMP":
                return 2.0
            return 3.0

        df["protocol_code"] = df[proto_col].apply(_encode_proto).astype(float)

    # Approximate connection/port/flag features from per-flow statistics
    # These are not a perfect match to the online rolling-window counters
    # but preserve similar semantics for model training.

    # Use flow packets/sec as a proxy for short-term connection intensity when available
    flow_pkts_s_col = None
    for cand in ["Flow Pkts/s", "Flow Packets/s"]:
        if cand in df.columns:
            flow_pkts_s_col = cand
            break
    if flow_pkts_s_col:
        df["connection_count_10s"] = (df[flow_pkts_s_col].astype(float) * 10.0).clip(lower=0.0)
    else:
        df["connection_count_10s"] = df["total_packets"].astype(float)

    # Distinct destination ports in 10s window are not directly available per-flow;
    # use a minimal proxy of 1 connection per distinct port.
    df["distinct_dst_ports_10s"] = 1.0

    # Flag counts per flow approximate 10s SYN/RST activity
    df["syn_count_10s"] = df.get("SYN Flag Count", pd.Series(0, index=df.index)).astype(float)
    df["rst_count_10s"] = df.get("RST Flag Count", pd.Series(0, index=df.index)).astype(float)

    # Map raw labels to consolidated attack classes
    df["attack_type"] = df[RAW_LABEL_COL].apply(_map_attack_label)

    # Drop rows where engineered features are missing
    df = df.dropna(subset=FEATURE_COLUMNS + ["attack_type"]).reset_index(drop=True)

    return df


def _build_feature_and_label_matrices(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    # Feature matrix
    X = df[FEATURE_COLUMNS].astype(float).to_numpy(dtype=np.float32)

    # Binary label for anomaly detection: normal vs attack
    is_normal = df["attack_type"] == "Normal Traffic"
    y_binary = (~is_normal).astype(int).to_numpy(dtype=np.int64)

    # Multiclass labels for RandomForest
    label_to_index = {name: i for i, name in enumerate(ATTACK_LABELS)}
    y_multi = df["attack_type"].map(label_to_index).fillna(label_to_index["Normal Traffic"]).astype(int)
    y_multi_arr = y_multi.to_numpy(dtype=np.int64)

    return X, y_binary, y_multi_arr


def train_models(df: pd.DataFrame) -> Tuple[IsolationForest, RandomForestClassifier]:
    df_proc = _preprocess(df)
    X, y_binary, y_multi = _build_feature_and_label_matrices(df_proc)

    # Isolation Forest on normal traffic only
    X_norm = X[df_proc["attack_type"] == "Normal Traffic"]
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
                    n_jobs=-1,
                ),
            ),
        ]
    )
    iso.fit(X_norm)

    # Random Forest for multiclass attack classification
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_multi,
        test_size=0.2,
        random_state=42,
        stratify=y_multi,
    )

    clf = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            (
                "model",
                RandomForestClassifier(
                    n_estimators=220,
                    random_state=7,
                    class_weight="balanced_subsample",
                    n_jobs=-1,
                ),
            ),
        ]
    )
    clf.fit(X_train, y_train)

    # Evaluation
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="macro", zero_division=0)
    rec = recall_score(y_test, y_pred, average="macro", zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print("RandomForest evaluation on CICIDS2018 test split:")
    print(f"  Accuracy : {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall   : {rec:.4f}")
    print("  Confusion matrix (rows=true, cols=pred):")
    print(cm)

    return iso, clf


def save_models(iso: IsolationForest, clf: RandomForestClassifier, models_dir: str | None = None) -> None:
    out_dir = models_dir or settings.models_dir
    os.makedirs(out_dir, exist_ok=True)

    iso_path = os.path.join(out_dir, "isolation_forest.joblib")
    clf_path = os.path.join(out_dir, "random_forest.joblib")

    joblib.dump(iso, iso_path)
    joblib.dump(clf, clf_path)

    print(f"Saved IsolationForest to {iso_path}")
    print(f"Saved RandomForest to {clf_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train IsolationForest and RandomForest on CICIDS2018")
    parser.add_argument(
        "--data",
        "-d",
        nargs="+",
        required=True,
        help="Path(s) to CICIDS2018 CSV file(s)",
    )
    parser.add_argument(
        "--models-dir",
        "-m",
        default=settings.models_dir,
        help="Directory to store trained models (default: settings.models_dir)",
    )

    args = parser.parse_args()

    df_raw = _load_dataset(args.data)
    iso, clf = train_models(df_raw)
    save_models(iso, clf, models_dir=args.models_dir)


if __name__ == "__main__":
    main()
