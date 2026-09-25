"""
test_phase8.py — Phase 8 ML checks

Runs the FULL pipeline end-to-end on a tiny temporary CSV fixture
(written to a temp dir, never in ml/data, never shown as app data):
missing/infinite values, feature mapping, model training, persistence,
and honest inference. Everything else is offline logic checks.

Run from the `backend` folder:
    python test_phase8.py
"""

import importlib
import json
import sys
import tempfile
import time
from pathlib import Path

import pandas as pd

ML_DIR = Path(__file__).resolve().parent.parent / "ml"
BACKEND = Path(__file__).resolve().parent
sys.path.insert(0, str(ML_DIR))
sys.path.insert(0, str(BACKEND))

import preprocessing  # noqa: E402
from flow_analysis import FlowEngine, flow_key  # noqa: E402

CHECKS = []


def check(name, condition):
    CHECKS.append((name, bool(condition)))
    print(("PASS" if condition else "FAIL"), "-", name)


# ======================================================================
# Preprocessing (§3, §5, §29): cleaning + mapping
# ======================================================================
dirty = pd.DataFrame({
    "Source IP": ["10.0.0.1"] * 3,
    "Destination Port": [80, 443, 22],
    "Flow Duration": [1000, float("inf"), 3000],
    "Total Fwd Packets": [1, 1, 1],
    "Total Backward Packets": [1, 1, 1],
    "Flow Bytes/s": [1e12, 5.0, float("-inf")],
    "Flow IAT Mean": [10.0, None, 30.0],
    "Label": ["BENIGN", "BENIGN", "DoS"],
})
cleaned = preprocessing.clean_dataframe(dirty)
check("identifier columns dropped (§5)", "Source IP" not in cleaned.columns
      and "Destination Port" not in cleaned.columns)
check("infinite -> 0", cleaned["Flow Bytes/s"].iloc[2] == 0.0)
check("finite extreme kept", cleaned["Flow Bytes/s"].iloc[0] == 1e12)
check("missing -> 0", cleaned["Flow IAT Mean"].iloc[1] == 0.0)
check("valid values kept", cleaned["Flow Duration"].iloc[0] == 1000.0)

features, labels = preprocessing.build_features(dirty)
check("10 canonical features built", list(features.columns) == preprocessing.FEATURE_NAMES)
check("SYN ratio derived (no flag column -> 0)", features["SYN_Ratio"].sum() == 0.0)
check("labels passed through", list(labels) == ["BENIGN", "BENIGN", "DoS"])

resolved, label_col = preprocessing.resolve_columns(dirty)
check("Flow Duration mapped", resolved["Flow_Duration"] == "Flow Duration")
check("Byte Rate mapped", resolved["Byte_Rate"] == "Flow Bytes/s")
check("label column found", label_col == "Label")

# Ratios with flag counts present.
with_flags = dirty.copy()
with_flags["SYN Flag Count"] = [1, 0, 2]
features_flags, _ = preprocessing.build_features(with_flags)
check("SYN ratio computed from flag counts",
      features_flags["SYN_Ratio"].iloc[2] == 1.0)   # 2 SYN / 2 packets

# ======================================================================
# Flow engine ML counters (§13): IAT + flags (additive to Phase 4)
# ======================================================================
engine = FlowEngine()
NOW = 1000.0
record = {
    "timestamp": NOW, "source_ip": "192.168.1.10", "destination_ip": "142.x.x.x",
    "source_port": 52341, "destination_port": 443, "protocol": "TCP",
    "size": 600, "tcp_flags": "SYN",
}
engine.observe(dict(record, timestamp=NOW))
engine.observe(dict(record, timestamp=NOW + 0.5, tcp_flags="ACK"))
engine.observe(dict(record, timestamp=NOW + 1.5, tcp_flags="RST"))
flow_row = list(engine.active.values())[0].to_row()
# Gaps: 0.5 s and 1.0 s -> mean 0.75 s, streaming std 0.25 s.
check("IAT mean ~750 ms", flow_row["iat_mean_ms"] is not None
      and abs(flow_row["iat_mean_ms"] - 750.0) < 1)
check("IAT std ~250 ms", flow_row["iat_std_ms"] is not None
      and abs(flow_row["iat_std_ms"] - 250.0) < 1)
check("syn_ratio 1/3", abs(flow_row["syn_ratio"] - 1 / 3) < 0.001)
check("rst_ratio 1/3", abs(flow_row["rst_ratio"] - 1 / 3) < 0.001)
check("Phase 4 metrics intact", flow_row["total_packets"] == 3
      and flow_row["total_bytes"] == 1800)

# ======================================================================
# Feature mapping live->ML (§14): unit alignment
# ======================================================================
import ml_service as ml_service_module  # noqa: E402

ml_features = ml_service_module.flow_to_features(flow_row)
check("live flow -> 10 ML features", ml_features is not None
      and len(ml_features) == 10)
check("duration converted s -> µs", ml_features["Flow_Duration"] == 1_500_000.0)
check("IAT converted ms -> µs", abs(ml_features["IAT_Mean"] - 750_000.0) < 1000)

zero_duration = dict(flow_row, duration=0)
check("zero-duration flow is still valid (0 µs, not missing)",
      ml_service_module.flow_to_features(zero_duration) is not None)
check("missing IAT -> flow skipped honestly",
      ml_service_module.flow_to_features(dict(flow_row, iat_mean_ms=None)) is None)

# ======================================================================
# Inference honesty WITHOUT trained models (§16, §27)
# ======================================================================
import inference  # noqa: E402

status = inference.model_status()
if status["classifier_available"] or status["anomaly_model_available"]:
    print("(models already trained — skipping unavailable-model checks)")
else:
    result = inference.analyze_flow(ml_features)
    check("no models -> classification unavailable",
          result["classification"]["label"] is None
          and result["classification"]["available"] is False)
    check("no models -> anomaly unavailable",
          result["anomaly"]["status"] is None)

check("incomplete features -> skipped", not inference.features_available(
    {name: 1.0 for name in preprocessing.FEATURE_NAMES[:-1]}))

# ======================================================================
# FULL PIPELINE: train on a temp fixture, then infer (§7-§12, §29)
# ======================================================================
with tempfile.TemporaryDirectory() as tmp:
    data_dir = Path(tmp) / "data"
    models_dir = Path(tmp) / "models"
    data_dir.mkdir()
    models_dir.mkdir()

    rows = []
    rng = 12345
    for i in range(220):          # BENIGN: slow, small, calm
        rng = (rng * 1103515245 + 12345) % 2 ** 31
        rows.append({
            "Flow Duration": 500_000 + rng % 100_000,
            "Total Fwd Packets": 8 + rng % 5, "Total Backward Packets": 6 + rng % 5,
            "Flow Bytes/s": 5000 + rng % 2000, "Flow Packets/s": 12 + rng % 6,
            "Flow IAT Mean": 40_000 + rng % 10_000, "Flow IAT Std": 5_000 + rng % 3_000,
            "SYN Flag Count": 1, "RST Flag Count": 0,
            "Average Packet Size": 300 + rng % 100, "Label": "BENIGN",
        })
    for i in range(60):           # DoS-like: fast, big, aggressive
        rows.append({
            "Flow Duration": 2_000_000 + i * 1000,
            "Total Fwd Packets": 900 + i, "Total Backward Packets": 2,
            "Flow Bytes/s": 900_000 + i * 100, "Flow Packets/s": 900 + i,
            "Flow IAT Mean": 100 + i, "Flow IAT Std": 20 + i,
            "SYN Flag Count": 400 + i, "RST Flag Count": 100 + i,
            "Average Packet Size": 1400 + i, "Label": "DoS",
        })
    pd.DataFrame(rows).to_csv(data_dir / "fixture.csv", index=False)

    original_data = preprocessing.DATA_DIR
    original_models = preprocessing.MODELS_DIR
    original_inference_models = inference.MODELS_DIR
    preprocessing.DATA_DIR = data_dir
    preprocessing.MODELS_DIR = models_dir
    inference.MODELS_DIR = models_dir   # inference must read the SAME dir
    try:
        import train_anomaly
        import train_classifier

        importlib.reload(train_classifier)
        importlib.reload(train_anomaly)
        train_classifier.DATA_DIR = data_dir     # modules read their own
        train_classifier.MODELS_DIR = models_dir
        train_anomaly.MODELS_DIR = models_dir

        check("classifier trains on fixture", train_classifier.main() == 0)
        check("anomaly model trains on fixture", train_anomaly.main() == 0)
        check("model files persisted",
              (models_dir / "classifier.joblib").exists()
              and (models_dir / "isolation_forest.joblib").exists()
              and (models_dir / "training_metrics.json").exists())
        metrics = json.loads((models_dir / "training_metrics.json").read_text())
        check("metrics are real numbers", 0.0 <= metrics["accuracy"] <= 1.0)

        # Inference against the freshly trained models.
        inference.reload_models()
        trained = inference._load_models()
        check("inference loads trained models",
              trained["classifier"] is not None and trained["isolation_forest"] is not None)

        calm = dict(ml_features)
        calm.update({
            "Flow_Duration": 500_000.0, "Pkt_Count_Fwd": 10, "Pkt_Count_Bwd": 8,
            "Byte_Rate": 6000.0, "Pkt_Rate": 14.0, "IAT_Mean": 45_000.0,
            "IAT_Std": 6_000.0, "SYN_Ratio": 0.05, "RST_Ratio": 0.0,
            "Avg_Pkt_Size": 350.0,
        })
        calm_result = inference.analyze_flow(calm)
        print("  (calm result)", calm_result)
        if calm_result["classification"]["label"] is None:
            print("  (diagnostic)", inference.last_error)
        check("calm flow classified with real confidence",
              calm_result["classification"]["label"] in ("BENIGN", "DoS")
              and 0.0 <= (calm_result["classification"]["confidence"] or 0) <= 1.0)
        check("calm flow anomaly score is a number",
              isinstance(calm_result["anomaly"]["score"], float))

        flood = dict(calm, Pkt_Rate=1500.0, Byte_Rate=1_200_000.0,
                     SYN_Ratio=0.9, RST_Ratio=0.4, IAT_Mean=500.0)
        flood_result = inference.detect_anomaly(flood)
        check("aggressive flow scores more anomalous than calm one",
              flood_result["score"] is not None
              and calm_result["anomaly"]["score"] is not None
              and flood_result["score"] >= calm_result["anomaly"]["score"])
    finally:
        preprocessing.DATA_DIR = original_data
        preprocessing.MODELS_DIR = original_models
        inference.MODELS_DIR = original_inference_models
        inference.reload_models()   # restore the real models' cache

# ======================================================================
failed = [name for name, ok in CHECKS if not ok]
print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed.")
if failed:
    print("FAILED:", *failed, sep="\n  - ")
    raise SystemExit(1)
