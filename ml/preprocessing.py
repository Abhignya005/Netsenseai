"""
preprocessing.py — PHASE 8: reusable ML preprocessing pipeline

WHAT THIS FILE DOES
-------------------
Turns raw CICIDS2017-style CSV files into clean, numerical ML
features. Every step is reusable and beginner-readable:

    1. discover_csv_files()  find the CSVs the user placed in ml/data
    2. load_dataset()        load + concatenate (columns may differ!)
    3. build_features()      map dataset columns -> NetSense features,
                             derive ratios (SYN/RST), clean values
    4. clean_dataframe()     drop unusable columns, fix NaN/inf
    5. make_splits()         stratified train/test split (reproducible)

DATA-LEAKAGE RULE (section 5)
-----------------------------
IP addresses, ports and timestamps are NEVER used as ML features —
they would let the model memorize one environment instead of
learning traffic BEHAVIOR. Only behavioral flow features are used.
"""

import json
import math
from pathlib import Path

import pandas as pd

RANDOM_SEED = 42
TEST_FRACTION = 0.2

ML_DIR = Path(__file__).resolve().parent
DATA_DIR = ML_DIR / "data"
MODELS_DIR = ML_DIR / "models"

# ----------------------------------------------------------------------
# NetSense's canonical behavioral feature set (sections 4 + 14).
# These are the ONLY columns the models are trained on.
# ----------------------------------------------------------------------
FEATURE_NAMES = [
    "Flow_Duration",
    "Pkt_Count_Fwd",
    "Pkt_Count_Bwd",
    "Byte_Rate",
    "Pkt_Rate",
    "IAT_Mean",
    "IAT_Std",
    "SYN_Ratio",
    "RST_Ratio",
    "Avg_Pkt_Size",
]

# ----------------------------------------------------------------------
# Dataset column -> NetSense feature mapping layer (section 4).
# CICIDS2017 uses several aliases across its CSV files; the FIRST
# matching column name wins. Extend this table for other datasets.
# ----------------------------------------------------------------------
COLUMN_ALIASES = {
    "Flow_Duration": ["Flow Duration", "flow_duration", "Duration"],
    "Pkt_Count_Fwd": ["Total Fwd Packets", "Tot Fwd Pkts", "Fwd Packets", "Subflow Fwd Packets"],
    "Pkt_Count_Bwd": ["Total Backward Packets", "Tot Bwd Pkts", "Bwd Packets", "Subflow Bwd Packets"],
    "Byte_Rate": ["Flow Bytes/s", "Flow Bytes Per Second", "Bytes/s"],
    "Pkt_Rate": ["Flow Packets/s", "Flow Packets Per Second", "Packets/s"],
    "IAT_Mean": ["Flow IAT Mean", "Flow IAT Mean (ms)"],
    "IAT_Std": ["Flow IAT Std", "Flow IAT Std (ms)"],
    "SYN_Flag_Count": ["SYN Flag Count", "Tot Fwd Pkts with SYN", "Fwd PSH Flags"],
    "RST_Flag_Count": ["RST Flag Count", "Fwd RST Flags"],
    "Average_Packet_Size": ["Average Packet Size", "Avg Packet Size", "Packet Length Mean"],
}

# Any column containing one of these substrings is dropped outright —
# identifiers and free text are not behavioral features (section 5).
DROP_PATTERNS = ("Source IP", "Destination IP", "Src IP", "Dst IP",
                 "Source Port", "Destination Port", "Src Port", "Dst Port",
                 "Timestamp", "Flow ID")


def discover_csv_files(data_dir=None):
    """Find every CSV the user placed in ml/data (section 2)."""
    directory = Path(data_dir) if data_dir else DATA_DIR
    if not directory.exists():
        return []
    return sorted(directory.glob("*.csv"))


def resolve_columns(dataframe):
    """Map dataset columns onto NetSense's canonical names (§4, §14).

    Returns {canonical_name: actual_column_or_None}. Never guesses:
    an unmatched feature stays None and is simply unavailable.
    """
    columns = {name.strip(): name for name in dataframe.columns}  # exact first
    lowered = {name.strip().lower(): name for name in dataframe.columns}
    resolved = {}
    for canonical, aliases in COLUMN_ALIASES.items():
        resolved[canonical] = next(
            (columns[a] for a in aliases if a in columns),
            next((lowered[a.lower()] for a in aliases if a.lower() in lowered), None),
        )
    # The label column: common CICIDS2017 names, else anything named ~label.
    label = next(
        (columns[a] for a in ("Label", "label", "Label ") if a in columns),
        next((lowered[k] for k in ("label", "class", "attack") if k in lowered), None),
    )
    return resolved, label


def clean_dataframe(dataframe):
    """Drop unusable columns and repair bad numeric values (§3, §29).

    * identifier columns (IPs/ports/timestamps) are removed (§5)
    * +/-inf becomes NaN, NaN becomes 0.0 — a flow with one broken
      field is still usable, it is simply neutral there
    * rows that are ALL NaN are dropped entirely
    """
    frame = dataframe.copy()
    for pattern in DROP_PATTERNS:
        matching = [col for col in frame.columns if pattern.lower() in str(col).lower()]
        frame = frame.drop(columns=matching, errors="ignore")
    frame = frame.apply(pd.to_numeric, errors="coerce")
    frame = frame.replace([float("inf"), float("-inf")], math.nan)
    frame = frame.dropna(how="all")
    return frame.fillna(0.0)


def build_features(raw_frame):
    """Build NetSense's behavioral feature matrix from raw data (§4).

    Returns (features_df, labels_series_or_None). Direct features are
    mapped via resolve_columns(); ratios (SYN/RST per packet) are
    DERIVED here because live flows expose them the same way (§14).
    """
    resolved, label_column = resolve_columns(raw_frame)
    labels = raw_frame[label_column].astype(str).str.strip() if label_column else None

    features = pd.DataFrame(index=raw_frame.index)
    for name in FEATURE_NAMES:
        source = resolved.get(name)
        features[name] = pd.to_numeric(raw_frame[source], errors="coerce") if source else 0.0

    syn = resolved.get("SYN_Flag_Count")
    rst = resolved.get("RST_Flag_Count")
    syn_values = pd.to_numeric(raw_frame[syn], errors="coerce") if syn else 0.0
    rst_values = pd.to_numeric(raw_frame[rst], errors="coerce") if rst else 0.0
    total_packets = (features["Pkt_Count_Fwd"] + features["Pkt_Count_Bwd"]).replace(0, 1)
    features["SYN_Ratio"] = syn_values / total_packets
    features["RST_Ratio"] = rst_values / total_packets

    features = features.replace([float("inf"), float("-inf")], math.nan).fillna(0.0)
    return features, labels


def make_splits(features, labels):
    """Reproducible stratified 80/20 split (§8). Falls back to a plain
    split when a class is too rare to stratify."""
    from sklearn.model_selection import train_test_split

    if labels is None:
        return train_test_split(features, test_size=TEST_FRACTION, random_state=RANDOM_SEED)
    try:
        return train_test_split(
            features, labels,
            test_size=TEST_FRACTION, random_state=RANDOM_SEED, stratify=labels,
        )
    except ValueError:
        return train_test_split(features, labels, test_size=TEST_FRACTION, random_state=RANDOM_SEED)


def save_feature_config(path=None):
    """Persist the feature contract so inference matches training (§6, §9)."""
    config = {
        "features": FEATURE_NAMES,
        "random_seed": RANDOM_SEED,
        "test_fraction": TEST_FRACTION,
    }
    target = Path(path) if path else MODELS_DIR / "feature_config.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config


def load_feature_config(path=None):
    """Load the saved feature contract (or the defaults)."""
    target = Path(path) if path else MODELS_DIR / "feature_config.json"
    if target.exists():
        try:
            return json.loads(target.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"features": FEATURE_NAMES, "random_seed": RANDOM_SEED, "test_fraction": TEST_FRACTION}
