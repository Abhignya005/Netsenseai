"""
train_anomaly.py — PHASE 8: unsupervised anomaly detection

Trains an Isolation Forest to learn NORMAL network behavior. The
detector is trained on BENIGN-labeled rows only when labels exist;
without a dataset it cannot train at all (nothing is invented).

Usage (from the netsense/ folder):
    python ml/train_anomaly.py

Saved to ml/models/: isolation_forest.joblib (the scorer uses the
same behavioral feature contract as the classifier — section 11).
"""

import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

ML_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ML_DIR))

from preprocessing import (  # noqa: E402
    MODELS_DIR, discover_csv_files, build_features,
    save_feature_config,
)

BENIGN_LABELS = ("benign", "normal")
# Labels CONTAINING "benign" (e.g. CICIDS2017 "BENIGN", the demo set's
# "SAMPLE-BENIGN") also count as normal traffic.
BENIGN_SUBSTRING = "benign"


def load_dataset(files):
    """Load + concatenate CSVs, normalizing column names (§3)."""
    frames = []
    for path in files:
        print(f"  loading {path.name} …")
        frame = pd.read_csv(path, low_memory=False)
        frame.columns = [str(col).strip() for col in frame.columns]
        frames.append(frame)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def main():
    print("=" * 50)
    print("NetSense ML Training — Anomaly Detection (Isolation Forest)")
    print("=" * 50)

    files = discover_csv_files()
    if not files:
        print("\nNo CSV files found in ml/data/ — see ml/README.md.")
        print("Nothing was trained.")
        return 1

    dataset = load_dataset(files)
    print(f"\nDataset rows: {len(dataset):,}")

    # Same rule as the classifier: raw dataset in, behavioral features
    # out — labels (used to select BENIGN rows) stay untouched strings.
    features, labels = build_features(dataset)

    # Train on NORMAL traffic only, so 'normal' is actually learned (§10).
    if labels is not None:
        lowered = labels.str.lower()
        benign_mask = lowered.isin(BENIGN_LABELS) | lowered.str.contains(
            BENIGN_SUBSTRING, na=False
        )
        if benign_mask.any():
            features = features[benign_mask]
            print(f"Training on {len(features):,} BENIGN rows only.")
        else:
            print("No BENIGN rows found — training on the full dataset.")
    print(f"Feature columns: {list(features.columns)}")

    model = IsolationForest(
        n_estimators=150, contamination=0.05, random_state=42, n_jobs=1,
    )
    print("\nTraining Isolation Forest …")
    model.fit(features)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODELS_DIR / "isolation_forest.joblib")
    save_feature_config()

    # Self-check on TRAINING data: mostly normal by construction.
    sample = features.sample(n=min(1000, len(features)), random_state=42)
    scores = model.score_samples(sample)
    print("\nSanity check on benign sample:")
    print(f"  mean score: {scores.mean():.3f}   (higher = more normal)")

    print("\nAnomaly model saved successfully to ml/models/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
