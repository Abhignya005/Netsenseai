"""
train_classifier.py — PHASE 8: supervised traffic classification

Trains a Random Forest on the dataset the user placed in ml/data/
(CICIDS2017 expected). Training is EXPLICIT — it never runs when the
backend starts (section 9).

Usage (from the netsense/ folder):
    python ml/train_classifier.py

Steps (sections 3-9 + 25-26): load -> inspect columns -> clean ->
build behavioral features -> stratified split -> train -> evaluate
(accuracy/precision/recall/F1 + confusion matrix) -> save model,
label encoder and feature config into ml/models/.
"""

import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.preprocessing import LabelEncoder

ML_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ML_DIR.parent / "backend"
sys.path.insert(0, str(ML_DIR))
sys.path.insert(0, str(BACKEND_DIR))

from preprocessing import (  # noqa: E402
    MODELS_DIR, discover_csv_files, build_features,
    make_splits, save_feature_config,
)


def load_dataset(files):
    """Load + concatenate CSVs; columns may differ between files (§3)."""
    frames = []
    for path in files:
        print(f"  loading {path.name} …")
        frame = pd.read_csv(path, low_memory=False)
        frame.columns = [str(col).strip() for col in frame.columns]
        frames.append(frame)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def main():
    print("=" * 50)
    print("NetSense ML Training — Traffic Classification")
    print("=" * 50)

    files = discover_csv_files()
    if not files:
        print("\nNo CSV files found in ml/data/.")
        print("Download CICIDS2017 (or another flow dataset) and place the")
        print("CSV files there — see ml/README.md. Nothing was trained.")
        return 1

    dataset = load_dataset(files)
    print(f"\nDataset rows: {len(dataset):,}")
    print(f"Dataset columns: {len(dataset.columns)}")

    # build_features() maps only KNOWN behavioral columns and cleans
    # them per-feature; the raw dataset is passed so the Label column
    # keeps its original strings (clean_dataframe would coerce it to
    # numbers and destroy the classes).
    features, labels = build_features(dataset)
    if labels is None:
        print("No label column found — a classifier needs labels.")
        return 1

    # Classes come from the DATASET only — never invented (§7, §27).
    class_counts = labels.value_counts()
    print(f"\nClasses in dataset: {len(class_counts)}")
    for name, count in class_counts.items():
        print(f"  {name}: {count:,}")
    usable = class_counts[class_counts >= 2].index
    mask = labels.isin(usable)
    features, labels = features[mask], labels[mask]

    x_train, x_test, y_train, y_test = make_splits(features, labels)
    print(f"\nTraining samples: {len(x_train):,}   Testing samples: {len(x_test):,}")

    encoder = LabelEncoder()
    y_train_encoded = encoder.fit_transform(y_train)
    y_test_encoded = encoder.transform(y_test)

    model = RandomForestClassifier(
        # n_jobs=1: on Windows, parallel worker processes re-import the
        # entry script and can hang inside captured consoles. Single-
        # threaded training is slower but ALWAYS safe and reproducible.
        n_estimators=120, max_depth=16, n_jobs=1, random_state=42, class_weight="balanced_subsample",
    )
    print("\nTraining Random Forest …")
    model.fit(x_train, y_train_encoded)

    predictions = model.predict(x_test)
    average = "weighted" if len(encoder.classes_) > 2 else "binary"
    accuracy = accuracy_score(y_test_encoded, predictions)
    precision = precision_score(y_test_encoded, predictions, average=average, zero_division=0)
    recall = recall_score(y_test_encoded, predictions, average=average, zero_division=0)
    f1 = f1_score(y_test_encoded, predictions, average=average, zero_division=0)

    print("\n" + "-" * 50)
    print("Test-set metrics (never claimed to be perfect — §27):")
    print(f"  Accuracy : {accuracy * 100:.1f}%")
    print(f"  Precision: {precision * 100:.1f}%")
    print(f"  Recall   : {recall * 100:.1f}%")
    print(f"  F1 score : {f1 * 100:.1f}%")
    print("\nConfusion matrix (rows = true class, columns = predicted):")
    print(pd.DataFrame(
        confusion_matrix(y_test_encoded, predictions),
        index=[f"true {c}" for c in encoder.classes_],
        columns=[f"pred {c}" for c in encoder.classes_],
    ).to_string())

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODELS_DIR / "classifier.joblib")
    joblib.dump(encoder, MODELS_DIR / "label_encoder.joblib")
    config = save_feature_config()
    # Metrics are persisted so /api/ml/model-info can show REAL numbers
    # — never invented ones (sections 9, 17, 26, 27).
    import json

    (MODELS_DIR / "training_metrics.json").write_text(
        json.dumps({
            "accuracy": round(float(accuracy), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1": round(float(f1), 4),
            "samples_train": int(len(x_train)),
            "samples_test": int(len(x_test)),
            "classes": [str(c) for c in encoder.classes_],
        }, indent=2),
        encoding="utf-8",
    )
    importances = sorted(
        zip(config["features"], model.feature_importances_),
        key=lambda pair: pair[1], reverse=True,
    )
    print("\nFeature importance (model-derived, section 20):")
    for name, value in importances:
        # ASCII bars: the Windows console cannot print Unicode blocks.
        print(f"  {name:<18} {'#' * max(1, round(value * 40))} {value:.3f}")

    print("\nModels saved successfully to ml/models/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
