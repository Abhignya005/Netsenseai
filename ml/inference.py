"""
inference.py — PHASE 8: ML inference

Loads the models saved by the training scripts and answers two
questions about ONE flow's behavioral features (section 12):

    classify_flow(features)  -> {label, confidence} | {"label": None}
    detect_anomaly(features) -> {status, score}
    analyze_flow(features)   -> both, in one call

HONESTY RULES (§1, §27)
-----------------------
* Missing models -> available=False; the caller shows "Not available".
  Nothing is ever fabricated.
* confidence is returned ONLY from real predict_proba probabilities.
* Anomaly wording is careful: "normal" / "potentially anomalous" —
  NEVER "attack".
"""

import sys
from pathlib import Path

import joblib

ML_DIR = Path(__file__).resolve().parent
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from preprocessing import FEATURE_NAMES, load_feature_config  # noqa: E402

MODELS_DIR = ML_DIR / "models"

# Score threshold above which a flow is called potentially anomalous.
# Isolation Forest score_samples() returns NEGATIVE values, higher =
# more normal; the raw score is negated so that HIGHER = MORE anomalous.
ANOMALY_THRESHOLD = 0.0

_models = None   # lazy-loaded cache
last_error = None   # diagnostic for beginners: WHY is a result unavailable?


def _load_models():
    """Load models once; remember exactly what is available (§16)."""
    global _models
    if _models is not None:
        return _models
    classifier_path = MODELS_DIR / "classifier.joblib"
    encoder_path = MODELS_DIR / "label_encoder.joblib"
    forest_path = MODELS_DIR / "isolation_forest.joblib"
    _models = {
        "classifier": joblib.load(classifier_path) if classifier_path.exists() else None,
        "label_encoder": joblib.load(encoder_path) if encoder_path.exists() else None,
        "isolation_forest": joblib.load(forest_path) if forest_path.exists() else None,
    }
    return _models


def reload_models():
    """Drop the cache so newly trained models are picked up."""
    global _models
    _models = None


def features_available(feature_vector):
    """True when every required feature is a finite number (§13).

    Live flows that lack a feature are NEVER padded with invented
    values — inference is simply skipped for them.
    """
    try:
        return all(
            isinstance(feature_vector.get(name), (int, float))
            and feature_vector[name] == feature_vector[name]          # not NaN
            and abs(feature_vector[name]) != float("inf")
            for name in FEATURE_NAMES
        )
    except Exception:
        return False


def _ordered_vector(feature_vector):
    """Feature dict -> ordered numeric list in the TRAINING order."""
    return [float(feature_vector[name]) for name in FEATURE_NAMES]


def classify_flow(feature_vector):
    """Supervised prediction: {label, confidence} (§12, §18).

    Returns {"label": None, "confidence": None} when the classifier is
    unavailable or the features are incomplete — never a fake class.
    """
    models = _load_models()
    classifier = models["classifier"]
    encoder = models["label_encoder"]
    if classifier is None or encoder is None or not features_available(feature_vector):
        return {"label": None, "confidence": None, "available": False}

    global last_error
    try:
        import numpy as np

        probabilities = classifier.predict_proba(np.asarray([_ordered_vector(feature_vector)]))[0]
        best_index = int(probabilities.argmax())
        return {
            "label": str(encoder.inverse_transform([best_index])[0]),
            "confidence": round(float(probabilities[best_index]), 4),
            "available": True,
        }
    except Exception as error:
        last_error = f"classification failed: {error}"
        return {"label": None, "confidence": None, "available": False}


def detect_anomaly(feature_vector):
    """Unsupervised anomaly check: {status, score} (§10, §12).

    score = -(Isolation Forest score): HIGHER = MORE anomalous.
    Status wording is deliberately cautious (§27).
    """
    models = _load_models()
    forest = models["isolation_forest"]
    if forest is None or not features_available(feature_vector):
        return {"status": None, "score": None, "available": False}

    try:
        import numpy as np

        raw_score = float(forest.score_samples(np.asarray([_ordered_vector(feature_vector)]))[0])
        score = round(-raw_score, 4)   # negate: higher = more anomalous
        status = "potentially anomalous" if score > ANOMALY_THRESHOLD else "normal"
        return {"status": status, "score": score, "available": True}
    except Exception:
        return {"status": None, "score": None, "available": False}


def analyze_flow(feature_vector):
    """Both models in one call — the shape /api/ml/analyze returns."""
    return {
        "classification": classify_flow(feature_vector),
        "anomaly": detect_anomaly(feature_vector),
    }


def model_status():
    """What is actually available right now (section 16)."""
    models = _load_models()
    config = load_feature_config()
    return {
        "classifier_available": models["classifier"] is not None,
        "anomaly_model_available": models["isolation_forest"] is not None,
        "dataset": "CICIDS2017",
        "features": config.get("features", FEATURE_NAMES),
    }


def feature_importance():
    """Random Forest importances, model-derived only (section 20)."""
    models = _load_models()
    classifier = models["classifier"]
    if classifier is None:
        return None
    try:
        return sorted(
            ({"feature": name, "importance": round(float(value), 4)}
             for name, value in zip(FEATURE_NAMES, classifier.feature_importances_)),
            key=lambda item: item["importance"], reverse=True,
        )
    except Exception:
        return None


def model_info():
    """Everything /api/ml/model-info needs (section 17)."""
    models = _load_models()
    config = load_feature_config()
    classifier = models["classifier"]
    info = {
        "classifier": "Random Forest" if classifier else None,
        "anomaly_model": "Isolation Forest" if models["isolation_forest"] else None,
        "dataset": "CICIDS2017",
        "features": config.get("features", FEATURE_NAMES),
        "feature_count": len(config.get("features", FEATURE_NAMES)),
        "classes": [],
        "metrics": None,
        "training_status": "not trained",
        "shap": "unavailable (feature importance is used instead — §21)",
    }
    if classifier is not None and models["label_encoder"] is not None:
        info["classes"] = [str(c) for c in models["label_encoder"].classes_]
        info["training_status"] = "trained"
        metrics_path = MODELS_DIR / "training_metrics.json"
        if metrics_path.exists():
            try:
                import json

                info["metrics"] = json.loads(metrics_path.read_text(encoding="utf-8"))
            except Exception:
                pass
    return info
