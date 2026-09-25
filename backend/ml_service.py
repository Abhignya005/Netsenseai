"""
ml_service.py — PHASE 8: ML <-> NetSense integration layer

BRIDGE (sections 13-14)
-----------------------
    Packets -> Phase 4 flows -> flow features -> ML models -> result

* The feature mapping lives HERE: dataset feature names are aligned
  with the live flow fields the Phase 4 engine actually computes,
  WITH the correct units (CICIDS2017 durations/IATs are microseconds).
* A feature live traffic cannot produce is never invented — flows
  with missing fields are skipped honestly ("Unavailable").

BACKGROUND PROCESSING (section 23)
----------------------------------
A small daemon thread analyzes COMPLETED flows every few seconds.
The packet-capture thread only ever does O(1) counter updates, so ML
can never slow capture down. Results are stored in the SQLite
ml_predictions table (section 24) and summarized for the dashboard.
"""

import threading
import time

import sys
from pathlib import Path

ML_DIR = Path(__file__).resolve().parent.parent / "ml"
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from inference import (  # noqa: E402
    analyze_flow, features_available, model_info, model_status,
    reload_models, feature_importance,
)

# Background worker cadence.
ANALYSIS_INTERVAL_SECONDS = 5.0
MAX_STORED_PREDICTIONS = 2000   # newest kept in the ml_predictions table


def flow_to_features(flow_row):
    """Phase 4 flow row -> NetSense ML feature dict (sections 13-14).

    Returns None when a REQUIRED feature is missing/unavailable — the
    caller then skips ML for that flow instead of inventing values.

    Unit alignment with CICIDS2017:
        Flow_Duration  microseconds  <- flow.duration (seconds)
        IAT_Mean/Std   microseconds  <- flow.iat_mean_ms / iat_std_ms
        Byte_Rate      bytes/second  <- flow.byte_rate (already B/s)
    """
    try:
        duration = flow_row.get("duration")
        iat_mean_ms = flow_row.get("iat_mean_ms")
        iat_std_ms = flow_row.get("iat_std_ms")
        if duration is None or iat_mean_ms is None or iat_std_ms is None:
            return None   # e.g. zero-duration flow — nothing to analyze

        features = {
            "Flow_Duration": float(duration) * 1_000_000.0,      # s -> µs
            "Pkt_Count_Fwd": float(flow_row.get("forward_packets") or 0),
            "Pkt_Count_Bwd": float(flow_row.get("backward_packets") or 0),
            "Byte_Rate": float(flow_row.get("byte_rate") or 0.0),
            "Pkt_Rate": float(flow_row.get("packet_rate") or 0.0),
            "IAT_Mean": float(iat_mean_ms) * 1000.0,             # ms -> µs
            "IAT_Std": float(iat_std_ms) * 1000.0,               # ms -> µs
            "SYN_Ratio": float(flow_row.get("syn_ratio") or 0.0),
            "RST_Ratio": float(flow_row.get("rst_ratio") or 0.0),
            "Avg_Pkt_Size": float(flow_row.get("average_packet_size") or 0.0),
        }
        return features if features_available(features) else None
    except Exception:
        return None


class MlService:
    """Owns the background analysis loop and the prediction summary."""

    def __init__(self, flow_engine):
        self.flow_engine = flow_engine
        self._lock = threading.Lock()
        self._seen_flows = set()     # flow signatures already analyzed
        self._thread = None
        self._stop_event = threading.Event()
        self._summary = {"normal": 0, "potentially_anomalous": 0, "classified": 0}

    # ------------------------------------------------------------------
    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _run(self):
        """Background loop: analyze NEW completed flows, never capture."""
        while not self._stop_event.wait(timeout=ANALYSIS_INTERVAL_SECONDS):
            try:
                self.analyze_completed_flows()
            except Exception:
                pass   # one bad flow must never kill the loop

    # ------------------------------------------------------------------
    def _signature(self, flow_row):
        """Stable id so each completed flow is analyzed exactly once."""
        return (
            flow_row.get("source_ip"), flow_row.get("source_port"),
            flow_row.get("destination_ip"), flow_row.get("destination_port"),
            flow_row.get("protocol"), round(flow_row.get("start_time") or 0, 3),
        )

    def analyze_completed_flows(self):
        """Analyze completed flows not seen before (§13, §23)."""
        data = self.flow_engine.query(limit=200, status="COMPLETED")
        for flow_row in data.get("flows", []):
            signature = self._signature(flow_row)
            with self._lock:
                if signature in self._seen_flows:
                    continue
                self._seen_flows.add(signature)
            self.analyze_flow_row(flow_row, store=True)
        # Keep the seen-set bounded (only recent flows matter).
        with self._lock:
            if len(self._seen_flows) > 5000:
                self._seen_flows.clear()

    def analyze_flow_row(self, flow_row, store=True):
        """One flow -> features -> models -> result (+ storage)."""
        features = flow_to_features(flow_row)
        if features is None:
            return None   # honestly skipped — feature unavailable (§13)
        result = analyze_flow(features)

        with self._lock:
            anomaly_status = result["anomaly"]["status"]
            if anomaly_status == "potentially anomalous":
                self._summary["potentially_anomalous"] += 1
            elif anomaly_status == "normal":
                self._summary["normal"] += 1
            if result["classification"]["label"] is not None:
                self._summary["classified"] += 1

        if store and result["classification"]["available"] or result["anomaly"]["available"]:
            try:
                import database

                database.insert_ml_prediction({
                    "flow_id": str(self._signature(flow_row)),
                    "predicted_class": result["classification"]["label"],
                    "confidence": result["classification"]["confidence"],
                    "anomaly_score": result["anomaly"]["score"],
                    "anomaly_status": result["anomaly"]["status"],
                    "model_version": "phase8-v1",
                })
                self._trim_predictions()
            except Exception:
                pass   # storage trouble must never break analysis
        return result

    # ------------------------------------------------------------------
    def _trim_predictions(self):
        try:
            import database

            database.trim_ml_predictions(MAX_STORED_PREDICTIONS)
        except Exception:
            pass

    def summary(self):
        """Dashboard counts (section 22) — only REAL inference results."""
        with self._lock:
            counts = dict(self._summary)
        return counts | {"total": sum(counts.values())}

    def status(self):
        """/api/ml/status body (section 16)."""
        return model_status()

    def info(self):
        """/api/ml/model-info body (section 17)."""
        return model_info()

    def importance(self):
        """Model-derived Random Forest importances (section 20)."""
        return feature_importance()

    def reload(self):
        """Re-read models after (re)training (section 9)."""
        reload_models()


# Shared singleton wired to the Phase 4 flow engine.
from flow_analysis import flow_engine  # noqa: E402

ml_service = MlService(flow_engine)
