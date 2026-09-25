"""
alerts.py — PHASE 9: intelligent alerts & alert management

PIPELINE (section 1)
--------------------
    Network Traffic -> Packet Analysis -> Flow Analysis
        -> Performance Metrics -> ML Analysis
        -> Rule Engine + ML Results -> Alert Generation
        -> Alert Storage (SQLite) -> Alert Dashboard

HOW IT WORKS
------------
* A tiny background thread builds a SNAPSHOT from the REAL phase
  singletons every EVALUATOR_INTERVAL seconds (section 12: it never
  touches the packet-capture thread).
* The RuleEngine compares the snapshot against CONFIGURABLE
  thresholds. A rule only fires when its input data actually exists —
  missing data never becomes a fake zero (sections: "Do NOT create
  fake alerts").
* Machine-learning alerts come from the Phase 8 ML worker's REAL
  summary (potentially-anomalous flow counts).
* Every alert is worded carefully (section 1): "Potentially anomalous
  behavior", never "this is an attack".
* Cooldown + observed-value growth checks keep the alert list calm:
  the same steady condition does not re-fire every 10 seconds.

STORAGE (section: Alert Storage)
--------------------------------
Alerts are appended to the SQLite `alerts` table (best-effort, like
every other database write in NetSense) and kept in a bounded
in-memory deque for fast API queries.
"""

import json
import threading
import time
from collections import deque
from datetime import datetime, timezone

EVALUATOR_INTERVAL_SECONDS = 10.0   # background snapshot cadence
MAX_MEMORY_ALERTS = 500             # in-memory history is bounded
RESTORE_ON_START = 200              # alerts re-loaded from SQLite


# ----------------------------------------------------------------------
# Default thresholds — all user-configurable at runtime through
# GET/POST /api/alerts/thresholds. Defaults are starting points, NOT
# measurements; the alerts themselves always carry the real values.
# ----------------------------------------------------------------------
DEFAULT_THRESHOLDS = {
    "high_traffic_bytes_per_second": 10_000_000.0,  # 10 MB/s (section 2 example)
    "high_packet_rate_packets_per_second": 500.0,   # section 3 example
    "high_syn_ratio": 0.50,                         # section 4 example
    "high_rst_ratio": 0.25,                         # RSTs are normally rare
    "incomplete_connections": 50,                   # section 6-style count rule
    "cooldown_seconds": 300.0,                      # same rule waits 5 minutes
}

# Smallest TCP-flag packet sample before ratio rules are allowed to
# judge — ratios from 3 packets would be noise, not evidence.
MIN_FLAG_SAMPLE = 50


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def format_bytes_per_second(value):
    """Human-readable B/s (850 Kbps style) for alert messages."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return "Unavailable"
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if abs(value) < 1024.0 or unit == "GB/s":
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} GB/s"


def format_rate(value, unit):
    try:
        return f"{float(value):.1f} {unit}"
    except (TypeError, ValueError):
        return "Unavailable"


class RuleEngine:
    """Compares a real snapshot against configurable thresholds.

    Each rule:
      * bails out honestly when its data is missing (no fake alerts),
      * respects a per-rule cooldown,
      * only re-fires when the observed value GREW meaningfully since
        the last alert for that rule (the signature check below).
    """

    def __init__(self, thresholds=None):
        self._lock = threading.Lock()
        self.thresholds = dict(DEFAULT_THRESHOLDS)
        if thresholds:
            self.thresholds.update({
                k: v for k, v in thresholds.items() if k in DEFAULT_THRESHOLDS
            })
        # rule_id -> {"time": last fire, "value": observed when fired}
        self._last_fired = {}

    # ------------------------------------------------------------------
    def get_thresholds(self):
        with self._lock:
            return dict(self.thresholds)

    def set_thresholds(self, updates):
        """Merge validated updates; unknown keys are ignored."""
        clean = {}
        for key, value in (updates or {}).items():
            if key not in DEFAULT_THRESHOLDS:
                continue
            try:
                number = float(value)
                if number <= 0:
                    continue
                clean[key] = number
            except (TypeError, ValueError):
                continue
        with self._lock:
            self.thresholds.update(clean)
        return self.get_thresholds()

    # ------------------------------------------------------------------
    def _should_fire(self, rule_id, observed_value, now):
        """Cooldown + value-growth gate shared by every rule."""
        with self._lock:
            cooldown = self.thresholds.get("cooldown_seconds", 300.0)
            last = self._last_fired.get(rule_id)
            if last is not None:
                if now - last["time"] < cooldown:
                    return False
                # Same steady value -> not news. Fire again only when the
                # observation grew by >10% (or, for counts, by >= 5).
                previous = last.get("value") or 0.0
                if observed_value is not None and previous:
                    if observed_value <= previous * 1.10 and observed_value - previous < 5:
                        return False
            self._last_fired[rule_id] = {"time": now, "value": observed_value}
        return True

    # ------------------------------------------------------------------
    # RULE G — ML classification results (section 7: classification
    # alerts). Data-driven, never hardcoded: fires when the newest
    # classified flow's predicted class differs from the DOMINANT class
    # among recent predictions — i.e. the classifier now sees a class it
    # has rarely seen before. No class names are invented.
    # ------------------------------------------------------------------
    def _rule_ml_classification(self, snapshot, now):
        ml = snapshot.get("ml")
        if not isinstance(ml, dict):
            return []
        classification = ml.get("latest_classification") or {}
        if not isinstance(classification, dict):
            return []
        label = classification.get("label")
        dominant = classification.get("dominant_class")
        if not label or not dominant or label == dominant:
            return []
        if not self._should_fire("ml_classification", 1.0, now):
            return []
        return [{
            "created_at": _now_iso(),
            "category": "ml_classification",
            "source": "ml",
            "severity": "low",
            "title": "Unusual Traffic Class (ML)",
            "message": (
                f"The classifier labeled the most recent analyzed flow as "
                f"'{label}' while recent traffic was mostly '{dominant}'. "
                f"This is a model prediction — not proof of any behavior."
            ),
            "observed": {
                "predicted_class": label,
                "dominant_recent_class": dominant,
                "confidence": classification.get("confidence"),
            },
            "threshold": None,
            "status": "active",
        }]

    # ------------------------------------------------------------------
    def evaluate(self, snapshot):
        """Run every rule against ONE snapshot; return new alerts."""
        alerts = []
        now = snapshot.get("time") or time.time()
        alerts += self._rule_high_traffic(snapshot, now)
        alerts += self._rule_high_packet_rate(snapshot, now)
        alerts += self._rule_syn_activity(snapshot, now)
        alerts += self._rule_rst_activity(snapshot, now)
        alerts += self._rule_incomplete_connections(snapshot, now)
        alerts += self._rule_ml_anomaly(snapshot, now)
        alerts += self._rule_ml_classification(snapshot, now)
        return alerts

    # ------------------------------------------------------------------
    # RULE A — High traffic (section 2)
    # ------------------------------------------------------------------
    def _rule_high_traffic(self, snapshot, now):
        traffic = snapshot.get("traffic")
        if not traffic:
            return []   # no capture / no data yet -> honestly silent
        bps = traffic.get("bits_per_second")
        byps = traffic.get("bytes_per_second")
        if bps is None or byps is None:
            return []
        threshold = self.thresholds.get("high_traffic_bytes_per_second", 10_000_000.0)
        if byps <= threshold:
            return []
        if not self._should_fire("high_traffic", byps, now):
            return []
        severity = "high" if byps >= threshold * 2 else "medium"
        return [{
            "created_at": _now_iso(),
            "category": "high_traffic",
            "source": "rule",
            "severity": severity,
            "title": "High Traffic Detected",
            "message": (
                f"Observed traffic reached {format_bytes_per_second(byps)} "
                f"({format_rate(bps, 'bps')}). Configured threshold: "
                f"{format_bytes_per_second(threshold)}. This may be normal "
                f"for this network — compare with baseline activity."
            ),
            "observed": {
                "bytes_per_second": round(byps, 1),
                "bits_per_second": round(bps, 1),
            },
            "threshold": threshold,
            "status": "active",
        }]

    # ------------------------------------------------------------------
    # RULE B — High packet rate (section 3)
    # ------------------------------------------------------------------
    def _rule_high_packet_rate(self, snapshot, now):
        traffic = snapshot.get("traffic")
        if not traffic:
            return []
        rate = traffic.get("packets_per_second")
        if rate is None:
            return []
        threshold = self.thresholds.get(
            "high_packet_rate_packets_per_second", 500.0
        )
        if rate <= threshold:
            return []
        if not self._should_fire("high_packet_rate", rate, now):
            return []
        severity = "high" if rate >= threshold * 2 else "medium"
        return [{
            "created_at": _now_iso(),
            "category": "high_packet_rate",
            "source": "rule",
            "severity": severity,
            "title": "High Packet Rate",
            "message": (
                f"Observed packet rate reached {format_rate(rate, 'packets/sec')}. "
                f"Configured threshold: {format_rate(threshold, 'packets/sec')}."
            ),
            "observed": {"packets_per_second": round(rate, 1)},
            "threshold": threshold,
            "status": "active",
        }]

    # ------------------------------------------------------------------
    # RULE C — Unusual SYN activity (section 4)
    # ------------------------------------------------------------------
    def _rule_syn_activity(self, snapshot, now):
        tcp = snapshot.get("tcp")
        if not isinstance(tcp, dict):
            return []
        flags = tcp.get("flag_counts") or {}
        if not isinstance(flags, dict):
            return []
        syn = flags.get("syn", 0)
        total = sum(int(v) for v in flags.values())
        # A ratio needs a meaningful sample — otherwise it is noise.
        if total < MIN_FLAG_SAMPLE or syn == 0:
            return []
        ratio = syn / total
        threshold = self.thresholds.get("high_syn_ratio", 0.50)
        if ratio <= threshold:
            return []
        if not self._should_fire("high_syn_ratio", ratio, now):
            return []
        severity = "high" if ratio >= threshold * 1.5 else "medium"
        return [{
            "created_at": _now_iso(),
            "category": "high_syn_activity",
            "source": "rule",
            "severity": severity,
            "title": "Unusual SYN Activity Detected",
            "message": (
                f"SYN ratio reached {ratio:.2f} across {total} TCP packets "
                f"(threshold {threshold:.2f}). Potentially anomalous "
                f"behavior — this alone does not indicate an attack."
            ),
            "observed": {
                "syn_ratio": round(ratio, 3),
                "syn_packets": syn,
                "tcp_flag_packets": total,
            },
            "threshold": threshold,
            "status": "active",
        }]

    # ------------------------------------------------------------------
    # RULE D — Unusual RST activity (section 5)
    # ------------------------------------------------------------------
    def _rule_rst_activity(self, snapshot, now):
        tcp = snapshot.get("tcp")
        if not isinstance(tcp, dict):
            return []
        flags = tcp.get("flag_counts") or {}
        if not isinstance(flags, dict):
            return []
        rst = flags.get("rst", 0)
        total = sum(int(v) for v in flags.values())
        if total < MIN_FLAG_SAMPLE or rst == 0:
            return []
        ratio = rst / total
        threshold = self.thresholds.get("high_rst_ratio", 0.25)
        if ratio <= threshold:
            return []
        if not self._should_fire("high_rst_ratio", ratio, now):
            return []
        return [{
            "created_at": _now_iso(),
            "category": "high_rst_activity",
            "source": "rule",
            "severity": "medium",
            "title": "Unusual TCP Reset Activity",
            "message": (
                f"TCP RST ratio reached {ratio:.2f} across {total} TCP "
                f"packets (threshold {threshold:.2f}). The observed "
                f"behavior may indicate rejected or refused connections."
            ),
            "observed": {
                "rst_ratio": round(ratio, 3),
                "rst_packets": rst,
                "tcp_flag_packets": total,
            },
            "threshold": threshold,
            "status": "active",
        }]

    # ------------------------------------------------------------------
    # RULE E — Incomplete TCP connections (section 6)
    # ------------------------------------------------------------------
    def _rule_incomplete_connections(self, snapshot, now):
        tcp = snapshot.get("tcp")
        if not tcp:
            return []
        summary = tcp.get("summary") or {}
        incomplete = summary.get("incomplete")
        total = summary.get("total")
        if incomplete is None or not total:
            return []
        threshold = self.thresholds.get("incomplete_connections", 50.0)
        if incomplete <= threshold:
            return []
        if not self._should_fire("incomplete_connections", incomplete, now):
            return []
        severity = "high" if incomplete >= threshold * 2 else "medium"
        return [{
            "created_at": _now_iso(),
            "category": "incomplete_connections",
            "source": "rule",
            "severity": severity,
            "title": "High Number of Incomplete Connections",
            "message": (
                f"{incomplete} TCP connections are in handshake/partial "
                f"states (SYN_SENT, SYN_RECEIVED, INCOMPLETE, PARTIAL) out "
                f"of {total} tracked (threshold {int(threshold)}). Some "
                f"incompleteness is normal for passive monitoring."
            ),
            "observed": {
                "incomplete_connections": incomplete,
                "total_connections": total,
            },
            "threshold": threshold,
            "status": "active",
        }]

    # ------------------------------------------------------------------
    # RULE F — ML anomaly results (section 1: ML-based detection)
    # ------------------------------------------------------------------
    def _rule_ml_anomaly(self, snapshot, now):
        ml = snapshot.get("ml")
        if not isinstance(ml, dict):
            return []   # models not trained / worker not running
        summary = ml.get("summary")
        if not isinstance(summary, dict):
            return []
        anomalous = summary.get("potentially_anomalous") or 0
        if not isinstance(anomalous, (int, float)) or anomalous <= 0:
            return []
        # Fire when the count of potentially-anomalous flows has grown.
        if not self._should_fire("ml_anomaly", float(anomalous), now):
            return []
        latest = ml.get("latest_anomaly") or {}
        severity = "high" if latest.get("score") is not None and latest["score"] >= 0.8 else "medium"
        return [{
            "created_at": _now_iso(),
            "category": "ml_anomaly",
            "source": "ml",
            "severity": severity,
            "title": "Potentially Anomalous Behavior (ML)",
            "message": (
                f"The anomaly model flagged {anomalous} flow(s) as "
                f"potentially anomalous. This is a statistical signal, "
                f"not proof of malicious activity."
            ),
            "observed": {
                "potentially_anomalous_flows": anomalous,
                "latest_anomaly_score": latest.get("score"),
            },
            "threshold": None,
            "status": "active",
        }]


def _build_snapshot():
    """Gather ONE snapshot from the real phase singletons.

    Lazy imports keep this module import-order safe; any failing
    source simply contributes nothing (never a fake zero).
    """
    snapshot = {"time": time.time()}
    try:
        from performance import traffic_monitor
        snapshot["traffic"] = traffic_monitor.current()
    except Exception:
        snapshot["traffic"] = None
    try:
        from tcp_analysis import tcp_tracker
        snapshot["tcp"] = tcp_tracker.summary()
    except Exception:
        snapshot["tcp"] = None
    try:
        from ml_service import ml_service, database as _database  # noqa: F401
        payload = {"summary": ml_service.summary()}
        try:
            import database
            payload["latest_anomaly"] = database.latest_ml_anomaly()
            # Phase 10: classification alerts compare the newest predicted
            # class with the dominant recent class (both real data).
            payload["latest_classification"] = database.latest_ml_classification()
        except Exception:
            payload["latest_anomaly"] = None
            payload["latest_classification"] = None
        snapshot["ml"] = payload
    except Exception:
        snapshot["ml"] = None
    return snapshot


class AlertManager:
    """Owns rule evaluation, storage, history, and status management."""

    def __init__(self, snapshot_fn=None, thresholds=None):
        self.snapshot_fn = snapshot_fn or _build_snapshot
        self.rule_engine = RuleEngine(thresholds)
        self._lock = threading.Lock()
        self._alerts = deque(maxlen=MAX_MEMORY_ALERTS)
        self._next_id = 1
        self._thread = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    def start(self):
        """Restore recent history, then start the background evaluator."""
        if self._thread is not None and self._thread.is_alive():
            return
        try:
            import database
            for alert in reversed(database.load_recent_alerts(RESTORE_ON_START)):
                with self._lock:
                    self._alerts.append(alert)
                    if alert.get("id") is not None:
                        self._next_id = max(self._next_id, alert["id"] + 1)
        except Exception:
            pass   # fresh database / first run — fine
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _run(self):
        while not self._stop_event.wait(timeout=EVALUATOR_INTERVAL_SECONDS):
            try:
                self.evaluate_now()
            except Exception:
                pass   # one bad snapshot must never kill the loop

    # ------------------------------------------------------------------
    def evaluate_now(self):
        """One evaluation cycle: snapshot -> rules -> storage."""
        snapshot = self.snapshot_fn() or {}
        return self.process_snapshot(snapshot)

    def process_snapshot(self, snapshot):
        """Evaluate an explicit snapshot (also the test entry point)."""
        new_alerts = self.rule_engine.evaluate(snapshot)
        for alert in new_alerts:
            self.record(alert)
        return new_alerts

    # ------------------------------------------------------------------
    def record(self, alert):
        """Store one alert in memory + SQLite (best-effort)."""
        with self._lock:
            alert = dict(alert)
            alert.setdefault("created_at", _now_iso())
            alert.setdefault("status", "active")
            alert["id"] = self._next_id
            self._next_id += 1
            self._alerts.appendleft(alert)
            row_id = alert["id"]
        try:
            import database
            db_id = database.insert_alert(alert)
            if db_id is not None:
                with self._lock:
                    alert["id"] = db_id
                    row_id = db_id
            database.trim_alerts(MAX_MEMORY_ALERTS)
        except Exception:
            pass   # storage trouble must never break the engine
        return row_id

    # ------------------------------------------------------------------
    def query(self, limit=100, status=None, category=None, source=None):
        """Filtered alert list, newest first (status OPEN == ACTIVE)."""
        if status and str(status).upper() == "OPEN":
            status = "ACTIVE"
        with self._lock:
            alerts = list(self._alerts)
        result = []
        for alert in alerts:
            if status and alert.get("status") != status:
                continue
            if category and alert.get("category") != category:
                continue
            if source and alert.get("source") != source:
                continue
            result.append(alert)
        try:
            limit = max(1, int(limit))
        except (TypeError, ValueError):
            limit = 100
        return result[:limit]

    def set_status(self, alert_id, status):
        """ACTIVE (alias: OPEN) / ACKNOWLEDGED / RESOLVED (management UI)."""
        status = str(status or "").upper()
        if status == "OPEN":            # section 7 alias for ACTIVE
            status = "ACTIVE"
        if status not in ("ACTIVE", "ACKNOWLEDGED", "RESOLVED"):
            return None
        with self._lock:
            updated = None
            for alert in self._alerts:
                if alert.get("id") == alert_id:
                    alert["status"] = status
                    updated = dict(alert)
                    break
        if updated is not None:
            try:
                import database
                database.update_alert_status(alert_id, status.lower())
            except Exception:
                pass
        return updated

    def stats(self):
        """Counts for the alerts dashboard (only REAL alerts)."""
        with self._lock:
            alerts = list(self._alerts)
        by_status = {}
        by_category = {}
        by_severity = {}
        for alert in alerts:
            by_status[alert.get("status", "active")] = (
                by_status.get(alert.get("status", "active"), 0) + 1
            )
            by_category[alert.get("category", "unknown")] = (
                by_category.get(alert.get("category", "unknown"), 0) + 1
            )
            by_severity[alert.get("severity", "low")] = (
                by_severity.get(alert.get("severity", "low"), 0) + 1
            )
        return {
            "total": len(alerts),
            "by_status": by_status,
            "by_category": by_category,
            "by_severity": by_severity,
        }

    def get_thresholds(self):
        return self.rule_engine.get_thresholds()

    def set_thresholds(self, updates):
        return self.rule_engine.set_thresholds(updates)


# Shared singleton used by main.py.
alert_manager = AlertManager()
