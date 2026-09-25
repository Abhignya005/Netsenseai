"""
test_phase9.py — Phase 9 backend checks (runs WITHOUT capture or network)

Every check builds explicit snapshots or uses a temporary SQLite
database — nothing is written to the real netsense.db, and no fake
network traffic is invented. The rule engine only ever sees REAL
snapshot dicts, exactly like the background evaluator will.

Run from the `backend` folder:
    python test_phase9.py
"""

import importlib
import sys
import tempfile
import time
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND))

# Point the database module at a throwaway file BEFORE importing it,
# so alert-storage checks never touch the real netsense.db.
# ignore_cleanup_errors=True: on Windows SQLite may briefly hold the
# file open at interpreter exit — the temp dir is disposable anyway.
_tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
import database as database_module  # noqa: E402

database_module.DB_PATH = Path(_tmp_dir.name) / "phase9_test.db"

import alerts as alerts_module  # noqa: E402
from alerts import AlertManager, RuleEngine, format_bytes_per_second  # noqa: E402


class Phase9Tests(unittest.TestCase):
    passed = 0
    failed = 0

    # ------------------------------------------------------------------
    def setUp(self):
        # A FRESH manager (and rule engine) per test — cooldown state
        # from one test must never suppress another test's firing.
        self.manager = AlertManager(snapshot_fn=lambda: {})
        self.rules = self.manager.rule_engine

    def record(self, name, condition, detail=""):
        if condition:
            type(self).passed += 1
            print(f"  PASS  {name}")
        else:
            type(self).failed += 1
            print(f"  FAIL  {name} {detail}")

    # ==================================================================
    # Rule A — high traffic (section 2)
    # ==================================================================
    def test_01_high_traffic(self):
        print("RULE: high traffic")
        no_data = self.rules.evaluate({"time": time.time(), "traffic": None})
        self.record("no traffic data -> no alert (honest silence)",
                    len(no_data) == 0)

        calm = self.rules.evaluate({
            "time": time.time(),
            "traffic": {"bytes_per_second": 1_000_000.0,
                        "bits_per_second": 8_000_000.0,
                        "packets_per_second": 120.0},
        })
        self.record("traffic below threshold -> no alert", len(calm) == 0)

        loud = self.rules.evaluate({
            "time": time.time(),
            "traffic": {"bytes_per_second": 18.5 * 1024 * 1024,
                        "bits_per_second": 18.5 * 1024 * 1024 * 8,
                        "packets_per_second": 850.0},
        })
        self.record("traffic above threshold -> fires",
                    any(a["category"] == "high_traffic" for a in loud))
        alert = next(a for a in loud if a["category"] == "high_traffic")
        self.record("alert message shows real observed + threshold",
                    "MB/s" in alert["message"] and "threshold" in alert["message"],
                    alert["message"])
        self.record("careful wording — no attack claim",
                    "attack" not in alert["message"].lower())

    # ==================================================================
    # Rule B — high packet rate (section 3)
    # ==================================================================
    def test_02_packet_rate(self):
        print("RULE: packet rate")
        fired = self.rules.evaluate({
            "time": time.time(),
            "traffic": {"bytes_per_second": 20_000_000.0,
                        "bits_per_second": 160_000_000.0,
                        "packets_per_second": 850.0},
        })
        alert = next((a for a in fired if a["category"] == "high_packet_rate"), None)
        self.record("packet rate above threshold -> fires", alert is not None)
        if alert:
            self.record("observed carried in payload",
                        alert["observed"]["packets_per_second"] == 850.0)

        # Cooldown: identical snapshot must NOT immediately re-fire.
        again = self.rules.evaluate({
            "time": time.time(),
            "traffic": {"bytes_per_second": 20_000_001.0,
                        "bits_per_second": 160_000_008.0,
                        "packets_per_second": 851.0},
        })
        self.record("cooldown prevents immediate re-fire",
                    not any(a["category"] == "high_packet_rate" for a in again))

    # ==================================================================
    # Rule C/D — SYN and RST ratios (sections 4-5)
    # ==================================================================
    def test_03_flag_ratios(self):
        print("RULE: SYN / RST ratios")
        tiny = self.rules.evaluate({
            "time": time.time(),
            "tcp": {"summary": {"incomplete": 100, "total": 100},
                    "flag_counts": {"syn": 4, "ack": 2}},  # sample < MIN_FLAG_SAMPLE
        })
        self.record("tiny flag sample -> no ratio alert (noise guard)",
                    not any("activity" in a["category"] for a in tiny))

        syn_heavy = {"syn": 80, "syn_ack": 5, "ack": 10, "fin": 3, "rst": 2}
        fired = self.rules.evaluate({
            "time": time.time(),
            "tcp": {"summary": {"incomplete": 40, "total": 50},
                    "flag_counts": syn_heavy},
        })
        syn_alert = next(
            (a for a in fired if a["category"] == "high_syn_activity"), None)
        self.record("SYN ratio 0.80 > 0.50 -> fires", syn_alert is not None)
        if syn_alert:
            self.record("message describes behavior, not an attack",
                        "Potentially anomalous" in syn_alert["message"]
                        and "does not indicate an attack" in syn_alert["message"])

        rst_heavy = {"syn": 10, "syn_ack": 5, "ack": 30, "fin": 5, "rst": 50}
        fired = self.rules.evaluate({
            "time": time.time(),
            "tcp": {"summary": {"incomplete": 10, "total": 50},
                    "flag_counts": rst_heavy},
        })
        self.record("RST ratio 0.50 > 0.25 -> fires",
                    any(a["category"] == "high_rst_activity" for a in fired))

    # ==================================================================
    # Rule E — incomplete connections (section 6)
    # ==================================================================
    def test_04_incomplete_connections(self):
        print("RULE: incomplete connections")
        fired = self.rules.evaluate({
            "time": time.time(),
            "tcp": {"summary": {"incomplete": 125, "total": 300},
                    "flag_counts": {"ack": 400}},
        })
        alert = next((a for a in fired
                      if a["category"] == "incomplete_connections"), None)
        self.record("125 incomplete > 50 threshold -> fires", alert is not None)
        if alert:
            self.record("message names the tracked states",
                        "SYN_SENT" in alert["message"]
                        and "passive monitoring" in alert["message"])

    # ==================================================================
    # Rule F — ML anomaly alerts (ML-based detection)
    # ==================================================================
    def test_05_ml_alerts(self):
        print("RULE: ML anomaly")
        none = self.rules.evaluate({"time": time.time(), "ml": None})
        self.record("no ML data -> no alert", len(none) == 0)

        zero = self.rules.evaluate({
            "time": time.time(),
            "ml": {"summary": {"potentially_anomalous": 0},
                   "latest_anomaly": None},
        })
        self.record("zero anomalies -> no alert", len(zero) == 0)

        fired = self.rules.evaluate({
            "time": time.time(),
            "ml": {"summary": {"potentially_anomalous": 3},
                   "latest_anomaly": {"score": 0.82}},
        })
        alert = next((a for a in fired if a["source"] == "ml"), None)
        self.record("3 potentially-anomalous flows -> ML alert", alert is not None)
        if alert:
            self.record("ML wording is statistical, never certain",
                        "not proof of malicious activity" in alert["message"])
            self.record("real ML score attached",
                        alert["observed"]["latest_anomaly_score"] == 0.82)

    # ==================================================================
    # Thresholds (configurable, section examples)
    # ==================================================================
    def test_06_thresholds(self):
        print("THRESHOLD configuration")
        thresholds = self.rules.get_thresholds()
        self.record("defaults exposed",
                    thresholds["high_traffic_bytes_per_second"] == 10_000_000.0
                    and thresholds["high_packet_rate_packets_per_second"] == 500.0)

        updated = self.rules.set_thresholds({
            "high_packet_rate_packets_per_second": 800.0,
            "not_a_real_key": 999,          # ignored
            "high_syn_ratio": -1,           # invalid -> ignored
        })
        self.record("valid update applied, invalid ignored",
                    updated["high_packet_rate_packets_per_second"] == 800.0
                    and updated["high_syn_ratio"] == 0.50)

        fired = self.rules.evaluate({
            "time": time.time(),
            "traffic": {"bytes_per_second": 20_000_000.0,
                        "bits_per_second": 160_000_000.0,
                        "packets_per_second": 600.0},
        })
        self.record("new threshold respected (600 < 800 -> silent)",
                    not any(a["category"] == "high_packet_rate" for a in fired))

    # ==================================================================
    # Storage + status management (sections: storage, management)
    # ==================================================================
    def test_07_storage_and_status(self):
        print("STORAGE + status management")
        database_module.init_db()   # ensure temp tables exist for this suite
        snapshot = {
            "time": time.time(),
            "traffic": {"bytes_per_second": 20_000_000.0,
                        "bits_per_second": 160_000_000.0,
                        "packets_per_second": 850.0},
            "tcp": {"summary": {"incomplete": 125, "total": 300},
                    "flag_counts": {"syn": 80, "ack": 10}},
            "ml": {"summary": {"potentially_anomalous": 3},
                   "latest_anomaly": {"score": 0.82}},
        }
        produced = self.manager.process_snapshot(snapshot)
        self.record("combined snapshot -> 4+ alerts", len(produced) >= 4,
                    f"got {len(produced)}")

        rows = self.manager.query(limit=50)
        self.record("query returns newest first",
                    len(rows) >= 4 and rows[0]["id"] is not None)

        target = rows[0]["id"]
        updated = self.manager.set_status(target, "ACKNOWLEDGED")
        self.record("acknowledge works", updated and updated["status"] == "ACKNOWLEDGED")
        self.record("status filter finds it",
                    any(a["id"] == target
                        for a in self.manager.query(status="ACKNOWLEDGED")))
        resolved = self.manager.set_status(target, "RESOLVED")
        self.record("resolve works", resolved and resolved["status"] == "RESOLVED")
        self.record("invalid status rejected",
                    self.manager.set_status(target, "EXPLODED") is None)

        db_rows = database_module.load_recent_alerts(limit=10)
        self.record("alerts persisted to temp SQLite",
                    len(db_rows) >= 4 and db_rows[0]["category"] in (
                        "ml_anomaly", "incomplete_connections",
                        "high_syn_activity", "high_packet_rate",
                        "high_traffic"))

        stats = self.manager.stats()
        self.record("stats count only real alerts",
                    stats["total"] >= 4 and "by_category" in stats)

    # ==================================================================
    # Persistence round-trip via a fresh manager (startup restore)
    # ==================================================================
    def test_08_startup_restore(self):
        print("STARTUP restore")
        fresh = AlertManager(snapshot_fn=lambda: {})
        fresh.start()
        time.sleep(0.2)
        fresh.stop()
        restored = fresh.query(limit=10)
        self.record("history restored from SQLite on start",
                    len(restored) >= 4,
                    f"got {len(restored)}")

    # ==================================================================
    # Formatting + malformed-input safety
    # ==================================================================
    def test_09_safety(self):
        print("SAFETY + formatting")
        self.record("bytes formatting ladder",
                    format_bytes_per_second(1024 * 1024 * 18.5) == "18.5 MB/s")
        broken = self.rules.evaluate({
            "time": time.time(),
            "traffic": {"bytes_per_second": "banana",
                        "bits_per_second": None},
            "tcp": {"summary": {"incomplete": "many", "total": None},
                    "flag_counts": "not-a-dict"},
            "ml": {"summary": "junk"},
        })
        self.record("malformed snapshot -> no crash, no alert", len(broken) == 0)

    def test_10_ml_classification(self):
        print("RULE: ML classification (Phase 10)")
        none = self.rules.evaluate({"time": time.time(), "ml": None})
        self.record("no ML data -> no classification alert", len(none) == 0)

        same = self.rules.evaluate({
            "time": time.time(),
            "ml": {"latest_classification": {"label": "BENIGN",
                                             "dominant_class": "BENIGN",
                                             "confidence": 0.9}},
        })
        self.record("label == dominant -> no alert", len(same) == 0)

        fired = self.rules.evaluate({
            "time": time.time(),
            "ml": {"latest_classification": {"label": "DoS Hulk",
                                             "dominant_class": "BENIGN",
                                             "confidence": 0.77}},
        })
        alert = next((a for a in fired if a["category"] == "ml_classification"), None)
        self.record("rare class -> classification alert", alert is not None)
        if alert:
            self.record("uses only REAL dataset classes",
                        alert["observed"]["predicted_class"] == "DoS Hulk"
                        and alert["observed"]["dominant_recent_class"] == "BENIGN")
            self.record("wording stays cautious",
                        "not proof" in alert["message"])

    def test_11_open_alias(self):
        print("STATUS: OPEN alias (Phase 10)")
        produced = self.manager.process_snapshot({
            "time": time.time(),
            "traffic": {"bytes_per_second": 20_000_000.0,
                        "bits_per_second": 160_000_000.0,
                        "packets_per_second": 850.0},
        })
        self.record("snapshot produced an alert", len(produced) >= 1)
        alert = self.manager.query(limit=1)[0]
        self.record("OPEN accepted as ACTIVE on update",
                    (self.manager.set_status(alert["id"], "OPEN") or {})
                    .get("status") == "ACTIVE")
        self.record("OPEN accepted as filter",
                    any(a["id"] == alert["id"]
                        for a in self.manager.query(status="OPEN")))


def main():
    loader = unittest.TestLoader()
    loader.sortTestMethodsUsing = None   # run in numbered order
    suite = loader.loadTestsFromTestCase(Phase9Tests)
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    total = Phase9Tests.passed + Phase9Tests.failed
    print(f"\nPhase 9 checks: {Phase9Tests.passed}/{total} passed")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
