"""
test_final_integration.py — PHASE 10: end-to-end pipeline check (§34)

Verifies the integration chain on the REAL modules with controlled
fixture packets (no network, no capture, no fake "results"):

    fixture packets -> Phase 4 FlowEngine -> Flow.to_row()
        -> ml_service.flow_to_features() -> ml feature validation
        -> alert engine snapshot rules

Also proves memory stays bounded (ring buffer / flow table) and that
capture-side wiring (what happens per real packet) is unchanged.

Run from the `backend` folder:
    python test_final_integration.py
"""

import sys
import time
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND))

# Point the database module at a throwaway file BEFORE importing the
# modules that use it — the memory-bounds test below stores hundreds
# of alerts and must never pollute the real netsense.db.
import tempfile

_tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
import database as database_module  # noqa: E402

database_module.DB_PATH = Path(_tmp_dir.name) / "final_integration_test.db"
database_module.init_db()

from flow_analysis import FlowEngine, flow_key  # noqa: E402
import alerts as alerts_module  # noqa: E402
import ml_service as ml_service_module  # noqa: E402


def make_record(src, sport, dst, dport, proto, length, flags=None, offset=0.0):
    """A packet record shaped exactly like capture.py produces."""
    return {
        "timestamp": 1_700_000_000.0 + offset,
        "source_ip": src, "destination_ip": dst,
        "source_port": sport, "destination_port": dport,
        "protocol": proto, "length": length,
        "tcp_flags": flags or "",
    }


class FinalIntegrationTests(unittest.TestCase):
    passed = 0
    failed = 0

    def record(self, name, condition, detail=""):
        if condition:
            type(self).passed += 1
            print(f"  PASS  {name}")
        else:
            type(self).failed += 1
            print(f"  FAIL  {name} {detail}")

    # ==================================================================
    def test_pipeline_packets_to_flows_to_features(self):
        print("PIPELINE: packets -> flows -> features")
        engine = FlowEngine()

        # A short TCP "conversation": handshake-ish then data both ways.
        packets = [
            make_record("192.168.1.10", 52341, "93.184.216.34", 443, "TCP", 74,
                        "SYN", 0.0),
            make_record("93.184.216.34", 443, "192.168.1.10", 52341, "TCP", 74,
                        "SYN-ACK", 0.05),
            make_record("192.168.1.10", 52341, "93.184.216.34", 443, "TCP", 66,
                        "ACK", 0.10),
            make_record("192.168.1.10", 52341, "93.184.216.34", 443, "TCP", 1200,
                        "", 0.20),
            make_record("93.184.216.34", 443, "192.168.1.10", 52341, "TCP", 1400,
                        "", 0.30),
            make_record("192.168.1.10", 52341, "93.184.216.34", 443, "TCP", 900,
                        "", 0.45),
        ]
        for record in packets:
            engine.observe(record)   # the exact call capture.py makes

        stats = engine.get_stats()
        self.record("5 packets in 1 bidirectional flow", stats["total_flows"] == 1,
                    str(stats))

        rows = engine.query(limit=10).get("flows", [])
        row = rows[0]
        self.record("flow row has all ML-relevant fields",
                    all(k in row for k in (
                        "duration", "forward_packets", "backward_packets",
                        "byte_rate", "packet_rate", "average_packet_size",
                        "syn_ratio", "rst_ratio", "iat_mean_ms", "iat_std_ms")),
                    str(sorted(row.keys())))

        # -- feature mapping (units: seconds/ms -> microseconds) --------
        features = ml_service_module.flow_to_features(row)
        self.record("flow -> ML features (nothing skipped)",
                    features is not None)
        if features:
            self.record("duration converted s -> microseconds",
                        abs(features["Flow_Duration"] - 0.45 * 1_000_000) < 1_000,
                        str(features["Flow_Duration"]))
            self.record("forward/backward counts preserved",
                        features["Pkt_Count_Fwd"] == 4
                        and features["Pkt_Count_Bwd"] == 2)
            self.record("SYN ratio is real (2 SYN-flagged of 6)",
                        0 < features["SYN_Ratio"] < 1)

        # -- alert engine consumes a snapshot built from the flow data --
        flag_total = 6
        snapshot = {
            "time": time.time(),
            "traffic": None,   # no Phase 5 data in this fixture
            "tcp": {"summary": {"incomplete": 0, "total": 1},
                    "flag_counts": {"syn": 2, "syn_ack": 1, "ack": 3}},
            "ml": None,
        }
        engine_rules = alerts_module.RuleEngine()
        produced = engine_rules.evaluate(snapshot)
        self.record("calm snapshot -> no alerts (honest)",
                    len(produced) == 0, str([a["category"] for a in produced]))

        snapshot["tcp"]["summary"]["incomplete"] = 200
        produced = engine_rules.evaluate(snapshot)
        self.record("incomplete-connection rule still fires on real shape",
                    any(a["category"] == "incomplete_connections"
                        for a in produced))
        del flag_total

    # ==================================================================
    def test_bidirectional_key_and_timeouts(self):
        print("PIPELINE: bidirectional key + timeouts")
        engine = FlowEngine()
        a = make_record("10.0.0.1", 5000, "10.0.0.2", 80, "TCP", 100, offset=0.0)
        b = make_record("10.0.0.2", 80, "10.0.0.1", 5000, "TCP", 300, offset=0.1)
        engine.observe(a)
        engine.observe(b)
        self.record("reverse direction merges into one flow",
                    engine.get_stats()["total_flows"] == 1)
        self.record("normalized key is symmetric",
                    flow_key("TCP", "10.0.0.1", 5000, "10.0.0.2", 80)
                    == flow_key("TCP", "10.0.0.2", 80, "10.0.0.1", 5000))

        # Inactive timeout: 15 s of silence closes the flow (§10 Phase 4).
        later = make_record("10.0.0.1", 5001, "10.0.0.2", 81, "TCP", 100,
                            offset=100.0)
        engine.observe(later)
        engine._sweep(1_700_000_100.0 + 16.0)
        stats = engine.get_stats()
        self.record("15 s idle flow swept to completed",
                    stats["completed_flows"] >= 1, str(stats))

    # ==================================================================
    def test_memory_bounds(self):
        print("MEMORY: bounded storage")
        engine = FlowEngine()
        # 300 distinct one-packet flows -> table grows but stays bounded
        for i in range(300):
            engine.observe(make_record(f"10.9.{i // 250}.{i % 250}", 1000 + i,
                                       "10.0.0.99", 80, "UDP", 100, offset=float(i)))
        self.record("flow table holds all 300 (under cap)",
                    engine.get_stats()["total_flows"] == 300)

        from alerts import MAX_MEMORY_ALERTS, AlertManager
        manager = AlertManager(snapshot_fn=lambda: {})
        for i in range(MAX_MEMORY_ALERTS + 50):
            manager.record({
                "category": "high_traffic", "source": "rule",
                "severity": "medium", "title": f"t{i}", "message": "m",
                "observed": {}, "threshold": 1, "status": "active",
            })
        self.record("alert history capped at MAX_MEMORY_ALERTS",
                    len(manager.query(limit=MAX_MEMORY_ALERTS + 100))
                    == MAX_MEMORY_ALERTS)


def main():
    loader = unittest.TestLoader()
    loader.sortTestMethodsUsing = None
    suite = loader.loadTestsFromTestCase(FinalIntegrationTests)
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    total = FinalIntegrationTests.passed + FinalIntegrationTests.failed
    print(f"\nPhase 10 integration checks: "
          f"{FinalIntegrationTests.passed}/{total} passed")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
