"""
test_performance.py — Phase 5 backend checks (no capture, no real pings)

Every check uses in-memory packet records or monkey-patched probes —
nothing is written to the database, nothing pings the network.

Run from the `backend` folder:
    python test_performance.py
"""

import time

import performance


CHECKS = []


def check(name, condition):
    CHECKS.append((name, bool(condition)))
    print(("PASS" if condition else "FAIL"), "-", name)


# ----------------------------------------------------------------------
# Section 3: readable bps formatting
# ----------------------------------------------------------------------
check("format 0 bps", performance.format_bits_per_second(0) == "0 bps")
check("format Kbps", performance.format_bits_per_second(850_000) == "850.0 Kbps")
check("format Mbps", performance.format_bits_per_second(4_200_000) == "4.2 Mbps")
check("format Gbps", performance.format_bits_per_second(1_500_000_000) == "1.5 Gbps")
check("format None -> '-'", performance.format_bits_per_second(None) == "-")

# ----------------------------------------------------------------------
# Sections 2 + 5 + 6: traffic buckets
# ----------------------------------------------------------------------
monitor = performance.TrafficMonitor()
check("empty current -> zero rates + None avg size",
      monitor.current()["average_packet_size"] is None)

# Feed packets "now" — they land in the current bucket.
for size in (100, 200, 300):
    monitor.observe({"size": size})
current = monitor.current()
check("current counts packets", current["packets_per_second"] > 0)
check("current bytes -> bits", current["bits_per_second"] == current["bytes_per_second"] * 8)
check("current avg packet size = 200 B", current["average_packet_size"] == 200.0)

# Force-close a bucket and verify rates math.
monitor._bucket_start = time.time() - 2.0  # pretend the bucket is 2 s old
monitor.on_tick()
check("bucket closed into history", len(monitor.history) == 1)
closed = monitor.history[0]
check("closed bucket has 3 packets", closed["packets"] == 3)
check("closed bucket has 600 bytes", closed["bytes"] == 600)

# Rolling window must never exceed TRAFFIC_HISTORY_POINTS.
monitor._bucket_start = time.time() - 2.0
for _ in range(performance.TRAFFIC_HISTORY_POINTS + 10):
    monitor.on_tick()
    monitor.observe({"size": 10})
    monitor._bucket_start = time.time() - 2.0
check("history rolling window bounded",
      len(monitor.history) <= performance.TRAFFIC_HISTORY_POINTS)

# history_rows: oldest first, bits included.
rows = monitor.history_rows(limit=10)
check("history rows limited", len(rows) == 10)
check("history rows carry bits", rows[0]["bits"] == rows[0]["bytes"] * 8)
check("history rows oldest first", rows[0]["time"] <= rows[-1]["time"])

# _rates_from over synthetic buckets.
rates = monitor._rates_from(
    [{"packets": 10, "bytes": 1000}, {"packets": 30, "bytes": 3000}]
)
check("avg packet rate", rates["avg_packets_per_second"] == 20.0)
check("peak packet rate", rates["peak_packets_per_second"] == 30)
check("avg bps", rates["avg_bits_per_second"] == (8000 + 24000) / 2)
check("overall avg size", rates["overall_average_packet_size"] == 100.0)
empty = monitor._rates_from([])
check("empty rates -> None", empty["avg_bits_per_second"] is None)

# ----------------------------------------------------------------------
# Sections 8-11: RTT prober with FAKE probes (no network access)
# ----------------------------------------------------------------------
prober = performance.RttProber()
summary = prober.summary()
check("no target -> everything None", summary["rtt_ms"] is None)
check("no target -> unavailable reason set", summary["unavailable_reason"] is not None)

prober.set_target("192.168.1.1", "Test gateway")
sent_probe = {"calls": 0}


def fake_probe_good(target):
    sent_probe["calls"] += 1
    return [5.0, 6.0, 5.0, 8.0, 5.2][sent_probe["calls"] - 1]


original_probe = performance._run_one_probe
performance._run_one_probe = fake_probe_good
try:
    for _ in range(5):
        prober.probe_once()
finally:
    performance._run_one_probe = original_probe

summary = prober.summary()
check("5 probes sent/received", summary["probes_sent"] == 5 and summary["probes_received"] == 5)
check("current RTT = last value", summary["rtt_ms"] == 5.2)
check("avg RTT", summary["avg_rtt_ms"] == round((5 + 6 + 5 + 8 + 5.2) / 5, 2))
check("min RTT", summary["min_rtt_ms"] == 5.0)
check("max RTT", summary["max_rtt_ms"] == 8.0)
# Jitter = mean(|6-5|, |5-6|, |8-5|, |5.2-8|) = mean(1,1,3,2.8) = 1.95
check("jitter from variation", summary["jitter_ms"] == 1.95)
check("probe loss 0%", summary["packet_loss_percent"] == 0.0)
check("unavailable_reason cleared", summary["unavailable_reason"] is None)

# Packet loss: 2 of 5 probes fail.
sent_probe["calls"] = 0


def fake_probe_lossy(target):
    sent_probe["calls"] += 1
    return None if sent_probe["calls"] in (2, 4, 5) else 4.0


performance._run_one_probe = fake_probe_lossy
try:
    lossy = performance.RttProber()
    lossy.set_target("192.168.1.1")
    for _ in range(5):
        lossy.probe_once()
finally:
    performance._run_one_probe = original_probe

summary = lossy.summary()
check("lossy: 2 of 5 received", summary["probes_received"] == 2)
check("probe loss 60%", summary["packet_loss_percent"] == 60.0)
check("lossy: error recorded after final failed probe", summary["error"] is not None)

# Jitter with insufficient data is None (never faked).
tiny = performance.RttProber()
tiny.set_target("x")
performance._run_one_probe = lambda target: 5.0
try:
    tiny.probe_once()
finally:
    performance._run_one_probe = original_probe
check("single RTT -> jitter None", tiny.summary()["jitter_ms"] is None)

# ----------------------------------------------------------------------
# Sections 18-19: background monitor loop safety
# ----------------------------------------------------------------------
perf_monitor = performance.PerformanceMonitor(monitor, prober)
perf_monitor.start()
time.sleep(1.3)  # let it tick once
perf_monitor.stop()
perf_monitor._thread.join(timeout=3)
check(
    "monitor thread runs and stops",
    perf_monitor._stop_event.is_set()
    and perf_monitor._thread is not None
    and not perf_monitor._thread.is_alive(),
)

snapshot = perf_monitor.snapshot()
check("snapshot has traffic", "traffic" in snapshot and "rtt" in snapshot)
check("snapshot never raises without DB", snapshot["timestamp"] > 0)

# _persist_snapshot is best-effort: must not raise even with a broken DB.
import database  # noqa: E402
original_insert = database.insert_performance_metric
database.insert_performance_metric = lambda row: (_ for _ in ()).throw(
    RuntimeError("boom")
)
try:
    perf_monitor._persist_snapshot()
    check("persist swallows DB errors", True)
except Exception:
    check("persist swallows DB errors", False)
finally:
    database.insert_performance_metric = original_insert

# ----------------------------------------------------------------------
failed = [name for name, ok in CHECKS if not ok]
print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed.")
if failed:
    print("FAILED:", *failed, sep="\n  - ")
    raise SystemExit(1)
