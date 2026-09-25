"""
performance.py — PHASE 5: network performance monitoring

WHAT THIS FILE DOES
-------------------
Answers "How is the network performing?" using ONLY real observations:

  1. TRAFFIC RATES (sections 2-7)
     Every captured packet lands in a 1-SECOND WINDOW ("bucket").
     When a bucket closes we know, for that second:
         packets, bytes, packets/sec, bytes/sec, bits/sec
     The last 120 seconds are kept as a rolling history for charts.

  2. RTT / LATENCY (sections 8-9)
     A background thread pings an authorized target (default: the
     default gateway) using the OPERATING SYSTEM's own ping command.
     Why not Scapy? Scapy ICMP needs Npcap + Administrator rights and
     would fail on machines without them; the OS ping works everywhere
     and is completely non-intrusive (1 packet per measurement).

  3. JITTER (section 10)
     Average of |RTT[i] - RTT[i-1]| over the recent history — pure
     variation between consecutive measurements, never invented.

  4. PROBE PACKET LOSS (section 11)
     From the same probes: (sent - received) / sent * 100.
     HONESTLY LABELED "probe packet loss" — it says nothing about the
     network as a whole.

DATA ACCURACY RULE (sections 1 + 27)
------------------------------------
Anything that cannot be measured is reported as None (the UI shows
"Unavailable"). This module NEVER invents a number.

Performance-safety rule (sections 18-19)
----------------------------------------
observe() does O(1) counter math — it can never slow down capture.
All heavier work (history rotation, ping probes) happens on this
module's own background thread.
"""

import re
import subprocess
import threading
import time

# ----------------------------------------------------------------------
# Configuration — every tunable in ONE place
# ----------------------------------------------------------------------
WINDOW_SECONDS = 1.0          # one measurement bucket = 1 second
TRAFFIC_HISTORY_POINTS = 120  # keep ~2 minutes of 1-second buckets

RTT_INTERVAL_SECONDS = 10     # one probe every 10 s (gentle, non-intrusive)
MAX_RTT_HISTORY = 60          # keep the last 60 RTT measurements
RTT_TIMEOUT_MS = 2000         # give up on a probe after 2 s
JITTER_WINDOW = 20            # jitter = avg |diff| over the last 20 RTTs

# Persistence: at most one row per minute in performance_metrics.
DB_WRITE_INTERVAL_SECONDS = 60.0

# Parses "time=4ms" (Windows), "time=4.2 ms" (Linux), "time=4 msec" (macOS)
_RTT_LINE = re.compile(r"time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*m?s?e?c?", re.IGNORECASE)


def format_bits_per_second(bits):
    """Human-readable rate: 850 Kbps / 4.2 Mbps (section 3)."""
    if bits is None:
        return "-"
    if bits >= 1_000_000_000:
        return f"{bits / 1_000_000_000:.1f} Gbps"
    if bits >= 1_000_000:
        return f"{bits / 1_000_000:.1f} Mbps"
    if bits >= 1_000:
        return f"{bits / 1_000:.1f} Kbps"
    return f"{bits:.0f} bps"


# ======================================================================
# Part 1 — traffic rates from captured packets
# ======================================================================
class TrafficMonitor:
    """Folds captured packets into 1-second buckets (section 2)."""

    def __init__(self):
        self.lock = threading.Lock()
        # The bucket currently being filled.
        self._bucket_start = time.time()
        self._bucket_packets = 0
        self._bucket_bytes = 0
        # Closed buckets: {"time": epoch, "packets": n, "bytes": n}
        self.history = []

    # ------------------------------------------------------------------
    def observe(self, record):
        """Add one packet's counters. Runs on the CAPTURE thread, so it
        must stay tiny (O(1), no I/O) — see section 19."""
        try:
            size = int(record.get("size") or 0)
        except Exception:
            size = 0
        with self.lock:
            self._bucket_packets += 1
            self._bucket_bytes += size

    # ------------------------------------------------------------------
    def on_tick(self):
        """Close the current 1-second bucket and start a new one.

        Called by the monitor thread once per second.
        """
        now = time.time()
        with self.lock:
            elapsed = now - self._bucket_start
            if elapsed < WINDOW_SECONDS:
                return  # tick arrived early — nothing to close yet
            packets = self._bucket_packets
            byte_count = self._bucket_bytes
            bucket_time = self._bucket_start + elapsed / 2  # bucket midpoint
            self._bucket_start = now
            self._bucket_packets = 0
            self._bucket_bytes = 0
            self.history.append(
                {"time": bucket_time, "packets": packets, "bytes": byte_count}
            )
            # Rolling window: the chart must never grow indefinitely (§13).
            if len(self.history) > TRAFFIC_HISTORY_POINTS:
                del self.history[: len(self.history) - TRAFFIC_HISTORY_POINTS]

    # ------------------------------------------------------------------
    def current(self):
        """Live rates from the PARTIALLY filled current bucket.

        Estimated over the time elapsed inside the bucket, so the UI
        moves smoothly between 1-second bucket closings. Returns None
        values (never fake zeros) when no data exists yet.
        """
        now = time.time()
        with self.lock:
            elapsed = max(now - self._bucket_start, 0.001)
            packets = self._bucket_packets
            byte_count = self._bucket_bytes
            recent = list(self.history[-5:])  # short trend for averages

        packets_per_second = packets / elapsed
        bytes_per_second = byte_count / elapsed
        return {
            "packets_per_second": round(packets_per_second, 1),
            "bytes_per_second": round(bytes_per_second, 1),
            "bits_per_second": round(bytes_per_second * 8, 1),
            "average_packet_size": round(byte_count / packets, 1) if packets else None,
        } | self._rates_from(recent)

    def _rates_from(self, buckets):
        """Average/peak over a list of closed buckets (None when empty)."""
        if not buckets:
            return {
                "avg_packets_per_second": None,
                "avg_bits_per_second": None,
                "peak_packets_per_second": None,
                "peak_bits_per_second": None,
                "overall_average_packet_size": None,
            }
        rates = [b["packets"] for b in buckets]
        bits = [b["bytes"] * 8 for b in buckets]
        total_packets = sum(b["packets"] for b in buckets)
        total_bytes = sum(b["bytes"] for b in buckets)
        return {
            "avg_packets_per_second": round(sum(rates) / len(rates), 1),
            "avg_bits_per_second": round(sum(bits) / len(bits), 1),
            "peak_packets_per_second": max(rates),
            "peak_bits_per_second": max(bits),
            "overall_average_packet_size": (
                round(total_bytes / total_packets, 1) if total_packets else None
            ),
        }

    def history_rows(self, limit=60):
        """Oldest-first chart rows (§13 rolling window)."""
        with self.lock:
            rows = list(self.history)
        rows = rows[-limit:]
        return [
            {
                "time": r["time"],
                "packets": r["packets"],
                "bytes": r["bytes"],
                "bits": r["bytes"] * 8,
            }
            for r in rows
        ]


# ======================================================================
# Part 2 — RTT / jitter / probe loss (sections 8-11)
# ======================================================================
def default_gateway():
    """Best-effort default gateway lookup (the preferred RTT target).

    On Windows:  `route print 0.0.0.0`  prints the routing table.
    Falls back to the first two octets of our own IP (e.g. 192.168.1.1)
    when the route table cannot be parsed. Returns None if nothing
    sensible is found — the caller then shows "RTT unavailable".
    """
    import socket
    import struct

    try:
        output = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        for line in output.splitlines():
            parts = line.split()
            # A gateway row: 0.0.0.0  0.0.0.0  <gateway>  <iface> <metric>
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and re.match(
                r"^\d+\.\d+\.\d+\.\d+$", parts[2]
            ) and parts[2] != "0.0.0.0":
                return parts[2], "Default gateway (routing table)"
    except Exception:
        pass

    # Fallback guess: our own subnet's .1 (common home-router address).
    try:
        probe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe_socket.connect(("8.8.8.8", 80))  # no traffic is actually sent
        local_ip = probe_socket.getsockname()[0]
        probe_socket.close()
        network_prefix = local_ip.rsplit(".", 1)[0]
        return f"{network_prefix}.1", f"Gateway guess ({network_prefix}.1)"
    except Exception:
        return None, None


def _run_one_probe(target):
    """Send ONE ICMP echo with the OS ping command; return RTT in ms.

    Returns (rtt_ms | None). Never raises — every failure mode
    (no route, blocked ICMP, timeout) simply yields None (§29).
    """
    try:
        completed = subprocess.run(
            ["ping", "-n", "1", "-w", str(RTT_TIMEOUT_MS), target],  # Windows
            capture_output=True, text=True, timeout=RTT_TIMEOUT_MS / 1000 + 3,
        )
        match = _RTT_LINE.search(completed.stdout or "")
        if match:
            return float(match.group(1))
    except FileNotFoundError:
        # Non-Windows OS: ping uses -c/-W instead of -n/-w.
        try:
            completed = subprocess.run(
                ["ping", "-c", "1", "-W", "2", target],
                capture_output=True, text=True, timeout=5,
            )
            match = _RTT_LINE.search(completed.stdout or "")
            if match:
                return float(match.group(1))
        except Exception:
            return None
    except Exception:
        return None
    return None


class RttProber:
    """Measures RTT against ONE authorized target (section 8)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.target = None
        self.target_description = None
        self.history = []          # recent RTT values, newest last
        self.probes_sent = 0
        self.probes_received = 0
        self.last_error = None

    # ------------------------------------------------------------------
    def set_target(self, target, description=None):
        """Point the prober at an authorized target (user choice)."""
        with self.lock:
            self.target = target
            self.target_description = description or target
            self.history = []
            self.probes_sent = 0
            self.probes_received = 0
            self.last_error = None

    # ------------------------------------------------------------------
    def probe_once(self):
        """Run one measurement cycle (1 ICMP packet)."""
        with self.lock:
            target = self.target
        if not target:
            return
        self.probes_sent += 1
        rtt = _run_one_probe(target)
        with self.lock:
            if rtt is None:
                self.last_error = f"No reply from {target} (probe failed or blocked)"
                return
            self.probes_received += 1
            self.last_error = None
            self.history.append(rtt)
            if len(self.history) > MAX_RTT_HISTORY:
                del self.history[: len(self.history) - MAX_RTT_HISTORY]

    # ------------------------------------------------------------------
    def summary(self):
        """Current/avg/min/max RTT + jitter + probe loss.

        Every field is None when there are not enough measurements —
        the UI then shows "Unavailable" instead of a fake number.
        """
        with self.lock:
            values = list(self.history)
            sent = self.probes_sent
            received = self.probes_received
            error = self.last_error
            target = self.target
            description = self.target_description

        result = {
            "target": target,
            "target_description": description,
            "rtt_ms": values[-1] if values else None,
            "avg_rtt_ms": round(sum(values) / len(values), 2) if values else None,
            "min_rtt_ms": min(values) if len(values) >= 3 else None,
            "max_rtt_ms": max(values) if len(values) >= 3 else None,
            "history": list(values[-30:]),
            "measurements": len(values),
            "probes_sent": sent,
            "probes_received": received,
            # Section 10: jitter = mean |RTT[i] - RTT[i-1]|.
            "jitter_ms": self._jitter(values),
            # Section 11: PROBE packet loss only — honestly labeled.
            "packet_loss_percent": self._loss(sent, received),
            "error": error,
            "unavailable_reason": None if values else
            "No RTT measurements yet — probing has not run or replies are blocked",
        }
        return result

    @staticmethod
    def _jitter(values):
        recent = values[-(JITTER_WINDOW + 1):]
        if len(recent) < 2:
            return None
        differences = [
            abs(recent[i] - recent[i - 1]) for i in range(1, len(recent))
        ]
        return round(sum(differences) / len(differences), 2)

    @staticmethod
    def _loss(sent, received):
        if sent <= 0:
            return None
        return round((sent - received) / sent * 100, 1)


# ======================================================================
# Part 3 — the background monitor thread (sections 18-19)
# ======================================================================
class PerformanceMonitor:
    """Owns the 1-second tick and the RTT probe loop.

    Started lazily by main.py on the first /api/performance request —
    it must never block or crash packet capture.
    """

    def __init__(self, traffic_monitor, rtt_prober):
        self.traffic = traffic_monitor
        self.rtt = rtt_prober
        self._thread = None
        self._stop_event = threading.Event()
        self._last_db_write = 0.0

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _run(self):
        """Main loop: tick traffic buckets every second, probe RTT every
        RTT_INTERVAL_SECONDS, persist a summary row once a minute."""
        last_probe = 0.0
        while not self._stop_event.wait(timeout=1.0):
            try:
                self.traffic.on_tick()
                now = time.time()
                if now - last_probe >= RTT_INTERVAL_SECONDS:
                    last_probe = now
                    self.rtt.probe_once()
                if now - self._last_db_write >= DB_WRITE_INTERVAL_SECONDS:
                    self._last_db_write = now
                    self._persist_snapshot()
            except Exception:
                pass  # one failed measurement must never kill the loop

    def _persist_snapshot(self):
        """Write ONE small row per minute into performance_metrics (§18).
        Best effort — database problems must never affect monitoring."""
        try:
            import database

            snapshot = self.snapshot()
            database.insert_performance_metric(snapshot)
        except Exception:
            pass

    def snapshot(self):
        """Everything the Performance API needs, JSON-safe, Nones intact."""
        traffic = self.traffic.current()
        rtt = self.rtt.summary()
        return {
            "timestamp": time.time(),
            "capture_running": None,  # filled in by main.py from capture status
            "traffic": traffic,
            "rtt": rtt,
        }


# Shared singletons (imported by capture.py and main.py).
traffic_monitor = TrafficMonitor()
rtt_prober = RttProber()
performance_monitor = PerformanceMonitor(traffic_monitor, rtt_prober)
