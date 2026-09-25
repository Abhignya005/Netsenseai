"""
flow_analysis.py — PHASE 4: network flow engine

WHAT THIS FILE DOES
-------------------
Groups captured packets into NETWORK FLOWS using the standard
5-tuple (section 8):

    source IP, destination IP, source port, destination port, protocol

Key design points:

    * BIDIRECTIONAL (section 9): the two endpoint pairs are sorted, so
      A:52341 -> B:443 and B:443 -> A:443 land in the SAME flow.
      "Forward" = the direction of the first packet we observed;
      backward = the reverse direction. Separate counters are kept
      for each.

    * TIMEOUTS (section 10), configured in ONE place:
          FLOW_INACTIVE_TIMEOUT = 15s  -> no packet for 15s closes it
          FLOW_ACTIVE_TIMEOUT  = 120s -> rotate into a new flow
                                         segment even while busy
      Completed flows keep their metrics; the newest segment is the
      ACTIVE one.

    * METRICS (section 11): start/end/duration, forward/backward/total
      packets and bytes, packet rate, byte rate, average packet size.
      Division-by-zero is impossible: durations below
      _MIN_DURATION_SECONDS report 0.0 rates.

Privacy: only the Phase 3 metadata dictionary is read — no payloads.
This module never raises on a malformed record (section 20).
"""

import os
import time

# ---- Flow timeout configuration (section 10) -------------------------
# Configurable in backend (with 15s inactive and 120s active defaults).
FLOW_INACTIVE_TIMEOUT = float(os.getenv("NETSENSE_FLOW_INACTIVE_TIMEOUT", "15.0"))
FLOW_ACTIVE_TIMEOUT = float(os.getenv("NETSENSE_FLOW_ACTIVE_TIMEOUT", "120.0"))

# Safety bounds
MAX_COMPLETED_FLOWS = 2000      # keep memory bounded
_MIN_DURATION_SECONDS = 0.001   # never divide by (near) zero


# ----------------------------------------------------------------------
# Bidirectional flow identifier (sections 8 + 9)
# ----------------------------------------------------------------------
def flow_key(protocol, src_ip, src_port, dst_ip, dst_port):
    """Normalized, direction-independent 5-tuple key.

    Ports default to 0 for protocols without ports (ICMP, ARP).
    """
    endpoint_a = (str(src_ip or "-"), int(src_port or 0))
    endpoint_b = (str(dst_ip or "-"), int(dst_port or 0))
    if endpoint_b < endpoint_a:
        endpoint_a, endpoint_b = endpoint_b, endpoint_a
    return (str(protocol or "Other").upper(), endpoint_a, endpoint_b)


class Flow:
    """One flow segment (a 5-tuple conversation between two timeouts)."""

    def __init__(self, record, now):
        self.protocol = (record.get("protocol") or "Other").upper()
        # First-seen direction defines the displayed forward direction.
        self.source_ip = record.get("source_ip") or "-"
        self.source_port = record.get("source_port") or 0
        self.destination_ip = record.get("destination_ip") or "-"
        self.destination_port = record.get("destination_port") or 0
        self.key = flow_key(
            self.protocol,
            self.source_ip, self.source_port,
            self.destination_ip, self.destination_port,
        )
        self.first_direction = (self.source_ip, self.source_port)

        self.start_time = now
        self.last_seen = now
        self.forward_packets = 0
        self.backward_packets = 0
        self.forward_bytes = 0
        self.backward_bytes = 0
        self.status = "ACTIVE"
        # ---- Phase 8 ML counters (additive; §13) -------------------
        self._last_timestamp = now     # previous packet, for IAT
        self._has_previous = False     # becomes True after packet #1
        self.iat_sum = 0.0             # Σ inter-arrival gaps (seconds)
        self.iat_sq_sum = 0.0          # Σ gaps² (streaming variance)
        self.iat_count = 0             # number of gaps
        self.syn_count = 0             # packets carrying SYN
        self.rst_count = 0             # packets carrying RST

    def observe(self, record, now):
        """Count one packet on the correct (forward/backward) side."""
        if (record.get("source_ip"), record.get("source_port")) == self.first_direction:
            self.forward_packets += 1
            self.forward_bytes += int(record.get("size") or 0)
        else:
            self.backward_packets += 1
            self.backward_bytes += int(record.get("size") or 0)
        # ---- Phase 8: IAT statistics (streaming, O(1) per packet) ---
        # Only REAL gaps count: packet #1 has no previous packet, so it
        # contributes nothing (count stays 0 for a 1-packet flow).
        if self._has_previous:
            gap = max(0.0, now - self._last_timestamp)
            self.iat_sum += gap
            self.iat_sq_sum += gap * gap
            self.iat_count += 1
        self._has_previous = True
        self._last_timestamp = now
        # ---- Phase 8: TCP flag counters for SYN/RST ratios ----------
        flags = str(record.get("tcp_flags") or "").upper()
        if "SYN" in flags:
            self.syn_count += 1
        if "RST" in flags:
            self.rst_count += 1
        self.last_seen = max(self.last_seen, now)

    def to_row(self):
        """JSON-safe row with every metric from section 11."""
        duration = max(0.0, self.last_seen - self.start_time)
        total_packets = self.forward_packets + self.backward_packets
        total_bytes = self.forward_bytes + self.backward_bytes

        # Rate safety: a flow seen at a single instant has duration ~0.
        if duration >= _MIN_DURATION_SECONDS:
            packet_rate = round(total_packets / duration, 2)
            byte_rate = round(total_bytes / duration, 2)
        else:
            packet_rate = 0.0
            byte_rate = 0.0
        average_size = round(total_bytes / total_packets, 1) if total_packets else 0.0

        return {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.last_seen,
            "duration": round(duration, 2),
            "forward_packets": self.forward_packets,
            "backward_packets": self.backward_packets,
            "total_packets": total_packets,
            "forward_bytes": self.forward_bytes,
            "backward_bytes": self.backward_bytes,
            "total_bytes": total_bytes,
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "average_packet_size": average_size,
            # ---- Phase 8 ML feature fields (§13-14) -----------------
            # IAT in MILLISECONDS (CICIDS2017 convention); the streaming
            # variance formula is Var = E[x²] − (E[x])², floored at 0.
            "iat_mean_ms": round(self.iat_sum / self.iat_count * 1000, 3) if self.iat_count else None,
            "iat_std_ms": (
                round(max(0.0, self.iat_sq_sum / self.iat_count - (self.iat_sum / self.iat_count) ** 2) ** 0.5 * 1000, 3)
                if self.iat_count else None
            ),
            "syn_ratio": round(self.syn_count / total_packets, 4) if total_packets else None,
            "rst_ratio": round(self.rst_count / total_packets, 4) if total_packets else None,
        }


class FlowEngine:
    """Owns the active flows and the completed-flow history."""

    def __init__(self):
        self.active = {}          # flow_key -> Flow
        self.completed = []       # list[Flow], newest appended last

    # ------------------------------------------------------------------
    def observe(self, record, now=None):
        """Feed one packet record into the engine (never raises)."""
        try:
            if not record.get("source_ip") or not record.get("destination_ip"):
                return   # nothing meaningful to key a flow on
            timestamp = float(now if now is not None else record.get("timestamp") or time.time())

            # Sweep first so the inactive timeout is always enforced.
            self._sweep(timestamp)

            key = flow_key(
                record.get("protocol"),
                record.get("source_ip"), record.get("source_port"),
                record.get("destination_ip"), record.get("destination_port"),
            )
            flow = self.active.get(key)

            # Active timeout (section 10): rotate even while busy.
            if flow is not None and timestamp - flow.start_time >= FLOW_ACTIVE_TIMEOUT:
                self._complete(key, flow)
                flow = None

            if flow is None:
                flow = Flow(record, timestamp)
                self.active[key] = flow
            flow.observe(record, timestamp)
        except Exception:
            return   # one malformed record must never stop capture

    # ------------------------------------------------------------------
    def _sweep(self, now):
        """Close flows idle for longer than FLOW_INACTIVE_TIMEOUT."""
        expired = [
            key for key, flow in self.active.items()
            if now - flow.last_seen >= FLOW_INACTIVE_TIMEOUT
        ]
        for key in expired:
            self._complete(key, self.active[key])

    def _complete(self, key, flow):
        """Move a flow from active to the completed history and persist to SQLite."""
        flow.status = "COMPLETED"
        self.completed.append(flow)
        del self.active[key]
        # Keep only the newest history entries.
        if len(self.completed) > MAX_COMPLETED_FLOWS:
            del self.completed[: len(self.completed) - MAX_COMPLETED_FLOWS]

        # Phase 4 section 15: persist finalized flow to SQLite database
        try:
            import database
            database.insert_flow(flow.to_row())
        except Exception:
            pass

    # ------------------------------------------------------------------
    @staticmethod
    def _matches(flow, protocol=None, src_ip=None, dst_ip=None,
                 src_port=None, dst_port=None, status=None):
        """Apply the simple filters from section 13 (all optional)."""
        if protocol and flow.protocol != protocol.upper():
            return False
        if src_ip and src_ip not in str(flow.source_ip):
            return False
        if dst_ip and dst_ip not in str(flow.destination_ip):
            return False
        if src_port and int(flow.source_port or 0) != int(src_port):
            return False
        if dst_port and int(flow.destination_port or 0) != int(dst_port):
            return False
        if status and flow.status != status.upper():
            return False
        return True

    def get_stats(self):
        """Summary metrics across all flows for GET /api/flows/stats (section 16)."""
        now = time.time()
        self._sweep(now)
        active_rows = list(self.active.values())
        all_rows = list(self.completed) + active_rows
        return {
            "total_flows": len(all_rows),
            "active_flows": len(active_rows),
            "completed_flows": len(self.completed),
            "total_bytes": sum(f.forward_bytes + f.backward_bytes for f in all_rows),
            "total_packets": sum(f.forward_packets + f.backward_packets for f in all_rows),
        }

    def query(self, limit=200, **filters):
        """Return matching flows (newest activity first) + summary.

        filters: protocol, src_ip, dst_ip, src_port, dst_port, status
        (section 13). Filters apply to the FLOW's forward direction,
        which is the simplest beginner-friendly interpretation.
        """
        try:
            limit = int(limit)
        except (ValueError, TypeError):
            limit = 200
        now = time.time()
        self._sweep(now)

        # Normalize alias parameter names
        normalized_filters = dict(filters)
        if "source_ip" in normalized_filters and "src_ip" not in normalized_filters:
            normalized_filters["src_ip"] = normalized_filters.pop("source_ip")
        if "destination_ip" in normalized_filters and "dst_ip" not in normalized_filters:
            normalized_filters["dst_ip"] = normalized_filters.pop("destination_ip")
        if "source_port" in normalized_filters and "src_port" not in normalized_filters:
            normalized_filters["src_port"] = normalized_filters.pop("source_port")
        if "destination_port" in normalized_filters and "dst_port" not in normalized_filters:
            normalized_filters["dst_port"] = normalized_filters.pop("destination_port")

        rows = list(self.completed) + list(self.active.values())
        rows = [f for f in rows if self._matches(f, **normalized_filters)]
        rows.sort(key=lambda f: f.last_seen, reverse=True)

        return {
            "summary": self.get_stats(),
            "count": len(rows),
            "flows": [f.to_row() for f in rows[:limit]],
        }


# One global engine shared by the capture engine and the API.
flow_engine = FlowEngine()
