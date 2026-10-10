"""
tcp_analysis.py — PHASE 4: TCP connection tracking

WHAT THIS FILE DOES
-------------------
Turns the per-packet TCP metadata extracted in Phase 3 into tracked
TCP CONNECTIONS:

    * A bidirectional connection key, so A:52341 -> B:443 and
      B:443 -> A:52341 are recognized as ONE connection (section 6).
    * A small state machine driven by observed TCP flags (section 3):

          SYN observed            -> SYN_SENT
          SYN + ACK observed      -> SYN_RECEIVED
          ACK after SYN-ACK       -> ESTABLISHED
          FIN observed            -> FIN_WAIT
          FIN seen in both dirs   -> CLOSED
          RST observed            -> RESET

    * A flag/handshake statistics counter (section 4).

IMPORTANT PASSIVE-SNiffING LIMITATION (section 7)
-------------------------------------------------
We observe traffic passively: capture often starts AFTER a connection
was already established, and packets can be missed. Therefore:

    * If the first packet we see for a connection is NOT a SYN, the
      connection never enters the handshake states — it is marked
      PARTIAL (we observed it mid-flight; we do not claim to have
      reconstructed it).
    * If a handshake starts (SYN seen) but never completes and then
      goes quiet for INCOMPLETE_AFTER_SECONDS, it is shown as
      INCOMPLETE.

We NEVER claim perfect TCP state tracking.

Privacy: this module only ever reads the metadata dictionary built by
protocol_analysis.analyze_packet() — no packet payloads exist here.
"""

import time

# Keep at most this many tracked connections (oldest evicted first),
# so a long capture cannot grow memory forever.
MAX_CONNECTIONS = 2000

# A handshake that started (SYN) but has been quiet for this long
# without reaching ESTABLISHED is reported as INCOMPLETE.
INCOMPLETE_AFTER_SECONDS = 10.0


# ----------------------------------------------------------------------
# Connection identifier (section 6): bidirectional / normalized key
# ----------------------------------------------------------------------
def connection_key(src_ip, src_port, dst_ip, dst_port):
    """Return a normalized, direction-independent connection key.

    (192.168.1.5, 52341) <-> (8.8.8.8, 443) is the SAME key no matter
    which side sent the packet we are looking at, because the two
    endpoint tuples are sorted. This is what keeps A->B and B->A in a
    single connection instead of two.
    """
    endpoint_a = (str(src_ip or "-"), int(src_port or 0))
    endpoint_b = (str(dst_ip or "-"), int(dst_port or 0))
    return (endpoint_a, endpoint_b) if endpoint_a <= endpoint_b else (endpoint_b, endpoint_a)


def parse_tcp_flags(flags_string):
    """Turn a Phase 3 flag string ("SYN, ACK") into a set {"SYN", "ACK"}.

    Returns an empty set for None/garbage — malformed input must never
    raise (section 20 error handling).
    """
    if not flags_string:
        return set()
    return {part.strip().upper() for part in str(flags_string).split(",") if part.strip()}


class TcpConnection:
    """One tracked TCP connection (both directions combined)."""

    def __init__(self, record, now):
        # First-seen direction becomes the display "Source -> Destination".
        self.source_ip = record.get("source_ip") or "-"
        self.source_port = record.get("source_port") or 0
        self.destination_ip = record.get("destination_ip") or "-"
        self.destination_port = record.get("destination_port") or 0
        self.key = connection_key(
            self.source_ip, self.source_port, self.destination_ip, self.destination_port
        )
        self.first_direction = (self.source_ip, self.source_port)

        self.state = None          # raw state: None until a TCP event is seen
        self.observed_start = False    # did we see the initial SYN?
        self.handshake_complete = False  # SYN -> SYN-ACK -> ACK all observed?
        self.fin_directions = set()   # which directions sent FIN ("f"/"b")

        self.forward_packets = 0
        self.backward_packets = 0
        self.forward_bytes = 0
        self.backward_bytes = 0

        self.start_time = now
        self.last_seen = now
        # Sequence ladder events for interactive handshake/timeline visualization
        self.events = []

    # Which side of the (normalized) connection sent this packet?
    def direction(self, record):
        if (record.get("source_ip"), record.get("source_port")) == self.first_direction:
            return "f"
        return "b"

    def display_state(self, now=None):
        """Human-facing state string (section 3 + section 7).

        - No handshake events observed at all -> PARTIAL (we started
          watching mid-connection; we do not pretend to know more).
        - Handshake started but stalled (quiet for
          INCOMPLETE_AFTER_SECONDS) -> INCOMPLETE.
        - Otherwise the raw state machine value.
        """
        if self.state is None:
            return "PARTIAL"
        if self.state in ("SYN_SENT", "SYN_RECEIVED"):
            reference = now if now is not None else time.time()
            if reference - self.last_seen >= INCOMPLETE_AFTER_SECONDS:
                return "INCOMPLETE"
        return self.state

    def to_row(self, now=None):
        """JSON-safe row for the TCP Analysis connection table."""
        total_packets = self.forward_packets + self.backward_packets
        total_bytes = self.forward_bytes + self.backward_bytes
        return {
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "state": self.display_state(now),
            "packets": total_packets,
            "bytes": total_bytes,
            "forward_packets": self.forward_packets,
            "backward_packets": self.backward_packets,
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "observed_start": self.observed_start,
            "handshake_complete": self.handshake_complete,
            "events": list(self.events),
        }


class TcpTracker:
    """Watches every captured TCP packet and maintains connections."""

    def __init__(self):
        self.connections = {}   # connection_key -> TcpConnection
        # Packet-level flag counters (section 4 handshake statistics)
        self.flag_counts = {"syn": 0, "syn_ack": 0, "ack": 0, "fin": 0, "rst": 0}

    # ------------------------------------------------------------------
    def observe(self, record):
        """Feed one Phase 3 packet record into the tracker.

        Non-TCP packets and records without IPs/ports are ignored.
        This function must never raise (one bad packet must not stop
        capture — section 20).
        """
        try:
            if (record.get("protocol") or "").upper() != "TCP":
                return
            if not record.get("source_ip") or not record.get("destination_ip"):
                return

            now = float(record.get("timestamp") or time.time())
            flags = parse_tcp_flags(record.get("tcp_flags"))
            size = int(record.get("size") or 0)

            key = connection_key(
                record.get("source_ip"), record.get("source_port"),
                record.get("destination_ip"), record.get("destination_port"),
            )
            connection = self.connections.get(key)
            if connection is None:
                connection = TcpConnection(record, now)
                self.connections[key] = connection
                self._evict_if_needed()
            direction = connection.direction(record)

            # ---- byte/packet counters (both directions) ---------------
            if direction == "f":
                connection.forward_packets += 1
                connection.forward_bytes += size
            else:
                connection.backward_packets += 1
                connection.backward_bytes += size
            connection.last_seen = max(connection.last_seen, now)

            # ---- packet-level flag statistics (section 4) -------------
            has_syn = "SYN" in flags
            has_ack = "ACK" in flags
            has_fin = "FIN" in flags
            has_rst = "RST" in flags
            if has_rst:
                self.flag_counts["rst"] += 1
            elif has_syn and has_ack:
                self.flag_counts["syn_ack"] += 1
            elif has_syn:
                self.flag_counts["syn"] += 1
            elif has_fin:
                self.flag_counts["fin"] += 1
            elif has_ack:
                # Plain ACK (no SYN/FIN/RST): pure acknowledgement /
                # data-carrying segment.
                self.flag_counts["ack"] += 1

            # ---- state machine (section 3) ----------------------------
            if has_rst:
                connection.state = "RESET"
            elif has_syn and has_ack:
                # SYN-ACK: only meaningful right after a SYN we saw.
                if not connection.handshake_complete:
                    connection.observed_start = True
                    if connection.state in (None, "SYN_SENT", "PARTIAL"):
                        connection.state = "SYN_RECEIVED"
            elif has_syn:
                # Initial SYN. If we already saw FIN/RST do not rewind.
                if connection.state in (None, "PARTIAL"):
                    connection.observed_start = True
                    connection.state = "SYN_SENT"
            elif has_fin:
                if connection.state not in ("RESET", "CLOSED"):
                    connection.state = "FIN_WAIT"
                    connection.fin_directions.add(direction)
                    # Both sides said FIN -> connection teardown finished.
                    if len(connection.fin_directions) >= 2:
                        connection.state = "CLOSED"
            elif has_ack and connection.state == "SYN_RECEIVED":
                # Final ACK of the three-way handshake.
                connection.state = "ESTABLISHED"
                connection.handshake_complete = True
            # Plain ACK/data on a connection we joined mid-flight keeps
            # state None -> displayed as PARTIAL (section 7).

            # ---- Record event for the interactive ladder visualizer ---
            if len(connection.events) < 50:
                summary_text = "Data / ACK"
                if has_rst:
                    summary_text = "Abort: RST (Connection Reset)"
                elif has_syn and has_ack:
                    summary_text = "Handshake Step 2: SYN-ACK (Server Response)"
                elif has_syn:
                    summary_text = "Handshake Step 1: SYN (Connection Request)"
                elif has_fin:
                    summary_text = "Teardown: FIN (Close Connection)"
                elif has_ack and connection.handshake_complete and len(connection.events) <= 2:
                    summary_text = "Handshake Step 3: ACK (Handshake Complete)"
                elif size > 0:
                    summary_text = f"Payload Data ({size} B)"
                elif has_ack:
                    summary_text = "Acknowledgment (ACK)"

                connection.events.append({
                    "timestamp": now,
                    "delta_ms": round(max(0.0, (now - connection.start_time) * 1000), 1),
                    "direction": direction,  # "f" (client -> server) or "b" (server -> client)
                    "flags": sorted(list(flags)),
                    "flags_str": record.get("tcp_flags") or "None",
                    "seq": record.get("tcp_seq"),
                    "ack": record.get("tcp_ack"),
                    "size": size,
                    "state_after": connection.display_state(now),
                    "summary": summary_text,
                })
        except Exception:
            return   # never let one malformed record break capture

    # ------------------------------------------------------------------
    def _evict_if_needed(self):
        """Keep memory bounded: drop the least-recently-seen connection."""
        while len(self.connections) > MAX_CONNECTIONS:
            oldest_key = min(
                self.connections, key=lambda k: self.connections[k].last_seen
            )
            del self.connections[oldest_key]

    # ------------------------------------------------------------------
    def summary(self, now=None):
        """Statistics for the TCP Analysis cards (sections 4 + 5)."""
        reference = now if now is not None else time.time()
        states = [conn.display_state(reference) for conn in self.connections.values()]

        active = sum(1 for s in states if s not in ("CLOSED", "RESET"))
        established = sum(1 for s in states if s == "ESTABLISHED")
        incomplete = sum(
            1 for s in states if s in ("PARTIAL", "INCOMPLETE", "SYN_SENT", "SYN_RECEIVED")
        )
        reset = sum(1 for s in states if s == "RESET")
        closed = sum(1 for s in states if s == "CLOSED")

        # Handshake-level statistics (section 4)
        completed_handshakes = sum(
            1 for c in self.connections.values() if c.handshake_complete
        )
        incomplete_handshakes = sum(
            1 for c in self.connections.values()
            if c.observed_start and not c.handshake_complete and c.state != "RESET"
        )

        return {
            "summary": {
                "total": len(self.connections),
                "active": active,
                "established": established,
                "incomplete": incomplete,
                "reset": reset,
                "closed": closed,
                "completed_handshakes": completed_handshakes,
                "inactive_or_partial": incomplete_handshakes,
            },
            "flag_counts": dict(self.flag_counts),
        }

    def connection_rows(self, limit=100, now=None):
        """Newest-first rows for the TCP Analysis table."""
        try:
            limit = int(limit)
        except (ValueError, TypeError):
            limit = 100
        reference = now if now is not None else time.time()
        ordered = sorted(
            self.connections.values(), key=lambda c: c.last_seen, reverse=True
        )
        return [conn.to_row(reference) for conn in ordered[:limit]]


# One global tracker shared by the capture engine and the API.
tcp_tracker = TcpTracker()
