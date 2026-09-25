"""
test_phase4.py — Phase 4 backend check (runs WITHOUT capture)

IMPORTANT: these tests BUILD packet records in memory purely to verify
the connection state machine and the flow engine's logic. They are
never written to the database and never shown in the UI — the app only
ever displays REAL captured traffic.

Run from the `backend` folder:
    python test_phase4.py
"""

import time

from flow_analysis import (
    FLOW_ACTIVE_TIMEOUT,
    FLOW_INACTIVE_TIMEOUT,
    FlowEngine,
    flow_key,
)
from tcp_analysis import TcpTracker, connection_key, parse_tcp_flags

_passed = 0
_failed = 0


def check(condition, message):
    """Print PASS/FAIL for one assertion."""
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"[PASS] {message}")
    else:
        _failed += 1
        print(f"[FAIL] {message}")


def tcp_record(src, sport, dst, dport, flags, size=100, ts=1000.0):
    """A Phase-3-shaped metadata dict for one TCP packet."""
    return {
        "timestamp": ts, "size": size,
        "source_ip": src, "destination_ip": dst,
        "source_port": sport, "destination_port": dport,
        "protocol": "TCP", "tcp_flags": flags,
    }


def main():
    now = time.time()

    # ---- 1) Bidirectional connection key (section 6) -------------------
    k1 = connection_key("192.168.1.5", 52341, "8.8.8.8", 443)
    k2 = connection_key("8.8.8.8", 443, "192.168.1.5", 52341)
    check(k1 == k2, "A:52341->B:443 equals B:443->A:52341 (one connection)")
    check(
        connection_key("10.0.0.1", 1, "10.0.0.2", 2)
        != connection_key("10.0.0.1", 1, "10.0.0.2", 3),
        "Different destination ports are different connections",
    )

    # ---- 2) Flag string parsing ----------------------------------------
    check(parse_tcp_flags("SYN, ACK") == {"SYN", "ACK"}, "Flag string 'SYN, ACK' parsed")
    check(parse_tcp_flags(None) == set(), "Flag string None -> empty set")
    check(parse_tcp_flags("garbage") == {"GARBAGE"}, "Unknown flag text still parses safely")

    # ---- 3) Full handshake state machine (sections 2 + 3) --------------
    tracker = TcpTracker()
    client, server = "192.168.1.5", "142.250.190.78"
    tracker.observe(tcp_record(client, 52341, server, 443, "SYN", ts=now - 5))
    conn = next(iter(tracker.connections.values()))
    check(conn.display_state(now) == "SYN_SENT", "SYN observed -> SYN_SENT")

    tracker.observe(tcp_record(server, 443, client, 52341, "SYN, ACK", ts=now - 4))
    check(conn.display_state(now) == "SYN_RECEIVED", "SYN-ACK observed -> SYN_RECEIVED")

    tracker.observe(tcp_record(client, 52341, server, 443, "ACK", ts=now - 3))
    check(conn.display_state(now) == "ESTABLISHED", "Final ACK -> ESTABLISHED")
    check(conn.handshake_complete, "Handshake marked complete")

    stats = tracker.summary(now)
    check(stats["flag_counts"]["syn"] == 1, "SYN packet counted (1)")
    check(stats["flag_counts"]["syn_ack"] == 1, "SYN-ACK packet counted (1)")
    check(stats["flag_counts"]["ack"] == 1, "ACK packet counted (1)")
    check(stats["summary"]["completed_handshakes"] == 1, "1 completed handshake")
    check(stats["summary"]["established"] == 1, "1 established connection")

    # ---- 4) Bidirectional packets stay ONE connection (section 6) -------
    # So far: SYN (f), SYN-ACK (b), ACK (f) = 3 packets.
    tracker.observe(tcp_record(server, 443, client, 52341, "ACK", size=500, ts=now - 2))
    check(len(tracker.connections) == 1, "Reverse direction joins the same connection")
    # Now 4 packets: forward = SYN + ACK (2), backward = SYN-ACK + ACK (2)
    row = tracker.connection_rows(now=now)[0]
    check(row["forward_packets"] == 2 and row["backward_packets"] == 2,
          f"Forward/backward counts split correctly (f={row['forward_packets']}, b={row['backward_packets']})")
    check(row["packets"] == 4 and row["bytes"] == 800,
          f"Totals = f+b (pkts={row['packets']}, bytes={row['bytes']})")

    # ---- 5) Teardown: FIN both ways -> CLOSED ---------------------------
    tracker.observe(tcp_record(client, 52341, server, 443, "FIN, ACK", ts=now - 1))
    check(conn.display_state(now) == "FIN_WAIT", "First FIN -> FIN_WAIT")
    tracker.observe(tcp_record(server, 443, client, 52341, "FIN, ACK", ts=now - 0.5))
    check(conn.display_state(now) == "CLOSED", "FIN both directions -> CLOSED")

    # ---- 6) RST -> RESET -------------------------------------------------
    tracker.observe(tcp_record("192.168.1.9", 60000, "93.184.216.34", 80, "RST", ts=now))
    states = [c.display_state(now) for c in tracker.connections.values()]
    check("RESET" in states, "RST observed -> RESET")
    check(tracker.summary(now)["flag_counts"]["rst"] >= 1, "RST packet counted")

    # ---- 7) Passive observation: mid-connection join -> PARTIAL (sec 7) --
    partial_tracker = TcpTracker()
    partial_tracker.observe(
        tcp_record("10.0.0.2", 51000, "151.101.1.69", 443, "PSH, ACK", ts=now)
    )
    conn2 = next(iter(partial_tracker.connections.values()))
    check(conn2.display_state(now) == "PARTIAL",
          "First packet is data (no SYN) -> PARTIAL, no false claim")
    check(not conn2.observed_start, "observed_start stays False without a SYN")

    # ---- 8) Stalled handshake -> INCOMPLETE ------------------------------
    stalled = TcpTracker()
    stalled.observe(tcp_record("10.0.0.3", 51001, "10.0.0.4", 443, "SYN", ts=now - 60))
    conn3 = next(iter(stalled.connections.values()))
    check(conn3.display_state(now) == "INCOMPLETE",
          "SYN with no reply for 60s -> INCOMPLETE")

    # ---- 9) Malformed TCP record must not crash the tracker (section 20)
    try:
        tracker.observe({"protocol": "TCP"})          # every field missing
        tracker.observe(None)
        check(True, "Malformed TCP records ignored without crash")
    except Exception as error:
        check(False, f"Malformed TCP record raised: {error}")
    check(tracker.observe({"protocol": "UDP"}) is None, "Non-TCP packet ignored")

    # ---- 10) Flow key is bidirectional (sections 8 + 9) ------------------
    f1 = flow_key("TCP", "192.168.1.10", 52341, "142.1.1.1", 443)
    f2 = flow_key("TCP", "142.1.1.1", 443, "192.168.1.10", 52341)
    check(f1 == f2, "Forward and backward 5-tuples are the SAME flow")
    check(
        flow_key("TCP", "192.168.1.10", 52341, "142.1.1.1", 443)
        != flow_key("UDP", "192.168.1.10", 52341, "142.1.1.1", 443),
        "Different protocols are different flows",
    )

    # ---- 11) Flow metrics (section 11) -----------------------------------
    engine = FlowEngine()
    base = 10000.0
    engine.observe({"timestamp": base, "size": 100, "source_ip": "1.1.1.1",
                    "destination_ip": "2.2.2.2", "source_port": 1111,
                    "destination_port": 80, "protocol": "TCP"})
    engine.observe({"timestamp": base + 10, "size": 300, "source_ip": "2.2.2.2",
                    "destination_ip": "1.1.1.1", "source_port": 80,
                    "destination_port": 1111, "protocol": "TCP"})
    flow = next(iter(engine.active.values()))
    row = flow.to_row()
    check(row["duration"] == 10.0, f"Duration = 10s ({row['duration']})")
    check(row["forward_packets"] == 1 and row["backward_packets"] == 1,
          "Forward/backward packet counts tracked separately")
    check(row["total_packets"] == 2 and row["total_bytes"] == 400,
          f"Totals correct (pkts={row['total_packets']}, bytes={row['total_bytes']})")
    check(row["packet_rate"] == 0.2, f"Packet rate = 2/10 ({row['packet_rate']})")
    check(row["byte_rate"] == 40.0, f"Byte rate = 400/10 ({row['byte_rate']})")
    check(row["average_packet_size"] == 200.0, f"Avg packet size ({row['average_packet_size']})")

    # ---- 12) Zero-duration flow must not divide by zero (section 11) -----
    engine2 = FlowEngine()
    engine2.observe({"timestamp": base, "size": 50, "source_ip": "3.3.3.3",
                     "destination_ip": "4.4.4.4", "source_port": 5,
                     "destination_port": 6, "protocol": "UDP"})
    instant_row = next(iter(engine2.active.values())).to_row()
    check(instant_row["packet_rate"] == 0.0 and instant_row["byte_rate"] == 0.0,
          "Zero-duration flow reports 0.0 rates (no ZeroDivisionError)")

    # ---- 13) Inactive timeout closes idle flows (section 10) -------------
    check(FLOW_INACTIVE_TIMEOUT == 15.0, "Inactive timeout is 15 seconds")
    check(FLOW_ACTIVE_TIMEOUT == 120.0, "Active timeout is 120 seconds")
    # 6 seconds after flow1's last packet: NOT yet expired (6 < 15).
    engine.observe({"timestamp": base + 16, "size": 10, "source_ip": "5.5.5.5",
                    "destination_ip": "6.6.6.6", "source_port": 1,
                    "destination_port": 2, "protocol": "UDP"})
    check(len(engine.completed) == 0,
          "Flow idle only 6s is still active (15s not reached)")
    check(len(engine.active) == 2, "Both flows active before the timeout")
    # 24+ seconds later: both older flows exceed the 15s idle window.
    engine.observe({"timestamp": base + 40, "size": 10, "source_ip": "9.9.9.9",
                    "destination_ip": "10.0.0.10", "source_port": 77,
                    "destination_port": 78, "protocol": "UDP"})
    check(len(engine.completed) == 2,
          "Flows idle >15s were closed by the sweep")
    check(len(engine.active) == 1, "Only the newest flow remains active")

    # ---- 14) Active timeout rotates a busy flow (section 10) -------------
    busy = FlowEngine()
    start = 20000.0
    busy.observe({"timestamp": start, "size": 10, "source_ip": "7.7.7.7",
                  "destination_ip": "8.8.8.8", "source_port": 9,
                  "destination_port": 10, "protocol": "TCP"})
    busy.observe({"timestamp": start + FLOW_ACTIVE_TIMEOUT + 1, "size": 10,
                  "source_ip": "7.7.7.7", "destination_ip": "8.8.8.8",
                  "source_port": 9, "destination_port": 10, "protocol": "TCP"})
    check(len(busy.completed) == 1 and len(busy.active) == 1,
          "Active timeout rotated the flow into a new segment")

    # ---- 15) Flow filtering (section 13) ---------------------------------
    result = engine.query(protocol="TCP")
    check(result["summary"]["total_flows"] >= 2, "Summary counts are global")
    check(all(f["protocol"] == "TCP" for f in result["flows"]),
          "protocol=TCP filter returns only TCP flows")
    result2 = engine.query(status="COMPLETED")
    check(all(f["status"] == "COMPLETED" for f in result2["flows"]),
          "status=COMPLETED filter works")
    result3 = engine.query(src_ip="7.7.7.7")
    check(result3["count"] == 0, "Filters combine (7.7.7.7 not in engine, only busy)")

    # ---- 16) Malformed flow record must not crash the engine -------------
    try:
        engine.observe({"protocol": "TCP"})     # no IPs
        engine.observe(None)
        check(True, "Malformed flow records ignored without crash")
    except Exception as error:
        check(False, f"Malformed flow record raised: {error}")

    # ---- 17) flows.py module & get_stats (sections 14 & 16) --------------
    import flows
    check(hasattr(flows, "flow_engine"), "backend/flows.py provides flow_engine")
    stats = engine.get_stats()
    check("total_flows" in stats and "active_flows" in stats, "get_stats() returns summary statistics")

    # ---- 18) Query alias filtering (source_ip / destination_ip) ----------
    res_alias = engine.query(source_ip="1.1.1.1")
    check(res_alias["count"] > 0, "Query with source_ip alias filters correctly")

    # ---- 19) Database flows table (section 15) ---------------------------
    import database
    database.init_db()
    init_flow_count = database.flow_count()
    check(init_flow_count >= 0, "database.flow_count() queries flows table successfully")

    print(f"\n{_passed}/{_passed + _failed} checks passed.")
    if _failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
