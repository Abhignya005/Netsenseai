"""
test_phase6.py — Phase 6 backend checks (no capture, no network access)

Every check uses in-memory packet records and a fresh registry/engine.
Nothing is written to the database, nothing touches the real network.

Run from the `backend` folder:
    python test_phase6.py
"""

import socket
import time

import devices as devices_module
import topology as topology_module
from devices import DeviceRegistry
from flow_analysis import FlowEngine

CHECKS = []


def check(name, condition):
    CHECKS.append((name, bool(condition)))
    print(("PASS" if condition else "FAIL"), "-", name)


def make_record(src_ip, dst_ip, src_mac=None, dst_mac=None, size=100,
                protocol="TCP", timestamp=None):
    return {
        "timestamp": timestamp or time.time(),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_mac": src_mac,
        "destination_mac": dst_mac,
        "protocol": protocol,
        "size": size,
    }


# ======================================================================
# Device discovery (sections 2-3, 21)
# ======================================================================
registry = DeviceRegistry()

check("empty registry -> no devices", registry.rows() == [])
check("empty stats", registry.stats()["total_devices"] == 0)

# One packet with both endpoints -> two devices.
registry.observe(make_record(
    "192.168.1.10", "192.168.1.1", "AA:AA:AA:AA:AA:01", "GG:GG:GG:GG:GG:01",
    size=500, protocol="TCP",
))
check("two devices from one packet", len(registry.rows()) == 2)

# 999 more packets from the same IP/MAC -> still ONE device (section 21).
for _ in range(999):
    registry.observe(make_record(
        "192.168.1.10", "192.168.1.1", "AA:AA:AA:AA:AA:01", "GG:GG:GG:GG:GG:01",
        size=100, protocol="TCP",
    ))
rows = {r["ip"]: r for r in registry.rows()}
check("no duplicate devices (1000 packets)", len(registry.rows()) == 2)
check("packet count aggregated", rows["192.168.1.10"]["packet_count"] == 1000)
check("bytes aggregated", rows["192.168.1.10"]["bytes"] == 500 + 999 * 100)
check("protocols observed", rows["192.168.1.10"]["protocols"] == ["TCP"])

# IP-only and MAC-only endpoints (section 3).
registry.observe(make_record("10.0.0.99", "192.168.1.10", None, "AA:AA:AA:AA:AA:01"))
rows = {r["ip"]: r for r in registry.rows()}
check("ip-only device created", "10.0.0.99" in rows)
check("ip-only device has unknown MAC", rows["10.0.0.99"]["mac"] is None)
check("mac-only endpoint merged into existing device",
      rows["192.168.1.10"]["mac"] == "AA:AA:AA:AA:AA:01")

# THE MERGE TEST: a device known by IP only and a device known by MAC
# only become ONE device when a packet shows both together (section 3).
registry.observe(make_record("10.0.0.77", "192.168.1.1", None, None, protocol="UDP"))
before = len(registry.rows())
registry.observe(make_record(
    "10.0.0.77", "192.168.1.1", "CC:CC:CC:CC:CC:01", "GG:GG:GG:GG:GG:01",
))
merged_rows = {r["ip"]: r for r in registry.rows()}
check("IP+MAC proof merges devices", len(registry.rows()) == before)
check("merged device carries both counters",
      merged_rows["10.0.0.77"]["packet_count"] == 2)
check("merged device has the MAC", merged_rows["10.0.0.77"]["mac"] == "CC:CC:CC:CC:CC:01")

# IPv6 devices are discovered the same way (section 3).
registry.observe(make_record(
    "fe80::1", "ff02::fb", "66:66:66:66:66:66", "33:33:00:00:00:fb",
    protocol="ICMP",
))
check("IPv6 device discovered",
      any(r["ip"] == "fe80::1" for r in registry.rows()))

# Exception safety (section 29).
registry.observe(None)
registry.observe({})
registry.observe({"timestamp": "not-a-number"})
check("malformed records never raise", True)

# Memory bound: 600 unique MACs -> at most MAX_DEVICES stay tracked.
bounded = DeviceRegistry()
for i in range(600):
    bounded.observe(make_record(
        f"10.9.0.{i % 250 + 1}", "10.9.0.250",
        f"DE:AD:BE:EF:00:{i % 256:02x}" if i < 256 else f"DE:AD:BE:EF:01:{(i - 256) % 256:02x}",
        None,
    ))
check("device memory bounded", len(bounded.devices) <= devices_module.MAX_DEVICES)

# ======================================================================
# Gateway + local identification (sections 13-14) — never guessed
# ======================================================================
gw_registry = DeviceRegistry()
gw_registry.observe(make_record("192.168.1.1", "192.168.1.10", "GG:GG:GG:GG:GG:01", None))
gw_registry.set_gateway("192.168.1.1")     # confirmed address
gw_registry.set_local(ips=["192.168.1.50"])
gw_registry.observe(make_record("192.168.1.10", "192.168.1.1", None, "GG:GG:GG:GG:GG:01"))
gw_registry.observe(make_record("192.168.1.50", "192.168.1.1", None, None))
rows = {r["ip"]: r for r in gw_registry.rows()}
check("gateway flagged from confirmed IP", rows["192.168.1.1"]["is_gateway"] is True)
check("gateway flag survives later packets",
      (gw_registry.observe(make_record("192.168.1.10", "192.168.1.1", None, None)),
       {r["ip"]: r for r in gw_registry.rows()}["192.168.1.1"]["is_gateway"])[1])
check("local device flagged", rows["192.168.1.50"]["is_local"] is True)
check("other devices not flagged", rows["192.168.1.10"]["is_gateway"] is False)

# Unknown gateway must NOT flag anything.
no_gw = DeviceRegistry()
no_gw.observe(make_record("192.168.1.1", "192.168.1.10"))
no_gw.set_gateway(None)
check("unknown gateway flags nothing",
      all(not r["is_gateway"] for r in no_gw.rows()))

# ======================================================================
# Hostname resolution (section 4) — cached, background, never per packet
# ======================================================================
hn_registry = DeviceRegistry()
hn_registry.observe(make_record("203.0.113.7", "192.168.1.1"))

calls = {"n": 0}
real_gethostbyaddr = socket.gethostbyaddr


def fake_gethostbyaddr(ip):
    calls["n"] += 1
    if ip == "203.0.113.7":
        return ("laptop.example.test", [], [ip])
    raise OSError("not found")


socket.gethostbyaddr = fake_gethostbyaddr
try:
    hn_registry._resolve_and_store("203.0.113.7")
    first = hn_registry.rows()[0]
    check("hostname resolved via system resolver", first["hostname"] == "laptop.example.test")
    hn_registry._resolve_and_store("203.0.113.7")   # second attempt
    check("hostname lookup cached (one query only)", calls["n"] == 1)
    hn_registry.observe(make_record("203.0.113.99", "192.168.1.1"))
    hn_registry._resolve_and_store("203.0.113.99")  # unresolvable
    unresolved = [r for r in hn_registry.rows() if r["ip"] == "203.0.113.99"]
    check("unresolvable hostname -> Unknown, no crash",
          unresolved and unresolved[0]["hostname"] is None)
finally:
    socket.gethostbyaddr = real_gethostbyaddr

# ======================================================================
# Topology (sections 9-12) — nodes from devices, edges from REAL flows
# ======================================================================
flow_engine = FlowEngine()
top_registry = DeviceRegistry()
NOW = time.time()

# Three devices talk: laptop -> gateway (TCP, both directions), and
# laptop -> phone (UDP, one direction).
for i in range(5):
    flow_engine.observe(make_record(
        "192.168.1.10", "192.168.1.1", "AA:..:01", "GG:..:01",
        size=600, protocol="TCP", timestamp=NOW + i,
    ))
    flow_engine.observe(make_record(
        "192.168.1.1", "192.168.1.10", "GG:..:01", "AA:..:01",
        size=1200, protocol="TCP", timestamp=NOW + i,
    ))
    flow_engine.observe(make_record(
        "192.168.1.10", "192.168.1.20", "AA:..:01", "PH:..:01",
        size=200, protocol="UDP", timestamp=NOW + i,
    ))
    for record in (
        make_record("192.168.1.10", "192.168.1.1", "AA:..:01", "GG:..:01", timestamp=NOW + i),
        make_record("192.168.1.1", "192.168.1.10", "GG:..:01", "AA:..:01", timestamp=NOW + i),
        make_record("192.168.1.10", "192.168.1.20", "AA:..:01", "PH:..:01", timestamp=NOW + i),
        make_record("192.168.1.20", "192.168.1.10", "PH:..:01", "AA:..:01", timestamp=NOW + i),
    ):
        top_registry.observe(record)

topology = topology_module.build_topology(top_registry, flow_engine)

check("three nodes observed", len(topology["nodes"]) == 3)
check("two edges from real flows", len(topology["edges"]) == 2)
node_ids = {n["data"]["id"] for n in topology["nodes"]}
check("node ids are device keys", "AA:..:01" in node_ids and "GG:..:01" in node_ids)

# The bidirectional laptop<->gateway flows must be ONE edge with the
# summed packets of BOTH directions (section 11).
gateway_edge = next(
    e for e in topology["edges"]
    if {e["data"]["source"], e["data"]["target"]} == {"AA:..:01", "GG:..:01"}
)
check("bidirectional edge merged", gateway_edge["data"]["packets"] == 10)
check("edge bytes summed", gateway_edge["data"]["bytes"] == 5 * (600 + 1200))
check("edge protocol recorded", gateway_edge["data"]["protocols"] == ["TCP"])
check("edge carries last seen", gateway_edge["data"]["last_seen"] > 0)

# No device data -> empty topology (section 12, no-data test).
empty = topology_module.build_topology(DeviceRegistry(), FlowEngine())
check("empty topology -> no nodes/edges",
      empty["nodes"] == [] and empty["edges"] == [])

# Malformed flow data must not break the builder (section 29).
class BrokenEngine:
    def query(self, **kwargs):
        raise RuntimeError("boom")

broken = topology_module.build_topology(top_registry, BrokenEngine())
check("broken flow engine -> nodes survive", len(broken["nodes"]) == 3)

# ======================================================================
failed = [name for name, ok in CHECKS if not ok]
print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed.")
if failed:
    print("FAILED:", *failed, sep="\n  - ")
    raise SystemExit(1)
