"""
test_phase7.py — Phase 7 backend checks (no real network calls)

All tracert/route/ipconfig outputs are FAKE STRINGS pasted from real
command shapes — the tests exercise the PARSERS and VALIDATOR only,
so the suite is fast, offline and deterministic.

Run from the `backend` folder:
    python test_phase7.py
"""

import routing

CHECKS = []


def check(name, condition):
    CHECKS.append((name, bool(condition)))
    print(("PASS" if condition else "FAIL"), "-", name)


# ======================================================================
# Target validation (sections 6 + 14): injection attempts must fail
# ======================================================================
for good in ("example.com", "8.8.8.8", "192.168.1.1", "my-server.local.lan",
             "fe80::1", "a-b.example.co"):
    check(f"valid target accepted: {good}", routing.validate_target(good))

for bad in ("", "example.com; rm -rf /", "8.8.8.8 && whoami", "$(whoami)",
            "example com", "-h", "--help", "a" * 300, "exam ple.com",
            "http://example.com", "example.com/path", "..", "host_name"):
    check(f"invalid target rejected: {bad[:24]!r}", not routing.validate_target(bad))

# ======================================================================
# route print parsing (section 4)
# ======================================================================
ROUTE_PRINT = """
===========================================================================
Interface List
  5...aa bb cc dd ee ff ......Realtek Wi-Fi Adapter
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.44     30
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      192.168.1.0    255.255.255.0         On-link     192.168.1.44    311
===========================================================================
Persistent Routes:
  None
"""
routes = routing._parse_route_print(ROUTE_PRINT)
check("3 real routes parsed", len(routes) == 3)
default = routes[0]
check("default route destination", default["destination"] == "0.0.0.0")
check("default route gateway", default["gateway"] == "192.168.1.1")
check("default route interface", default["interface"] == "192.168.1.44")
check("default route metric", default["metric"] == 30)
onlink = routes[1]
check("On-link -> gateway None", onlink["gateway"] is None)
check("mask 255.0.0.0 -> prefix 8", onlink["prefix"] == 8)
check("mask 255.255.255.0 -> prefix 24", routes[2]["prefix"] == 24)

# ======================================================================
# ipconfig parsing (section 2)
# ======================================================================
IPCONFIG = """
Windows IP Configuration

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . : home
   Description. . . . . . . . . . . : Realtek 8822CE Wireless
   Physical Address. . . . . . . . : AA-BB-CC-DD-EE-FF
   IPv4 Address. . . . . . . . . . : 192.168.1.44(Preferred)
   Subnet Mask . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . : 192.168.1.1

Ethernet adapter Ethernet:

   Media State . . . . . . . . . . : Media disconnected
   Physical Address. . . . . . . . : 11-22-33-44-55-66
   Connection-specific DNS Suffix  . :
"""
interfaces = routing._parse_ipconfig(IPCONFIG)
check("two adapters listed", len(interfaces) == 2)
wifi = interfaces[0]
check("adapter name", wifi["name"] == "Wireless LAN adapter Wi-Fi")
check("adapter ipv4", wifi["ipv4"] == "192.168.1.44")
check("adapter mac", wifi["mac"] == "AA-BB-CC-DD-EE-FF")
check("adapter gateway", wifi["gateway"] == "192.168.1.1")
check("adapter subnet", wifi["subnet"] == "255.255.255.0")
ethernet = interfaces[1]
check("disconnected adapter status down", ethernet["status"] == "down")
check("disconnected adapter keeps mac", ethernet["mac"] == "11-22-33-44-55-66")

# ======================================================================
# tracert parsing (sections 6-7) — real Windows output shapes
# ======================================================================
TRACERT = """
Tracing route to example.com [93.184.216.34]
over a maximum of 30 hops:

  1     2 ms     1 ms     2 ms  192.168.1.1
  2     8 ms     7 ms     9 ms  10.10.0.1
  3    12 ms    12 ms    14 ms  93.184.216.34

Trace complete.
"""
hops = routing.parse_tracert(TRACERT)
check("three hops parsed", len(hops) == 3)
check("hop numbers correct", [h["hop"] for h in hops] == [1, 2, 3])
check("hop 1 ip", hops[0]["ip"] == "192.168.1.1")
check("hop 1 rtt (min of probes)", hops[0]["rtt_ms"] == 1.0)
check("hop 1 reachable", hops[0]["status"] == "reachable")
check("hop 3 ip", hops[2]["ip"] == "93.184.216.34")

TIMEOUT_TRACERT = """
  1     2 ms     1 ms     2 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3    15 ms    13 ms    14 ms  93.184.216.34
"""
timeout_hops = routing.parse_tracert(TIMEOUT_TRACERT)
check("timeout hop present", len(timeout_hops) == 3)
check("timeout hop number", timeout_hops[1]["hop"] == 2)
check("timeout hop ip None", timeout_hops[1]["ip"] is None)
check("timeout hop rtt None", timeout_hops[1]["rtt_ms"] is None)
check("timeout hop status", timeout_hops[1]["status"] == "timeout")
check("reachable after timeout", timeout_hops[2]["status"] == "reachable")

# Hostname extraction: reverse-DNS names are kept, timing tokens are
# stripped, and RTT-only lines yield hostname=None (§7).
HOSTNAME_TRACERT = (
    "  1     2 ms     1 ms     2 ms  router.home [192.168.1.1]\n"
    "  2     8 ms     7 ms     9 ms  10.10.0.1\n"
)
hostname_hops = routing.parse_tracert(HOSTNAME_TRACERT)
check("hostname kept", hostname_hops[0]["hostname"] == "router.home")
check("rtt-only line -> hostname None", hostname_hops[1]["hostname"] is None)
check("hostname hop ip", hostname_hops[0]["ip"] == "192.168.1.1")

# IPv6 + bracketed address shape.
V6_TRACERT = "  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n  2    9 ms  fe80::1\n"
v6_hops = routing.parse_tracert(V6_TRACERT)
check("ipv6 hop parsed", any(h["ip"] == "fe80::1" for h in v6_hops))
check("sub-millisecond rtt", v6_hops[0]["rtt_ms"] == 1.0)

# Garbage lines never crash the parser (section 13).
garbage = routing.parse_tracert("hello world\n\n\x00\x01binary\n  99 x\n")
check("garbage lines ignored", isinstance(garbage, list))

# ======================================================================
# Linux traceroute parsing (fallback)
# ======================================================================
LINUX = (
    " 1  192.168.1.1  2.412 ms  1.998 ms  2.100 ms\n"
    " 2  10.10.0.1  8.510 ms  9.002 ms\n"
    " 3  * * *\n"
)
linux_hops = routing.parse_linux_traceroute(LINUX)
check("linux hops parsed", len(linux_hops) == 3)
check("linux hop 1 rtt", linux_hops[0]["rtt_ms"] == 1.998)
check("linux timeout hop", linux_hops[2]["status"] == "timeout")

# ======================================================================
# Gateway from REAL parsed table (section 3)
# ======================================================================
class FakeTable:
    pass


original = routing.get_routing_table
try:
    routing.get_routing_table = lambda: {"routes": routes, "source": "fake"}
    gateway = routing.get_gateway()
    check("gateway from real route table", gateway["gateway"] == "192.168.1.1")
    check("gateway interface", gateway["interface"] == "192.168.1.44")

    routing.get_routing_table = lambda: {"routes": [], "source": "fake"}
    no_gateway = routing.get_gateway()
    check("no gateway -> null + message", no_gateway["gateway"] is None
          and no_gateway["message"] is not None)
finally:
    routing.get_routing_table = original

# ======================================================================
failed = [name for name, ok in CHECKS if not ok]
print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed.")
if failed:
    print("FAILED:", *failed, sep="\n  - ")
    raise SystemExit(1)
