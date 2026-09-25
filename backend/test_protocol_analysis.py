"""
test_protocol_analysis.py — Stage 3 backend check (runs WITHOUT capture)

IMPORTANT: these tests BUILD packets in memory purely to verify the
analyzer's logic. They are never written to the database and never
shown in the UI as captured data — the app only ever displays REAL
traffic (Stage 3 section 16).

Run from the `backend` folder:
    python test_protocol_analysis.py
"""

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from protocol_analysis import (
    analyze_packet,
    classify_protocol,
    icmp_type_name,
    tcp_flags_to_string,
)

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


def main():
    # ---- 1) TCP handshake opener (SYN) --------------------------------
    syn = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:66")
        / IP(dst="8.8.8.8", ttl=64)
        / TCP(sport=52341, dport=443, flags="S", seq=1000, ack=0)
    )
    r = analyze_packet(syn)
    check(r["protocol"] == "TCP", "TCP packet classified as TCP")
    check(r["tcp_flags"] == "SYN", f"TCP flags decoded -> {r['tcp_flags']}")
    check(
        r["tcp_seq"] == 1000 and r["tcp_ack"] == 0,
        "TCP sequence/acknowledgement numbers extracted (1000/0)",
    )
    check(
        r["eth_type"] is not None and "0x0800" in r["eth_type"],
        f"Ethernet type extracted -> {r['eth_type']}",
    )
    check(
        r["source_port"] == 52341 and r["destination_port"] == 443,
        "TCP ports extracted (52341 -> 443)",
    )
    check(r["ip_version"] == 4 and r["ttl"] == 64, "IPv4 + TTL extracted")
    check(
        r["source_mac"] is not None and r["destination_mac"] is not None,
        "Source/destination MAC extracted",
    )
    check(
        r["icmp_type"] is None and r["dns_query"] is None and r["arp_operation"] is None,
        "Unused fields stay None (JSON null)",
    )

    # ---- 2) Combined TCP flags ----------------------------------------
    check(tcp_flags_to_string("SA") == "SYN, ACK", "Combined flags -> 'SYN, ACK'")
    check(tcp_flags_to_string("A") == "ACK", "ACK only -> 'ACK'")
    check(tcp_flags_to_string(0x12) == "SYN, ACK", "Integer flags 0x12 -> 'SYN, ACK'")
    check(tcp_flags_to_string("FA") == "FIN, ACK", "FIN+ACK -> 'FIN, ACK'")

    # ---- 3) DNS query over UDP/53 WITH a real DNS layer ---------------
    dns_query = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:66")
        / IP(dst="8.8.8.8")
        / UDP(sport=50000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="google.com"))
    )
    r = analyze_packet(dns_query)
    check(r["protocol"] == "DNS", "Real DNS layer classified as DNS")
    check(r["dns_query"] == "google.com", f"DNS query name -> {r['dns_query']}")
    check(r["dns_qr"] == "Query", "DNS direction -> Query")
    check(r["dns_qtype"] == "A", f"DNS query type -> {r['dns_qtype']}")
    check(r["source_port"] == 50000 and r["destination_port"] == 53, "DNS UDP ports kept")

    # ---- 4) Port 53 WITHOUT a DNS layer must stay UDP (section 5) ------
    not_dns = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:66")
        / IP(dst="8.8.8.8")
        / UDP(sport=50001, dport=53)
        / b"\x00\x01not-a-dns-packet"
    )
    r = analyze_packet(not_dns)
    check(r["protocol"] == "UDP", f"UDP/53 without DNS layer stays {r['protocol']} (not DNS)")

    # ---- 5) ICMP echo request (what `ping` sends) ----------------------
    echo = Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:66") / IP(dst="8.8.8.8") / ICMP(type=8, code=0)
    r = analyze_packet(echo)
    check(r["protocol"] == "ICMP", "ICMP packet classified as ICMP")
    check(r["icmp_type"] == 8 and r["icmp_code"] == 0, "ICMP type/code = 8/0")
    check(icmp_type_name(r["icmp_type"]) == "Echo Request", "ICMP type 8 named 'Echo Request'")
    check(icmp_type_name(0) == "Echo Reply", "ICMP type 0 named 'Echo Reply'")
    check(r["source_port"] is None and r["destination_port"] is None, "ICMP has no ports -> None")
    check(
        r["tcp_seq"] is None and r["tcp_ack"] is None and r["tcp_flags"] is None,
        "ICMP has no TCP fields -> None",
    )

    # ---- 6) ARP request (no IP layer at all) ---------------------------
    arp = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, psrc="192.168.1.5", pdst="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01")
    )
    r = analyze_packet(arp)
    check(r["protocol"] == "ARP", "ARP classified as ARP")
    check(r["arp_operation"] == "Request", "ARP operation -> Request")
    check(
        r["source_ip"] == "192.168.1.5" and r["destination_ip"] == "192.168.1.1",
        "ARP sender/target IPs extracted",
    )
    check(
        r["source_port"] is None and r["ip_version"] is None and r["ttl"] is None,
        "ARP has no ports/IP version/TTL -> None",
    )

    # ---- 7) IPv6 TCP ---------------------------------------------------
    # (explicit MACs: without them Scapy would try neighbor discovery,
    #  which needs Npcap — irrelevant for analyzer logic tests)
    v6 = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:66")
        / IPv6(dst="2001:4860:4860::8888")
        / TCP(dport=443, flags="A")
    )
    r = analyze_packet(v6)
    check(r["ip_version"] == 6, "IPv6 version recorded")
    check(r["protocol"] == "TCP" and r["tcp_flags"] == "ACK", "IPv6 TCP classified + flags")

    # ---- 8) Bare Ethernet frame -> classifies safely --------------------
    bare = Ether(dst="ff:ff:ff:ff:ff:ff")
    check(
        classify_protocol(bare) in ("Ethernet", "Other"),
        f"Bare Ethernet frame classifies safely -> {classify_protocol(bare)}",
    )

    # ---- 9) Malformed payload must not crash the analyzer ---------------
    junk = Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:66") / IP() / b"\xde\xad\xbe\xef"
    try:
        r = analyze_packet(junk)
        check(
            r["protocol"] in ("IPv4", "TCP", "UDP", "ICMP", "Other"),
            f"Malformed payload handled without crash -> {r['protocol']}",
        )
    except Exception as error:                       # pragma: no cover
        check(False, f"Malformed payload raised: {error}")

    # ---- 10) A deliberately broken packet object ------------------------
    check(
        classify_protocol(None) == "Other",
        "classify_protocol(None) degrades to 'Other' without raising",
    )

    print(f"\n{_passed}/{_passed + _failed} checks passed.")
    if _failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
