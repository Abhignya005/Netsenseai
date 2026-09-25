"""
protocol_analysis.py — STAGE 3: protocol-aware packet analysis

WHAT THIS FILE DOES
-------------------
Turns one raw Scapy packet into a small metadata dictionary:

    timestamp, source/destination MAC, source/destination IP,
    IP version, protocol name, source/destination port, size,
    TTL, TCP flags, ICMP type/code, ARP operation, DNS query info

The two main entry points:
    analyze_packet(packet)     -> the full metadata dictionary
    classify_protocol(packet)  -> one of:
        TCP / UDP / ICMP / ARP / DNS / IPv4 / IPv6 / Ethernet / Other

PRIVACY (same rule as Stage 2): we only read header fields that Scapy
parsed into layers. Packet payloads are never read or stored. The DNS
query name is a single safe metadata field (the domain name), not the
full DNS message.

ERROR SAFETY (Stage 3 section 17): every field access is guarded — a
packet missing a layer (ARP has no ports!), a malformed header, or an
unexpected Scapy object must never crash the capture engine.
"""

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

# ---- TCP flags: bit values straight from the TCP header (RFC 9293) ----
# One flags byte can combine several bits, e.g. 0x12 = SYN + ACK.
TCP_FLAG_BITS = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]

# Shorthand flag letters Scapy uses ("SA" = SYN+ACK), for crafted packets.
_FLAG_CHARS = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}

# ---- Ethernet "type" field: which protocol follows the L2 header ----
ETHER_TYPES = {
    0x0800: "IPv4 (0x0800)",
    0x0806: "ARP (0x0806)",
    0x86DD: "IPv6 (0x86DD)",
}

# ---- ICMP types we can give a human name (RFC 792) ----
ICMP_TYPE_NAMES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

# ---- Common DNS query types (RFC 1035 and friends) ----
DNS_QUERY_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


def tcp_flags_to_string(flags):
    """Convert TCP flags into a readable string: 'SYN', 'SYN, ACK', ...

    Accepts whatever Scapy hands us:
      - a FlagValue object (sniffed packets)  -> has .value (an int)
      - a shorthand string like "SA"          -> crafted packets
      - a plain int                          -> raw header byte
    Returns None when no known flag bits are set.
    """
    try:
        if hasattr(flags, "value"):          # scapy FlagValue
            value = int(flags.value)
        elif isinstance(flags, str):         # shorthand like "SA"
            names = [_FLAG_CHARS[ch] for ch in flags.upper() if ch in _FLAG_CHARS]
            return ", ".join(names) if names else None
        else:                                # plain integer
            value = int(flags)
    except (TypeError, ValueError, AttributeError):
        return None

    names = [name for bit, name in TCP_FLAG_BITS if value & bit]
    return ", ".join(names) if names else None


def icmp_type_name(icmp_type):
    """Human name for an ICMP type, e.g. 8 -> 'Echo Request'."""
    return ICMP_TYPE_NAMES.get(icmp_type, f"Type {icmp_type}")


def classify_protocol(packet):
    """Return the main protocol name of a packet (Stage 3 section 9).

    Order matters:
      1. DNS  — only when Scapy actually decoded a DNS layer.
                Port 53 alone is NOT enough (section 5).
      2. ARP  — Layer 2 protocol, no IP addresses involved.
      3. TCP / UDP / ICMP — transport and control layers.
      4. IPv6 with next-header 58 = ICMPv6 -> counted as ICMP
         (this is what `ping` over IPv6 produces).
      5. Fallbacks: IPv6, IPv4, Ethernet, Other.

    Any unexpected/malformed packet classifies as 'Other' —
    this function must never raise.
    """
    try:
        if packet.haslayer(DNS):
            return "DNS"
        if packet.haslayer(ARP):
            return "ARP"
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(IPv6):
            # Next header 58 = ICMP for IPv6 (ping6, neighbor discovery)
            if int(packet[IPv6].nh) == 58:
                return "ICMP"
            return "IPv6"
        if packet.haslayer(IP):
            return "IPv4"
        if packet.haslayer(Ether):
            return "Ethernet"
        return "Other"
    except Exception:
        return "Other"   # malformed packet -> never crash


def analyze_packet(packet):
    """Build the Stage 3 metadata dictionary for one packet.

    Every field that does not exist for this packet stays None
    (the API serialises None as JSON null; the UI shows '-').
    Only header fields are read — never payload content.
    """
    record = {
        "timestamp": float(packet.time),
        "size": int(len(packet)),
        # Layer 2 (Ethernet)
        "source_mac": None,
        "destination_mac": None,
        "eth_type": None,       # e.g. "IPv4 (0x0800)"
        # Layer 3
        "source_ip": None,
        "destination_ip": None,
        "ip_version": None,      # 4 or 6
        "ttl": None,
        # Layer 4 / classification
        "protocol": "Other",
        "source_port": None,
        "destination_port": None,
        "tcp_flags": None,       # e.g. "SYN, ACK"
        "tcp_seq": None,         # TCP sequence number (Phase 3 section 6)
        "tcp_ack": None,         # TCP acknowledgement number
        "icmp_type": None,
        "icmp_code": None,
        # ARP specifics
        "arp_operation": None,   # "Request" / "Reply"
        # DNS specifics (safe metadata only)
        "dns_query": None,       # query name, e.g. "google.com"
        "dns_qr": None,          # "Query" / "Response"
        "dns_qtype": None,       # "A", "AAAA", ...
    }

    # ---- Ethernet (L2) ---------------------------------------------
    if packet.haslayer(Ether):
        ether = packet[Ether]
        record["source_mac"] = str(ether.src)
        record["destination_mac"] = str(ether.dst)
        # The Ethernet type field identifies the Layer 3 protocol
        # that follows (0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6).
        try:
            ether_type = int(ether.type)
            record["eth_type"] = ETHER_TYPES.get(ether_type, hex(ether_type))
        except (TypeError, ValueError):
            pass   # malformed header -> stays None

    # ---- ARP (has NO IP layer; carries its own addresses) ----------
    if packet.haslayer(ARP):
        arp = packet[ARP]
        record["arp_operation"] = {1: "Request", 2: "Reply"}.get(int(arp.op), str(arp.op))
        record["source_ip"] = str(arp.psrc)        # sender IP
        record["destination_ip"] = str(arp.pdst)   # target IP
        # Fill the MAC fields from ARP if there was no Ethernet header
        record["source_mac"] = record["source_mac"] or str(arp.hwsrc)
        record["destination_mac"] = record["destination_mac"] or str(arp.hwdst)

    # ---- IPv4 / IPv6 ------------------------------------------------
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        record["ip_version"] = 4
        record["source_ip"] = str(ip_layer.src)
        record["destination_ip"] = str(ip_layer.dst)
        record["ttl"] = int(ip_layer.ttl)
    elif packet.haslayer(IPv6):
        ip6_layer = packet[IPv6]
        record["ip_version"] = 6
        record["source_ip"] = str(ip6_layer.src)
        record["destination_ip"] = str(ip6_layer.dst)
        record["ttl"] = int(ip6_layer.hlim)   # IPv6 calls TTL "hop limit"

    # ---- TCP ----------------------------------------------------------
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        record["source_port"] = int(tcp.sport)
        record["destination_port"] = int(tcp.dport)
        record["tcp_flags"] = tcp_flags_to_string(tcp.flags)
        # Sequence / acknowledgement numbers are header METADATA.
        # NOTE: this is NOT connection-state tracking (SYN_SENT,
        # ESTABLISHED, ...) — that belongs to Phase 4.
        try:
            record["tcp_seq"] = int(tcp.seq)
            record["tcp_ack"] = int(tcp.ack)
        except (TypeError, ValueError):
            pass   # malformed header -> stays None

    # ---- UDP ----------------------------------------------------------
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        record["source_port"] = int(udp.sport)
        record["destination_port"] = int(udp.dport)

    # ---- ICMP (type + code; ping = type 8 then type 0) --------------
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        record["icmp_type"] = int(icmp.type)
        record["icmp_code"] = int(icmp.code)

    # ---- DNS: only when a REAL DNS layer was decoded ----------------
    # (Port 53 alone does NOT make a packet DNS — section 5.)
    if packet.haslayer(DNS):
        try:
            dns = packet[DNS]
            record["dns_qr"] = "Response" if int(dns.qr) == 1 else "Query"
            if dns.qd is not None:
                # qd = question section; qname is the domain being
                # looked up — one safe metadata string, not the payload.
                qname = dns.qd.qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                record["dns_query"] = str(qname).rstrip(".")
                record["dns_qtype"] = DNS_QUERY_TYPES.get(int(dns.qd.qtype), str(dns.qd.qtype))
        except Exception:
            pass   # malformed DNS -> fields stay None, capture continues

    record["protocol"] = classify_protocol(packet)
    return record
