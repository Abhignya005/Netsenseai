// src/protocolLabels.js — Phase 3: human-readable protocol labels
//
// Shared by the Live Packets table so the protocol column can show
// meaningful suffixes (Phase 3 section 17):
//     TCP  — SYN / ACK / FIN / RST ...
//     ICMP — Echo Request / Echo Reply
//     ARP  — Request / Reply
//     DNS / UDP — shown plain, no suffix
//
// Everything here reads METADATA only — never packet content.

// ICMP type numbers -> friendly names (mirrors the backend map).
const ICMP_TYPE_NAMES = {
  0: 'Echo Reply',
  3: 'Destination Unreachable',
  5: 'Redirect',
  8: 'Echo Request',
  11: 'Time Exceeded',
  12: 'Parameter Problem',
  13: 'Timestamp Request',
  14: 'Timestamp Reply',
}

// 8 -> "Echo Request"; unknown numbers -> "Type 99".
export function icmpTypeName(type) {
  if (type == null) return null
  return ICMP_TYPE_NAMES[type] ?? `Type ${type}`
}

// The detail label shown after "protocol — " in tables.
// Returns null when there is nothing meaningful to append.
export function protocolDetailLabel(packet) {
  switch (packet.protocol) {
    case 'TCP':
      return packet.tcp_flags ?? null
    case 'ICMP':
      return icmpTypeName(packet.icmp_type)
    case 'ARP':
      return packet.arp_operation ?? null
    default:
      return null // DNS, UDP, IPv4, ... display plain
  }
}
