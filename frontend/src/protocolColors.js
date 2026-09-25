// src/protocolColors.js — one chart color per protocol (Stage 3).
// Shared by the Dashboard donut and the Protocol Analysis chart so
// TCP looks the same everywhere in the app.

export const PROTOCOL_COLORS = {
  TCP: '#0ea5e9',
  UDP: '#22d3ee',
  DNS: '#fbbf24',
  ICMP: '#a855f7',
  ARP: '#f97316',
  IPv4: '#3b82f6',
  IPv6: '#8b5cf6',
  Ethernet: '#14b8a6',
  'Other (IP)': '#64748b',
  Other: '#94a3b8',
}

// Fallback: unknown protocols get the neutral 'Other' color.
export function protocolColor(name) {
  return PROTOCOL_COLORS[name] || PROTOCOL_COLORS.Other
}
