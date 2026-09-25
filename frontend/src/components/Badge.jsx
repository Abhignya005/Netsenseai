// src/components/Badge.jsx
//
// A tiny colored pill, e.g. "HIGH", "MEDIUM", "LOW" for alerts
// or "Online" / "Idle" for devices.

const COLORS = {
  HIGH: 'bg-rose-100 text-rose-700',
  MEDIUM: 'bg-amber-100 text-amber-700',
  LOW: 'bg-sky-100 text-sky-700',
  Online: 'bg-emerald-100 text-emerald-700',
  Idle: 'bg-slate-100 text-slate-600',

  // Protocol names (Stage 2 packet table)
  TCP: 'bg-sky-100 text-sky-700',
  UDP: 'bg-cyan-100 text-cyan-700',
  DNS: 'bg-amber-100 text-amber-700',
  HTTP: 'bg-lime-100 text-lime-700',
  TLS: 'bg-pink-100 text-pink-700',
  ICMP: 'bg-violet-100 text-violet-700',
  ICMPv6: 'bg-violet-100 text-violet-700',
  DHCP: 'bg-teal-100 text-teal-700',
  NTP: 'bg-indigo-100 text-indigo-700',

  // More protocol names (Stage 3 classification results)
  ARP: 'bg-orange-100 text-orange-700',
  IPv4: 'bg-blue-100 text-blue-700',
  IPv6: 'bg-purple-100 text-purple-700',
  Ethernet: 'bg-teal-100 text-teal-700',
  OTHER: 'bg-slate-100 text-slate-600',

  // TCP connection states (Phase 4 section 3)
  SYN_SENT: 'bg-amber-100 text-amber-700',
  SYN_RECEIVED: 'bg-orange-100 text-orange-700',
  ESTABLISHED: 'bg-emerald-100 text-emerald-700',
  FIN_WAIT: 'bg-cyan-100 text-cyan-700',
  CLOSED: 'bg-slate-100 text-slate-600',
  RESET: 'bg-rose-100 text-rose-700',
  INCOMPLETE: 'bg-rose-100 text-rose-700',
  PARTIAL: 'bg-violet-100 text-violet-700',

  // Flow status (Phase 4 section 12)
  ACTIVE: 'bg-emerald-100 text-emerald-700',
  COMPLETED: 'bg-slate-100 text-slate-600',
}

export default function Badge({ children }) {
  const color = COLORS[children] || 'bg-slate-100 text-slate-600'
  return (
    <span className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold ${color}`}>
      {children}
    </span>
  )
}
