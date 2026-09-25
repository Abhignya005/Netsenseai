// src/pages/ProtocolAnalysis.jsx — STAGE 3: real protocol analysis
//
// Data sources (both REAL — no fake packets anywhere on this page):
//   GET /api/protocols -> flat {protocol: count} from stored packets
//   GET /api/packets   -> recent analyzed packets (optionally filtered)
// The page polls every 3 seconds, so counts move while capture runs.
//
// Layout:
//   1. Protocol summary cards (TCP, UDP, DNS, ICMP, ARP, IPv4, IPv6)
//   2. Protocol distribution bar chart (Recharts)
//   3. Protocol details table — click a row to inspect ALL fields
//      (MACs, TTL, ICMP type/code, ARP operation, DNS query, ...)

import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import Badge from '../components/Badge.jsx'
import DataTable from '../components/DataTable.jsx'
import SectionCard from '../components/SectionCard.jsx'
import { fetchCaptureStatus, fetchPackets, fetchProtocolStats } from '../api.js'
import { protocolColor } from '../protocolColors.js'

// The seven summary cards the Stage 3 spec asks for.
const SUMMARY_CARDS = ['TCP', 'UDP', 'DNS', 'ICMP', 'ARP', 'IPv4', 'IPv6']

// Options in the table's protocol filter (maps to ?protocol=...).
const PROTOCOL_FILTERS = ['TCP', 'UDP', 'DNS', 'ICMP', 'ARP']

// ICMP type numbers -> friendly names (mirrors the backend map).
const ICMP_TYPE_NAMES = {
  0: 'Echo Reply',
  3: 'Destination Unreachable',
  5: 'Redirect',
  8: 'Echo Request',
  11: 'Time Exceeded',
}

function formatTime(epochSeconds) {
  return new Date(epochSeconds * 1000).toLocaleTimeString('en-GB')
}

// Stable identity for a packet row (survives the 3s refresh).
function rowKey(packet) {
  return `${packet.timestamp}-${packet.source_ip}-${packet.destination_ip}-${packet.source_port}-${packet.size}`
}

// Every field Stage 3 extracts, with '-' when unavailable (section 3).
function detailRows(packet) {
  const icmpName =
    packet.icmp_type != null
      ? `${ICMP_TYPE_NAMES[packet.icmp_type] ?? `Type ${packet.icmp_type}`} (${packet.icmp_type})`
      : '-'
  const dnsInfo = packet.dns_qr
    ? `${packet.dns_qr}${packet.dns_qtype ? ` · ${packet.dns_qtype}` : ''}${
        packet.dns_query ? ` · ${packet.dns_query}` : ''
      }`
    : '-'

  return [
    ['Timestamp', new Date(packet.timestamp * 1000).toLocaleString('en-GB')],
    ['Source MAC', packet.source_mac ?? '-'],
    ['Destination MAC', packet.destination_mac ?? '-'],
    ['Ethernet type', packet.eth_type ?? '-'],
    ['Source IP', packet.source_ip ?? '-'],
    ['Destination IP', packet.destination_ip ?? '-'],
    ['IP version', packet.ip_version ? `IPv${packet.ip_version}` : '-'],
    ['Protocol', packet.protocol ?? '-'],
    ['Source port', packet.source_port ?? '-'],
    ['Destination port', packet.destination_port ?? '-'],
    ['Packet size', `${packet.size} B`],
    ['TTL', packet.ttl ?? '-'],
    ['TCP flags', packet.tcp_flags ?? '-'],
    ['TCP sequence no.', packet.tcp_seq ?? '-'],
    ['TCP ack no.', packet.tcp_ack ?? '-'],
    ['ICMP type', icmpName],
    ['ICMP code', packet.icmp_code ?? '-'],
    ['ARP operation', packet.arp_operation ? `ARP ${packet.arp_operation}` : '-'],
    ['DNS', dnsInfo],
  ]
}

export default function ProtocolAnalysis() {
  const [stats, setStats] = useState(null)     // {TCP: 12, ...}
  const [packets, setPackets] = useState([])    // table rows
  const [status, setStatus] = useState(null)    // capture engine status
  const [filter, setFilter] = useState('')      // '' = all protocols
  const [selected, setSelected] = useState(null)      // clicked packet
  const [selectedKey, setSelectedKey] = useState('')  // its row key
  const [error, setError] = useState(null)
  const timer = useRef(null)

  const isRunning = status?.running === true
  const total = stats ? Object.values(stats).reduce((sum, n) => sum + n, 0) : 0

  const refresh = useCallback(async () => {
    try {
      const [protocolStats, packetData, captureStatus] = await Promise.all([
        fetchProtocolStats(),
        fetchPackets({ limit: 100, protocol: filter || undefined }),
        fetchCaptureStatus(),
      ])
      setStats(protocolStats)
      setPackets(packetData.packets)
      setStatus(captureStatus)
      setError(null)
    } catch (e) {
      setError(e.message)
    }
  }, [filter])

  useEffect(() => {
    refresh()
    timer.current = setInterval(refresh, 3000) // auto-refresh every 3s
    return () => clearInterval(timer.current)
  }, [refresh])

  // Chart data: one bar per protocol, colored by protocol.
  const chartData = Object.entries(stats || {}).map(([name, count]) => ({
    name,
    count,
  }))

  return (
    <div className="p-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Protocol Analysis</h1>
          <p className="mt-1 text-sm text-slate-500">
            Real captured packets, analyzed per protocol layer — metadata only, no payloads.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <Badge>{isRunning ? 'Online' : 'Idle'}</Badge>
          <span>{isRunning ? 'capturing…' : 'not capturing'} · refreshes every 3s</span>
        </div>
      </header>

      {error && (
        <p className="mb-4 rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          ⚠ {error}
        </p>
      )}

      {/* 1. ---- Protocol summary cards ---- */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 xl:grid-cols-7">
        {SUMMARY_CARDS.map((name) => (
          <div key={name} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
              <span
                className="inline-block h-2.5 w-2.5 rounded-full"
                style={{ backgroundColor: protocolColor(name) }}
              />
              {name}
            </p>
            <p className="mt-2 text-2xl font-bold text-slate-900">
              {(stats?.[name] ?? 0).toLocaleString()}
            </p>
            <p className="text-[11px] text-slate-400">packets</p>
          </div>
        ))}
      </div>

      {/* 2. ---- Distribution chart ---- */}
      <div className="mt-6">
        <SectionCard
          title="Protocol Distribution"
          subtitle={
            total > 0
              ? `Counts across ${total.toLocaleString()} stored packets (real data)`
              : 'Real captured data'
          }
        >
          {total > 0 ? (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} fontSize={12} />
                  <YAxis tickLine={false} axisLine={false} fontSize={12} allowDecimals={false} />
                  <Tooltip
                    formatter={(value) => [`${value} packets`, 'Count']}
                    cursor={{ fill: '#f1f5f9' }}
                  />
                  <Bar dataKey="count" name="Packets" radius={[4, 4, 0, 0]}>
                    {chartData.map((entry) => (
                      <Cell key={entry.name} fill={protocolColor(entry.name)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="py-16 text-center text-sm text-slate-400">
              No packet data available. Start capture on the Live Packets page —
              these counts only ever come from real captured packets.
            </p>
          )}
        </SectionCard>
      </div>

      {/* 3. ---- Protocol details table ---- */}
      <div className="mt-6">
        <SectionCard
          title="Protocol Details"
          subtitle="Newest first — click any row to see every extracted field"
        >
          <div className="mb-3 flex items-center gap-2 text-sm text-slate-600">
            Protocol:
            <select
              value={filter}
              onChange={(e) => {
                setFilter(e.target.value)
                setSelected(null)
                setSelectedKey('')
              }}
              className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-800"
            >
              <option value="">All protocols</option>
              {PROTOCOL_FILTERS.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
            <span className="ml-auto text-xs text-slate-400">{packets.length} shown</span>
          </div>

          {packets.length === 0 ? (
            <p className="py-8 text-center text-sm text-slate-400">
              No packets in the current capture session. Start capture on the
              Live Packets page to fill this table with real traffic.
            </p>
          ) : (
            <DataTable
              headers={['Time', 'Source', 'Destination', 'Protocol', 'Src Port', 'Dst Port', 'Size', 'TCP Flags']}
            >
              {packets.map((packet) => {
                const key = rowKey(packet)
                return (
                  <tr
                    key={key}
                    onClick={() => {
                      setSelected(packet)
                      setSelectedKey(key)
                    }}
                    className={`cursor-pointer hover:bg-slate-50 ${
                      selectedKey === key ? 'bg-sky-50' : ''
                    }`}
                  >
                    <td className="px-3 py-2.5 text-slate-500">{formatTime(packet.timestamp)}</td>
                    <td className="px-3 py-2.5 font-medium text-slate-800">
                      {packet.source_ip ?? '-'}
                    </td>
                    <td className="px-3 py-2.5 font-medium text-slate-800">
                      {packet.destination_ip ?? '-'}
                    </td>
                    <td className="px-3 py-2.5">
                      <Badge>{packet.protocol}</Badge>
                    </td>
                    <td className="px-3 py-2.5 text-slate-500">{packet.source_port ?? '-'}</td>
                    <td className="px-3 py-2.5 text-slate-500">{packet.destination_port ?? '-'}</td>
                    <td className="px-3 py-2.5 text-slate-500">{packet.size} B</td>
                    <td className="px-3 py-2.5 text-slate-600">{packet.tcp_flags ?? '-'}</td>
                  </tr>
                )
              })}
            </DataTable>
          )}
        </SectionCard>
      </div>

      {/* ---- Selected packet: every Stage 3 field ---- */}
      {selected && (
        <div className="mt-6">
          <SectionCard
            title="Packet Details"
            subtitle="All metadata extracted for the clicked packet ('-' = not present in this packet)"
          >
            <dl className="grid grid-cols-1 gap-x-6 sm:grid-cols-2 lg:grid-cols-3">
              {detailRows(selected).map(([label, value]) => (
                <div
                  key={label}
                  className="flex items-baseline justify-between gap-2 border-b border-slate-100 py-1.5 text-sm"
                >
                  <dt className="shrink-0 text-slate-500">{label}</dt>
                  <dd className="break-all text-right font-mono text-slate-800">{value}</dd>
                </div>
              ))}
            </dl>
          </SectionCard>
        </div>
      )}
    </div>
  )
}
