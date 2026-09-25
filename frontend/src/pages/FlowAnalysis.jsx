// src/pages/FlowAnalysis.jsx — PHASE 4: network flow analysis
//
// Data source (REAL flows grouped from captured packets):
//   GET /api/flows?protocol=&src_ip=&dst_ip=&src_port=&dst_port=&status=
// Polls every 3 seconds.
//
// Flows are BIDIRECTIONAL 5-tuples: forward = first packet direction,
// backward = the reverse. Timeouts (15s inactive / 120s active) are
// handled by the backend flow engine.

import { useCallback, useEffect, useRef, useState } from 'react'

import Badge from '../components/Badge.jsx'
import DataTable from '../components/DataTable.jsx'
import SectionCard from '../components/SectionCard.jsx'
import { fetchCaptureStatus, fetchFlows } from '../api.js'

function formatBytes(bytes) {
  if (bytes == null) return '-'
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

// Protocols offered in the filter dropdown (section 13).
const PROTOCOL_OPTIONS = ['TCP', 'UDP', 'DNS', 'ICMP', 'ARP']

const EMPTY_FILTERS = {
  protocol: '',
  src_ip: '',
  dst_ip: '',
  src_port: '',
  dst_port: '',
  status: '',
}

export default function FlowAnalysis() {
  const [summary, setSummary] = useState(null)   // global engine counts
  const [flows, setFlows] = useState([])         // (filtered) table rows
  const [draft, setDraft] = useState(EMPTY_FILTERS)   // filter inputs
  const [applied, setApplied] = useState(EMPTY_FILTERS) // what's queried
  const [isRunning, setIsRunning] = useState(false)
  const [error, setError] = useState(null)
  const timer = useRef(null)

  const refresh = useCallback(async () => {
    try {
      const clean = {}
      for (const [key, value] of Object.entries(applied)) {
        if (value !== '') clean[key] = value
      }
      const [data, statusData] = await Promise.all([
        fetchFlows(clean),
        fetchCaptureStatus(),
      ])
      setSummary(data.summary)
      setFlows(data.flows)
      setIsRunning(statusData.running === true)
      setError(null)
    } catch (e) {
      setError(e.message)
    }
  }, [applied])

  useEffect(() => {
    refresh()
    timer.current = setInterval(refresh, 2000)
    return () => clearInterval(timer.current)
  }, [refresh])

  function applyFilters(event) {
    event.preventDefault()
    setApplied({ ...draft })
  }

  function resetFilters() {
    setDraft(EMPTY_FILTERS)
    setApplied(EMPTY_FILTERS)
  }

  // The five cards from Phase 4 section 12.
  const cards = [
    { label: 'Total Flows', value: summary?.total_flows },
    { label: 'Active Flows', value: summary?.active_flows },
    { label: 'Completed Flows', value: summary?.completed_flows },
    { label: 'Total Flow Bytes', value: summary?.total_bytes, bytes: true },
    { label: 'Total Flow Packets', value: summary?.total_packets },
  ]

  return (
    <div className="p-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Flow Analysis</h1>
          <p className="mt-1 text-sm text-slate-500">
            Packets grouped into bidirectional 5-tuple flows — 15s inactive /
            120s active timeout, real captured traffic only.
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

      {/* 1. ---- Summary cards (section 12) ---- */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-5">
        {cards.map((card) => (
          <div key={card.label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              {card.label}
            </p>
            <p className="mt-2 text-2xl font-bold text-slate-900">
              {card.bytes
                ? formatBytes(card.value ?? 0)
                : (card.value ?? 0).toLocaleString()}
            </p>
            <p className="text-[11px] text-slate-400">
              {card.bytes ? 'across all flows' : 'flows'}
            </p>
          </div>
        ))}
      </div>

      {/* 2. ---- Filters (section 13) ---- */}
      <form
        onSubmit={applyFilters}
        className="mt-6 flex flex-wrap items-end gap-3 rounded-xl border border-slate-200 bg-white p-4"
      >
        <label className="flex flex-col gap-1 text-xs font-medium text-slate-500">
          Protocol
          <select
            value={draft.protocol}
            onChange={(e) => setDraft({ ...draft, protocol: e.target.value })}
            className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-800"
          >
            <option value="">All</option>
            {PROTOCOL_OPTIONS.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1 text-xs font-medium text-slate-500">
          Source IP
          <input
            value={draft.src_ip}
            onChange={(e) => setDraft({ ...draft, src_ip: e.target.value })}
            placeholder="e.g. 192.168.1.5"
            className="w-36 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-800"
          />
        </label>

        <label className="flex flex-col gap-1 text-xs font-medium text-slate-500">
          Destination IP
          <input
            value={draft.dst_ip}
            onChange={(e) => setDraft({ ...draft, dst_ip: e.target.value })}
            placeholder="e.g. 8.8.8.8"
            className="w-36 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-800"
          />
        </label>

        <label className="flex flex-col gap-1 text-xs font-medium text-slate-500">
          Source Port
          <input
            value={draft.src_port}
            onChange={(e) => setDraft({ ...draft, src_port: e.target.value })}
            placeholder="e.g. 52341"
            inputMode="numeric"
            className="w-24 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-800"
          />
        </label>

        <label className="flex flex-col gap-1 text-xs font-medium text-slate-500">
          Destination Port
          <input
            value={draft.dst_port}
            onChange={(e) => setDraft({ ...draft, dst_port: e.target.value })}
            placeholder="e.g. 443"
            inputMode="numeric"
            className="w-24 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-800"
          />
        </label>

        <label className="flex flex-col gap-1 text-xs font-medium text-slate-500">
          Status
          <select
            value={draft.status}
            onChange={(e) => setDraft({ ...draft, status: e.target.value })}
            className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-800"
          >
            <option value="">All</option>
            <option value="ACTIVE">ACTIVE</option>
            <option value="COMPLETED">COMPLETED</option>
          </select>
        </label>

        <button
          type="submit"
          className="rounded-lg bg-sky-600 px-4 py-1.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-sky-700"
        >
          Apply
        </button>
        <button
          type="button"
          onClick={resetFilters}
          className="rounded-lg border border-slate-300 px-4 py-1.5 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-50"
        >
          Reset
        </button>
      </form>

      {/* 3. ---- Flow table (section 12) ---- */}
      <div className="mt-6">
        <SectionCard
          title={`Flows${flows.length ? ` (${flows.length} shown)` : ''}`}
          subtitle="Newest activity first — forward = first observed direction"
        >
          {flows.length === 0 ? (
            <p className="py-10 text-center text-sm text-slate-400">
              No flows match. Start capture on the Live Packets page and
              generate traffic (browse, ping, nslookup) to build flows.
            </p>
          ) : (
            <DataTable
              headers={[
                'Source', 'Destination', 'Protocol', 'Source Port', 'Destination Port', 'Duration',
                'Forward Packets', 'Backward Packets', 'Total Bytes', 'Packet Rate', 'Byte Rate',
                'Status',
              ]}
            >
              {flows.map((flow, index) => (
                <tr
                  key={`${flow.source_ip}-${flow.source_port}-${flow.destination_ip}-${flow.destination_port}-${flow.start_time}-${index}`}
                  className="hover:bg-slate-50"
                >
                  <td className="px-3 py-2.5 font-medium text-slate-800">{flow.source_ip}</td>
                  <td className="px-3 py-2.5 font-medium text-slate-800">{flow.destination_ip}</td>
                  <td className="px-3 py-2.5"><Badge>{flow.protocol}</Badge></td>
                  <td className="whitespace-nowrap px-3 py-2.5 font-mono text-xs text-slate-500">
                    {flow.source_port || '—'}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2.5 font-mono text-xs text-slate-500">
                    {flow.destination_port || '—'}
                  </td>
                  <td className="px-3 py-2.5 text-slate-500">{flow.duration} sec</td>
                  <td className="px-3 py-2.5 text-slate-500">{flow.forward_packets.toLocaleString()}</td>
                  <td className="px-3 py-2.5 text-slate-500">{flow.backward_packets.toLocaleString()}</td>
                  <td className="px-3 py-2.5 text-slate-500">{formatBytes(flow.total_bytes)}</td>
                  <td className="px-3 py-2.5 text-slate-500">{flow.packet_rate}/s</td>
                  <td className="px-3 py-2.5 text-slate-500">{flow.byte_rate} B/s</td>
                  <td className="px-3 py-2.5"><Badge>{flow.status}</Badge></td>
                </tr>
              ))}
            </DataTable>
          )}
        </SectionCard>
      </div>
    </div>
  )
}
