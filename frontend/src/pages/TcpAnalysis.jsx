// src/pages/TcpAnalysis.jsx — PHASE 4: TCP connection tracking
//
// Data sources (REAL tracked connections from captured packets):
//   GET /api/tcp/stats        -> connection + handshake statistics
//   GET /api/tcp/connections  -> bidirectional connection table
// Polls every 3 seconds while you browse/capture.
//
// IMPORTANT (Phase 4 section 7): NetSense observes passively — a
// connection may have started before capture began, so states like
// PARTIAL / INCOMPLETE are shown honestly instead of pretending every
// connection was fully reconstructed.

import { useCallback, useEffect, useRef, useState } from 'react'

import Badge from '../components/Badge.jsx'
import DataTable from '../components/DataTable.jsx'
import SectionCard from '../components/SectionCard.jsx'
import TcpLadderModal from '../components/TcpLadderModal.jsx'
import { fetchCaptureStatus, fetchTcpConnections, fetchTcpStats } from '../api.js'

function formatTime(epochSeconds) {
  if (!epochSeconds) return '-'
  return new Date(epochSeconds * 1000).toLocaleTimeString('en-GB')
}

function formatBytes(bytes) {
  if (bytes == null) return '-'
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

export default function TcpAnalysis() {
  const [stats, setStats] = useState(null)      // {summary, flag_counts}
  const [connections, setConnections] = useState([])
  const [selectedConn, setSelectedConn] = useState(null) // Active ladder visualizer connection
  const [isRunning, setIsRunning] = useState(false)
  const [error, setError] = useState(null)
  const timer = useRef(null)

  const refresh = useCallback(async () => {
    try {
      const [statData, connData, statusData] = await Promise.all([
        fetchTcpStats(),
        fetchTcpConnections({ limit: 100 }),
        fetchCaptureStatus(),
      ])
      setStats(statData)
      setConnections(connData.connections)
      setIsRunning(statusData.running === true)
      setError(null)

      // Keep selected connection synchronized with live updates
      setSelectedConn((prev) => {
        if (!prev) return null
        return (
          connData.connections.find(
            (c) =>
              c.source_ip === prev.source_ip &&
              c.source_port === prev.source_port &&
              c.destination_ip === prev.destination_ip &&
              c.destination_port === prev.destination_port
          ) || prev
        )
      })
    } catch (e) {
      setError(e.message)
    }
  }, [])

  useEffect(() => {
    refresh()
    timer.current = setInterval(refresh, 2000)
    return () => clearInterval(timer.current)
  }, [refresh])

  const summary = stats?.summary ?? {}
  const flags = stats?.flag_counts ?? {}

  // The eight cards from Phase 4 section 5.
  const stateCards = [
    { label: 'Active Connections', value: summary.active },
    { label: 'Established', value: summary.established },
    { label: 'Incomplete', value: summary.incomplete },
    { label: 'Reset', value: summary.reset },
  ]
  const flagCards = [
    { label: 'SYN Packets', value: flags.syn },
    { label: 'SYN-ACK Packets', value: flags.syn_ack },
    { label: 'FIN Packets', value: flags.fin },
    { label: 'RST Packets', value: flags.rst },
  ]

  return (
    <div className="p-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">TCP Analysis</h1>
          <p className="mt-1 text-sm text-slate-500">
            TCP connections tracked from real captured packets — handshake states
            observed passively, never guessed.
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

      {/* 1. ---- Connection state cards (section 5) ---- */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {stateCards.map((card) => (
          <div key={card.label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              {card.label}
            </p>
            <p className="mt-2 text-2xl font-bold text-slate-900">
              {(card.value ?? 0).toLocaleString()}
            </p>
            <p className="text-[11px] text-slate-400">connections</p>
          </div>
        ))}
      </div>

      {/* 2. ---- Flag + handshake statistics (section 4) ---- */}
      <div className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
        {flagCards.map((card) => (
          <div key={card.label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              {card.label}
            </p>
            <p className="mt-2 text-2xl font-bold text-slate-900">
              {(card.value ?? 0).toLocaleString()}
            </p>
            <p className="text-[11px] text-slate-400">packets observed</p>
          </div>
        ))}
      </div>

      <div className="mt-4 flex flex-wrap gap-6 rounded-xl border border-slate-200 bg-white px-5 py-3 text-sm">
        <p className="text-slate-600">
          Completed handshakes:{' '}
          <span className="font-semibold text-emerald-600">
            {(summary.completed_handshakes ?? 0).toLocaleString()}
          </span>
        </p>
        <p className="text-slate-600">
          Incomplete handshakes:{' '}
          <span className="font-semibold text-amber-600">
            {(summary.inactive_or_partial ?? 0).toLocaleString()}
          </span>
        </p>
        <p className="text-slate-600">
          Plain ACK packets:{' '}
          <span className="font-semibold text-slate-900">
            {(flags.ack ?? 0).toLocaleString()}
          </span>
        </p>
        <p className="text-slate-600">
          Closed cleanly:{' '}
          <span className="font-semibold text-slate-900">
            {(summary.closed ?? 0).toLocaleString()}
          </span>
        </p>
        <p className="ml-auto text-xs text-slate-400">
          States: SYN_SENT → SYN_RECEIVED → ESTABLISHED → FIN_WAIT → CLOSED ·
          PARTIAL = joined mid-connection (no SYN observed)
        </p>
      </div>

      {/* 3. ---- Connection table (section 5) ---- */}
      <div className="mt-6">
        <SectionCard
          title={`TCP Connections${connections.length ? ` (${connections.length} shown)` : ''}`}
          subtitle="Both directions appear as ONE connection — click any row to inspect its interactive sequence ladder diagram"
        >
          {connections.length === 0 ? (
            <p className="py-10 text-center text-sm text-slate-400">
              No connection data available. Start capture on the Live Packets
              page, then open an HTTPS website to generate TCP handshakes.
            </p>
          ) : (
            <DataTable
              headers={[
                'Connection', 'Source', 'Destination', 'Source Port', 'Destination Port',
                'State', 'Packets', 'Bytes', 'Start Time', 'Last Seen', 'Visualizer',
              ]}
            >
              {connections.map((conn, index) => {
                const isSelected =
                  selectedConn &&
                  selectedConn.source_ip === conn.source_ip &&
                  selectedConn.source_port === conn.source_port &&
                  selectedConn.destination_ip === conn.destination_ip &&
                  selectedConn.destination_port === conn.destination_port

                return (
                  <tr
                    key={`${conn.source_ip}-${conn.source_port}-${conn.destination_ip}-${conn.destination_port}-${index}`}
                    onClick={() => setSelectedConn(conn)}
                    className={`cursor-pointer transition-colors ${
                      isSelected ? 'bg-sky-50 ring-1 ring-sky-300' : 'hover:bg-slate-50'
                    }`}
                  >
                    <td className="whitespace-nowrap px-3 py-2.5 font-mono text-xs font-medium text-slate-800">
                      {conn.source_ip}:{conn.source_port} → {conn.destination_ip}:{conn.destination_port}
                    </td>
                    <td className="px-3 py-2.5 font-medium text-slate-800">{conn.source_ip}</td>
                    <td className="px-3 py-2.5 font-medium text-slate-800">{conn.destination_ip}</td>
                    <td className="px-3 py-2.5 text-slate-500">{conn.source_port}</td>
                    <td className="px-3 py-2.5 text-slate-500">{conn.destination_port}</td>
                    <td className="px-3 py-2.5"><Badge>{conn.state}</Badge></td>
                    <td className="px-3 py-2.5 text-slate-500">{conn.packets.toLocaleString()}</td>
                    <td className="px-3 py-2.5 text-slate-500">{formatBytes(conn.bytes)}</td>
                    <td className="px-3 py-2.5 text-slate-500">{formatTime(conn.start_time)}</td>
                    <td className="px-3 py-2.5 text-slate-500">{formatTime(conn.last_seen)}</td>
                    <td className="px-3 py-2.5">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation()
                          setSelectedConn(conn)
                        }}
                        className="inline-flex items-center gap-1 rounded-md border border-sky-300 bg-sky-50 px-2 py-0.5 text-xs font-semibold text-sky-700 shadow-2xs hover:bg-sky-100 transition-colors"
                      >
                        Ladder
                      </button>
                    </td>
                  </tr>
                )
              })}
            </DataTable>
          )}
        </SectionCard>
      </div>

      {/* Interactive Sequence Ladder Modal */}
      {selectedConn && (
        <TcpLadderModal conn={selectedConn} onClose={() => setSelectedConn(null)} />
      )}
    </div>
  )
}
