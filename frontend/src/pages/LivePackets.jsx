// src/pages/LivePackets.jsx — REAL captured packets (STAGE 2)
//
// This page talks to the actual FastAPI packet-capture endpoints:
//   GET  /api/capture/status     -> the control panel state
//   GET  /api/capture/interfaces -> interface dropdown
//   POST /api/capture/start      -> Start button
//   POST /api/capture/stop       -> Stop button
//   GET  /api/packets            -> the packet table
//
// While capture is running, the packet table refreshes every 2 seconds.

import { useCallback, useEffect, useRef, useState } from 'react'
import { Play, Square, Wifi } from 'lucide-react'

import Badge from '../components/Badge.jsx'
import DataTable from '../components/DataTable.jsx'
import SectionCard from '../components/SectionCard.jsx'
import {
  fetchCaptureStatus,
  fetchInterfaces,
  fetchPackets,
  startCapture,
  stopCapture,
} from '../api.js'
import { protocolDetailLabel } from '../protocolLabels.js'

// Turn epoch seconds into "20:45:12" for display.
function formatTime(epochSeconds) {
  return new Date(epochSeconds * 1000).toLocaleTimeString('en-GB')
}

// Round the packet size to a readable string.
function formatSize(bytes) {
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

export default function LivePackets() {
  const [status, setStatus] = useState(null)          // capture engine state
  const [interfaces, setInterfaces] = useState([])    // for the dropdown
  const [selectedInterface, setSelectedInterface] = useState('') // '' = default
  const [packets, setPackets] = useState([])          // table rows
  const [busy, setBusy] = useState(false)             // Start/Stop clicked
  const [error, setError] = useState(null)            // last error message
  const refreshTimer = useRef(null)                   // polling interval

  const isRunning = status?.running === true

  // ---- one-time load: status + interface list -------------------------
  useEffect(() => {
    fetchCaptureStatus()
      .then((s) => {
        setStatus(s)
        // If the engine already failed earlier (e.g. Npcap missing),
        // show the stored error immediately — no need to click first.
        if (s.error) setError(s.error)
      })
      .catch((e) => setError(e.message))
    fetchInterfaces()
      .then((data) => setInterfaces(data.interfaces || []))
      .catch(() => setInterfaces([]))
  }, [])

  // ---- packet table polling (only while running) ----------------------
  const refreshPackets = useCallback(async () => {
    try {
      const data = await fetchPackets({ limit: 100 })
      setPackets(data.packets || [])
      setStatus(data.status) // same response also refreshes the status card
      setError(null)
    } catch (e) {
      setError(e.message)
    }
  }, [])

  useEffect(() => {
    if (isRunning) {
      refreshPackets() // fetch immediately…
      refreshTimer.current = setInterval(refreshPackets, 2000) // …then every 2s
    }
    return () => {
      if (refreshTimer.current) clearInterval(refreshTimer.current)
    }
  }, [isRunning, refreshPackets])

  // ---- button handlers -------------------------------------------------
  async function handleStart() {
    setBusy(true)
    setError(null)
    try {
      const result = await startCapture(
        selectedInterface === '' ? undefined : selectedInterface,
      )
      setStatus(result.status)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  async function handleStop() {
    setBusy(true)
    setError(null)
    try {
      const result = await stopCapture()
      setStatus(result.status)
      await refreshPackets() // one last fetch so the table isn't stale
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  // ---- derived numbers for the small status chips ----------------------
  const totalPackets = status?.total_packets ?? 0
  const bufferedPackets = status?.buffered_packets ?? 0

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-2xl font-bold text-slate-900">Live Packets</h1>
        <p className="mt-1 text-sm text-slate-500">
          Real packet capture via Scapy — metadata only (no packet content is
          ever stored).
        </p>
      </header>

      {/* ---- Capture control panel ---- */}
      <SectionCard title="Capture Control" subtitle="Start or stop the live sniffer">
        <div className="flex flex-wrap items-center gap-4">
          {/* Start / Stop button */}
          {isRunning ? (
            <button
              onClick={handleStop}
              disabled={busy}
              className="inline-flex items-center gap-2 rounded-lg bg-rose-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-rose-700 disabled:opacity-50"
            >
              <Square className="h-4 w-4" />
              {busy ? 'Stopping…' : 'Stop Capture'}
            </button>
          ) : (
            <button
              onClick={handleStart}
              disabled={busy}
              className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-emerald-700 disabled:opacity-50"
            >
              <Play className="h-4 w-4" />
              {busy ? 'Starting…' : 'Start Capture'}
            </button>
          )}

          {/* Interface picker */}
          <label className="flex items-center gap-2 text-sm text-slate-600">
            Interface:
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={isRunning}
              className="max-w-xs rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 disabled:opacity-50"
            >
              <option value="">Default (auto-detected)</option>
              {interfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                  {iface.description || iface.name}
                  {iface.ip ? ` — ${iface.ip}` : ''}
                </option>
              ))}
            </select>
          </label>

          {/* Live status chips */}
          <div className="ml-auto flex items-center gap-2">
            <Badge>{isRunning ? 'Online' : 'Idle'}</Badge>
            <span className="text-xs text-slate-500">
              {isRunning ? (
                <span className="flex items-center gap-1.5">
                  <Wifi className="h-3.5 w-3.5 animate-pulse text-emerald-500" />
                  capturing…
                </span>
              ) : (
                'not capturing'
              )}
            </span>
          </div>
        </div>

        {/* Numbers + errors */}
        <div className="mt-4 flex flex-wrap gap-6 border-t border-slate-100 pt-4 text-sm">
          <p className="text-slate-600">
            Total captured:{' '}
            <span className="font-semibold text-slate-900">{totalPackets.toLocaleString()}</span>
          </p>
          <p className="text-slate-600">
            In memory buffer:{' '}
            <span className="font-semibold text-slate-900">{bufferedPackets.toLocaleString()}</span>
          </p>
          {status?.started_at && (
            <p className="text-slate-600">
              Started:{' '}
              <span className="font-semibold text-slate-900">
                {new Date(status.started_at).toLocaleTimeString('en-GB')}
              </span>
            </p>
          )}
        </div>

        {error && (
          <p className="mt-4 rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            ⚠ {error}
          </p>
        )}
      </SectionCard>

      {/* ---- Packet table ---- */}
      <div className="mt-6">
        <SectionCard
          title={`Captured Packets${packets.length ? ` (${packets.length} shown)` : ''}`}
          subtitle="Newest first — table refreshes every 2 seconds while capturing"
        >
          {packets.length === 0 ? (
            <p className="py-10 text-center text-sm text-slate-400">
              No packets yet. Click <span className="font-semibold text-slate-600">Start Capture</span> above,
              then browse the web or ping a device to generate traffic.
            </p>
          ) : (
            <DataTable
              headers={['Time', 'Source IP', 'Destination IP', 'Protocol', 'Src Port', 'Dst Port', 'Size']}
            >
              {packets.map((packet, index) => (
                <tr key={`${packet.timestamp}-${index}`} className="hover:bg-slate-50">
                  <td className="px-3 py-2.5 text-slate-500">{formatTime(packet.timestamp)}</td>
                  <td className="px-3 py-2.5 font-medium text-slate-800">{packet.source_ip}</td>
                  <td className="px-3 py-2.5 font-medium text-slate-800">{packet.destination_ip}</td>
                  <td className="whitespace-nowrap px-3 py-2.5">
                    <Badge>{packet.protocol}</Badge>
                    {/* Phase 3 section 17: "TCP — SYN", "ICMP — Echo
                        Request", "ARP — Request"; plain DNS/UDP show
                        no suffix. */}
                    {protocolDetailLabel(packet) && (
                      <span className="ml-1.5 text-xs text-slate-400">
                        — {protocolDetailLabel(packet)}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 text-slate-500">{packet.source_port ?? '—'}</td>
                  <td className="px-3 py-2.5 text-slate-500">{packet.destination_port ?? '—'}</td>
                  <td className="px-3 py-2.5 text-slate-500">{formatSize(packet.size)}</td>
                </tr>
              ))}
            </DataTable>
          )}
        </SectionCard>
      </div>
    </div>
  )
}
