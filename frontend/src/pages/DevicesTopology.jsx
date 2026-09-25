// src/pages/DevicesTopology.jsx — PHASE 6: devices + network topology
//
// Data sources (all PASSIVE observations — NetSense never scans):
//   GET /api/devices          -> discovered device table
//   GET /api/devices/stats    -> summary cards
//   GET /api/topology         -> Cytoscape.js {nodes, edges}
// Polls every 3 seconds (section 22 — no WebSockets needed).
//
// Layout (sections 6-16):
//   1. Summary cards (devices / MACs / gateway / traffic)
//   2. Topology graph (Cytoscape.js, zoom/pan/select)
//   3. Device table with simple filters
//   4. Detail panels for a selected device or edge

import { useCallback, useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'

import Badge from '../components/Badge.jsx'
import DataTable from '../components/DataTable.jsx'
import SectionCard from '../components/SectionCard.jsx'
import {
  fetchCaptureStatus,
  fetchDeviceDetails,
  fetchDevices,
  fetchTopology,
} from '../api.js'
import { protocolColor } from '../protocolColors.js'

function formatBytes(bytes) {
  if (bytes == null) return 'Unknown'
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

function formatTime(epochSeconds) {
  if (!epochSeconds) return '-'
  return new Date(epochSeconds * 1000).toLocaleTimeString('en-GB')
}

const dash = (value) => (value === null || value === undefined || value === '' ? 'Unknown' : value)

export default function DevicesTopology() {
  const [devices, setDevices] = useState([])
  const [topology, setTopology] = useState(null)
  const [isRunning, setIsRunning] = useState(false)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)      // device row or edge data
  const [filters, setFilters] = useState({ ip: '', mac: '', hostname: '', protocol: '' })
  const cyRef = useRef(null)     // the Cytoscape instance
  const containerRef = useRef(null)

  // ---- data refresh (section 22: every 3 s, polling) -----------------
  const refresh = useCallback(async () => {
    try {
      const [deviceData, topoData, statusData] = await Promise.all([
        fetchDevices(),
        fetchTopology(),
        fetchCaptureStatus(),
      ])
      setDevices(deviceData.devices)
      setTopology(topoData)
      setIsRunning(statusData.running === true)
      setError(null)
    } catch (e) {
      setError(e.message)
    }
  }, [])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 3000)
    return () => clearInterval(id)
  }, [refresh])

  // ---- Cytoscape graph lifecycle -------------------------------------
  useEffect(() => {
    if (!containerRef.current) return undefined
    const cy = cytoscape({
      container: containerRef.current,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'background-color': '#0ea5e9',
            color: '#0f172a',
            'font-size': 10,
            'text-valign': 'bottom',
            'text-margin-y': 4,
            width: 22,
            height: 22,
          },
        },
        {
          selector: 'node[is_gateway], node[is_local]',
          style: { 'background-color': '#f59e0b', width: 28, height: 28 },
        },
        {
          selector: 'edge',
          style: {
            width: 2,
            'line-color': '#94a3b8',
            'target-arrow-color': '#94a3b8',
            'curve-style': 'bezier',
            label: 'data(protocols)',   // e.g. "TCP" / "UDP, DNS"
            'font-size': 9,
            color: '#64748b',
          },
        },
      ],
      layout: { name: 'cose', animate: false },   // force-directed
    })
    cy.on('tap', 'node', (event) => {
      const id = event.target.id()
      // The device table row carries the full details — reuse it.
      setSelected((current) => current?.id === id ? current : { type: 'device-id', id })
    })
    cy.on('tap', 'edge', (event) => {
      setSelected({ type: 'edge', data: event.target.data() })
    })
    cyRef.current = cy
    return () => {
      cy.destroy()
      cyRef.current = null
    }
  }, [])

  // Feed new topology data into the existing graph (no full rebuild).
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !topology) return
    cy.elements().remove()
    cy.add([...topology.nodes, ...topology.edges])
    cy.layout({ name: 'cose', animate: false }).run()
  }, [topology])

  // Resolve a node tap to its device row (section 15).
  useEffect(() => {
    if (selected?.type !== 'device-id') return
    let cancelled = false
    fetchDeviceDetails(selected.id)
      .then((row) => { if (!cancelled) setSelected({ type: 'device', row }) })
      .catch(() => { if (!cancelled) setSelected(null) })
    return () => { cancelled = true }
  }, [selected])

  // ---- simple filters (section 7) ------------------------------------
  const filtered = devices.filter((device) => {
    if (filters.ip && !(device.ip ?? '').toLowerCase().includes(filters.ip.toLowerCase())) return false
    if (filters.mac && !(device.mac ?? '').toLowerCase().includes(filters.mac.toLowerCase())) return false
    if (filters.hostname && !(device.hostname ?? '').toLowerCase().includes(filters.hostname.toLowerCase())) return false
    if (filters.protocol && !device.protocols.some((p) => p === filters.protocol.toUpperCase())) return false
    return true
  })

  const stats = topology?.nodes?.length
    ? {
        total: topology.nodes.length,
        gateways: topology.nodes.filter((n) => n.data.is_gateway).length,
        locals: topology.nodes.filter((n) => n.data.is_local).length,
        edges: topology.edges.length,
      }
    : { total: 0, gateways: 0, locals: 0, edges: 0 }

  const hasData = devices.length > 0

  return (
    <div className="p-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Devices &amp; Topology</h1>
          <p className="mt-1 text-sm text-slate-500">
            Devices discovered passively from captured packets — NetSense never
            scans your network.
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

      {/* 1. ---- Summary cards ---- */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          { label: 'Observed Devices', value: stats.total },
          { label: 'Gateway Identified', value: stats.gateways ? 'Yes' : 'Unknown' },
          { label: 'Topology Links', value: stats.edges },
          { label: 'Local Device', value: stats.locals ? 'Yes' : 'Unknown' },
        ].map((card) => (
          <div key={card.label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">{card.label}</p>
            <p className="mt-2 text-2xl font-bold text-slate-900">{card.value}</p>
          </div>
        ))}
      </div>

      {/* 2. ---- Topology graph (sections 9-16) ---- */}
      <SectionCard
        title="Network Topology"
        subtitle="Nodes = observed devices · edges = real observed communication (click a node or edge for details)"
        className="mt-6"
      >
        {hasData ? (
          <>
            <div ref={containerRef} className="h-96 w-full rounded-lg border border-slate-100 bg-slate-50" />
            {/* Legend (section 16) — no safety colors, just roles */}
            <div className="mt-3 flex flex-wrap items-center gap-5 text-xs text-slate-500">
              <span className="flex items-center gap-2">
                <span className="inline-block h-3 w-3 rounded-full bg-sky-500" /> Observed Device
              </span>
              <span className="flex items-center gap-2">
                <span className="inline-block h-3.5 w-3.5 rounded-full bg-amber-500" /> Gateway / Local Device
              </span>
              <span className="flex items-center gap-2">
                <span className="inline-block h-0.5 w-6 bg-slate-400" /> Observed Communication
              </span>
            </div>
          </>
        ) : (
          <div className="flex h-96 flex-col items-center justify-center text-center">
            <p className="text-sm font-medium text-slate-500">No device data available.</p>
            <p className="mt-1 max-w-[20rem] text-xs text-slate-400">
              Start capture on the Live Packets page and generate traffic (browse,
              ping, nslookup) — devices appear only from real observed packets.
            </p>
          </div>
        )}
      </SectionCard>

      {/* 3. ---- Device filters (section 7) ---- */}
      {hasData && (
        <form
          onSubmit={(e) => e.preventDefault()}
          className="mt-6 flex flex-wrap items-end gap-3 rounded-xl border border-slate-200 bg-white p-4"
        >
          {[
            { key: 'ip', label: 'IP address', placeholder: 'e.g. 192.168.1' },
            { key: 'mac', label: 'MAC address', placeholder: 'e.g. AA:BB' },
            { key: 'hostname', label: 'Hostname', placeholder: 'e.g. laptop' },
          ].map(({ key, label, placeholder }) => (
            <label key={key} className="flex flex-col gap-1 text-xs font-medium text-slate-500">
              {label}
              <input
                value={filters[key]}
                onChange={(e) => setFilters({ ...filters, [key]: e.target.value })}
                placeholder={placeholder}
                className="w-40 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-800"
              />
            </label>
          ))}
          <label className="flex flex-col gap-1 text-xs font-medium text-slate-500">
            Protocol
            <select
              value={filters.protocol}
              onChange={(e) => setFilters({ ...filters, protocol: e.target.value })}
              className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-800"
            >
              <option value="">All</option>
              {['TCP', 'UDP', 'DNS', 'ICMP', 'ARP'].map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={() => setFilters({ ip: '', mac: '', hostname: '', protocol: '' })}
            className="rounded-lg border border-slate-300 px-4 py-1.5 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-50"
          >
            Reset
          </button>
        </form>
      )}

      {/* 4. ---- Device table (section 6) ---- */}
      {hasData && (
        <div className="mt-6">
          <SectionCard
            title={`Discovered Devices${filtered.length ? ` (${filtered.length} shown)` : ''}`}
            subtitle="Click a row for full details"
          >
            <DataTable
              headers={[
                'IP Address', 'MAC Address', 'Hostname', 'Packets', 'Traffic',
                'Protocols', 'Role', 'First Seen', 'Last Seen',
              ]}
            >
              {filtered.map((device) => (
                <tr
                  key={device.id}
                  onClick={() => setSelected({ type: 'device', row: device })}
                  className={`cursor-pointer hover:bg-slate-50 ${selected?.type === 'device' && selected.row?.id === device.id ? 'bg-sky-50' : ''}`}
                >
                  <td className="px-3 py-2.5 font-mono text-xs font-medium text-slate-800">
                    {dash(device.ip)}
                    {device.ip_count > 1 && (
                      <span className="ml-1 text-[10px] text-slate-400">+{device.ip_count - 1}</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs text-slate-500">{dash(device.mac)}</td>
                  <td className="px-3 py-2.5 text-slate-700">{dash(device.hostname)}</td>
                  <td className="px-3 py-2.5 text-slate-500">{device.packet_count.toLocaleString()}</td>
                  <td className="px-3 py-2.5 text-slate-500">{formatBytes(device.bytes)}</td>
                  <td className="px-3 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {device.protocols.slice(0, 4).map((p) => (
                        <Badge key={p}>{p}</Badge>
                      ))}
                      {device.protocols.length > 4 && (
                        <span className="text-[10px] text-slate-400">+{device.protocols.length - 4}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2.5">
                    {device.is_gateway ? <Badge>GATEWAY</Badge>
                      : device.is_local ? <Badge>LOCAL</Badge>
                      : <span className="text-slate-300">—</span>}
                  </td>
                  <td className="px-3 py-2.5 text-slate-400">{formatTime(device.first_seen)}</td>
                  <td className="px-3 py-2.5 text-slate-400">{formatTime(device.last_seen)}</td>
                </tr>
              ))}
            </DataTable>
          </SectionCard>
        </div>
      )}

      {/* 5. ---- Detail panels (sections 8 + 15) ---- */}
      {selected?.type === 'device' && selected.row && (
        <SectionCard
          title={`Device Details — ${dash(selected.row.ip)}`}
          subtitle={selected.row.hostname ? selected.row.hostname : 'Hostname: Unknown'}
          className="mt-6"
        >
          <button
            type="button"
            onClick={() => setSelected(null)}
            className="float-right text-xs text-slate-400 hover:text-slate-600"
          >
            ✕ close
          </button>
          <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
            {[
              ['IP Address', dash(selected.row.ip)],
              ['MAC Address', dash(selected.row.mac)],
              ['Hostname', dash(selected.row.hostname)],
              ['Total Packets', selected.row.packet_count?.toLocaleString() ?? 'Unavailable'],
              ['Total Traffic', formatBytes(selected.row.bytes)],
              ['Protocols', selected.row.protocols?.join(', ') || 'Unknown'],
              ['Role', selected.row.is_gateway ? 'Gateway' : selected.row.is_local ? 'Local Device' : 'Observed device'],
              ['First Seen', formatTime(selected.row.first_seen)],
              ['Last Seen', formatTime(selected.row.last_seen)],
              ['IP Addresses Linked', String(selected.row.ip_count ?? 1)],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg border border-slate-100 p-3">
                <dt className="text-xs font-medium uppercase tracking-wider text-slate-400">{label}</dt>
                <dd className="mt-1 font-semibold text-slate-800">{value}</dd>
              </div>
            ))}
          </dl>
        </SectionCard>
      )}

      {selected?.type === 'edge' && (
        <SectionCard title="Connection Details" subtitle="Merged from real observed flows" className="mt-6">
          <button
            type="button"
            onClick={() => setSelected(null)}
            className="float-right text-xs text-slate-400 hover:text-slate-600"
          >
            ✕ close
          </button>
          <dl className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-5">
            {[
              ['Source', dash(selected.data.source)],
              ['Destination', dash(selected.data.target)],
              ['Protocols', selected.data.protocols?.join(', ') || 'Unknown'],
              ['Packets', selected.data.packets?.toLocaleString() ?? 'Unavailable'],
              ['Bytes', formatBytes(selected.data.bytes)],
            ].map(([label, value]) => (
              <div key={label} className="rounded-lg border border-slate-100 p-3">
                <dt className="text-xs font-medium uppercase tracking-wider text-slate-400">{label}</dt>
                <dd className="mt-1 font-semibold text-slate-800">{value}</dd>
              </div>
            ))}
          </dl>
        </SectionCard>
      )}
    </div>
  )
}
