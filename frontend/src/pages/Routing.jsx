// src/pages/Routing.jsx — PHASE 7: routing & path analysis
//
// Data sources (all read live from the OPERATING SYSTEM — nothing is
// hardcoded, nothing is invented; unavailable values show "Unavailable"):
//   GET /api/routing/interfaces            -> interface table
//   GET /api/routing/gateway               -> confirmed default gateway
//   GET /api/routing/table                 -> OS routing table
//   GET /api/routing/traceroute?target=... -> hop-by-hop path
//
// Layout (sections 5-9):
//   1. Network interfaces table
//   2. Default gateway card
//   3. Routing table
//   4. Traceroute form + hop table + Cytoscape path visualization
//
// Traceroute runs only against a destination YOU authorize and can
// take up to ~90 seconds; capture keeps running meanwhile (section 12).

import { useCallback, useEffect, useRef, useState } from 'react'
import cytoscape from 'cytoscape'

import Badge from '../components/Badge.jsx'
import DataTable from '../components/DataTable.jsx'
import SectionCard from '../components/SectionCard.jsx'
import {
  getGateway,
  getInterfaces,
  getRoutingTable,
  runTraceroute,
} from '../api.js'

const dash = (value) => (value === null || value === undefined || value === '' ? '—' : value)

export default function Routing() {
  const [interfaces, setInterfaces] = useState(null)
  const [gateway, setGateway] = useState(null)
  const [routes, setRoutes] = useState(null)
  const [osError, setOsError] = useState(null)

  const [target, setTarget] = useState('')
  const [running, setRunning] = useState(false)
  const [traceResult, setTraceResult] = useState(null)   // {target, hops}
  const [traceError, setTraceError] = useState(null)
  const cyRef = useRef(null)
  const containerRef = useRef(null)

  // ---- static OS info: loaded once + manual refresh ------------------
  const loadStatic = useCallback(async () => {
    setOsError(null)
    try {
      const [ifaceData, gatewayData, tableData] = await Promise.all([
        getInterfaces(),
        getGateway(),
        getRoutingTable(),
      ])
      setInterfaces(ifaceData.interfaces ?? [])
      setGateway(gatewayData)
      setRoutes(tableData.routes ?? [])
    } catch (e) {
      setOsError(e.message)
    }
  }, [])

  useEffect(() => {
    loadStatic()
  }, [loadStatic])

  // ---- Cytoscape path graph (section 9) ------------------------------
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
            'text-wrap': 'wrap',
            'text-valign': 'bottom',
            'text-margin-y': 4,
            width: 20,
            height: 20,
          },
        },
        {
          selector: 'node[role = "endpoint"]',
          style: { 'background-color': '#f59e0b', width: 26, height: 26 },
        },
        {
          selector: 'node[role = "timeout"]',
          style: { 'background-color': '#f43f5e' },
        },
        {
          selector: 'edge',
          style: { width: 2, 'line-color': '#94a3b8', 'curve-style': 'straight' },
        },
      ],
      layout: { name: 'preset' },   // we position the chain ourselves
    })
    cyRef.current = cy
    return () => {
      cy.destroy()
      cyRef.current = null
    }
  }, [])

  // Rebuild the path whenever new traceroute results arrive.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !traceResult) return
    const hops = traceResult.hops ?? []
    const elements = []
    const SPACING = 90

    elements.push({
      data: { id: 'local', label: 'Local Device', role: 'endpoint' },
      position: { x: 0, y: 0 },
    })
    hops.forEach((hop) => {
      const label = hop.status === 'timeout'
        ? `Hop ${hop.hop}\nTimeout`
        : `Hop ${hop.hop}\n${hop.ip ?? 'Timeout'}${hop.rtt_ms != null ? `\n${hop.rtt_ms} ms` : ''}`
      elements.push({
        data: {
          id: `hop-${hop.hop}`,
          label,
          role: hop.status === 'timeout' ? 'timeout' : 'hop',
        },
        position: { x: 0, y: hop.hop * SPACING },
      })
    })
    elements.push({
      data: { id: 'dest', label: traceResult.target, role: 'endpoint' },
      position: { x: 0, y: (hops.length + 1) * SPACING },
    })
    // Chain edges: local -> hop1 -> hop2 -> ... -> destination.
    const chain = ['local', ...hops.map((h) => `hop-${h.hop}`), 'dest']
    for (let i = 0; i < chain.length - 1; i += 1) {
      elements.push({ data: { source: chain[i], target: chain[i + 1] } })
    }

    cy.elements().remove()
    cy.add(elements)
    cy.fit(undefined, 40)
  }, [traceResult])

  // ---- traceroute runner (sections 6-8, 13) --------------------------
  async function startTrace(event) {
    event.preventDefault()
    if (!target.trim() || running) return
    setRunning(true)
    setTraceError(null)
    setTraceResult(null)
    try {
      const result = await runTraceroute(target.trim())
      setTraceResult(result)
    } catch (e) {
      setTraceError(e.message)   // e.g. "Invalid destination."
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-2xl font-bold text-slate-900">Routing</h1>
        <p className="mt-1 text-sm text-slate-500">
          Interfaces, gateway, routing table and hop-by-hop path analysis — read
          live from this machine's OS. Traceroute only against destinations you
          are authorized to analyze.
        </p>
      </header>

      {osError && (
        <p className="mb-4 rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          ⚠ {osError}
        </p>
      )}

      {/* 1. ---- Network interfaces (section 5) ---- */}
      <SectionCard
        title="Network Interfaces"
        subtitle="Real adapters from this machine"
        className="mt-2"
      >
        {interfaces && interfaces.length > 0 ? (
          <DataTable headers={['Interface', 'IPv4', 'IPv6', 'MAC', 'Status']}>
            {interfaces.map((iface, index) => (
              <tr key={`${iface.name}-${index}`} className="hover:bg-slate-50">
                <td className="px-3 py-2.5 font-medium text-slate-800">{iface.name}</td>
                <td className="px-3 py-2.5 font-mono text-xs text-slate-600">{dash(iface.ipv4)}</td>
                <td className="px-3 py-2.5 font-mono text-xs text-slate-500">{dash(iface.ipv6)}</td>
                <td className="px-3 py-2.5 font-mono text-xs text-slate-500">{dash(iface.mac)}</td>
                <td className="px-3 py-2.5">
                  <Badge>{iface.status === 'down' ? 'DOWN' : 'UP'}</Badge>
                </td>
              </tr>
            ))}
          </DataTable>
        ) : (
          <p className="py-6 text-center text-sm text-slate-400">
            Network information is currently unavailable.
          </p>
        )}
      </SectionCard>

      {/* 2. ---- Default gateway (section 5) ---- */}
      <SectionCard
        title="Default Gateway"
        subtitle="Confirmed from the routing table — never guessed"
        className="mt-6"
      >
        {gateway?.gateway ? (
          <div className="flex flex-wrap gap-8">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Gateway</p>
              <p className="mt-1 font-mono text-xl font-bold text-slate-900">{gateway.gateway}</p>
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Interface</p>
              <p className="mt-1 font-mono text-xl font-bold text-slate-900">{dash(gateway.interface)}</p>
            </div>
          </div>
        ) : (
          <p className="text-sm text-slate-500">Default gateway could not be determined.</p>
        )}
      </SectionCard>

      {/* 3. ---- Routing table (section 5) ---- */}
      <SectionCard
        title={`Routing Table${routes?.length ? ` (${routes.length} routes)` : ''}`}
        subtitle="Live from the OS — route print / ip route"
        className="mt-6"
      >
        {routes && routes.length > 0 ? (
          <DataTable headers={['Destination', 'Mask / Prefix', 'Gateway', 'Interface', 'Metric']}>
            {routes.map((route, index) => (
              <tr key={`${route.destination}-${route.interface}-${index}`} className="hover:bg-slate-50">
                <td className="px-3 py-2 font-mono text-xs font-medium text-slate-800">{route.destination}</td>
                <td className="px-3 py-2 font-mono text-xs text-slate-500">
                  {route.mask}
                  {route.prefix != null && <span className="ml-1 text-slate-400">/{route.prefix}</span>}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-slate-600">
                  {route.gateway ?? <span className="text-slate-400">On-link</span>}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-slate-500">{dash(route.interface)}</td>
                <td className="px-3 py-2 text-slate-500">{dash(route.metric)}</td>
              </tr>
            ))}
          </DataTable>
        ) : (
          <p className="py-6 text-center text-sm text-slate-400">
            Network information is currently unavailable.
          </p>
        )}
      </SectionCard>

      {/* 4. ---- Traceroute (sections 6-8) ---- */}
      <SectionCard
        title="Traceroute"
        subtitle="Hop-by-hop path to an authorized destination (may take up to ~90 s)"
        className="mt-6"
      >
        <form onSubmit={startTrace} className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-xs font-medium text-slate-500">
            Destination
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. example.com or 8.8.8.8"
              className="w-72 rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-mono text-sm text-slate-800"
            />
          </label>
          <button
            type="submit"
            disabled={running || !target.trim()}
            className="rounded-lg bg-sky-600 px-4 py-1.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-sky-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Run Traceroute
          </button>
          {running && (
            <p className="flex items-center gap-2 text-sm text-sky-600">
              <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-sky-500 border-t-transparent" />
              Running traceroute…
            </p>
          )}
        </form>

        {traceError && (
          <p className="mt-4 rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            ⚠ {traceError}
          </p>
        )}

        {traceResult && (
          <>
            <div className="mt-4">
              <DataTable headers={['Hop', 'IP Address', 'Hostname', 'RTT', 'Status']}>
                {traceResult.hops.map((hop) => (
                  <tr key={hop.hop} className="hover:bg-slate-50">
                    <td className="px-3 py-2 font-semibold text-slate-700">{hop.hop}</td>
                    <td className="px-3 py-2 font-mono text-xs text-slate-600">{dash(hop.ip)}</td>
                    <td className="px-3 py-2 text-slate-500">{dash(hop.hostname)}</td>
                    <td className="px-3 py-2 font-mono text-xs text-slate-600">
                      {hop.rtt_ms != null ? `${hop.rtt_ms} ms` : '—'}
                    </td>
                    <td className="px-3 py-2">
                      {hop.status === 'timeout'
                        ? <Badge>TIMEOUT</Badge>
                        : <Badge>REACHABLE</Badge>}
                    </td>
                  </tr>
                ))}
              </DataTable>
            </div>

            {/* 5. ---- Path visualization (section 9) ---- */}
            <div className="mt-4">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
                Path Visualization
              </p>
              <div ref={containerRef} className="h-80 w-full rounded-lg border border-slate-100 bg-slate-50" />
              <div className="mt-3 flex flex-wrap items-center gap-5 text-xs text-slate-500">
                <span className="flex items-center gap-2">
                  <span className="inline-block h-3 w-3 rounded-full bg-sky-500" /> Hop (reachable)
                </span>
                <span className="flex items-center gap-2">
                  <span className="inline-block h-3 w-3 rounded-full bg-rose-500" /> Timeout
                </span>
                <span className="flex items-center gap-2">
                  <span className="inline-block h-3.5 w-3.5 rounded-full bg-amber-500" /> Local / Destination
                </span>
              </div>
            </div>
          </>
        )}
      </SectionCard>
    </div>
  )
}
