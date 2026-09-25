// src/pages/Dashboard.jsx — the network overview (final Phase 10 form)
//
// Layout of this page (top to bottom):
//   1. Summary cards (Packets, Connections, Flows, Devices, Throughput,
//      Packet Rate, ML Status, Active Alerts — all real values or honest
//      "no data" text, never fake numbers)
//   2. Network Overview (live status panel, reads backend health)
//   3. Protocol Distribution (donut chart — real captured packets)
//   4. Traffic Overview (area chart — real observed rates, Phase 5)
//   5. Recent Alerts (table — real Phase 9 alerts)
//   6. Connected Devices (table — real Phase 6 observed devices)
//
// Every section uses REAL data or an explicit empty state. The old
// Stage-1 sample-data tables were removed in Phase 10 (§14/§15).

import { useEffect, useState } from 'react'
import {
  Area,
  AreaChart,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { CheckCircle2, XCircle } from 'lucide-react'

import Badge from '../components/Badge.jsx'
import DataTable from '../components/DataTable.jsx'
import SectionCard from '../components/SectionCard.jsx'
import StatCard from '../components/StatCard.jsx'
import {
  fetchCaptureStatus,
  fetchDeviceStats,
  fetchFlowStats,
  fetchAlertStats,
  fetchHealth,
  fetchMlStatus,
  fetchPerformanceSummary,
  fetchProtocolStats,
  fetchAlerts,
  fetchDevices,
  fetchTcpStats,
} from '../api.js'
import { protocolColor } from '../protocolColors.js'

function formatBytes(bytes) {
  if (bytes == null || bytes === 0) return '0 B'
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

// Human-readable bit rates for the real Traffic Overview chart (Phase 5).
function formatBits(bits) {
  if (bits == null) return '-'
  if (bits >= 1_000_000_000) return `${(bits / 1_000_000_000).toFixed(1)} Gbps`
  if (bits >= 1_000_000) return `${(bits / 1_000_000).toFixed(1)} Mbps`
  if (bits >= 1_000) return `${(bits / 1_000).toFixed(1)} Kbps`
  return `${Math.round(bits)} bps`
}

export default function Dashboard() {
  // ---- Backend health check -------------------------------------------
  const [backendStatus, setBackendStatus] = useState('checking')
  const [serviceInfo, setServiceInfo] = useState(null)
  // Stage 2: real state of the packet capture engine
  const [captureStatus, setCaptureStatus] = useState(null)
  // Stage 3: real protocol counts from captured packets
  const [protocolStats, setProtocolStats] = useState(null)
  // Phase 4: real TCP connection tracking and flow analysis
  const [tcpStats, setTcpStats] = useState(null)
  const [flowStats, setFlowStats] = useState(null)
  // Phase 5: real performance metrics (traffic history + RTT)
  const [perfSummary, setPerfSummary] = useState(null)
  // Phase 6: real device discovery summary
  const [deviceStats, setDeviceStats] = useState(null)
  // Phase 8: real ML availability + recent observation counts
  const [mlStatus, setMlStatus] = useState(null)
  // Phase 9: real alert counts (zero means nothing crossed a threshold)
  const [alertStats, setAlertStats] = useState(null)
  // Phase 10: real recent alerts + devices for the dashboard tables (§14/§15)
  const [recentAlerts, setRecentAlerts] = useState(null)
  const [recentDevices, setRecentDevices] = useState(null)

  useEffect(() => {
    fetchHealth()
      .then((data) => {
        setBackendStatus('online')
        setServiceInfo(data)
      })
      .catch(() => setBackendStatus('offline'))
  }, [])

  // Refresh real metrics every 3 seconds
  useEffect(() => {
    const refreshAll = () => {
      fetchCaptureStatus().then(setCaptureStatus).catch(() => {})
      fetchProtocolStats().then(setProtocolStats).catch(() => {})
      fetchTcpStats().then(setTcpStats).catch(() => {})
      fetchFlowStats().then(setFlowStats).catch(() => {})
      fetchPerformanceSummary().then(setPerfSummary).catch(() => {})
      fetchDeviceStats().then(setDeviceStats).catch(() => {})
      fetchMlStatus().then(setMlStatus).catch(() => {})
      fetchAlertStats().then(setAlertStats).catch(() => {})
      fetchAlerts({ limit: 5 })
        .then((data) => setRecentAlerts(data.alerts))
        .catch(() => {})
      fetchDevices({ limit: 5 })
        .then((data) => setRecentDevices(data.devices || []))
        .catch(() => {})
    }
    refreshAll()
    const id = setInterval(refreshAll, 3000)
    return () => clearInterval(id)
  }, [])

  // Stage 3: donut data from REAL protocol counts. IP versions are
  // folded into "Other (IP)" so each packet counts exactly once.
  const donutBuckets = {}
  for (const [name, value] of Object.entries(protocolStats || {})) {
    const key = name === 'IPv4' || name === 'IPv6' ? 'Other (IP)' : name
    donutBuckets[key] = (donutBuckets[key] || 0) + value
  }
  const donutData = Object.entries(donutBuckets).map(([name, value]) => ({
    name,
    value,
  }))
  const donutTotal = donutData.reduce((sum, entry) => sum + entry.value, 0)

  // Phase 5: real 1-second traffic buckets for the Traffic Overview chart.
  const perfHistory = (perfSummary?.history ?? []).map((point) => ({
    ...point,
    label: new Date(point.time * 1000).toLocaleTimeString('en-GB', { hour12: false }),
  }))

  const hasConnectionData =
    (tcpStats?.summary?.total ?? 0) > 0 || (flowStats?.total_flows ?? 0) > 0

  // Real Phase 4 stat cards (section 18)
  const realStatCards = [
    {
      id: 'total-packets',
      label: 'Total Packets',
      value: (captureStatus?.total_packets ?? 0).toLocaleString(),
      unit: 'pkts',
      subtitle: captureStatus?.running ? 'Capturing live' : 'Captured packets',
    },
    {
      id: 'active-connections',
      label: 'Active Connections',
      value: (tcpStats?.summary?.active ?? 0).toLocaleString(),
      unit: 'conns',
      subtitle: hasConnectionData ? 'TCP active' : 'No connection data available.',
    },
    {
      id: 'tcp-connections',
      label: 'TCP Connections',
      value: (tcpStats?.summary?.total ?? 0).toLocaleString(),
      unit: 'total',
      subtitle: hasConnectionData ? 'All observed' : 'No connection data available.',
    },
    {
      id: 'active-flows',
      label: 'Active Flows',
      value: (flowStats?.active_flows ?? 0).toLocaleString(),
      unit: 'flows',
      subtitle: hasConnectionData ? 'Within timeout' : 'No connection data available.',
    },
    {
      id: 'completed-flows',
      label: 'Completed Flows',
      value: (flowStats?.completed_flows ?? 0).toLocaleString(),
      unit: 'flows',
      subtitle: hasConnectionData ? 'Timed out / rotated' : 'No connection data available.',
    },
    {
      id: 'total-flow-bytes',
      label: 'Total Flow Volume',
      value: formatBytes(flowStats?.total_bytes ?? 0),
      unit: '',
      subtitle: `${(flowStats?.total_packets ?? 0).toLocaleString()} pkts in flows`,
    },
  ]

  return (
    <div className="p-8">
      <header className="mb-8">
        <h1 className="text-2xl font-bold text-slate-900">Dashboard</h1>
        <p className="mt-1 text-sm text-slate-500">
          Network overview with machine-learning intelligence — Phase 8 build.
        </p>
      </header>

      {/* 1. ---- Stat cards (Phase 4 section 18 real metrics) ---- */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        {realStatCards.map((stat) => (
          <StatCard key={stat.id} {...stat} />
        ))}
      </div>

      {!hasConnectionData && (
        <div className="mt-4 rounded-xl border border-slate-200 bg-white px-5 py-3.5 text-center text-sm font-medium text-slate-500 shadow-sm">
          No connection data available. Start packet capture on the Live Packets page to monitor real TCP connections and flows.
        </div>
      )}

      {/* 2. ---- Network Overview (real backend health check) -------- */}
      <SectionCard
        title="Network Overview"
        subtitle="Live status of the NetSense system"
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-8">
          <div className="rounded-lg border border-slate-200 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Capture Engine
            </p>
            <p className="mt-2 flex items-center gap-2 text-sm font-semibold text-slate-700">
              {captureStatus?.running ? (
                <>
                  <span className="relative flex h-2.5 w-2.5">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500" />
                  </span>
                  <span className="text-emerald-600">Capturing</span>
                </>
              ) : (
                <>
                  <Badge>Off</Badge>
                  <span className="font-normal text-slate-400">Live Packets page</span>
                </>
              )}
            </p>
            {captureStatus?.running && (
              <p className="mt-1 text-xs text-slate-400">
                {captureStatus.total_packets.toLocaleString()} packets captured
              </p>
            )}
          </div>

          <div className="rounded-lg border border-slate-200 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Backend API
            </p>
            <p className="mt-2 flex items-center gap-2 text-sm font-semibold text-slate-700">
              {backendStatus === 'online' && (
                <>
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                  <span className="text-emerald-600">Online</span>
                </>
              )}
              {backendStatus === 'offline' && (
                <>
                  <XCircle className="h-4 w-4 text-rose-500" />
                  <span className="text-rose-600">Offline</span>
                </>
              )}
              {backendStatus === 'checking' && <span className="text-slate-400">Checking…</span>}
            </p>
            {serviceInfo && (
              <p className="mt-1 text-xs text-slate-400">
                service: {serviceInfo.service}
              </p>
            )}
          </div>

          <div className="rounded-lg border border-slate-200 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              TCP Engine
            </p>
            <p className="mt-2 text-sm font-semibold text-slate-700">
              {tcpStats?.summary?.active ?? 0} active / {tcpStats?.summary?.total ?? 0} total
            </p>
            <p className="mt-1 text-xs text-slate-400">
              {tcpStats?.summary?.completed_handshakes ?? 0} completed handshakes
            </p>
          </div>

          <div className="rounded-lg border border-slate-200 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Flow Engine
            </p>
            <p className="mt-2 text-sm font-semibold text-slate-700">
              {flowStats?.active_flows ?? 0} active / {flowStats?.total_flows ?? 0} total
            </p>
            <p className="mt-1 text-xs text-slate-400">
              15s inactive · 120s active
            </p>
          </div>

          <div className="rounded-lg border border-slate-200 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Database
            </p>
            <p className="mt-2 flex items-center gap-2 text-sm font-semibold text-slate-700">
              <Badge>SQLite</Badge>
              <span className="font-normal text-slate-400">netsense.db</span>
            </p>
          </div>

          <div className="rounded-lg border border-slate-200 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Observed Devices
            </p>
            <p className="mt-2 text-sm font-semibold text-slate-700">
              {(deviceStats?.total_devices ?? 0).toLocaleString()}
              {deviceStats?.gateway_known ? ' · gateway known' : ''}
            </p>
            <p className="mt-1 truncate text-xs text-slate-400">
              {deviceStats?.most_active
                ? `top: ${deviceStats.most_active.hostname || deviceStats.most_active.ip || 'Unknown'} (${formatBytes(deviceStats.most_active.bytes)})`
                : 'No device data available.'}
            </p>
          </div>

          <div className="rounded-lg border border-slate-200 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              ML Status
            </p>
            <p className="mt-2 text-sm font-semibold text-slate-700">
              {mlStatus
                ? `${mlStatus.classifier_available ? 'Classifier ✓' : 'No classifier'} · ${mlStatus.anomaly_model_available ? 'Anomaly ✓' : 'No anomaly model'}`
                : 'Checking…'}
            </p>
            <p className="mt-1 truncate text-xs text-slate-400">
              {(mlStatus?.recent_observations?.total ?? 0) > 0
                ? `normal ${mlStatus.recent_observations.normal} · potentially anomalous ${mlStatus.recent_observations.potentially_anomalous}`
                : 'No inference data available.'}
            </p>
          </div>

          <div className="rounded-lg border border-slate-200 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              Active Alerts
            </p>
            <p className="mt-2 text-sm font-semibold text-slate-700">
              {alertStats
                ? `${alertStats.by_status?.ACTIVE ?? 0} active · ${alertStats.total} total`
                : 'Checking…'}
            </p>
            <p className="mt-1 truncate text-xs text-slate-400">
              {(alertStats?.total ?? 0) > 0
                ? `recent: ${Object.entries(alertStats.by_category || {})
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 1)
                    .map(([cat, n]) => `${cat.replaceAll('_', ' ')} (${n})`)
                    .join('')}`
                : 'No alerts — nothing crossed a threshold.'}
            </p>
          </div>
        </div>
      </SectionCard>

      {/* 3 + 4. ---- Charts side by side ------------------------------ */}
      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-5">
        {/* Protocol Distribution — REAL captured data (Stage 3) */}
        <SectionCard
          title="Protocol Distribution"
          subtitle={
            donutTotal > 0
              ? `${donutTotal.toLocaleString()} real captured packets`
              : 'Real captured data'
          }
        >
          {donutTotal > 0 ? (
            <>
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={donutData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={60}
                      outerRadius={90}
                      paddingAngle={3}
                    >
                      {donutData.map((entry) => (
                        <Cell key={entry.name} fill={protocolColor(entry.name)} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(value, name) => [`${value} packets`, name]} />
                    <Legend iconType="circle" />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </>
          ) : (
            <div className="flex h-72 flex-col items-center justify-center text-center">
              <p className="text-sm font-medium text-slate-500">No packet data available.</p>
              <p className="mt-1 max-w-[16rem] text-xs text-slate-400">
                Start capture on the Live Packets page — this chart only ever
                shows real captured packets, never fake values.
              </p>
            </div>
          )}
        </SectionCard>

        {/* Traffic Overview — REAL observed rates (Phase 5 section 21) */}
        <SectionCard
          title="Traffic Overview"
          subtitle={
            perfHistory.length > 0
              ? 'Observed capture rate (bits/sec) — last 60 seconds, real data'
              : 'Observed capture rate (real data)'
          }
        >
          {perfHistory.length > 0 ? (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={perfHistory} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="realTrafficFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#0ea5e9" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="#0ea5e9" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="label" tickLine={false} axisLine={false} fontSize={11} minTickGap={40} />
                  <YAxis
                    tickLine={false} axisLine={false} fontSize={11} width={80}
                    tickFormatter={formatBits}
                  />
                  <Tooltip formatter={(value) => [formatBits(value), 'Observed rate']} />
                  <Area
                    type="monotone"
                    dataKey="bits"
                    stroke="#0ea5e9"
                    strokeWidth={2}
                    fill="url(#realTrafficFill)"
                    name="Observed traffic"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="flex h-72 flex-col items-center justify-center text-center">
              <p className="text-sm font-medium text-slate-500">Waiting for network data.</p>
              <p className="mt-1 max-w-[16rem] text-xs text-slate-400">
                Start capture on the Live Packets page — this chart shows only
                real observed traffic, never sample values.
              </p>
            </div>
          )}
        </SectionCard>
      </div>

      {/* 5 + 6. ---- Tables side by side ------------------------------ */}
      <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-2">
        {/* Recent Alerts — REAL Phase 9 alerts (§14/§15) */}
        <SectionCard title="Recent Alerts" subtitle="Real alerts from the Phase 9 engine">
          {recentAlerts === null ? (
            <p className="py-6 text-center text-sm text-slate-400">Loading…</p>
          ) : recentAlerts.length === 0 ? (
            <p className="py-6 text-center text-sm text-slate-500">
              No alerts currently active — nothing has crossed a configured threshold.
            </p>
          ) : (
            <DataTable headers={['Severity', 'Message', 'Time']}>
              {recentAlerts.map((alert) => (
                <tr key={alert.id}>
                  <td className="px-3 py-3"><Badge>{alert.severity}</Badge></td>
                  <td className="px-3 py-3 text-slate-700">{alert.title} — {alert.message}</td>
                  <td className="px-3 py-3 text-slate-400">
                    {alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : '—'}
                  </td>
                </tr>
              ))}
            </DataTable>
          )}
        </SectionCard>

        {/* Connected Devices — REAL Phase 6 devices (§14/§15) */}
        <SectionCard title="Connected Devices" subtitle="Passively observed devices (Phase 6)">
          {recentDevices === null ? (
            <p className="py-6 text-center text-sm text-slate-400">Loading…</p>
          ) : recentDevices.length === 0 ? (
            <p className="py-6 text-center text-sm text-slate-500">
              No devices discovered yet — start packet capture to observe traffic.
            </p>
          ) : (
            <DataTable headers={['IP Address', 'MAC Address', 'Hostname', 'Packets', 'Traffic']}>
              {recentDevices.map((device) => (
                <tr key={device.ip || device.id}>
                  <td className="px-3 py-3 font-medium text-slate-800">{device.ip || 'Unknown'}</td>
                  <td className="px-3 py-3 text-slate-500">{device.mac || 'Unknown'}</td>
                  <td className="px-3 py-3 text-slate-700">{device.hostname || 'Unknown'}</td>
                  <td className="px-3 py-3 text-slate-600">{(device.packet_count ?? 0).toLocaleString()}</td>
                  <td className="px-3 py-3 text-slate-600">{formatBytes(device.bytes)}</td>
                </tr>
              ))}
            </DataTable>
          )}
        </SectionCard>
      </div>
    </div>
  )
}
