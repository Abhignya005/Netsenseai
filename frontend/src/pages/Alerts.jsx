// src/pages/Alerts.jsx — PHASE 9: intelligent alerts + alert management
//
// Data sources (all REAL — no fake alerts are ever generated):
//   GET  /api/alerts             -> alert list (filterable, newest first)
//   GET  /api/alerts/stats       -> counts by status / category / severity
//   GET  /api/alerts/thresholds  -> current configurable thresholds
//   POST /api/alerts/thresholds  -> save new thresholds
//   POST /api/alerts/{id}/status -> acknowledge / resolve
//   POST /api/alerts/evaluate    -> force one evaluation cycle now
//
// The alert engine polls in the background every 10 s; this page polls
// every 5 s just to render. Empty states are honest: "No alerts yet"
// really means nothing has crossed a threshold.

import { useCallback, useEffect, useState } from 'react'

import {
  evaluateAlertsNow,
  fetchAlertStats,
  fetchAlertThresholds,
  fetchAlerts,
  setAlertStatus,
  updateAlertThresholds,
} from '../api.js'

const CATEGORY_LABELS = {
  high_traffic: 'High Traffic',
  high_packet_rate: 'High Packet Rate',
  high_syn_activity: 'SYN Activity',
  high_rst_activity: 'RST Activity',
  incomplete_connections: 'Incomplete Connections',
  ml_anomaly: 'ML Anomaly',
}

const SEVERITY_STYLES = {
  high: 'bg-red-100 text-red-700',
  medium: 'bg-amber-100 text-amber-700',
  low: 'bg-slate-100 text-slate-600',
}

const STATUS_STYLES = {
  ACTIVE: 'bg-red-100 text-red-700',
  ACKNOWLEDGED: 'bg-amber-100 text-amber-700',
  RESOLVED: 'bg-emerald-100 text-emerald-700',
}

// Section 7 naming: an ACTIVE alert is shown as "Open".
const STATUS_LABELS = { ACTIVE: 'OPEN', ACKNOWLEDGED: 'ACKNOWLEDGED', RESOLVED: 'RESOLVED' }

function formatBytesPerSecond(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—'
  let v = Number(value)
  for (const unit of ['B/s', 'KB/s', 'MB/s', 'GB/s']) {
    if (Math.abs(v) < 1024 || unit === 'GB/s') return `${v.toFixed(1)} ${unit}`
    v /= 1024
  }
  return `${v.toFixed(1)} GB/s`
}

function formatObservedValue(key, value) {
  if (value === null || value === undefined) return '—'
  if (key === 'bytes_per_second') return formatBytesPerSecond(value)
  if (key === 'bits_per_second') {
    const Mbps = Number(value) / 1_000_000
    return Mbps >= 1 ? `${Mbps.toFixed(1)} Mbps` : `${(Number(value) / 1000).toFixed(1)} Kbps`
  }
  if (typeof value === 'number') {
    return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(3)
  }
  return String(value)
}

function formatThreshold(category, threshold) {
  if (threshold === null || threshold === undefined) return '—'
  if (category === 'high_traffic') return formatBytesPerSecond(threshold)
  if (category === 'high_packet_rate') return `${threshold.toLocaleString()} packets/sec`
  if (category === 'ml_anomaly') return '—'
  return Number(threshold).toFixed(2)
}

function ObservedCell({ alert }) {
  const observed = alert.observed || {}
  const keys = Object.keys(observed)
  if (keys.length === 0) return <span className="text-slate-400">—</span>
  return (
    <div className="space-y-0.5 text-xs text-slate-600">
      {keys.map((key) => (
        <div key={key}>
          <span className="text-slate-400">{key.replaceAll('_', ' ')}: </span>
          {formatObservedValue(key, observed[key])}
        </div>
      ))}
    </div>
  )
}

const THRESHOLD_FIELDS = [
  { key: 'high_traffic_bytes_per_second', label: 'High traffic (B/s)', step: '100000' },
  { key: 'high_packet_rate_packets_per_second', label: 'High packet rate (packets/sec)', step: '10' },
  { key: 'high_syn_ratio', label: 'High SYN ratio (0-1)', step: '0.05' },
  { key: 'high_rst_ratio', label: 'High RST ratio (0-1)', step: '0.05' },
  { key: 'incomplete_connections', label: 'Incomplete connections (count)', step: '5' },
  { key: 'cooldown_seconds', label: 'Cooldown per rule (seconds)', step: '30' },
]

export default function Alerts() {
  const [alerts, setAlerts] = useState(null)
  const [stats, setStats] = useState(null)
  const [thresholds, setThresholds] = useState(null)
  const [draftThresholds, setDraftThresholds] = useState({})
  const [statusFilter, setStatusFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [saving, setSaving] = useState(false)
  const [notice, setNotice] = useState(null)

  const load = useCallback(async () => {
    try {
      const [alertData, statData] = await Promise.all([
        fetchAlerts({
          limit: 200,
          status: statusFilter || undefined,
          category: categoryFilter || undefined,
          source: sourceFilter || undefined,
        }),
        fetchAlertStats(),
      ])
      setAlerts(alertData.alerts)
      setStats(statData)
    } catch {
      // Backend briefly unavailable — keep last data, retry on next poll.
    }
  }, [statusFilter, categoryFilter, sourceFilter])

  useEffect(() => {
    load()
    const timer = setInterval(load, 5000)
    return () => clearInterval(timer)
  }, [load])

  useEffect(() => {
    fetchAlertThresholds()
      .then((data) => {
        setThresholds(data)
        setDraftThresholds(data)
      })
      .catch(() => {})
  }, [])

  const saveThresholds = async () => {
    setSaving(true)
    setNotice(null)
    try {
      const cleaned = {}
      for (const [key, value] of Object.entries(draftThresholds)) {
        const number = Number(value)
        if (Number.isFinite(number) && number > 0) cleaned[key] = number
      }
      const updated = await updateAlertThresholds(cleaned)
      setThresholds(updated)
      setDraftThresholds(updated)
      setNotice('Thresholds saved.')
    } catch (error) {
      setNotice(error.message)
    } finally {
      setSaving(false)
    }
  }

  const changeStatus = async (alertId, status) => {
    try {
      await setAlertStatus(alertId, status)
      load()
    } catch {
      // keep last state; the next poll will reconcile
    }
  }

  const checkNow = async () => {
    try {
      await evaluateAlertsNow()
      load()
    } catch {
      // ignore — background evaluator keeps running anyway
    }
  }

  const activeCount = stats?.by_status?.ACTIVE ?? 0
  const acknowledgedCount = stats?.by_status?.ACKNOWLEDGED ?? 0
  const resolvedCount = stats?.by_status?.RESOLVED ?? 0

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-slate-900">Alerts</h1>
      <p className="mt-1 text-sm text-slate-500">
        Phase 9 build — alerts are generated ONLY from real observed metrics,
        configured thresholds, and real ML results. An alert describes
        potentially unusual behavior; it is never proof of an attack.
      </p>

      {/* Summary cards (real counts only) */}
      <div className="mt-5 grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[
          ['Open', activeCount, 'border-red-200 text-red-700'],
          ['Acknowledged', acknowledgedCount, 'border-amber-200 text-amber-700'],
          ['Resolved', resolvedCount, 'border-emerald-200 text-emerald-700'],
          ['Total alerts', stats?.total ?? 0, ''],
        ].map(([label, value, extra]) => (
          <div key={label} className={`rounded-lg border border-slate-200 p-4 ${extra}`}>
            <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
              {label}
            </p>
            <p className="mt-2 text-2xl font-bold">{Number(value).toLocaleString()}</p>
          </div>
        ))}
      </div>

      {/* Filters + manual evaluation */}
      <div className="mt-6 flex flex-wrap items-center gap-3">
        <select
          className="rounded-md border border-slate-300 px-3 py-1.5 text-sm"
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value)}
        >
          <option value="">All statuses</option>
          <option value="OPEN">Open</option>
          <option value="ACKNOWLEDGED">Acknowledged</option>
          <option value="RESOLVED">Resolved</option>
        </select>
        <select
          className="rounded-md border border-slate-300 px-3 py-1.5 text-sm"
          value={categoryFilter}
          onChange={(event) => setCategoryFilter(event.target.value)}
        >
          <option value="">All categories</option>
          {Object.entries(CATEGORY_LABELS).map(([value, label]) => (
            <option key={value} value={value}>{label}</option>
          ))}
        </select>
        <select
          className="rounded-md border border-slate-300 px-3 py-1.5 text-sm"
          value={sourceFilter}
          onChange={(event) => setSourceFilter(event.target.value)}
        >
          <option value="">Rule + ML</option>
          <option value="rule">Rule engine</option>
          <option value="ml">Machine learning</option>
        </select>
        <button
          type="button"
          onClick={checkNow}
          className="rounded-md bg-slate-800 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700"
        >
          Check now
        </button>
        <span className="text-xs text-slate-400">
          background evaluation runs every 10 s
        </span>
      </div>

      {/* Alert table */}
      <div className="mt-4 overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-sm">
        {alerts === null ? (
          <p className="p-6 text-sm text-slate-500">Loading alerts…</p>
        ) : alerts.length === 0 ? (
          <p className="p-6 text-sm text-slate-500">
            No alerts {statusFilter || categoryFilter || sourceFilter ? 'match the current filters' : 'yet'}.
            Alerts appear only when real observed metrics cross the configured
            thresholds — an empty list means nothing has.
          </p>
        ) : (
          <table className="min-w-full divide-y divide-slate-200 text-sm">
            <thead className="bg-slate-50 text-left text-xs uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">Alert</th>
                <th className="px-4 py-3">Observed</th>
                <th className="px-4 py-3">Threshold</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {alerts.map((alert) => (
                <tr key={alert.id} className="align-top">
                  <td className="px-4 py-3">
                    <span className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold ${SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.low}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-xs text-slate-500">
                    {alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-medium text-slate-700">
                      {CATEGORY_LABELS[alert.category] || alert.category}
                    </span>
                    <div className="mt-0.5 text-[11px] uppercase tracking-wide text-slate-400">
                      {alert.source === 'ml' ? 'ML model' : 'Rule engine'}
                    </div>
                  </td>
                  <td className="max-w-md px-4 py-3">
                    <p className="font-medium text-slate-800">{alert.title}</p>
                    <p className="mt-0.5 text-xs text-slate-500">{alert.message}</p>
                  </td>
                  <td className="px-4 py-3">
                    <ObservedCell alert={alert} />
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-600">
                    {formatThreshold(alert.category, alert.threshold)}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex rounded-full px-2.5 py-0.5 text-xs font-semibold ${STATUS_STYLES[alert.status] || 'bg-slate-100 text-slate-600'}`}>
                      {STATUS_LABELS[alert.status] || alert.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-col gap-1">
                      {alert.status === 'ACTIVE' && (
                        <button
                          type="button"
                          onClick={() => changeStatus(alert.id, 'ACKNOWLEDGED')}
                          className="rounded border border-amber-300 px-2 py-0.5 text-xs text-amber-700 hover:bg-amber-50"
                        >
                          Acknowledge
                        </button>
                      )}
                      {alert.status !== 'RESOLVED' && (
                        <button
                          type="button"
                          onClick={() => changeStatus(alert.id, 'RESOLVED')}
                          className="rounded border border-emerald-300 px-2 py-0.5 text-xs text-emerald-700 hover:bg-emerald-50"
                        >
                          Resolve
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Threshold configuration */}
      <div className="mt-6 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-base font-semibold text-slate-900">Alert thresholds</h2>
        <p className="mt-0.5 text-xs text-slate-500">
          Defaults are starting points, not measurements. A rule fires only when a
          real observation crosses its threshold; the same steady condition does
          not re-fire until the cooldown passes (and the value grew).
        </p>
        {thresholds && (
          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {THRESHOLD_FIELDS.map(({ key, label, step }) => (
              <label key={key} className="text-xs text-slate-600">
                {label}
                <input
                  type="number"
                  step={step}
                  min="0"
                  className="mt-1 w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm"
                  value={draftThresholds[key] ?? ''}
                  onChange={(event) =>
                    setDraftThresholds({ ...draftThresholds, [key]: event.target.value })
                  }
                />
              </label>
            ))}
          </div>
        )}
        <div className="mt-4 flex items-center gap-3">
          <button
            type="button"
            onClick={saveThresholds}
            disabled={saving}
            className="rounded-md bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Save thresholds'}
          </button>
          {notice && <span className="text-xs text-slate-500">{notice}</span>}
        </div>
      </div>
    </div>
  )
}
