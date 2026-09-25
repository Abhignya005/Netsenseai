// src/pages/Performance.jsx — PHASE 5: network performance monitoring
//
// Data sources (all REAL measurements — unavailable metrics are null
// and shown as "Unavailable", never fake numbers):
//   GET /api/performance/summary  -> live rates + RTT detail + history
//   POST /api/performance/target  -> change the authorized RTT target
//
// Layout (Phase 5 sections 12-15):
//   1. Six summary cards (Traffic, Packet Rate, Avg Size, RTT, Jitter, Loss)
//   2. Traffic rate chart (bits/sec over time, rolling 60 points)
//   3. Packet rate chart (packets/sec over time)
//   4. RTT chart + min/avg/max (only when RTT measurements exist)
// Polls every 1 second while the tab is open.

import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import Badge from '../components/Badge.jsx'
import SectionCard from '../components/SectionCard.jsx'
import {
  fetchCaptureStatus,
  fetchPerformanceSummary,
  setPerformanceTarget,
} from '../api.js'

function formatBits(bits) {
  if (bits == null) return 'Unavailable'
  if (bits >= 1_000_000_000) return `${(bits / 1_000_000_000).toFixed(1)} Gbps`
  if (bits >= 1_000_000) return `${(bits / 1_000_000).toFixed(1)} Mbps`
  if (bits >= 1_000) return `${(bits / 1_000).toFixed(1)} Kbps`
  return `${Math.round(bits)} bps`
}

function formatMs(value) {
  return value == null ? 'Unavailable' : `${value.toFixed(1)} ms`
}

function chartTime(epochSeconds) {
  const date = new Date(epochSeconds * 1000)
  return date.toLocaleTimeString('en-GB', { hour12: false })
}

// Metric value or the honest "Unavailable" placeholder (section 1).
function Metric({ value, render }) {
  return <>{value == null ? <span className="text-slate-400">Unavailable</span> : render(value)}</>
}

export default function Performance() {
  const [summary, setSummary] = useState(null)
  const [isRunning, setIsRunning] = useState(false)
  const [error, setError] = useState(null)
  const [targetDraft, setTargetDraft] = useState('')
  const [targetMessage, setTargetMessage] = useState(null)
  const timer = useRef(null)

  const refresh = useCallback(async () => {
    try {
      const [data, statusData] = await Promise.all([
        fetchPerformanceSummary(),
        fetchCaptureStatus(),
      ])
      setSummary(data)
      setIsRunning(statusData.running === true)
      setError(null)
    } catch (e) {
      setError(e.message)
    }
  }, [])

  useEffect(() => {
    refresh()
    timer.current = setInterval(refresh, 1000) // section 13: ~1 s updates
    return () => clearInterval(timer.current)
  }, [refresh])

  const traffic = summary?.traffic ?? {}
  const rtt = summary?.rtt ?? {}
  const history = (summary?.history ?? []).map((point) => ({
    ...point,
    label: chartTime(point.time),
  }))

  async function applyTarget(event) {
    event.preventDefault()
    if (!targetDraft.trim()) return
    try {
      await setPerformanceTarget(targetDraft.trim())
      setTargetMessage({ ok: true, text: `RTT target set to ${targetDraft.trim()} — first measurement in ~10 s` })
      setTargetDraft('')
      refresh()
    } catch (e) {
      setTargetMessage({ ok: false, text: e.message })
    }
  }

  // ---- Page status banner (section 20) --------------------------------
  const hasTraffic = history.length > 0
  const rttAvailable = (rtt.measurements ?? 0) > 0
  const pageStatus = !isRunning
    ? { text: 'WAITING FOR PACKET DATA', tone: 'bg-slate-100 text-slate-600' }
    : hasTraffic
      ? { text: 'LIVE', tone: 'bg-emerald-100 text-emerald-700' }
      : { text: 'WAITING FOR PACKET DATA', tone: 'bg-amber-100 text-amber-700' }

  // ---- Six summary cards (section 12) ---------------------------------
  const cards = [
    {
      label: 'Current Traffic',
      value: formatBits(traffic.bits_per_second),
      sub: traffic.bits_per_second != null ? 'observed traffic rate' : 'start capture to measure',
    },
    {
      label: 'Current Packet Rate',
      value: traffic.packets_per_second != null ? `${traffic.packets_per_second}/s` : 'Unavailable',
      sub: traffic.avg_packets_per_second != null
        ? `avg ${traffic.avg_packets_per_second}/s · peak ${traffic.peak_packets_per_second}/s`
        : 'no closed windows yet',
    },
    {
      label: 'Average Packet Size',
      value: traffic.average_packet_size != null ? `${traffic.average_packet_size} B` : 'Unavailable',
      sub: traffic.overall_average_packet_size != null
        ? `overall avg ${traffic.overall_average_packet_size} B`
        : 'bytes ÷ packets',
    },
    {
      label: 'Current RTT',
      value: formatMs(rtt.rtt_ms),
      sub: rtt.target ? `target: ${rtt.target}` : 'no RTT target configured',
    },
    {
      label: 'Jitter',
      value: formatMs(rtt.jitter_ms),
      sub: 'variation between consecutive RTTs',
    },
    {
      label: 'Packet Loss',
      value: rtt.packet_loss_percent != null ? `${rtt.packet_loss_percent}%` : 'Unavailable',
      sub: 'PROBE loss — not whole-network loss',
    },
  ]

  return (
    <div className="p-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Performance</h1>
          <p className="mt-1 text-sm text-slate-500">
            Traffic rates, RTT, jitter and probe packet loss — every value is a
            real measurement; unmeasurable metrics show Unavailable.
          </p>
        </div>
        <span className={`rounded-full px-3 py-1 text-xs font-bold tracking-wider ${pageStatus.tone}`}>
          {pageStatus.text}
        </span>
      </header>

      {error && (
        <p className="mb-4 rounded-lg border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          ⚠ {error}
        </p>
      )}

      {/* 1. ---- Summary cards ---- */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3 xl:grid-cols-6">
        {cards.map((card) => (
          <div key={card.label} className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">{card.label}</p>
            <p className="mt-2 text-xl font-bold text-slate-900">{card.value}</p>
            <p className="mt-1 text-[11px] leading-snug text-slate-400">{card.sub}</p>
          </div>
        ))}
      </div>

      {/* Secondary rates row (section 12: peak/average) */}
      <div className="mt-4 flex flex-wrap gap-6 rounded-xl border border-slate-200 bg-white px-5 py-3 text-sm">
        <p className="text-slate-600">
          Peak traffic: <span className="font-semibold text-slate-900">{formatBits(traffic.peak_bits_per_second)}</span>
        </p>
        <p className="text-slate-600">
          Average traffic: <span className="font-semibold text-slate-900">{formatBits(traffic.avg_bits_per_second)}</span>
        </p>
        <p className="text-slate-600">
          Peak packet rate: <span className="font-semibold text-slate-900">
            {traffic.peak_packets_per_second != null ? `${traffic.peak_packets_per_second}/s` : 'Unavailable'}
          </span>
        </p>
        <p className="text-slate-600">
          RTT min/avg/max: <span className="font-semibold text-slate-900">
            {rttAvailable
              ? `${rtt.min_rtt_ms ?? '-'} / ${rtt.avg_rtt_ms ?? '-'} / ${rtt.max_rtt_ms ?? '-'} ms`
              : 'Unavailable'}
          </span>
        </p>
        <p className="ml-auto text-xs text-slate-400">
          probes sent {rtt.probes_sent ?? 0} · received {rtt.probes_received ?? 0}
        </p>
      </div>

      {/* 2. ---- Traffic chart (section 13) ---- */}
      <SectionCard
        title="Traffic Rate vs Time"
        subtitle="Observed capture rate in bits/sec — rolling 60-second window"
        className="mt-6"
      >
        {hasTraffic ? (
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={history} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#0ea5e9" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#0ea5e9" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="label" tickLine={false} axisLine={false} fontSize={11} minTickGap={40} />
                <YAxis
                  tickLine={false} axisLine={false} fontSize={11} width={80}
                  tickFormatter={(v) => formatBits(v)}
                />
                <Tooltip formatter={(value) => [formatBits(value), 'Observed rate']} />
                <Area type="monotone" dataKey="bits" stroke="#0ea5e9" strokeWidth={2} fill="url(#trafficFill)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="flex h-64 flex-col items-center justify-center text-center">
            <p className="text-sm font-medium text-slate-500">No packet data available.</p>
            <p className="mt-1 max-w-[18rem] text-xs text-slate-400">
              Start capture on the Live Packets page — this chart only ever shows
              real measured traffic.
            </p>
          </div>
        )}
      </SectionCard>

      {/* 3. ---- Packet rate chart (section 14) ---- */}
      <SectionCard
        title="Packets per Second vs Time"
        subtitle="Same rolling window — packets observed in each 1-second bucket"
        className="mt-6"
      >
        {hasTraffic ? (
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={history} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="packetFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#a3e635" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#a3e635" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="label" tickLine={false} axisLine={false} fontSize={11} minTickGap={40} />
                <YAxis tickLine={false} axisLine={false} fontSize={11} width={50} />
                <Tooltip formatter={(value) => [`${value} pkt/s`, 'Packet rate']} />
                <Area type="monotone" dataKey="packets" stroke="#84cc16" strokeWidth={2} fill="url(#packetFill)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="flex h-56 items-center justify-center text-center text-sm text-slate-400">
            Waiting for packet data.
          </div>
        )}
      </SectionCard>

      {/* 4. ---- RTT chart (section 15) — only when measurable ---- */}
      <SectionCard
        title="RTT vs Time"
        subtitle={rtt.target ? `ICMP probes to ${rtt.target} · one packet every 10 s` : 'RTT measurement unavailable — no target configured'}
        className="mt-6"
      >
        {rttAvailable && (rtt.history ?? []).length >= 2 ? (
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart
                data={(rtt.history ?? []).map((ms, index) => ({ index, ms }))}
                margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="index" tickLine={false} axisLine={false} fontSize={11} />
                <YAxis
                  tickLine={false} axisLine={false} fontSize={11} width={60}
                  tickFormatter={(v) => `${v} ms`}
                  domain={[0, (dataMax) => Math.max(10, Math.ceil(dataMax * 1.2))]}
                />
                <Tooltip formatter={(value) => [`${value} ms`, 'RTT']} />
                <Line type="monotone" dataKey="ms" stroke="#8b5cf6" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="flex h-56 flex-col items-center justify-center text-center">
            <p className="text-sm font-medium text-slate-500">RTT measurement unavailable</p>
            <p className="mt-1 max-w-[20rem] text-xs text-slate-400">
              {rtt.error
                ? rtt.error
                : 'NetSense probes the default gateway gently (1 packet / 10 s). Set an authorized target below, or wait for the first measurements.'}
            </p>
          </div>
        )}
      </SectionCard>

      {/* RTT target control (section 8: user-selected authorized target) */}
      <form
        onSubmit={applyTarget}
        className="mt-6 flex flex-wrap items-end gap-3 rounded-xl border border-slate-200 bg-white p-4"
      >
        <label className="flex flex-col gap-1 text-xs font-medium text-slate-500">
          Authorized RTT target
          <input
            value={targetDraft}
            onChange={(e) => setTargetDraft(e.target.value)}
            placeholder="e.g. 192.168.1.1 (your gateway)"
            className="w-64 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-800"
          />
        </label>
        <button
          type="submit"
          className="rounded-lg bg-sky-600 px-4 py-1.5 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-sky-700"
        >
          Set target
        </button>
        {targetMessage && (
          <p className={`text-xs ${targetMessage.ok ? 'text-emerald-600' : 'text-rose-600'}`}>
            {targetMessage.text}
          </p>
        )}
        <p className="ml-auto max-w-md text-xs text-slate-400">
          Only probe hosts you are authorized to measure (your gateway, your own
          servers). NetSense sends one small ICMP packet every 10 seconds.
        </p>
      </form>
    </div>
  )
}
