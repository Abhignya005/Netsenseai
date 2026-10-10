// src/components/TcpLadderModal.jsx — Interactive TCP Sequence Ladder Visualizer
//
// Visualizes observed TCP packets (SYN, SYN-ACK, ACK, data, FIN, RST)
// as an animated sequence ladder diagram between Client and Server.

import {
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Clock,
  Layers,
  X,
  XCircle,
} from 'lucide-react'
import Badge from './Badge.jsx'

function formatBytes(bytes) {
  if (bytes == null) return '-'
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

function getEventStyle(event) {
  const flags = event.flags || []
  if (flags.includes('RST')) {
    return {
      border: 'border-rose-400',
      bg: 'bg-rose-50 text-rose-800',
      badge: 'bg-rose-100 text-rose-700',
      arrow: 'text-rose-600',
      line: 'bg-rose-300',
    }
  }
  if (flags.includes('FIN')) {
    return {
      border: 'border-amber-400',
      bg: 'bg-amber-50 text-amber-800',
      badge: 'bg-amber-100 text-amber-700',
      arrow: 'text-amber-600',
      line: 'bg-amber-300',
    }
  }
  if (flags.includes('SYN')) {
    return {
      border: 'border-emerald-400',
      bg: 'bg-emerald-50 text-emerald-800',
      badge: 'bg-emerald-100 text-emerald-700',
      arrow: 'text-emerald-600',
      line: 'bg-emerald-400',
    }
  }
  if (flags.includes('ACK') && event.summary?.includes('Step 3')) {
    return {
      border: 'border-emerald-400',
      bg: 'bg-emerald-50 text-emerald-800',
      badge: 'bg-emerald-100 text-emerald-700',
      arrow: 'text-emerald-600',
      line: 'bg-emerald-400',
    }
  }
  return {
    border: 'border-sky-300',
    bg: 'bg-sky-50/60 text-sky-900',
    badge: 'bg-sky-100 text-sky-700',
    arrow: 'text-sky-600',
    line: 'bg-sky-300',
  }
}

export default function TcpLadderModal({ conn, onClose }) {
  if (!conn) return null

  const events = conn.events || []
  const clientEndpoint = `${conn.source_ip}:${conn.source_port}`
  const serverEndpoint = `${conn.destination_ip}:${conn.destination_port}`

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 p-4 backdrop-blur-sm animate-fadeIn"
      onClick={onClose}
    >
      <div
        className="flex max-h-[90vh] w-full max-w-4xl flex-col rounded-2xl border border-slate-200 bg-white shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <header className="flex items-center justify-between border-b border-slate-200 bg-slate-50/80 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-600 text-white shadow-sm">
              <Layers className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-slate-900">
                  TCP Sequence Ladder Visualizer
                </h2>
                <Badge>{conn.state}</Badge>
              </div>
              <p className="font-mono text-xs text-slate-500">
                {clientEndpoint} <span className="text-sky-600 font-semibold">⟷</span> {serverEndpoint}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-2 text-slate-400 hover:bg-slate-200 hover:text-slate-700 transition-colors"
            title="Close visualizer"
          >
            <X className="h-5 w-5" />
          </button>
        </header>

        {/* Status Highlights */}
        <div className="grid grid-cols-2 gap-3 border-b border-slate-200 bg-white px-6 py-3 text-xs sm:grid-cols-4">
          <div className="flex items-center gap-2">
            {conn.handshake_complete ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-500 shrink-0" />
            ) : (
              <XCircle className="h-4 w-4 text-amber-500 shrink-0" />
            )}
            <div>
              <p className="font-semibold text-slate-700">Handshake</p>
              <p className="text-slate-500">
                {conn.handshake_complete ? 'Full 3-Way Verified' : 'Incomplete / Passive'}
              </p>
            </div>
          </div>
          <div>
            <p className="font-semibold text-slate-700">Packets Exchanged</p>
            <p className="text-slate-500 font-mono">
              {conn.forward_packets} fwd · {conn.backward_packets} bwd ({conn.packets} total)
            </p>
          </div>
          <div>
            <p className="font-semibold text-slate-700">Payload Volume</p>
            <p className="text-slate-500 font-mono">{formatBytes(conn.bytes)}</p>
          </div>
          <div>
            <p className="font-semibold text-slate-700">Observation Mode</p>
            <p className="text-slate-500">
              {conn.observed_start ? 'Observed from SYN' : 'Mid-flight (PARTIAL)'}
            </p>
          </div>
        </div>

        {/* Diagram Area */}
        <div className="flex-1 overflow-y-auto p-6 bg-slate-50/40">
          {/* Lifeline Headers */}
          <div className="sticky top-0 z-10 mb-6 flex justify-between bg-slate-100/90 backdrop-blur-sm rounded-xl border border-slate-200 p-3 shadow-xs">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-sky-500 ring-2 ring-sky-200" />
              <div>
                <p className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  Client (Initiator)
                </p>
                <p className="font-mono text-[11px] text-slate-500">{clientEndpoint}</p>
              </div>
            </div>

            <div className="flex items-center gap-2 text-right">
              <div>
                <p className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  Server (Responder)
                </p>
                <p className="font-mono text-[11px] text-slate-500">{serverEndpoint}</p>
              </div>
              <span className="h-3 w-3 rounded-full bg-emerald-500 ring-2 ring-emerald-200" />
            </div>
          </div>

          {events.length === 0 ? (
            <div className="py-16 text-center text-sm text-slate-400">
              <p>No individual transmission steps recorded for this session yet.</p>
              <p className="mt-1 text-xs">
                Packets captured before the visualizer was attached appear in aggregate metrics.
              </p>
            </div>
          ) : (
            <div className="relative mx-auto max-w-3xl space-y-4">
              {/* Vertical lifeline guides */}
              <div className="absolute left-6 top-0 bottom-0 w-0.5 border-l-2 border-dashed border-slate-300 -z-0" />
              <div className="absolute right-6 top-0 bottom-0 w-0.5 border-r-2 border-dashed border-slate-300 -z-0" />

              {events.map((evt, idx) => {
                const style = getEventStyle(evt)
                const isForward = evt.direction === 'f'

                return (
                  <div
                    key={idx}
                    className="relative flex items-center justify-between text-xs transition-all hover:scale-[1.01]"
                  >
                    {/* Timestamp Bubble */}
                    <div className="absolute left-1/2 -translate-x-1/2 -top-2.5 z-10 rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] font-mono text-slate-500 shadow-xs flex items-center gap-1">
                      <Clock className="h-2.5 w-2.5 text-slate-400" />
                      +{evt.delta_ms} ms
                    </div>

                    {/* Arrow Line & Step Card */}
                    <div
                      className={`relative z-5 mx-6 flex w-full items-center rounded-xl border p-2.5 shadow-xs ${style.bg} ${style.border}`}
                    >
                      {/* Left icon indicator */}
                      <span className="h-2 w-2 rounded-full bg-slate-400 shrink-0" />

                      {/* Direction Arrow & Content */}
                      <div className="flex flex-1 items-center justify-between px-3">
                        {isForward ? (
                          <>
                            <div className="flex items-center gap-2">
                              <span className={`rounded-md px-2 py-0.5 font-mono text-xs font-bold ${style.badge}`}>
                                {evt.flags_str}
                              </span>
                              <span className="font-semibold text-slate-800">
                                {evt.summary}
                              </span>
                            </div>
                            <div className="flex items-center gap-2 font-mono text-[11px] text-slate-500">
                              {evt.seq != null && <span>Seq={evt.seq}</span>}
                              {evt.ack != null && <span>Ack={evt.ack}</span>}
                              {evt.size > 0 && <span className="font-semibold">{evt.size} B</span>}
                              <ArrowRight className={`h-4 w-4 ${style.arrow}`} />
                            </div>
                          </>
                        ) : (
                          <>
                            <div className="flex items-center gap-2 font-mono text-[11px] text-slate-500">
                              <ArrowLeft className={`h-4 w-4 ${style.arrow}`} />
                              {evt.seq != null && <span>Seq={evt.seq}</span>}
                              {evt.ack != null && <span>Ack={evt.ack}</span>}
                              {evt.size > 0 && <span className="font-semibold">{evt.size} B</span>}
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="font-semibold text-slate-800">
                                {evt.summary}
                              </span>
                              <span className={`rounded-md px-2 py-0.5 font-mono text-xs font-bold ${style.badge}`}>
                                {evt.flags_str}
                              </span>
                            </div>
                          </>
                        )}
                      </div>

                      {/* Right icon indicator */}
                      <span className="h-2 w-2 rounded-full bg-slate-400 shrink-0" />
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <footer className="flex items-center justify-between border-t border-slate-200 bg-slate-50 px-6 py-3 text-xs text-slate-500">
          <p>
            Step colors: <span className="text-emerald-700 font-semibold">Green (Handshake)</span> ·{' '}
            <span className="text-sky-700 font-semibold">Blue (Data/ACK)</span> ·{' '}
            <span className="text-amber-700 font-semibold">Amber (FIN Teardown)</span> ·{' '}
            <span className="text-rose-700 font-semibold">Red (Reset)</span>
          </p>
          <button
            onClick={onClose}
            className="rounded-lg bg-slate-800 px-4 py-1.5 font-medium text-white shadow-xs hover:bg-slate-700 transition-colors"
          >
            Close
          </button>
        </footer>
      </div>
    </div>
  )
}

