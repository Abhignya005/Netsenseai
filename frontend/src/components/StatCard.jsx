// src/components/StatCard.jsx
//
// A small card used for the six statistics at the top of the
// Dashboard (Total Packets, Active Connections, ...).

export default function StatCard({ label, value, unit, trend, trendUp, subtitle }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
        {label}
      </p>

      <p className="mt-2 text-3xl font-bold text-slate-900">
        {value}
        {unit ? <span className="ml-1.5 text-sm font-medium text-slate-400">{unit}</span> : null}
      </p>

      {trend ? (
        <p className={`mt-2 text-xs font-semibold ${trendUp ? 'text-emerald-600' : 'text-rose-500'}`}>
          {trendUp ? '▲' : '▼'} {trend}
          <span className="ml-1 font-normal text-slate-400">vs last hour</span>
        </p>
      ) : (
        <p className="mt-2 text-xs font-medium text-slate-400">
          {subtitle || 'Real captured data'}
        </p>
      )}
    </div>
  )
}
