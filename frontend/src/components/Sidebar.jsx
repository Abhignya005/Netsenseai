// src/components/Sidebar.jsx
//
// The left navigation menu. Each item is a react-router link.
// "Dashboard" is the only real page in Stage 1 — every other link
// goes to the generic PlaceholderPage ("Coming in next stage").

import { NavLink } from 'react-router-dom'
import {
  Activity,
  BrainCircuit,
  GitBranch,
  Gauge,
  LayoutDashboard,
  ListTree,
  Network,
  Radar,
  TriangleAlert,
  Waypoints,
} from 'lucide-react'

// Every navigation entry. `to` is the URL path, `end` tells NavLink
// that "/dashboard" should only be highlighted for the exact path.
const NAV_ITEMS = [
  { label: 'Dashboard', to: '/dashboard', icon: LayoutDashboard },
  { label: 'Live Packets', to: '/live-packets', icon: Activity },
  { label: 'Protocol Analysis', to: '/protocol-analysis', icon: Waypoints },
  { label: 'TCP Analysis', to: '/tcp-analysis', icon: ListTree },
  { label: 'Flow Analysis', to: '/flow-analysis', icon: Radar },
  { label: 'Performance', to: '/performance', icon: Gauge },
  { label: 'Devices & Topology', to: '/devices-topology', icon: Network },
  { label: 'Routing', to: '/routing', icon: GitBranch },
  { label: 'ML Analysis', to: '/ml-analysis', icon: BrainCircuit },
  { label: 'Alerts', to: '/alerts', icon: TriangleAlert },
]

export default function Sidebar() {
  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-slate-800 bg-slate-900">
      {/* Brand / logo */}
      <div className="flex items-center gap-2.5 px-5 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-500">
          <Radar className="h-5 w-5 text-white" />
        </div>
        <div>
          <p className="text-base font-bold text-white">NetSense</p>
          <p className="text-[10px] uppercase tracking-widest text-slate-400">Network Monitor</p>
        </div>
      </div>

      {/* Navigation links */}
      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-2">
        {NAV_ITEMS.map(({ label, to, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-sky-500/15 text-sky-400'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
              }`
            }
          >
            <Icon className="h-4 w-4 shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Stage badge at the bottom */}
      <div className="border-t border-slate-800 px-5 py-4">
        <p className="text-xs text-slate-500">
          Phase 9 <span className="text-slate-600">·</span> Intelligent Alerts
        </p>
      </div>
    </aside>
  )
}
