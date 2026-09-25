// src/App.jsx — top-level layout + routing
//
// Every page renders inside this shell:
//
//   +----------+-----------------------------------+
//   |          |                                   |
//   | Sidebar  |   <Outlet/>  (the current page)   |
//   |          |                                   |
//   +----------+-----------------------------------+
//
// Routes:
//   /dashboard           -> the real Stage 1 Dashboard
//   /live-packets        -> real packet capture page (Stage 2)
//   /protocol-analysis   -> real protocol analysis page (Stage 3)
//   /tcp-analysis        -> real TCP connection tracking (Phase 4)
//   /flow-analysis       -> real flow analysis page (Phase 4)
//   /performance         -> real performance monitoring page (Phase 5)
//   /devices-topology    -> real device discovery + topology (Phase 6)
//   /routing             -> real routing + traceroute analysis (Phase 7)
//   /ml-analysis         -> real ML classification + anomaly page (Phase 8)
//   /:slug               -> any other sidebar page -> PlaceholderPage
//   *                    -> unknown URL            -> PlaceholderPage

import { Navigate, Outlet, Route, Routes } from 'react-router-dom'

import Sidebar from './components/Sidebar.jsx'
import Dashboard from './pages/Dashboard.jsx'
import LivePackets from './pages/LivePackets.jsx'
import ProtocolAnalysis from './pages/ProtocolAnalysis.jsx'
import TcpAnalysis from './pages/TcpAnalysis.jsx'
import FlowAnalysis from './pages/FlowAnalysis.jsx'
import Performance from './pages/Performance.jsx'
import DevicesTopology from './pages/DevicesTopology.jsx'
import Routing from './pages/Routing.jsx'
import MLAnalysis from './pages/MLAnalysis.jsx'
import Alerts from './pages/Alerts.jsx'
import PlaceholderPage from './pages/PlaceholderPage.jsx'

function AppLayout() {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      {/* overflow-y-auto lets long pages (like the Dashboard) scroll
          independently while the sidebar stays fixed. */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        {/* Stage 2: the real packet capture page */}
        <Route path="/live-packets" element={<LivePackets />} />
        {/* Stage 3: the real protocol analysis page */}
        <Route path="/protocol-analysis" element={<ProtocolAnalysis />} />
        {/* Phase 4: TCP connection tracking */}
        <Route path="/tcp-analysis" element={<TcpAnalysis />} />
        {/* Phase 4: network flow analysis */}
        <Route path="/flow-analysis" element={<FlowAnalysis />} />
        {/* Phase 5: network performance monitoring */}
        <Route path="/performance" element={<Performance />} />
        {/* Phase 6: device discovery + network topology */}
        <Route path="/devices-topology" element={<DevicesTopology />} />
        {/* Phase 7: routing + traceroute analysis */}
        <Route path="/routing" element={<Routing />} />
        {/* Phase 8: machine-learning analysis */}
        <Route path="/ml-analysis" element={<MLAnalysis />} />
        {/* Phase 9: intelligent alerts + alert management */}
        <Route path="/alerts" element={<Alerts />} />
        {/* All the not-yet-implemented sidebar pages: */}
        <Route path="/:slug" element={<PlaceholderPage />} />
        {/* Unknown URLs fall back to the placeholder page too. */}
        <Route path="*" element={<PlaceholderPage />} />
      </Route>
    </Routes>
  )
}
