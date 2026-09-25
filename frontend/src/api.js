// src/api.js — every call the frontend makes to the FastAPI backend.
//
// Stage 2 adds the packet-capture endpoints. The backend URL is stored
// in ONE place so it is easy to change later.

const BASE_URL = 'http://localhost:8001'
// NOTE: NetSense's backend runs on port 8001 (port 8000 is shared with
// other projects on this machine). This is the ONE place to change it.

// ---- Stage 1 ---------------------------------------------------------

export async function fetchHealth() {
  const response = await fetch(`${BASE_URL}/api/health`)
  if (!response.ok) {
    throw new Error(`Backend responded with status ${response.status}`)
  }
  return response.json()
}

// ---- Stage 2: packet capture ------------------------------------------

export async function fetchCaptureStatus() {
  const response = await fetch(`${BASE_URL}/api/capture/status`)
  if (!response.ok) throw new Error('Could not read capture status')
  return response.json()
}

export async function fetchInterfaces() {
  const response = await fetch(`${BASE_URL}/api/capture/interfaces`)
  if (!response.ok) throw new Error('Could not list interfaces')
  return response.json()
}

export async function startCapture(interfaceName) {
  // interfaceName may be undefined -> endpoint uses the default interface
  const query = interfaceName ? `?interface=${encodeURIComponent(interfaceName)}` : ''
  const response = await fetch(`${BASE_URL}/api/capture/start${query}`, { method: 'POST' })
  const body = await response.json()
  if (!response.ok) throw new Error(body.detail || 'Could not start capture')
  return body
}

export async function stopCapture() {
  const response = await fetch(`${BASE_URL}/api/capture/stop`, { method: 'POST' })
  const body = await response.json()
  if (!response.ok) throw new Error(body.detail || 'Could not stop capture')
  return body
}

export async function fetchPackets({ limit = 100, protocol } = {}) {
  const params = new URLSearchParams({ limit: String(limit) })
  if (protocol) params.set('protocol', protocol)
  const response = await fetch(`${BASE_URL}/api/packets?${params.toString()}`)
  if (!response.ok) throw new Error('Could not fetch packets')
  return response.json()
}

// ---- Stage 3: protocol analysis ----------------------------------------

export async function fetchProtocolStats() {
  // Flat {protocol: count} map computed from stored REAL packets.
  const response = await fetch(`${BASE_URL}/api/protocols`)
  if (!response.ok) throw new Error('Could not fetch protocol statistics')
  return response.json()
}

// ---- Phase 4: TCP connections + flows ---------------------------------

export async function fetchTcpStats() {
  // {summary: {...}, flag_counts: {...}} from tracked TCP connections.
  const response = await fetch(`${BASE_URL}/api/tcp/stats`)
  if (!response.ok) throw new Error('Could not fetch TCP statistics')
  return response.json()
}

export async function fetchTcpConnections({ limit = 100 } = {}) {
  const response = await fetch(`${BASE_URL}/api/tcp/connections?limit=${limit}`)
  if (!response.ok) throw new Error('Could not fetch TCP connections')
  return response.json()
}

export async function fetchFlows(filters = {}) {
  // Only non-empty filters are sent; the backend treats all as optional.
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== null && value !== '') {
      params.set(key, String(value))
    }
  }
  const query = params.toString()
  const response = await fetch(`${BASE_URL}/api/flows${query ? `?${query}` : ''}`)
  if (!response.ok) throw new Error('Could not fetch flows')
  return response.json()
}

export async function fetchFlowStats() {
  const response = await fetch(`${BASE_URL}/api/flows/stats`)
  if (!response.ok) throw new Error('Could not fetch flow statistics')
  return response.json()
}

// ---- Phase 5: network performance --------------------------------------

export async function fetchPerformanceSummary() {
  // One call: live traffic rates + RTT/jitter/loss + 60s history.
  // Unavailable metrics come back as null (never fake numbers).
  const response = await fetch(`${BASE_URL}/api/performance/summary`)
  if (!response.ok) throw new Error('Could not fetch performance data')
  return response.json()
}

export async function fetchPerformanceHistory(points = 60) {
  const response = await fetch(`${BASE_URL}/api/performance/history?points=${points}`)
  if (!response.ok) throw new Error('Could not fetch performance history')
  return response.json()
}

export async function setPerformanceTarget(target) {
  // Point RTT probing at a user-authorized target (e.g. the gateway).
  const response = await fetch(
    `${BASE_URL}/api/performance/target?target=${encodeURIComponent(target)}`,
    { method: 'POST' },
  )
  const body = await response.json()
  if (!response.ok) throw new Error(body.detail || 'Could not set RTT target')
  return body
}

// ---- Phase 6: device discovery + topology -------------------------------

export async function fetchDevices({ limit } = {}) {
  // Devices learned PASSIVELY from captured packets (never scanned).
  // Optional limit keeps dashboard queries small (§11).
  const query = limit ? `?limit=${encodeURIComponent(limit)}` : ''
  const response = await fetch(`${BASE_URL}/api/devices${query}`)
  if (!response.ok) throw new Error('Could not fetch devices')
  return response.json()
}

export async function fetchDeviceStats() {
  const response = await fetch(`${BASE_URL}/api/devices/stats`)
  if (!response.ok) throw new Error('Could not fetch device statistics')
  return response.json()
}

export async function fetchDeviceDetails(deviceId) {
  const response = await fetch(
    `${BASE_URL}/api/devices/${encodeURIComponent(deviceId)}`,
  )
  if (response.status === 404) throw new Error('Device not found (not observed)')
  if (!response.ok) throw new Error('Could not fetch device details')
  return response.json()
}

export async function fetchTopology() {
  // Cytoscape.js-ready {nodes, edges} built from real devices + flows.
  const response = await fetch(`${BASE_URL}/api/topology`)
  if (!response.ok) throw new Error('Could not fetch topology')
  return response.json()
}

// ---- Phase 7: routing & path analysis -----------------------------------

export async function getInterfaces() {
  // Real network interfaces read from the OS (ipconfig /all or ip).
  const response = await fetch(`${BASE_URL}/api/routing/interfaces`)
  if (!response.ok) throw new Error('Network information is currently unavailable.')
  return response.json()
}

export async function getGateway() {
  // Default gateway CONFIRMED from the routing table (never guessed).
  const response = await fetch(`${BASE_URL}/api/routing/gateway`)
  if (!response.ok) throw new Error('Default gateway could not be determined.')
  return response.json()
}

export async function getRoutingTable() {
  // The OS routing table (route print / ip route).
  const response = await fetch(`${BASE_URL}/api/routing/table`)
  if (!response.ok) throw new Error('Network information is currently unavailable.')
  return response.json()
}

export async function runTraceroute(target) {
  // Hop-by-hop path to an AUTHORIZED destination. Can take up to ~90 s.
  const response = await fetch(
    `${BASE_URL}/api/routing/traceroute?target=${encodeURIComponent(target)}`,
  )
  const body = await response.json()
  if (!response.ok) throw new Error(body.detail || 'Traceroute failed.')
  return body
}

// ---- Phase 8: machine learning -------------------------------------------

export async function fetchMlStatus() {
  // Are trained models available? Honest false when not trained yet.
  const response = await fetch(`${BASE_URL}/api/ml/status`)
  if (!response.ok) throw new Error('Could not fetch ML status')
  return response.json()
}

export async function fetchMlFeatures() {
  // The 10 behavioral features + live-traffic availability.
  const response = await fetch(`${BASE_URL}/api/ml/features`)
  if (!response.ok) throw new Error('Could not fetch ML features')
  return response.json()
}

export async function fetchMlModelInfo() {
  // Model metadata, real classes/metrics, feature importance.
  const response = await fetch(`${BASE_URL}/api/ml/model-info`)
  if (!response.ok) throw new Error('Could not fetch model info')
  return response.json()
}

export async function analyzeFlow(features) {
  // POST one flow's behavioral features; models answer class + anomaly.
  const response = await fetch(`${BASE_URL}/api/ml/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(features),
  })
  const body = await response.json()
  if (!response.ok) throw new Error(body.detail || 'Analysis failed')
  return body
}

// ---- Phase 9: intelligent alerts ----

export async function fetchAlerts({ limit = 100, status, category, source } = {}) {
  // Filtered alert list, newest first. Empty is a REAL result: nothing
  // has crossed a threshold (no fake alerts are ever generated).
  const params = new URLSearchParams({ limit: String(limit) })
  if (status) params.set('status', status)
  if (category) params.set('category', category)
  if (source) params.set('source', source)
  const response = await fetch(`${BASE_URL}/api/alerts?${params.toString()}`)
  if (!response.ok) throw new Error('Could not fetch alerts')
  return response.json()
}

export async function fetchAlertStats() {
  const response = await fetch(`${BASE_URL}/api/alerts/stats`)
  if (!response.ok) throw new Error('Could not fetch alert stats')
  return response.json()
}

export async function fetchAlertThresholds() {
  const response = await fetch(`${BASE_URL}/api/alerts/thresholds`)
  if (!response.ok) throw new Error('Could not fetch alert thresholds')
  return response.json()
}

export async function updateAlertThresholds(thresholds) {
  const response = await fetch(`${BASE_URL}/api/alerts/thresholds`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(thresholds),
  })
  const body = await response.json()
  if (!response.ok) throw new Error(body.detail || 'Could not update thresholds')
  return body
}

export async function setAlertStatus(alertId, status) {
  // ACKNOWLEDGED / RESOLVED / ACTIVE (alert management).
  const response = await fetch(`${BASE_URL}/api/alerts/${alertId}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  })
  const body = await response.json()
  if (!response.ok) throw new Error(body.detail || 'Could not update alert')
  return body
}

export async function evaluateAlertsNow() {
  // Force one evaluation cycle immediately (polling continues in background).
  const response = await fetch(`${BASE_URL}/api/alerts/evaluate`, { method: 'POST' })
  if (!response.ok) throw new Error('Could not run alert evaluation')
  return response.json()
}
