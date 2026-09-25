# NetSense — Network Traffic Monitoring & Intelligent Analysis System

NetSense captures authorized network traffic on a local machine, turns raw
packets into understandable network information (protocols, TCP connections,
flows, performance, devices, routing), applies Machine Learning to flow-level
behavior, and raises careful, rule-based alerts — all in one dashboard.

> **Authorized monitoring only.** NetSense is a passive monitoring tool for
> networks you are authorized to observe. It never scans, never injects
> packets, and never stores packet payloads.

---

## Architecture

```
                NETWORK
                   ↓
            PACKET CAPTURE (Scapy, metadata only)
                   ↓
              PACKET ANALYSIS
                   ↓
     ┌─────────────┼──────────────┐
     ↓             ↓              ↓
PROTOCOL       TCP / FLOW      PERFORMANCE
ANALYSIS       ANALYSIS        MONITORING (RTT, jitter, rates)
     ↓             ↓              ↓
     └─────────────┼──────────────┘
                   ↓
            DEVICE DISCOVERY  →  NETWORK TOPOLOGY (Cytoscape.js)
                   ↓
            ROUTING ANALYSIS (interfaces, gateway, table, traceroute)
                   ↓
            FLOW FEATURE ENGINE
                   ↓
              MACHINE LEARNING
               ↙            ↘
        CLASSIFICATION     ANOMALY (Isolation Forest)
               ↘            ↙
                ALERT ENGINE (rules + ML, cooldowns)
                   ↓
              SQLITE DATABASE
                   ↓
               FASTAPI API
                   ↓
             REACT DASHBOARD
```

This diagram reflects the real implementation: each box is one backend module
(`backend/*.py`), wired together in `capture.py` (per-packet feeds) and
`main.py` (endpoints + background workers).

## Technologies

| Layer | Technology |
| --- | --- |
| Frontend | React 18 + Vite + Tailwind CSS + Recharts + Cytoscape.js |
| Backend | Python 3.10+ + FastAPI + Uvicorn |
| Capture | Scapy (Npcap driver on Windows) |
| Database | SQLite (WAL mode, created automatically) |
| ML | scikit-learn — Random Forest (classifier), Isolation Forest (anomaly) |

## Project Structure

```
netsense/
├── .env.example            optional environment overrides (no secrets)
├── ml/                     Phase 8 ML intelligence layer
│   ├── README.md           dataset placement + training guide
│   ├── data/               <- you place CICIDS2017 CSVs here
│   ├── models/             trained models land here (joblib)
│   ├── preprocessing.py    reusable load/clean/map/split pipeline
│   ├── train_classifier.py Random Forest training + metrics report
│   ├── train_anomaly.py    Isolation Forest training
│   └── inference.py        model loading + classify/detect/analyze
├── backend/
│   ├── main.py             FastAPI app: all 35 endpoints + lifespan
│   ├── config.py           central configuration (env-overridable)
│   ├── capture.py          Scapy capture engine + per-packet wiring
│   ├── protocol_analysis.py Ethernet/IPv4/IPv6/TCP/UDP/ICMP/ARP/DNS
│   ├── tcp_analysis.py     TCP connection tracking + handshake states
│   ├── flow_analysis.py    bidirectional 5-tuple flows (15s/120s timeouts)
│   ├── performance.py      1s traffic buckets, RTT prober, jitter, loss
│   ├── devices.py          passive device discovery + hostnames
│   ├── topology.py         Cytoscape.js node/edge builder
│   ├── routing.py          ipconfig/route print/tracert parsing (safe)
│   ├── ml_service.py       flow→features mapping + background ML worker
│   ├── alerts.py           rule engine + ML alerts + cooldowns
│   ├── database.py         SQLite schema, migrations, helpers (WAL)
│   ├── flows.py            Phase 4 flow-manager facade (interface §14)
│   ├── requirements.txt    Python dependencies
│   └── test_*.py           8 test suites, 315 offline checks
└── frontend/
    └── src/
        ├── api.js          every backend call in one place
        ├── pages/          Dashboard, LivePackets, ProtocolAnalysis,
        │                   TcpAnalysis, FlowAnalysis, Performance,
        │                   DevicesTopology, Routing, MLAnalysis, Alerts
        └── components/     Sidebar, StatCard, SectionCard, Badge, DataTable
```

## Installation

1. **Python 3.10+** (<https://www.python.org>) — on Windows tick *"Add to PATH"*.
2. **Node.js 18+ LTS** (<https://nodejs.org>).
3. **Npcap (Windows only, for packet capture)** — installer from
   <https://npcap.com/#download>; tick **"Install Npcap in WinPcap
   API-compatible Mode"**. Packet capture must run from a terminal opened
   **as Administrator**. Everything except live capture works without it.

```bash
# backend
cd netsense/backend
python -m venv venv
venv\Scripts\activate            # Windows   (source venv/bin/activate on Linux)
pip install -r requirements.txt

# frontend
cd ../frontend
npm install
```

## Running the Application

```bash
# terminal 1 — backend (Administrator on Windows, for capture)
cd netsense/backend
venv\Scripts\activate
uvicorn main:app --port 8001        # or: python main.py

# terminal 2 — frontend
cd netsense/frontend
npm run dev                         # open http://localhost:5173
```

Ports and paths are configurable — see `.env.example` and `backend/config.py`
(`NETSENSE_API_PORT`, `NETSENSE_DB_PATH`, …). Defaults: API **8001**,
frontend **5173**.

## Usage (workflow)

1. Open **Live Packets** → choose an interface → **Start Capture**.
2. Generate normal traffic (browse the web, `ping`, `nslookup`).
3. Watch **Protocol Analysis**, **TCP Analysis**, and **Flow Analysis** fill
   with real connections and flows.
4. **Performance** shows observed traffic rates, RTT/jitter to your default
   gateway, and probe packet loss.
5. **Devices & Topology** maps the machines you actually exchanged packets
   with; **Routing** shows interfaces, the gateway, the OS routing table, and
   can run a traceroute to a destination you authorize.
6. Train ML models once (see `ml/README.md`) — **ML Analysis** then
   classifies completed flows and scores anomalies.
7. **Alerts** fires only when real metrics cross your configured thresholds;
   acknowledge or resolve alerts there.

## Demo Workflow (2-minute story)

```
Start NetSense → Dashboard → Start Capture → Live Packets →
Protocol Analysis → TCP Connections → Flow Analysis → Performance →
Devices & Topology → Routing → run Traceroute → ML Analysis → Alerts →
return to Dashboard
```

One continuous story: raw packets → understanding → intelligence → action.

## Privacy

* **Metadata-first.** Packet payloads are never read, stored, or displayed.
* Only traffic metadata, flow statistics, and performance measurements are
  persisted (SQLite, bounded and trimmed).
* No port scanning, ping sweeps, vulnerability scanning, packet injection, or
  credential collection — anywhere in the codebase.
* Traceroute runs only against a destination the user types in, via
  subprocess **argument lists** (no shell strings — nothing to inject).
* No secrets exist in the project; `.env.example` contains empty placeholders.

## Testing

```bash
cd netsense/backend
for t in test_protocol_analysis test_phase4 test_performance test_phase6 \
         test_phase7 test_phase8 test_phase9 test_final_integration; do
  python $t.py
done
```

All suites are offline (fixture packets, temp databases, fake command output
— never fake *results*): **315 checks** across 8 suites. Frontend: `npm run
build` must succeed; every page was DOM-verified with clean console output.

## Limitations

* **Passive capture** — connections that started before capture, or whose
  packets were missed, are honestly marked PARTIAL/INCOMPLETE rather than
  guessed.
* **Missing packets** — Wi-Fi off-channel capture and driver drops mean
  counters are lower bounds, not exact totals.
* **Traceroute** — intermediate routers may not reply (shown as `Timeout`).
  `tracert -d` is used, so hop hostnames are unavailable by design.
* **RTT/loss** — measured by probing the default gateway (or a user-set
  authorized target) with OS `ping`; the loss figure describes the probe
  path only.
* **ML** — models are only as good as the training dataset (CICIDS2017 is
  2017-era office traffic); classes come from the dataset, accuracy is
  reported from real train/test splits, and no result is ever called "an
  attack". IP addresses/timestamps/ephemeral ports are excluded as features
  to prevent environment memorization (data-leakage control).
* **Windows/Linux** — developed on Windows; `ipconfig`/`route print`/
  `tracert` paths are fully exercised, Linux `ip`/`traceroute` parsers are
  unit-tested but not run on real Linux hosts.
* Npcap is required for live capture on Windows; without it the UI explains
  exactly what to install.

## Roadmap status

- ✅ Stage 1 — dashboard, FastAPI, SQLite, navigation
- ✅ Stage 2 — real packet capture, Live Packets
- ✅ Stage 3 — protocol analysis (L2–L7 metadata, flags, stats)
- ✅ Stage 4 — TCP connection tracking + bidirectional flow analysis
- ✅ Stage 5 — performance monitoring (rates, RTT, jitter, probe loss)
- ✅ Stage 6 — passive device discovery + Cytoscape topology
- ✅ Stage 7 — routing table, interfaces, gateway, traceroute
- ✅ Stage 8 — ML classification (Random Forest) + anomaly detection
- ✅ Stage 9 — intelligent alerts (rules + ML, thresholds, management)
- ✅ Stage 10 — final integration, testing, optimization, documentation
