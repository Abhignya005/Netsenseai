"""
main.py — NetSense backend (STAGE 3)

This is the entry point of the FastAPI server.

How to run it (from the `backend` folder):
    uvicorn main:app --reload --port 8001
    (Port 8001: port 8000 may be used by other projects on this
     machine. On Windows, start the terminal as ADMINISTRATOR so
     packet capture works — see README.)

API endpoints:
    GET  /api/health              health check (Stage 1)
    GET  /api/capture/status      is capture running? how many packets?
    GET  /api/capture/interfaces  list network interfaces
    POST /api/capture/start       begin capturing
    POST /api/capture/stop        stop capturing
    GET  /api/packets             recent packet metadata (newest first)
    GET  /api/protocols           protocol counts for analysis (Stage 3)
    GET  /api/tcp/stats           TCP handshake/connection stats (Phase 4)
    GET  /api/tcp/connections     tracked TCP connections (Phase 4)
    GET  /api/flows               network flows + metrics (Phase 4)
    GET  /api/flows/stats         flow summary counts (Phase 4)
    GET  /api/performance/current live traffic rates + RTT (Phase 5)
    GET  /api/performance/history 1-second traffic buckets for charts (Phase 5)
    GET  /api/performance/rtt     RTT/jitter/loss detail (Phase 5)
    GET  /api/performance/summary everything in one call (Phase 5)
    POST /api/performance/target  change the authorized RTT target (Phase 5)
    GET  /api/devices             discovered devices (Phase 6)
    GET  /api/devices/stats       device summary counts (Phase 6)
    GET  /api/devices/{device_id} one device's details (Phase 6)
    GET  /api/topology            Cytoscape.js nodes + edges (Phase 6)
    GET  /api/routing/interfaces  real network interfaces (Phase 7)
    GET  /api/routing/gateway     confirmed default gateway (Phase 7)
    GET  /api/routing/table       OS routing table (Phase 7)
    GET  /api/routing/traceroute  hop-by-hop path to a target (Phase 7)
    GET  /api/ml/status           are the ML models available? (Phase 8)
    GET  /api/ml/features         feature list + live availability (Phase 8)
    GET  /api/ml/model-info       model metadata + real metrics (Phase 8)
    POST /api/ml/analyze          analyze one flow's features (Phase 8)

No alerts logic here — that is Phase 9, exactly as the plan says.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from alerts import alert_manager
import config
import database
from capture import capture_manager, flow_engine, list_interfaces, tcp_tracker
from devices import device_registry

# PHASE 8: make the ml/ package importable BEFORE importing inference.
# ml_service.py does this too, but import order in Python is not
# guaranteed to be friendly — this bootstrap makes the dependency
# explicit and keeps the backend starting cleanly from the backend/ dir.
import sys
from pathlib import Path

_ML_DIR = Path(__file__).resolve().parent.parent / "ml"
if str(_ML_DIR) not in sys.path:
    sys.path.insert(0, str(_ML_DIR))

from inference import analyze_flow, features_available  # noqa: E402
from ml_service import flow_to_features, ml_service  # noqa: E402
from performance import default_gateway, performance_monitor, rtt_prober
from routing import get_gateway, get_interfaces, get_routing_table, run_traceroute
from topology import build_topology


# "lifespan" runs when the server starts (before the yield) and when it
# shuts down (after the yield).
@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()  # create/upgrade SQLite tables
    # PHASE 5 (section 8): prefer the DEFAULT GATEWAY as the RTT target.
    # It is the least intrusive authorized target on any local network.
    gateway, description = default_gateway()
    if gateway:
        rtt_prober.set_target(gateway, description)
        # PHASE 6 (section 13): the same CONFIRMED gateway identifies
        # the Gateway node in the topology.
        device_registry.set_gateway(gateway)
        print(f"[NetSense] Gateway: {gateway} ({description})")
    else:
        print("[NetSense] RTT unavailable — no default gateway detected; "
              "set one via POST /api/performance/target")

    # PHASE 6 (section 14): remember this machine's own addresses so its
    # node can be labeled "Local Device".
    local_ips, local_macs = set(), set()
    try:
        import socket as _socket

        probe = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))          # no packet is sent
        local_ips.add(probe.getsockname()[0])
        probe.close()
    except Exception:
        pass
    try:
        for iface in list_interfaces():
            if iface.get("ip"):
                local_ips.add(iface["ip"])
    except Exception:
        pass
    device_registry.set_local(ips=local_ips, macs=local_macs)

    # PHASE 5: start the background performance thread (1-second traffic
    # buckets + gentle RTT probing). It is a daemon, so it can never
    # block shutdown, and it never blocks packet capture.
    performance_monitor.start()
    # PHASE 6: start the device registry's slow lane (cached hostname
    # lookups + one-minute persistence). Also a daemon thread.
    device_registry.start()
    # PHASE 8: start the ML worker (background analysis of COMPLETED
    # flows). Skips silently when models are not trained yet.
    ml_service.start()
    # PHASE 9: start the alert evaluator (background snapshot -> rule
    # engine + ML results -> SQLite). A daemon that never touches the
    # capture thread.
    alert_manager.start()
    yield
    alert_manager.stop()
    ml_service.stop()
    device_registry.stop()
    performance_monitor.stop()
    # If capture is still running when the server stops, stop it cleanly.
    if capture_manager.get_status()["running"]:
        capture_manager.stop()
    print("[NetSense] Backend shutting down. Goodbye!")


app = FastAPI(
    title="NetSense API",
    version="0.8.0",
    description=(
        "Backend for the NetSense network traffic monitoring system. "
        "Phase 5: network performance monitoring — traffic rates, RTT, "
        "jitter, probe packet loss. All values are real measurements; "
        "unmeasurable metrics are returned as null, never invented."
    ),
    lifespan=lifespan,
)

# ------------------------------------------------------------------
# CORS middleware
# ------------------------------------------------------------------
# The frontend (http://localhost:5173) and backend (http://localhost:8001)
# are different "origins". Browsers block cross-origin requests by
# default, so we explicitly allow the frontend.
app.add_middleware(
    CORSMiddleware,
    # PHASE 10: the allowed frontend origin comes from config.py
    # (env override: NETSENSE_FRONTEND_ORIGIN).
    allow_origins=[config.FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------
# Health check (Stage 1 — unchanged)
# ------------------------------------------------------------------
@app.get("/api/health")
def health_check():
    """Simple health check so the frontend can verify the backend is up."""
    return {
        "status": "ok",
        "service": "NetSense",
    }


# ------------------------------------------------------------------
# Capture control endpoints (Stage 2)
# ------------------------------------------------------------------
@app.get("/api/capture/status")
def capture_status():
    """Current state of the packet capture engine."""
    return capture_manager.get_status()


@app.get("/api/capture/interfaces")
def capture_interfaces():
    """Network interfaces the sniffer could use."""
    return {"interfaces": list_interfaces()}


@app.post("/api/capture/start")
def capture_start(interface: str | None = Query(default=None)):
    """Start capturing packets.

    Optional query parameter: ?interface=<name> to choose a specific
    network interface; omitted = Scapy's default interface.
    """
    ok, message = capture_manager.start(interface=interface)
    if not ok:
        # 409 Conflict = the request cannot be done right now
        raise HTTPException(status_code=409, detail=message)
    return {"ok": ok, "message": message, "status": capture_manager.get_status()}


@app.post("/api/capture/stop")
def capture_stop():
    """Stop capturing packets."""
    ok, message = capture_manager.stop()
    if not ok and "not running" in message.lower():
        raise HTTPException(status_code=409, detail=message)
    return {"ok": ok, "message": message, "status": capture_manager.get_status()}


# ------------------------------------------------------------------
# Captured packets endpoint (Stage 2)
# ------------------------------------------------------------------
@app.get("/api/packets")
def get_packets(
    limit: int = Query(default=100, ge=1, le=500),
    protocol: str | None = Query(default=None),
):
    """Return recent packet metadata, newest first.

    Query parameters:
        limit     how many packets (1..500, default 100)
        protocol  optional filter, e.g. ?protocol=TCP

    NOTE: this returns metadata only — no payload content is stored
    or served, anywhere in NetSense.
    """
    packets = capture_manager.get_recent_packets(limit=limit, protocol=protocol)
    return {
        "count": len(packets),
        "packets": packets,
        "status": capture_manager.get_status(),
    }


# ------------------------------------------------------------------
# Protocol statistics (Stage 3)
# ------------------------------------------------------------------
@app.get("/api/protocols")
def protocol_statistics():
    """Protocol packet counts computed from stored (REAL) packets.

    Returns a flat {protocol: count} map, e.g.:
        {"TCP": 120, "UDP": 80, "DNS": 30, "ICMP": 10,
         "ARP": 5, "IPv4": 70, "IPv6": 5, "Other": 2}

    Note: "IPv4"/"IPv6" count packets by IP version, so a TCP packet
    over IPv4 appears under both "TCP" and "IPv4" — exactly the keys
    the Protocol Analysis page shows as cards.
    """
    counts = database.protocol_counts()
    for version, count in database.ip_version_counts().items():
        counts[version] = count
    # Largest first — nicer for charts and the UI.
    return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True))


# ------------------------------------------------------------------
# TCP connection analysis (Phase 4)
# ------------------------------------------------------------------
@app.get("/api/tcp/stats")
def tcp_statistics():
    """Handshake + connection-state statistics (sections 4 and 5).

    Example:
        {"summary": {"active": 24, "established": 18, ...},
         "flag_counts": {"syn": 40, "syn_ack": 20, ...}}
    """
    return tcp_tracker.summary()


@app.get("/api/tcp/connections")
def tcp_connections(limit: int = Query(default=100, ge=1, le=500)):
    """Tracked TCP connections, newest activity first (section 5).

    Each row is BIDIRECTIONAL: both packet directions of the same
    conversation appear as one connection.
    """
    rows = tcp_tracker.connection_rows(limit=limit)
    return {"count": len(rows), "connections": rows}


# ------------------------------------------------------------------
# Flow analysis (Phase 4)
# ------------------------------------------------------------------
@app.get("/api/flows/stats")
def flow_statistics():
    """Summary statistics across all network flows (Phase 4 section 16)."""
    return flow_engine.get_stats()


@app.get("/api/flows")
def get_flows(
    limit: int = Query(default=200, ge=1, le=500),
    protocol: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    dst_ip: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    destination_ip: str | None = Query(default=None),
    src_port: int | None = Query(default=None, ge=0, le=65535),
    dst_port: int | None = Query(default=None, ge=0, le=65535),
    source_port: int | None = Query(default=None, ge=0, le=65535),
    destination_port: int | None = Query(default=None, ge=0, le=65535),
    status: str | None = Query(default=None),   # ACTIVE | COMPLETED
):
    """Network flows with metrics (sections 8-13).

    All filters are optional; omitted = no filtering. Summary counts
    are always global so the dashboard cards show the true engine
    state regardless of the active filter. Supports both short (src_ip)
    and long (source_ip) query parameter names.
    """
    effective_src_ip = source_ip or src_ip
    effective_dst_ip = destination_ip or dst_ip
    effective_src_port = source_port if source_port is not None else src_port
    effective_dst_port = destination_port if destination_port is not None else dst_port

    return flow_engine.query(
        limit=limit,
        protocol=protocol,
        src_ip=effective_src_ip,
        dst_ip=effective_dst_ip,
        src_port=effective_src_port,
        dst_port=effective_dst_port,
        status=status,
    )


# ------------------------------------------------------------------
# Network performance (Phase 5)
# ------------------------------------------------------------------
def _performance_payload():
    """Shared body for the performance endpoints.

    Adds the capture state so the UI can show 'Waiting for packet
    data' instead of mistaking an idle engine for zero traffic (§20,
    §26).
    """
    payload = performance_monitor.snapshot()
    payload["capture_running"] = capture_manager.get_status()["running"]
    return payload


@app.get("/api/performance/current")
def performance_current():
    """Live traffic rates + latest RTT/jitter/loss (section 16).

    Every value is a real measurement; unavailable metrics are null.
    Also starts the monitor thread lazily so the first page visit
    activates performance sampling.
    """
    performance_monitor.start()
    return _performance_payload()


@app.get("/api/performance/history")
def performance_history(
    points: int = Query(default=60, ge=1, le=120),
):
    """Recent 1-second traffic buckets for the charts (sections 7, 13).

    Oldest first, at most `points` rows (the rolling window is 120 s).
    """
    from performance import traffic_monitor

    return {"points": traffic_monitor.history_rows(limit=points)}


@app.get("/api/performance/rtt")
def performance_rtt():
    """RTT detail: current/avg/min/max, jitter, PROBE packet loss (§9-11)."""
    performance_monitor.start()
    return rtt_prober.summary()


@app.get("/api/performance/summary")
def performance_summary():
    """One convenient call: live metrics + short traffic history (§16)."""
    performance_monitor.start()
    payload = _performance_payload()
    from performance import traffic_monitor

    payload["history"] = traffic_monitor.history_rows(limit=60)
    return payload


@app.post("/api/performance/target")
def performance_target(target: str = Query(description="Authorized target host or IP")):
    """Point RTT probing at a user-authorized target (section 8).

    Typical use: your default gateway or a local server you own.
    """
    rtt_prober.set_target(target, f"User-selected target ({target})")
    return {"ok": True, "target": target}


# ------------------------------------------------------------------
# Device discovery + topology (Phase 6)
# ------------------------------------------------------------------
@app.get("/api/devices")
def get_devices(limit: int | None = Query(default=None)):
    """All devices observed in captured traffic (sections 2, 17).

    Passive discovery only — a device exists here because its address
    appeared in a real captured packet. Never scanned, never invented.
    Optional `limit` keeps dashboard queries small (Phase 10 §11).
    """
    rows = device_registry.rows()
    if limit is not None and limit > 0:
        rows = rows[:limit]
    return {"count": len(rows), "devices": rows}


@app.get("/api/devices/stats")
def device_statistics():
    """Device summary for the dashboard (section 23)."""
    return device_registry.stats()


@app.get("/api/devices/{device_id}")
def device_details(device_id: str):
    """One device's full details (section 8). 404 when never observed."""
    row = device_registry.get(device_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Device not found (not observed in captured traffic)")
    return row


@app.get("/api/topology")
def network_topology():
    """Cytoscape.js-ready topology from REAL devices + flows (§9-12, §18)."""
    return build_topology(device_registry)


# ------------------------------------------------------------------
# Routing & path analysis (Phase 7)
# ------------------------------------------------------------------
# NOTE: these endpoints run short OS commands (ipconfig / route print /
# tracert) via subprocess in ARGUMENT-LIST form — never shell strings —
# so the frontend can never inject commands (Phase 7 sections 6+14).
# Packet capture keeps running in its own thread meanwhile (§12).
@app.get("/api/routing/interfaces")
def routing_interfaces():
    """Real network interfaces from the OS (section 2)."""
    return get_interfaces()


@app.get("/api/routing/gateway")
def routing_gateway():
    """Default gateway CONFIRMED from the routing table (section 3)."""
    return get_gateway()


@app.get("/api/routing/table")
def routing_table():
    """The OS routing table, real entries only (section 4)."""
    return get_routing_table()


@app.get("/api/routing/traceroute")
def routing_traceroute(target: str = Query(description="Authorized destination host or IP")):
    """Hop-by-hop path to an authorized destination (sections 6-7).

    Runs `tracert` (Windows) / `traceroute` (Linux) with a hard
    timeout — this request blocks its own worker for up to ~90 s but
    NEVER the capture thread (section 12).
    """
    result, status = run_traceroute(target)
    if status != 200:
        raise HTTPException(status_code=status, detail=result.get("error", "Traceroute failed"))
    return result


# ------------------------------------------------------------------
# Machine learning (Phase 8)
# ------------------------------------------------------------------
# The ML layer sits ON TOP of the network phases: it never touches
# raw packets, only Phase 4 flow metrics. Missing models are fine —
# every endpoint reports availability honestly instead of failing.
@app.get("/api/ml/status")
def ml_status():
    """Are the trained models available? (section 16)

    Also carries REAL recent-observation counts (section 22) from the
    ml_predictions table — zeros mean genuinely nothing analyzed yet.
    """
    payload = ml_service.status()
    payload["recent_observations"] = database.ml_prediction_counts()
    return payload


@app.get("/api/ml/features")
def ml_features():
    """Feature list + which of them live flows can provide (§14, §15)."""
    config = ml_service.info()
    sample_live = {
        "Flow_Duration": True, "Pkt_Count_Fwd": True, "Pkt_Count_Bwd": True,
        "Byte_Rate": True, "Pkt_Rate": True,
        "IAT_Mean": True, "IAT_Std": True,
        "SYN_Ratio": True, "RST_Ratio": True, "Avg_Pkt_Size": True,
    }
    return {
        "features": config["features"],
        "feature_count": config["feature_count"],
        "available_from_live_traffic": sample_live,
        "notes": [
            "All 10 features are produced by the Phase 4 flow engine.",
            "Durations and IATs are converted to microseconds (CICIDS2017 units).",
            "IP addresses, ports and timestamps are NEVER ML features (§5).",
        ],
    }


@app.get("/api/ml/model-info")
def ml_model_info():
    """Model metadata + persisted REAL training metrics (§17, §27)."""
    info = ml_service.info()
    info["feature_importance"] = ml_service.importance()
    return info


@app.post("/api/ml/analyze")
def ml_analyze(flow_features: dict):
    """Analyze one flow's behavioral features (§15, §18).

    Accepts either the raw API field names (flow_duration, ...) or
    canonical ML names (Flow_Duration, ...). Only known behavioral
    features are read — arbitrary model parameters are ignored.
    """
    if not isinstance(flow_features, dict):
        raise HTTPException(status_code=422, detail="Expected a JSON object of flow features")

    # Normalize snake_case API names onto the canonical feature names.
    normalized = dict(flow_features)
    aliases = {
        "flow_duration": "Flow_Duration", "pkt_count_fwd": "Pkt_Count_Fwd",
        "pkt_count_bwd": "Pkt_Count_Bwd", "byte_rate": "Byte_Rate",
        "pkt_rate": "Pkt_Rate", "iat_mean": "IAT_Mean", "iat_std": "IAT_Std",
        "syn_ratio": "SYN_Ratio", "rst_ratio": "RST_Ratio",
        "avg_pkt_size": "Avg_Pkt_Size",
    }
    for api_name, canonical in aliases.items():
        if api_name in normalized:
            normalized[canonical] = normalized.pop(api_name)

    # Convenience: accept seconds/ms here too (same units as the UI).
    if "Flow_Duration" in normalized:
        try:
            normalized["Flow_Duration"] = float(normalized["Flow_Duration"]) * 1_000_000.0
        except Exception:
            pass
    for ms_field, us_field in (("iat_mean", "IAT_Mean"), ("iat_std", "IAT_Std")):
        if ms_field in flow_features:
            try:
                normalized[us_field] = float(flow_features[ms_field]) * 1000.0
            except Exception:
                pass

    features = normalized
    if not features_available(features):
        return {
            "classification": {"label": None, "confidence": None, "available": False},
            "anomaly": {"status": None, "score": None, "available": False},
            "skipped": "One or more required features are unavailable.",
        }
    return analyze_flow(features)


# ------------------------------------------------------------------
# Intelligent alerts (Phase 9)
# ------------------------------------------------------------------
# Alerts come ONLY from real observed metrics (Phase 5 traffic, Phase 4
# TCP flags, Phase 8 ML results) crossing CONFIGURABLE thresholds. The
# background evaluator in alerts.py runs every 10 s as a daemon — it
# never touches the packet-capture thread (section 12).
@app.get("/api/alerts")
def alerts_list(
    limit: int = 100,
    status: str | None = Query(default=None),
    category: str | None = Query(default=None),
    source: str | None = Query(default=None),
):
    """Filtered alert list, newest first."""
    return {
        "alerts": alert_manager.query(
            limit=limit, status=status, category=category, source=source
        )
    }


@app.get("/api/alerts/stats")
def alerts_stats():
    """Counts by status/category/severity — only REAL alerts."""
    return alert_manager.stats()


@app.get("/api/alerts/thresholds")
def alerts_thresholds_get():
    """Current configurable thresholds (section 2-6 defaults)."""
    return alert_manager.get_thresholds()


class AlertThresholds(BaseModel):
    high_traffic_bytes_per_second: float | None = None
    high_packet_rate_packets_per_second: float | None = None
    high_syn_ratio: float | None = None
    high_rst_ratio: float | None = None
    incomplete_connections: float | None = None
    cooldown_seconds: float | None = None


class AlertStatusUpdate(BaseModel):
    status: str


@app.post("/api/alerts/thresholds")
def alerts_thresholds_post(body: AlertThresholds):
    """Update thresholds at runtime; unknown/invalid values are ignored."""
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No valid thresholds provided.")
    return alert_manager.set_thresholds(updates)


@app.post("/api/alerts/{alert_id}/status")
def alerts_set_status(alert_id: int, body: AlertStatusUpdate):
    """Acknowledge or resolve one alert (management, section 1)."""
    updated = alert_manager.set_status(alert_id, body.status)
    if updated is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found (or status must be ACTIVE/ACKNOWLEDGED/RESOLVED).",
        )
    return updated


@app.post("/api/alerts/evaluate")
def alerts_evaluate():
    """Force ONE evaluation cycle now (also used by the UI's Check now)."""
    produced = alert_manager.evaluate_now()
    return {"evaluated": True, "new_alerts": len(produced)}



# ----------------------------------------------------------------------
# Direct execution (Phase 10 section 22): `python main.py` starts the
# API with the centrally configured host/port (config.py), falling
# back to the historical 127.0.0.1:8001.
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.API_HOST, port=config.API_PORT)
