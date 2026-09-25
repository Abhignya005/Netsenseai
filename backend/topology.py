"""
topology.py — PHASE 6: network topology builder

WHAT THIS FILE DOES
-------------------
Turns the observed devices (devices.py) and the Phase 4 flows
(flow_analysis.py) into a Cytoscape.js-ready {nodes, edges} structure.

Everything is REAL:
    * a NODE exists because one of its addresses appeared in a
      captured packet (section 10 — no invented devices),
    * an EDGE exists because a real Phase 4 flow was observed between
      two nodes (section 11 — no fake edges).

EDGE MERGING
------------
The Phase 4 flow engine keeps one flow per 5-tuple segment. For the
topology all flows between the same pair of devices are MERGED into a
single edge carrying the summed packets/bytes, the protocol set and
the latest last-seen time.

Special nodes:
    * Gateway  — flagged only when the gateway IP is CONFIRMED from
      the system routing table (section 13 — never guessed),
    * Local Device — this machine's own addresses (section 14).
"""

import time

from flow_analysis import flow_engine as _global_flow_engine


def build_topology(registry, flow_engine=None, limit=200):
    """Return {nodes, edges, generated_at} for the topology view.

    flow_engine defaults to the global Phase 4 engine; tests may pass
    a fresh FlowEngine instance instead.
    """
    if flow_engine is None:
        flow_engine = _global_flow_engine
    now = time.time()

    with registry.lock:
        device_list = list(registry.devices.values())

    # ---- node id mapping: IP -> canonical device key -----------------
    node_by_ip = {}
    for device in device_list:
        for ip in device.ips:
            node_by_ip[ip] = device.key

    # ---- nodes (sections 10 + 13 + 14) -------------------------------
    nodes = []
    for device in device_list:
        ip = device.primary_ip
        if device.hostname:
            label = device.hostname
        elif device.is_gateway:
            label = "Gateway"
        elif device.is_local:
            label = "Local Device"
        elif ip:
            label = ip
        elif device.primary_mac:
            label = device.primary_mac
        else:
            label = "Unknown Device"
        nodes.append({
            "data": {
                "id": device.key,
                "label": label,
                "ip": ip or "Unknown",
                "mac": device.primary_mac or "Unknown",
                "hostname": device.hostname or "Unknown",
                "is_gateway": device.is_gateway,
                "is_local": device.is_local,
                "packet_count": device.packet_count,
                "bytes": device.bytes_total,
                "protocols": sorted(device.protocols),
                "last_seen": device.last_seen,
            },
        })

    nodes.sort(key=lambda n: n["data"]["packet_count"], reverse=True)
    nodes = nodes[:limit]
    kept_ids = {node["data"]["id"] for node in nodes}

    # ---- edges from REAL Phase 4 flows (sections 9-11) ----------------
    merged = {}
    try:
        flows = flow_engine.query(limit=500).get("flows", [])
    except Exception:
        flows = []   # flow engine trouble must never break the topology

    for flow in flows:
        source_key = node_by_ip.get(flow.get("source_ip"))
        target_key = node_by_ip.get(flow.get("destination_ip"))
        if not source_key or not target_key or source_key == target_key:
            continue   # both ends must be OBSERVED devices
        pair = tuple(sorted((source_key, target_key)))
        edge = merged.setdefault(
            pair,
            {
                "source": pair[0],
                "target": pair[1],
                "protocols": set(),
                "packets": 0,
                "bytes": 0,
                "last_seen": 0.0,
            },
        )
        edge["packets"] += int(flow.get("total_packets") or 0)
        edge["bytes"] += int(flow.get("total_bytes") or 0)
        edge["protocols"].add(flow.get("protocol") or "Other")
        try:
            edge["last_seen"] = max(edge["last_seen"], float(flow.get("last_seen") or flow.get("end_time") or 0))
        except Exception:
            pass

    edges = [
        {"data": {**row, "protocols": sorted(row["protocols"])}}
        for row in merged.values()
        if row["source"] in kept_ids and row["target"] in kept_ids
    ]
    edges.sort(key=lambda e: e["data"]["bytes"], reverse=True)

    return {"nodes": nodes, "edges": edges[:300], "generated_at": now}
