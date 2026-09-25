# NetSense — Demo Presentation Script

A ~5-minute walkthrough that tells one continuous story:
**raw packets → understanding → intelligence → action.**

---

## The 30-second pitch (say this first)

> "Modern networks generate traffic nobody can manually watch. NetSense
> captures that traffic on an authorized machine, turns raw packets into
> understandable network information — protocols, connections, flows,
> performance, devices, routing — then applies Machine Learning to flow
> behavior and raises careful alerts. It's a passive monitor: it never
> stores payload content and never scans the network."

## Before the demo (one-time setup)

```text
1. Install Npcap (npcap.com, tick "WinPcap API-compatible Mode")
2. Backend terminal AS ADMINISTRATOR:
       cd netsense/backend && venv\Scripts\activate
       uvicorn main:app --port 8001
3. Frontend terminal:
       cd netsense/frontend && npm run dev   →  http://localhost:5173
4. Generate some traffic: open a few websites, run: ping google.com
```

## The walkthrough (14 steps, ~5 minutes)

| # | Where | What to say / show |
| --- | --- | --- |
| 1 | **Dashboard** `/dashboard` | "The command center — every number is real, measured from captured packets." |
| 2 | **Live Packets** `/live-packets` | Select your Wi-Fi adapter → **Start Capture**. "Metadata only: IPs, ports, flags — never content." |
| 3 | Generate traffic | `ping google.com`, refresh a website. Watch rows appear live. |
| 4 | **Protocol Analysis** | "Every layer decoded — Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP, DNS — with real per-packet fields." |
| 5 | **TCP Analysis** | "Passive TCP state tracking: handshakes, ESTABLISHED / CLOSED / RESET, honest PARTIAL when we join mid-connection." |
| 6 | **Flow Analysis** | "Bidirectional 5-tuple flows with forward/backward counts, rates, and 15 s / 120 s timeouts." |
| 7 | **Performance** | "1-second traffic buckets, and live RTT to the default gateway — currently ~2 ms — with jitter and probe loss." |
| 8 | **Devices & Topology** | "Devices discovered passively from traffic — the graph is real conversations, not a scanned map." |
| 9 | **Routing** | "Straight from the OS: interfaces, the confirmed gateway, the routing table." |
| 10 | **Run a Traceroute** | Type `8.8.8.8` → Run. "Hop-by-hop with real RTTs; timeouts shown honestly." |
| 11 | **ML Analysis** | "Random Forest classifies flows; Isolation Forest scores anomalies. Trained, with real metrics and feature importance." |
| 12 | Demo ML live | On the ML page, analyze a flow — show predicted class + confidence. |
| 13 | **Alerts** | "Rules (traffic, packet rate, SYN/RST, incomplete connections) plus ML results. Thresholds are editable; alerts can be acknowledged and resolved. An alert is a signal — never claimed to be an attack." |
| 14 | **Dashboard** again | "Back where we started — now every card is populated by the story you just watched." |

## Closing line

> "That's the full pipeline: capture → understand → learn → alert —
> all local, all metadata-only, all real measurements."

## Likely questions & answers

* **"Is that attack traffic real?"** — No. Alerts say *potentially anomalous*;
  ML classes come from the (clearly labeled sample) CICIDS2017-schema dataset.
  Swap in the real dataset and retrain for production behavior.
* **"Can it see passwords?"** — No, by design: payloads are never read or stored.
* **"Does it scan the network?"** — Never. Devices exist only because their
  packets passed the capture point; traceroute runs only to a destination you type.
* **"What if packets are missed?"** — It says so: PARTIAL / INCOMPLETE states,
  "Unavailable" metrics. It never invents numbers.
* **"Where do the models come from?"** — `python ml/train_classifier.py` and
  `python ml/train_anomaly.py` (demo data is pre-generated and clearly labeled).

## One-slide summary (if needed)

* **Problem:** traffic is invisible; manual monitoring doesn't scale.
* **Solution:** NetSense — packets → protocols → connections → flows →
  performance → devices → routing → ML → alerts, in one dashboard.
* **CN component:** Ethernet→DNS analysis, TCP state machine, 5-tuple flows,
  rates/RTT/jitter, topology, routing/traceroute.
* **ML component:** 10 behavioral flow features → Random Forest +
  Isolation Forest, with leakage-safe feature selection.
* **Alert component:** network rules + performance + ML, with cooldowns and
  human-managed lifecycle (OPEN → ACKNOWLEDGED → RESOLVED).
