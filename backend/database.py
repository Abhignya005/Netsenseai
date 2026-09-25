"""
database.py — NetSense SQLite database (STAGES 1–3)

Stage 1 created empty tables. Stage 2 added src_port/dst_port.
Stage 3 (protocol analysis) adds the fields the analyzer needs:
    src_mac, dst_mac, ip_version, ttl, tcp_flags, tcp_seq, tcp_ack,
    icmp_type, icmp_code, arp_operation, dns_query, dns_qr, dns_qtype
plus two small stats helpers (protocol_counts / ip_version_counts)
powering GET /api/protocols.

If you still have an older netsense.db, the _migrate() function
upgrades it in place — existing packet records are NEVER deleted.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# How many rows we keep in the packets table. Old rows are deleted so
# the file stays small. (Stage 2 is about RECENT traffic, not archives.)
MAX_PACKET_ROWS = 5000

# PHASE 10: DB path is centrally configured (config.py). Falls back to
# the historical backend/netsense.db location when config is absent.
try:
    from config import DB_PATH as _CONFIG_DB_PATH

    DB_PATH = Path(_CONFIG_DB_PATH)
except Exception:
    DB_PATH = Path(__file__).resolve().parent / "netsense.db"


def get_connection():
    """Open a connection to the SQLite database.

    row_factory = sqlite3.Row lets us access columns by name,
    e.g. row["ip_address"] instead of row[1].
    """
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    # PHASE 10: WAL journal mode — readers (API queries) no longer
    # block writers (capture/ML/alert writers) and vice versa. Falls
    # back silently to the default journal on unusual filesystems.
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
    except sqlite3.Error:
        pass
    return connection


def init_db():
    """Create the tables once, when the FastAPI server starts."""
    connection = get_connection()
    cursor = connection.cursor()

    cursor.executescript(
        """
        -- Devices seen on the network (filled in a later stage)
        CREATE TABLE IF NOT EXISTS devices (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address   TEXT NOT NULL,
            mac_address  TEXT,
            hostname     TEXT,
            device_type  TEXT,
            first_seen   TEXT,
            last_seen    TEXT
        );

        -- Captured packet METADATA (Stage 3 fills this)
        CREATE TABLE IF NOT EXISTS packets (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT,
            source_ip      TEXT,
            destination_ip TEXT,
            protocol       TEXT,
            src_port       INTEGER,
            dst_port       INTEGER,
            length         INTEGER,
            -- Stage 3 protocol-analysis fields
            src_mac        TEXT,
            dst_mac        TEXT,
            ip_version     INTEGER,
            ttl            INTEGER,
            tcp_flags      TEXT,
            tcp_seq        INTEGER,
            tcp_ack        INTEGER,
            icmp_type      INTEGER,
            icmp_code      INTEGER,
            arp_operation  TEXT,
            dns_query      TEXT,
            dns_qr         TEXT,
            dns_qtype      TEXT
        );

        -- Alerts raised by the system (filled in a later stage)
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            severity  TEXT,
            message   TEXT
        );

        -- Network Flows (Phase 4 section 15)
        CREATE TABLE IF NOT EXISTS flows (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip         TEXT,
            dst_ip         TEXT,
            src_port       INTEGER,
            dst_port       INTEGER,
            protocol       TEXT,
            start_time     REAL,
            end_time       REAL,
            duration       REAL,
            fwd_packets    INTEGER,
            bwd_packets    INTEGER,
            fwd_bytes      INTEGER,
            bwd_bytes      INTEGER,
            total_packets  INTEGER,
            total_bytes    INTEGER,
            packet_rate    REAL,
            byte_rate      REAL,
            status         TEXT
        );

        -- Performance snapshots (Phase 5 section 18) — ONE row per
        -- minute at most, so the file stays small.
        CREATE TABLE IF NOT EXISTS performance_metrics (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp            TEXT,
            bytes_per_second     REAL,
            bits_per_second      REAL,
            packets_per_second   REAL,
            average_packet_size  REAL,
            rtt_ms               REAL,
            jitter_ms            REAL,
            packet_loss_percent  REAL
        );

        -- ML predictions (Phase 8 section 24) — flow-level results
        -- only; no packet payloads, no IP identifiers beyond the
        -- opaque flow signature.
        CREATE TABLE IF NOT EXISTS ml_predictions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id         TEXT,
            timestamp       TEXT,
            predicted_class TEXT,
            confidence      REAL,
            anomaly_score   REAL,
            anomaly_status  TEXT,
            model_version   TEXT
        );

        -- Alerts (Phase 9) — generated ONLY from real observed metrics,
        -- configured thresholds, or real ML results. `observed` holds a
        -- small JSON blob of the measurement that fired the alert;
        -- payloads and raw packet data are never stored.
        CREATE TABLE IF NOT EXISTS alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            category   TEXT,
            source     TEXT,
            severity   TEXT,
            title      TEXT,
            message    TEXT,
            observed   TEXT,
            threshold  REAL,
            status     TEXT
        );
        """
    )

    _migrate(cursor)  # upgrade old databases if needed
    _migrate_devices(cursor)  # Phase 6: devices table upgrades
    _migrate_alerts(cursor)  # Phase 9: full alert schema

    connection.commit()
    connection.close()
    print(f"[NetSense] SQLite database ready at: {DB_PATH}")


def _migrate_alerts(cursor):
    """Phase 9: upgrade the old Stage-1 placeholder alerts table.

    Stage 1 created (id, timestamp, severity, message) and never wrote
    to it, so CREATE TABLE IF NOT EXISTS kept the stale schema. If the
    full Phase 9 columns are missing, rebuild the table in place (the
    old table held no data worth keeping).
    """
    cursor.execute("PRAGMA table_info(alerts)")
    columns = {row[1] for row in cursor.fetchall()}
    required = {
        "created_at", "category", "source", "severity",
        "title", "message", "observed", "threshold", "status",
    }
    if required.issubset(columns):
        return
    cursor.execute("DROP TABLE IF EXISTS alerts")
    cursor.execute(
        """
        CREATE TABLE alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            category   TEXT,
            source     TEXT,
            severity   TEXT,
            title      TEXT,
            message    TEXT,
            observed   TEXT,
            threshold  REAL,
            status     TEXT
        )
        """
    )
    print("[NetSense] Migrated alerts table to the Phase 9 schema")


# Every column the `packets` table may be missing, in the order they
# were introduced. Older database files are upgraded in place.
PACKET_COLUMNS = [
    # Stage 2
    ("src_port", "INTEGER"),
    ("dst_port", "INTEGER"),
    # Stage 3
    ("src_mac", "TEXT"),
    ("dst_mac", "TEXT"),
    ("ip_version", "INTEGER"),
    ("ttl", "INTEGER"),
    ("tcp_flags", "TEXT"),
    ("tcp_seq", "INTEGER"),
    ("tcp_ack", "INTEGER"),
    ("icmp_type", "INTEGER"),
    ("icmp_code", "INTEGER"),
    ("arp_operation", "TEXT"),
    ("dns_query", "TEXT"),
    ("dns_qr", "TEXT"),
    ("dns_qtype", "TEXT"),
]


def _migrate(cursor):
    """Add any missing columns to an existing `packets` table.

    `PRAGMA table_info` returns the current column list; each missing
    column is added with ALTER TABLE. This never deletes rows — your
    Stage 1/2 packet records are kept.
    """
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(packets)")}
    for name, declaration in PACKET_COLUMNS:
        if name not in columns:
            cursor.execute(f"ALTER TABLE packets ADD COLUMN {name} {declaration}")
            print(f"[NetSense] Migrated packets table: added {name}")


def insert_packet(packet):
    """Store one packet's METADATA (never payload). Called by capture.py.

    Uses .get() for every field so a partially-extracted record can
    never crash the insert — missing fields are simply stored as NULL.
    """
    connection = get_connection()
    connection.execute(
        """
        INSERT INTO packets (
            timestamp, source_ip, destination_ip, protocol,
            src_port, dst_port, length,
            src_mac, dst_mac, ip_version, ttl, tcp_flags, tcp_seq, tcp_ack,
            icmp_type, icmp_code, arp_operation,
            dns_query, dns_qr, dns_qtype
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.fromtimestamp(packet["timestamp"], tz=timezone.utc).isoformat(),
            packet.get("source_ip"),
            packet.get("destination_ip"),
            packet.get("protocol"),
            packet.get("source_port"),
            packet.get("destination_port"),
            packet.get("size"),
            packet.get("source_mac"),
            packet.get("destination_mac"),
            packet.get("ip_version"),
            packet.get("ttl"),
            packet.get("tcp_flags"),
            packet.get("tcp_seq"),
            packet.get("tcp_ack"),
            packet.get("icmp_type"),
            packet.get("icmp_code"),
            packet.get("arp_operation"),
            packet.get("dns_query"),
            packet.get("dns_qr"),
            packet.get("dns_qtype"),
        ),
    )
    connection.commit()
    connection.close()


def protocol_counts():
    """Stage 3: {protocol_name: count} for every stored packet."""
    connection = get_connection()
    rows = connection.execute(
        "SELECT protocol, COUNT(*) AS n FROM packets "
        "GROUP BY protocol ORDER BY n DESC"
    ).fetchall()
    connection.close()
    return {(row["protocol"] or "Other"): row["n"] for row in rows}


def ip_version_counts():
    """Stage 3: {'IPv4': n, 'IPv6': m} (packets that have an IP layer)."""
    connection = get_connection()
    rows = connection.execute(
        "SELECT ip_version, COUNT(*) AS n FROM packets "
        "WHERE ip_version IS NOT NULL GROUP BY ip_version"
    ).fetchall()
    connection.close()
    return {("IPv4" if row["ip_version"] == 4 else "IPv6"): row["n"] for row in rows}


def packet_count():
    """How many rows are currently in the packets table."""
    connection = get_connection()
    (count,) = connection.execute("SELECT COUNT(*) FROM packets").fetchone()
    connection.close()
    return count


def trim_packets():
    """Delete old rows, keeping only the newest MAX_PACKET_ROWS.

    Returns how many rows were deleted.
    """
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        DELETE FROM packets
        WHERE id NOT IN (
            SELECT id FROM packets ORDER BY id DESC LIMIT ?
        )
        """,
        (MAX_PACKET_ROWS,),
    )
    deleted = cursor.rowcount
    connection.commit()
    connection.close()
    return deleted


# ------------------------------------------------------------------
# Network flow persistence (Phase 4 section 15)
# ------------------------------------------------------------------
def insert_flow(flow):
    """Store one flow record's metrics into the SQLite flows table.

    Uses .get() with fallbacks so partial records never raise.
    """
    try:
        connection = get_connection()
        connection.execute(
            """
            INSERT INTO flows (
                src_ip, dst_ip, src_port, dst_port, protocol,
                start_time, end_time, duration,
                fwd_packets, bwd_packets, fwd_bytes, bwd_bytes,
                total_packets, total_bytes, packet_rate, byte_rate,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                flow.get("source_ip") or flow.get("src_ip"),
                flow.get("destination_ip") or flow.get("dst_ip"),
                int(flow.get("source_port") or flow.get("src_port") or 0),
                int(flow.get("destination_port") or flow.get("dst_port") or 0),
                flow.get("protocol"),
                flow.get("start_time"),
                flow.get("end_time"),
                flow.get("duration"),
                int(flow.get("forward_packets") or flow.get("fwd_packets") or 0),
                int(flow.get("backward_packets") or flow.get("bwd_packets") or 0),
                int(flow.get("forward_bytes") or flow.get("fwd_bytes") or 0),
                int(flow.get("backward_bytes") or flow.get("bwd_bytes") or 0),
                int(flow.get("total_packets") or 0),
                int(flow.get("total_bytes") or 0),
                float(flow.get("packet_rate") or 0.0),
                float(flow.get("byte_rate") or 0.0),
                flow.get("status"),
            ),
        )
        connection.commit()
        connection.close()
    except Exception:
        pass


def flow_count():
    """How many rows are currently in the flows table."""
    try:
        connection = get_connection()
        (count,) = connection.execute("SELECT COUNT(*) FROM flows").fetchone()
        connection.close()
        return count
    except Exception:
        return 0


# ------------------------------------------------------------------
# Performance history persistence (Phase 5 section 18)
# ------------------------------------------------------------------
# Keep the performance table small: newest MAX_PERFORMANCE_ROWS rows.
MAX_PERFORMANCE_ROWS = 10080   # ~1 week of one-row-per-minute


def insert_performance_metric(snapshot):
    """Store ONE per-minute performance row (Phase 5).

    Called from performance.py's background thread — never per packet.
    All values may be None (unavailable) — that is stored as NULL.
    """
    traffic = snapshot.get("traffic") or {}
    rtt = snapshot.get("rtt") or {}
    connection = get_connection()
    connection.execute(
        """
        INSERT INTO performance_metrics (
            timestamp, bytes_per_second, bits_per_second,
            packets_per_second, average_packet_size,
            rtt_ms, jitter_ms, packet_loss_percent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            traffic.get("bytes_per_second"),
            traffic.get("bits_per_second"),
            traffic.get("packets_per_second"),
            traffic.get("average_packet_size"),
            rtt.get("rtt_ms"),
            rtt.get("jitter_ms"),
            rtt.get("packet_loss_percent"),
        ),
    )
    connection.commit()
    connection.close()


def trim_performance_metrics():
    """Keep only the newest MAX_PERFORMANCE_ROWS performance rows."""
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            DELETE FROM performance_metrics
            WHERE id NOT IN (
                SELECT id FROM performance_metrics ORDER BY id DESC LIMIT ?
            )
            """,
            (MAX_PERFORMANCE_ROWS,),
        )
        connection.commit()
        connection.close()
    except Exception:
        pass


# ------------------------------------------------------------------
# ML prediction storage (Phase 8 section 24)
# ------------------------------------------------------------------
def insert_ml_prediction(prediction):
    """Store ONE flow-level ML result (Phase 8). Best-effort write:
    database trouble must never stop the ML worker."""
    try:
        connection = get_connection()
        connection.execute(
            """
            INSERT INTO ml_predictions (
                flow_id, timestamp, predicted_class, confidence,
                anomaly_score, anomaly_status, model_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                prediction.get("flow_id"),
                datetime.now(timezone.utc).isoformat(),
                prediction.get("predicted_class"),
                prediction.get("confidence"),
                prediction.get("anomaly_score"),
                prediction.get("anomaly_status"),
                prediction.get("model_version"),
            ),
        )
        connection.commit()
        connection.close()
    except Exception:
        pass


def trim_ml_predictions(keep=2000):
    """Keep only the newest `keep` ML prediction rows."""
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            DELETE FROM ml_predictions
            WHERE id NOT IN (
                SELECT id FROM ml_predictions ORDER BY id DESC LIMIT ?
            )
            """,
            (keep,),
        )
        connection.commit()
        connection.close()
    except Exception:
        pass


def latest_ml_anomaly():
    """Most recent "potentially anomalous" ML result, or None.

    Gives the alert engine a REAL score to attach to ML alerts.
    """
    try:
        connection = get_connection()
        row = connection.execute(
            "SELECT anomaly_score, timestamp FROM ml_predictions "
            "WHERE anomaly_status = 'potentially anomalous' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        connection.close()
        if row is None:
            return None
        return {"score": row[0], "timestamp": row[1]}
    except Exception:
        return None


def latest_ml_classification():
    """Newest classification result + the dominant recent class.

    Feeds the Phase 10 classification alert: the label itself is REAL
    (never invented) and the dominant class is computed from actual
    stored predictions, not hardcoded.
    """
    try:
        connection = get_connection()
        row = connection.execute(
            "SELECT predicted_class, confidence, timestamp FROM ml_predictions "
            "WHERE predicted_class IS NOT NULL "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        dominant = connection.execute(
            "SELECT predicted_class, COUNT(*) AS n FROM ml_predictions "
            "WHERE predicted_class IS NOT NULL "
            "GROUP BY predicted_class ORDER BY n DESC LIMIT 1"
        ).fetchone()
        connection.close()
        if row is None:
            return None
        return {
            "label": row[0],
            "confidence": row[1],
            "timestamp": row[2],
            "dominant_class": dominant[0] if dominant else None,
        }
    except Exception:
        return None


def ml_prediction_counts():
    """Dashboard summary: normal vs potentially-anomalous counts (§22)."""
    try:
        connection = get_connection()
        rows = connection.execute(
            "SELECT anomaly_status, COUNT(*) FROM ml_predictions "
            "GROUP BY anomaly_status"
        ).fetchall()
        connection.close()
        counts = {(row[0] or "unknown"): row[1] for row in rows}
        return {
            "normal": counts.get("normal", 0),
            "potentially_anomalous": counts.get("potentially anomalous", 0),
            "total": sum(counts.values()),
        }
    except Exception:
        return {"normal": 0, "potentially_anomalous": 0, "total": 0}


# ------------------------------------------------------------------
# Alert storage (Phase 9)
# ------------------------------------------------------------------
# Best-effort writes like every other helper: database trouble must
# never stop packet capture, ML analysis, or the alert engine itself.
def insert_alert(alert):
    """Store ONE alert; returns the new row id (or None on failure)."""
    try:
        connection = get_connection()
        cursor = connection.execute(
            """
            INSERT INTO alerts (
                created_at, category, source, severity,
                title, message, observed, threshold, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.get("created_at"),
                alert.get("category"),
                alert.get("source"),
                alert.get("severity"),
                alert.get("title"),
                alert.get("message"),
                json.dumps(alert.get("observed")),
                alert.get("threshold"),
                alert.get("status", "active"),
            ),
        )
        connection.commit()
        row_id = cursor.lastrowid
        connection.close()
        return row_id
    except Exception:
        return None


def update_alert_status(alert_id, status):
    """Acknowledge/resolve one alert by id."""
    try:
        connection = get_connection()
        connection.execute(
            "UPDATE alerts SET status = ? WHERE id = ?",
            (status, alert_id),
        )
        connection.commit()
        connection.close()
        return True
    except Exception:
        return False


def load_recent_alerts(limit=200):
    """Newest alerts from SQLite (used to restore history on startup)."""
    try:
        connection = get_connection()
        rows = connection.execute(
            "SELECT id, created_at, category, source, severity, title, "
            "message, observed, threshold, status FROM alerts "
            "ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        connection.close()
        alerts = []
        for row in rows:
            try:
                observed = json.loads(row[7]) if row[7] else None
            except Exception:
                observed = None
            alerts.append({
                "id": row[0], "created_at": row[1], "category": row[2],
                "source": row[3], "severity": row[4], "title": row[5],
                "message": row[6], "observed": observed,
                "threshold": row[8], "status": row[9],
            })
        return alerts
    except Exception:
        return []


def trim_alerts(keep=500):
    """Keep only the newest `keep` alert rows."""
    try:
        connection = get_connection()
        connection.execute(
            """
            DELETE FROM alerts
            WHERE id NOT IN (
                SELECT id FROM alerts ORDER BY id DESC LIMIT ?
            )
            """,
            (int(keep),),
        )
        connection.commit()
        connection.close()
    except Exception:
        pass


# ------------------------------------------------------------------
# Device persistence (Phase 6 section 19)
# ------------------------------------------------------------------
# The devices table already exists since Stage 1 (id, ip_address,
# mac_address, hostname, device_type, first_seen, last_seen). Phase 6
# adds the aggregate columns below to older databases in place.
DEVICE_COLUMNS = [
    ("packet_count", "INTEGER"),
    ("total_bytes", "INTEGER"),
    ("protocols", "TEXT"),
    ("is_gateway", "INTEGER"),
    ("is_local", "INTEGER"),
]


def _migrate_devices(cursor):
    """Add any missing Phase 6 columns to the existing devices table."""
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(devices)")}
    for name, declaration in DEVICE_COLUMNS:
        if name not in columns:
            cursor.execute(f"ALTER TABLE devices ADD COLUMN {name} {declaration}")
            print(f"[NetSense] Migrated devices table: added {name}")


def upsert_device(device):
    """Store/update ONE device row (Phase 6 section 19).

    Called by devices.py once a minute — never per packet. The device
    is keyed by its canonical id (the MAC, or the IP if no MAC), so a
    machine seen 1000 times stays ONE row (section 21).
    """
    try:
        row = device.to_row()
        connection = get_connection()
        existing = connection.execute(
            "SELECT id FROM devices WHERE ip_address = ?", (row["ip"] or row["id"],)
        ).fetchone()
        values = (
            row["ip"] or row["id"],
            row["mac"],
            row["hostname"],
            "Gateway" if row["is_gateway"] else ("Local" if row["is_local"] else None),
            datetime.fromtimestamp(row["first_seen"], tz=timezone.utc).isoformat(),
            datetime.fromtimestamp(row["last_seen"], tz=timezone.utc).isoformat(),
            row["packet_count"],
            row["bytes"],
            ",".join(row["protocols"]),
            1 if row["is_gateway"] else 0,
            1 if row["is_local"] else 0,
        )
        if existing:
            connection.execute(
                """
                UPDATE devices SET mac_address=?, hostname=?, device_type=?,
                    first_seen=?, last_seen=?, packet_count=?, total_bytes=?,
                    protocols=?, is_gateway=?, is_local=?
                WHERE ip_address=?
                """,
                values[1:] + (values[0],),
            )
        else:
            connection.execute(
                """
                INSERT INTO devices (
                    ip_address, mac_address, hostname, device_type,
                    first_seen, last_seen, packet_count, total_bytes,
                    protocols, is_gateway, is_local
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
        connection.commit()
        connection.close()
    except Exception:
        pass   # database trouble must never stop device discovery

