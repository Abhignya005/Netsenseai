"""
config.py — PHASE 10: central configuration

WHY THIS EXISTS (section 22)
----------------------------
NetSense keeps its tunables close to the modules that use them (flow
timeouts live in flow_analysis.py, alert thresholds in alerts.py, ML
paths in ml/inference.py). This module is the single place that
DOCUMENTS every knob and lets the important ones be overridden with
environment variables — without any code change:

    set NETSENSE_DB_PATH=D:/data/netsense.db
    set NETSENSE_API_PORT=8002

Defaults are unchanged: a fresh checkout behaves exactly like before.
No secrets belong here — see .env.example for the (empty) template.
"""

import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BACKEND_DIR.parent
ML_DIR = PROJECT_DIR / "ml"


def _env(name, default):
    """Read an environment variable, falling back to the default."""
    value = os.environ.get(name)
    return value if value not in (None, "") else default


# ----------------------------------------------------------------------
# Database (section 22)
# ----------------------------------------------------------------------
# The SQLite file lives next to the backend by default.
DB_PATH = Path(_env("NETSENSE_DB_PATH", str(BACKEND_DIR / "netsense.db")))

# ----------------------------------------------------------------------
# API server (section 22) — defaults keep the historical 8001 port
# (8000 is often taken by other projects on shared machines).
# ----------------------------------------------------------------------
API_HOST = str(_env("NETSENSE_API_HOST", "127.0.0.1"))
API_PORT = int(_env("NETSENSE_API_PORT", "8001"))
FRONTEND_ORIGIN = str(_env("NETSENSE_FRONTEND_ORIGIN", "http://localhost:5173"))

# ----------------------------------------------------------------------
# Capture / analysis limits (section 12 — memory safety).
# These mirror the bounded sizes inside the modules; listed here so the
# whole system's memory profile is visible in one place.
# ----------------------------------------------------------------------
MAX_RECENT_PACKETS = 500          # live-packets ring buffer (capture.py)
MAX_CONNECTIONS = 2000            # TCP connection tracker (tcp_analysis.py)
MAX_ACTIVE_FLOWS = 5000           # flow engine (flow_analysis.py)
FLOW_INACTIVE_TIMEOUT = 15.0      # seconds (Phase 4 section 10)
FLOW_ACTIVE_TIMEOUT = 120.0       # seconds (Phase 4 section 10)

# ----------------------------------------------------------------------
# Alert engine defaults (Phase 9) — runtime-editable via the API.
# ----------------------------------------------------------------------
ALERT_EVALUATOR_INTERVAL = 10.0   # seconds between snapshot evaluations
ALERT_COOLDOWN = 300.0            # seconds a rule stays quiet after firing

# ----------------------------------------------------------------------
# ML paths (Phase 8) — dataset and trained models.
# ----------------------------------------------------------------------
ML_DATA_DIR = ML_DIR / "data"
ML_MODELS_DIR = ML_DIR / "models"


def summary():
    """One JSON-friendly view of the effective configuration."""
    return {
        "db_path": str(DB_PATH),
        "api_host": API_HOST,
        "api_port": API_PORT,
        "frontend_origin": FRONTEND_ORIGIN,
        "max_recent_packets": MAX_RECENT_PACKETS,
        "max_connections": MAX_CONNECTIONS,
        "max_active_flows": MAX_ACTIVE_FLOWS,
        "flow_inactive_timeout": FLOW_INACTIVE_TIMEOUT,
        "flow_active_timeout": FLOW_ACTIVE_TIMEOUT,
        "alert_evaluator_interval": ALERT_EVALUATOR_INTERVAL,
        "alert_cooldown": ALERT_COOLDOWN,
        "ml_data_dir": str(ML_DATA_DIR),
        "ml_models_dir": str(ML_MODELS_DIR),
    }
