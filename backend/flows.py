"""
flows.py — PHASE 4: dedicated flow manager module (section 14)

Re-exports and provides the flow engine interface as specified in Section 14:
    1. Receive packet metadata
    2. Determine the 5-tuple
    3. Normalize the bidirectional flow key
    4. Find an existing flow
    5. Update the flow
    6. Create a new flow if necessary
    7. Apply timeout rules (15s inactive, 120s active)
    8. Finalize expired flows
    9. Store/update flow statistics (in-memory + SQLite)
"""

from flow_analysis import (
    FLOW_ACTIVE_TIMEOUT,
    FLOW_INACTIVE_TIMEOUT,
    Flow,
    FlowEngine,
    flow_engine,
    flow_key,
)

__all__ = [
    "FLOW_ACTIVE_TIMEOUT",
    "FLOW_INACTIVE_TIMEOUT",
    "Flow",
    "FlowEngine",
    "flow_engine",
    "flow_key",
]

