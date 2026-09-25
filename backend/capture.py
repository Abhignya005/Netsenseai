"""
capture.py — NetSense packet capture engine (STAGES 2 + 3)

WHAT THIS FILE DOES
-------------------
It wraps Scapy's AsyncSniffer in a small class (CaptureManager) that can:
    1. START capturing packets in a background thread
    2. For every packet, extract ONLY METADATA (no payload/content):
         timestamp, MAC/IP addresses, IP version, protocol, ports,
         size, TTL, TCP flags, ICMP type/code, ARP operation,
         DNS query info  (Stage 3 — see protocol_analysis.py)
    3. Keep the most recent MAX_PACKETS packets in memory (a ring buffer),
       so the app cannot run out of RAM during long captures
    4. STOP capturing cleanly

Privacy note: the packet payload (the actual data inside the packet)
is NEVER read or stored — only the "envelope" header information.

Windows note: capturing requires the Npcap driver + administrator
rights. If the sniffer thread dies (e.g. Npcap missing or access
denied), we detect it and report a friendly error through
/api/capture/status instead of pretending to run.
"""

import threading
import time
from collections import deque
from datetime import datetime, timezone

from scapy.all import AsyncSniffer, conf, get_working_ifaces

from devices import device_registry
from flow_analysis import flow_engine
from performance import traffic_monitor
from protocol_analysis import analyze_packet
from tcp_analysis import tcp_tracker

# How many packets we keep in memory (the newest ones).
MAX_PACKETS = 500

# How long to wait after start() before declaring the sniffer healthy.
# If the thread has already died by then (missing Npcap, no admin
# rights, ...), we report the real error instead of a fake "running".
STARTUP_CHECK_SECONDS = 1.5


class CaptureManager:
    """Owns the sniffer thread and the in-memory packet buffer."""

    def __init__(self):
        self.sniffer = None            # the Scapy AsyncSniffer object
        self.packets = deque(maxlen=MAX_PACKETS)  # newest packets, thread-safe
        self.lock = threading.Lock()   # protects counters + state changes
        self.packet_counter = 0        # total packets seen this session
        self.running = False
        self.started_at = None         # when capture started
        self.interface_used = None
        self.last_error = None         # e.g. "Npcap missing" / "access denied"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _friendly_error(message):
        """Translate raw Scapy/Windows errors into beginner-friendly text."""
        text = str(message)
        if "WinError 5" in text or "access is denied" in text.lower() or "permission" in text.lower():
            return (
                "Access denied. On Windows you must run the backend terminal "
                "as Administrator (and have Npcap installed) to capture packets."
            )
        if "npcap" in text.lower() or "libpcap" in text.lower():
            return (
                "Npcap is missing or broken. Install it from https://npcap.com "
                "(tick 'Install Npcap in WinPcap API-compatible Mode'), then "
                "restart the backend terminal as Administrator."
            )
        return text

    # ------------------------------------------------------------------
    # Packet processing (runs on the sniffer thread for every packet)
    # ------------------------------------------------------------------
    def _process_packet(self, packet):
        """Analyze one packet and store its metadata (STAGE 3).

        Runs on the sniffer thread for every captured frame.
        protocol_analysis.analyze_packet() reads ONLY header fields
        and returns the full Stage 3 metadata dictionary (or None for
        packets that must be skipped).

        The whole body is exception-safe on purpose: ONE malformed
        packet must never crash the capture engine (Stage 3 section 17).
        """
        try:
            record = analyze_packet(packet)
        except Exception:
            return  # skip this packet, keep capturing

        with self.lock:
            self.packets.append(record)
            self.packet_counter += 1

        # PHASE 4: feed the same metadata record into the TCP
        # connection tracker and the flow engine. PHASE 5: the same
        # record also updates the 1-second traffic buckets. PHASE 6:
        # device discovery learns IP/MAC endpoints from it. All are
        # exception safe — one bad record must never stop the capture
        # thread.
        try:
            tcp_tracker.observe(record)
            flow_engine.observe(record)
            traffic_monitor.observe(record)   # Phase 5: bytes/packets per second
            device_registry.observe(record)   # Phase 6: passive device discovery
        except Exception:
            pass

        # Persist the metadata to SQLite (best effort). This is wrapped
        # in try/except on purpose: if the database ever fails, packet
        # CAPTURE must keep working.
        try:
            import database

            database.insert_packet(record)
            # Occasionally clean old rows so the file stays small.
            if self.packet_counter % 500 == 0:
                database.trim_packets()
        except Exception:
            pass  # never let a DB problem stop the capture thread

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------
    def start(self, interface=None):
        """Start sniffing. Returns (ok: bool, message: str)."""
        with self.lock:
            if self.running:
                return False, "Capture is already running"
            self.last_error = None

        try:
            kwargs = {
                "prn": self._process_packet,  # called for every packet
                "store": False,               # Scapy: do NOT keep raw packets
                # Stage 3: NO BPF filter on purpose — ARP and other
                # non-IP frames must reach the analyzer too.
            }
            if interface:
                kwargs["iface"] = interface

            self.sniffer = AsyncSniffer(**kwargs)
            self.sniffer.start()  # begins the background capture thread
        except Exception as error:
            message = self._friendly_error(error)
            with self.lock:
                self.last_error = message
            return False, message

        # ---- Startup health check -------------------------------------
        # AsyncSniffer.start() only launches a THREAD — real errors (no
        # Npcap, no admin rights) happen inside that thread and kill it
        # almost immediately. So we give it a moment and check whether
        # the thread is still alive before claiming success.
        time.sleep(STARTUP_CHECK_SECONDS)

        thread = getattr(self.sniffer, "thread", None)
        if thread is not None and not thread.is_alive():
            # The thread died: recover the actual exception it raised.
            thread_message = "Sniffer thread stopped immediately."
            try:
                self.sniffer.join()  # re-raises the thread's exception
            except Exception as error:
                thread_message = self._friendly_error(error)
            with self.lock:
                self.running = False
                self.last_error = thread_message
            return False, thread_message

        with self.lock:
            self.running = True
            self.started_at = datetime.now(timezone.utc).isoformat()
            self.interface_used = interface or "default"
        return True, "Capture started"

    def stop(self):
        """Stop sniffing. Returns (ok: bool, message: str)."""
        with self.lock:
            if not self.running:
                return False, "Capture is not running"

        try:
            # stop() halts the thread and (by default) waits for it.
            # It raises Scapy_Exception("Not running ! ...") if the
            # sniffer already died on its own — that is fine for us.
            self.sniffer.stop()
        except Exception as error:
            message = str(error)
            already_dead = "not running" in message.lower()
            with self.lock:
                self.running = False
                self.last_error = None if already_dead else self._friendly_error(error)
            if already_dead:
                return True, "Capture stopped"
            return False, f"Stopped with warning: {message}"

        with self.lock:
            self.running = False
            self.last_error = None
        return True, "Capture stopped"

    # ------------------------------------------------------------------
    # Status / data access
    # ------------------------------------------------------------------
    def get_status(self):
        """Return a JSON-safe snapshot of the capture state.

        Also acts as a watchdog: if the sniffer thread died silently
        while `running` is True (rare, but happens on driver hiccups),
        we flip to stopped + record the error, so the UI never shows a
        lie.
        """
        with self.lock:
            if self.running:
                thread = getattr(self.sniffer, "thread", None)
                if thread is not None and not thread.is_alive():
                    self.running = False
                    self.last_error = (
                        "The capture thread stopped unexpectedly. Check that "
                        "Npcap is installed and the backend runs as Administrator."
                    )

            return {
                "running": self.running,
                "total_packets": self.packet_counter,
                "buffered_packets": len(self.packets),
                "started_at": self.started_at,
                "interface": self.interface_used,
                "max_buffer": MAX_PACKETS,
                "error": self.last_error,
            }

    def get_recent_packets(self, limit=100, protocol=None):
        """Return the newest `limit` packets, newest first.

        Optionally filter by protocol name, e.g. protocol="TCP".
        """
        with self.lock:
            snapshot = list(self.packets)

        snapshot.reverse()  # newest first
        if protocol:
            wanted = protocol.upper()
            snapshot = [p for p in snapshot if p["protocol"].upper() == wanted]
        return snapshot[:limit]


# One global instance shared by all API endpoints.
capture_manager = CaptureManager()


def list_interfaces():
    """Return the network interfaces Scapy can use, for a dropdown in the UI."""
    interfaces = []
    try:
        for iface in get_working_ifaces():
            name = getattr(iface, "name", None) or str(iface)
            description = getattr(iface, "description", "") or ""
            # Friendly IP address if we can find one
            ip_address = None
            try:
                ip_address = iface.ip
            except Exception:
                pass
            interfaces.append(
                {"name": name, "description": str(description), "ip": ip_address}
            )
    except Exception:
        interfaces.append({"name": conf.iface.name, "description": "default", "ip": None})
    return interfaces
