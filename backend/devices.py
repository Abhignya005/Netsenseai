"""
devices.py — PHASE 6: passive device discovery

WHAT THIS FILE DOES
-------------------
Builds the list of devices seen on the monitored network from the
packet metadata NetSense already captures. NOTHING is scanned: a
device exists here only because one of its addresses appeared in a
real captured packet (section 20 — passive discovery).

DEVICE IDENTIFICATION (sections 2-3)
------------------------------------
Every packet has up to two endpoints (source, destination). An
endpoint may know its IP, its MAC, or both:

    * IP + MAC  -> one device, both addresses linked
    * IP only   -> device keyed by IP (MAC unknown)
    * MAC only  -> device keyed by MAC (IP unknown)

The same physical machine is ONE device even if we sometimes see it
by IP first and by MAC later: the registry keeps alias links
(ip -> device, mac -> device) and MERGES two records when a packet
proves they belong together (section 21 — never create duplicates).

HOSTNAMES (section 4)
---------------------
Resolved with the system's normal resolver (socket.gethostbyaddr),
at most ONE lookup per IP, cached forever, and NEVER on the capture
thread — unknown IPs are queued and resolved by this module's own
slow background thread. Unresolvable IPs simply stay "Unknown".

PRIVACY: addresses and counters only — no payload, no guesses about
people or device owners (section 28).
"""

import socket
import threading
import time

MAX_DEVICES = 500          # memory bound (oldest-evicted)
HOSTNAME_CACHE_MAX = 2000  # resolved IPs we never ask about again
PERSIST_INTERVAL_SECONDS = 60.0


class Device:
    """One observed machine: its addresses, counters and protocols."""

    def __init__(self, key, now):
        self.key = key              # canonical id: the MAC, or the IP if no MAC
        self.ips = set()            # every IP linked to this device
        self.macs = set()           # every MAC linked to this device
        self.hostname = None
        self.hostname_checked = False  # did we already TRY to resolve?
        self.packet_count = 0
        self.bytes_total = 0
        self.protocols = set()
        self.first_seen = now
        self.last_seen = now
        self.is_gateway = False     # set only when CONFIRMED (section 13)
        self.is_local = False       # true for this machine's own addresses

    # ------------------------------------------------------------------
    def add_endpoint(self, ip, mac):
        """Link an (ip, mac) endpoint pair to this device (section 3)."""
        if ip:
            self.ips.add(ip)
        if mac:
            self.macs.add(mac)

    def observe(self, record, protocol, now):
        """Fold one packet observation into the counters (section 21)."""
        self.packet_count += 1
        try:
            self.bytes_total += int(record.get("size") or 0)
        except Exception:
            pass
        if protocol:
            self.protocols.add(protocol)
        self.first_seen = min(self.first_seen, now)
        self.last_seen = max(self.last_seen, now)

    # ------------------------------------------------------------------
    @property
    def primary_ip(self):
        """Best IP to display: the gateway/local one, else the lowest."""
        if not self.ips:
            return None
        ordered = sorted(self.ips)
        return ordered[0]

    @property
    def primary_mac(self):
        return sorted(self.macs)[0] if self.macs else None

    def to_row(self):
        """JSON-safe summary row (section 6)."""
        return {
            "id": self.key,
            "ip": self.primary_ip,
            "mac": self.primary_mac,
            "hostname": self.hostname,          # None -> UI shows "Unknown"
            "packet_count": self.packet_count,
            "bytes": self.bytes_total,
            "protocols": sorted(self.protocols),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "is_gateway": self.is_gateway,
            "is_local": self.is_local,
            "ip_count": len(self.ips),
        }


class DeviceRegistry:
    """Owns every observed device. Exception-safe by design (section 29)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.devices = {}        # canonical key -> Device
        self.aliases = {}        # "ip:1.2.3.4" / "mac:AA:BB.." -> canonical key
        self.gateway_ip = None   # CONFIRMED gateway (section 13) or None
        self.local_ips = set()   # this machine's addresses (section 14)
        self.local_macs = set()
        self._hostname_cache = {}    # ip -> hostname or None (never re-queried)
        self._pending_hostnames = set()  # IPs waiting for background lookup
        self._thread = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Observation (called from the CAPTURE thread — must stay O(1))
    # ------------------------------------------------------------------
    def observe(self, record):
        """Update devices from one packet record. Never raises."""
        try:
            now = float(record.get("timestamp") or time.time())
            protocol = (record.get("protocol") or "").upper() or None
            with self.lock:
                for side in ("source", "destination"):
                    ip = record.get(f"{side}_ip")
                    mac = record.get(f"{side}_mac")
                    if not ip and not mac:
                        continue
                    device = self._find_or_create(ip, mac, now)
                    device.add_endpoint(ip, mac)
                    device.observe(record, protocol, now)
                    # Section 13/14: flag special devices the moment we
                    # see their confirmed addresses.
                    if ip and ip == self.gateway_ip:
                        device.is_gateway = True
                    if (ip and ip in self.local_ips) or (mac and mac in self.local_macs):
                        device.is_local = True
                    if ip and ip not in self._hostname_cache:
                        self._pending_hostnames.add(ip)
                self._evict_if_needed()
        except Exception:
            return  # one bad record must never stop capture

    # ------------------------------------------------------------------
    def _find_or_create(self, ip, mac, now):
        """Find the device for an endpoint, merging duplicates (§3, §21).

        Lookup order: exact IP alias -> exact MAC alias -> create new.
        When both an IP-alias and a MAC-alias exist but point to
        DIFFERENT devices, the packet just proved they are the same
        machine, so the two devices are merged.
        """
        ip_device = self.aliases.get(f"ip:{ip}") if ip else None
        mac_device = self.aliases.get(f"mac:{mac}") if mac else None

        if ip_device and mac_device and ip_device != mac_device:
            keep = self.devices.get(ip_device) or self.devices.get(mac_device)
            other_key = mac_device if keep.key == ip_device else ip_device
            other = self.devices.get(other_key)
            if keep is not None and other is not None:
                self._merge(keep, other)

        key = mac_device or ip_device
        if key and key in self.devices:
            device = self.devices[key]
        else:
            canonical = mac or ip
            device = Device(canonical, now)
            self.devices[canonical] = device
            key = canonical

        # (Re)register alias links so future packets find this device.
        if ip:
            self.aliases[f"ip:{ip}"] = device.key
        if mac:
            self.aliases[f"mac:{mac}"] = device.key
        return device

    def _merge(self, keep, other):
        """Fold `other` into `keep` — one machine, one record (§21)."""
        keep.ips |= other.ips
        keep.macs |= other.macs
        keep.packet_count += other.packet_count
        keep.bytes_total += other.bytes_total
        keep.protocols |= other.protocols
        keep.first_seen = min(keep.first_seen, other.first_seen)
        keep.last_seen = max(keep.last_seen, other.last_seen)
        if not keep.hostname and other.hostname:
            keep.hostname = other.hostname
        keep.is_gateway = keep.is_gateway or other.is_gateway
        keep.is_local = keep.is_local or other.is_local
        del self.devices[other.key]
        # Repoint every alias of the removed device at the survivor.
        for alias, target in list(self.aliases.items()):
            if target == other.key:
                self.aliases[alias] = keep.key

    def _evict_if_needed(self):
        """Memory bound: forget the least-recently-seen device."""
        while len(self.devices) > MAX_DEVICES:
            oldest_key = min(
                self.devices, key=lambda k: self.devices[k].last_seen
            )
            self._drop(oldest_key)

    def _drop(self, key):
        device = self.devices.pop(key, None)
        if device:
            for alias, target in list(self.aliases.items()):
                if target == key:
                    del self.aliases[alias]

    # ------------------------------------------------------------------
    # Gateway + local machine identification (sections 13-14)
    # ------------------------------------------------------------------
    def set_gateway(self, ip):
        """Store the CONFIRMED gateway IP and flag any existing device
        that already uses it. Never called with a guessed address."""
        if not ip:
            return
        with self.lock:
            self.gateway_ip = ip
            device_key = self.aliases.get(f"ip:{ip}")
            if device_key and device_key in self.devices:
                self.devices[device_key].is_gateway = True

    def set_local(self, ips=None, macs=None):
        """Store this machine's own addresses and flag its device."""
        with self.lock:
            self.local_ips.update(ips or [])
            self.local_macs.update(macs or [])
            for ip in ips or []:
                device_key = self.aliases.get(f"ip:{ip}")
                if device_key and device_key in self.devices:
                    self.devices[device_key].is_local = True
            for mac in macs or []:
                device_key = self.aliases.get(f"mac:{mac}")
                if device_key and device_key in self.devices:
                    self.devices[device_key].is_local = True

    def node_id_for_ip(self, ip):
        """Topology helper: canonical device key for an IP (or None)."""
        with self.lock:
            return self.aliases.get(f"ip:{ip}")

    # ------------------------------------------------------------------
    # Hostnames — background thread ONLY (section 4 + section 29)
    # ------------------------------------------------------------------
    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _run(self):
        """Slow lane: resolve one pending hostname per pass, persist
        devices to SQLite once a minute. Never touches capture."""
        last_persist = 0.0
        while not self._stop_event.wait(timeout=2.0):
            try:
                if self._pending_hostnames:
                    with self.lock:
                        ip = next(iter(self._pending_hostnames))
                        self._pending_hostnames.discard(ip)
                    self._resolve_and_store(ip)
                if time.time() - last_persist >= PERSIST_INTERVAL_SECONDS:
                    last_persist = time.time()
                    self._persist_all()
            except Exception:
                pass

    def _resolve_and_store(self, ip):
        """One cached system-resolver lookup (never re-queried)."""
        if ip in self._hostname_cache:
            return
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = None   # unresolvable -> stays Unknown (§4)
        with self.lock:
            if len(self._hostname_cache) > HOSTNAME_CACHE_MAX:
                self._hostname_cache.clear()   # crude but bounded
            self._hostname_cache[ip] = hostname
            self._pending_hostnames.discard(ip)
            device_key = self.aliases.get(f"ip:{ip}")
            if device_key and device_key in self.devices and hostname:
                self.devices[device_key].hostname = hostname
                self.devices[device_key].hostname_checked = True

    # ------------------------------------------------------------------
    # Queries (section 17)
    # ------------------------------------------------------------------
    def rows(self):
        """All devices, most-recently-active first."""
        with self.lock:
            rows = [d.to_row() for d in self.devices.values()]
        rows.sort(key=lambda r: r["last_seen"], reverse=True)
        return rows

    def get(self, key):
        with self.lock:
            device = self.devices.get(key)
            return device.to_row() if device else None

    def stats(self):
        """Summary for the dashboard (section 23)."""
        with self.lock:
            devices = list(self.devices.values())
        total_packets = sum(d.packet_count for d in devices)
        total_bytes = sum(d.bytes_total for d in devices)
        most_active = None
        if devices:
            top = max(devices, key=lambda d: d.bytes_total)
            most_active = {
                "id": top.key,
                "ip": top.primary_ip,
                "hostname": top.hostname,
                "bytes": top.bytes_total,
                "packet_count": top.packet_count,
            }
        return {
            "total_devices": len(devices),
            "with_mac": sum(1 for d in devices if d.macs),
            "gateway_known": any(d.is_gateway for d in devices),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "most_active": most_active,
        }

    def _persist_all(self):
        """Best-effort snapshot of devices into SQLite (section 19)."""
        try:
            import database

            with self.lock:
                devices = list(self.devices.values())
            for device in devices:
                database.upsert_device(device)
        except Exception:
            pass


# One global registry shared by capture, the API and the topology.
device_registry = DeviceRegistry()
