"""
routing.py — PHASE 7: routing & path analysis

WHAT THIS FILE DOES
-------------------
Reads the OPERATING SYSTEM's real networking configuration and runs
tracert/traceroute against user-authorized destinations:

    * interfaces   — name, IPv4, IPv6, MAC, status  (section 2)
    * gateway      — CONFIRMED from the routing table, never guessed (§3)
    * routes       — Windows `route print`, Linux `ip route` (§4)
    * traceroute   — Windows `tracert`, Linux `traceroute` (§6-7)

SAFETY RULES (sections 6 + 13 + 14)
-----------------------------------
* subprocess ALWAYS receives an argument LIST — never a shell string,
  so no injection is possible.
* The target is validated: hostname (letters/digits/dots/hyphens,
  each label 1-63 chars) or IPv4/IPv6 — nothing else.
* Hard timeouts on every command; a hung probe can never hang the API.
* Nothing is invented: unavailable values are None (the UI shows
  "Unavailable"/"Timeout").
"""

import ipaddress
import re
import socket
import subprocess

# Hard limits (sections 6 + 12): a tracert must never hang the API.
TRACERT_MAX_HOPS = 15
TRACERT_TIMEOUT_SECONDS = 90.0
_COMMAND_TIMEOUT_SECONDS = 100.0

_TARGET_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


def validate_target(target):
    """Accept only a plain hostname or IP address (sections 6 + 14).

    Returns True/False. Anything containing spaces, separators or
    shell metacharacters fails — the subprocess call below then never
    sees attacker-controlled text.
    """
    if not target or len(target) > 253:
        return False
    candidate = target.strip()
    try:
        ipaddress.ip_address(candidate)
        return True            # IPv4 or IPv6 literal
    except ValueError:
        pass
    return bool(_TARGET_RE.match(candidate))


def _run_command(arguments, timeout=_COMMAND_TIMEOUT_SECONDS):
    """Run a network command safely: argument list, no shell, timeout."""
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        return completed.stdout or ""
    except FileNotFoundError:
        return None            # command not on this system (§13)
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


# ======================================================================
# Network interfaces (section 2) — from real `ipconfig /all` output
# ======================================================================
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})")


def _looks_like_ipv6(text):
    return ":" in text and _IP_RE.match(text) is None


def _parse_ipconfig(output):
    """Parse `ipconfig /all` into interface dicts (Windows)."""
    interfaces = []
    current = None

    def new_entry(name):
        return {
            "name": name,
            "ipv4": None,
            "ipv6": None,
            "mac": None,
            "status": "up",       # ipconfig only lists configured adapters
            "subnet": None,
            "gateway": None,
        }

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        # Adapter headers are not indented and end with a colon.
        if not line.startswith(" ") and stripped.endswith(":"):
            if current:
                interfaces.append(current)
            current = new_entry(stripped.rstrip(":").strip())
            continue
        if current is None:
            continue
        if "Media disconnected" in stripped:
            current["status"] = "down"   # adapter exists but is not connected
        elif "Physical Address" in stripped:
            match = _MAC_RE.search(stripped)
            if match:
                current["mac"] = match.group(1).upper()
        elif "IPv4 Address" in stripped or (stripped.startswith("IP Address") and _IP_RE.match(stripped.split(":")[-1].strip() or "")):
            candidate = stripped.split(":")[-1].strip().rstrip("(Preferred)")
            candidate = re.sub(r"\(Preferred\)", "", candidate).strip()
            if _IP_RE.match(candidate) and not current["ipv4"]:
                current["ipv4"] = candidate
        elif _looks_like_ipv6(stripped.split(":")[-1]) and "IPv6 Address" in stripped:
            candidate = stripped.split(":")[-1].strip()
            if not current["ipv6"]:
                current["ipv6"] = candidate
        elif "Subnet Mask" in stripped:
            candidate = stripped.split(":")[-1].strip()
            if _IP_RE.match(candidate):
                current["subnet"] = candidate
        elif "Default Gateway" in stripped:
            candidate = stripped.split(":")[-1].strip()
            if _IP_RE.match(candidate) and not current["gateway"]:
                current["gateway"] = candidate
    if current:
        interfaces.append(current)
    # Skip adapters that clearly have no IP at all (virtual junk).
    return [i for i in interfaces if i["ipv4"] or i["ipv6"] or i["mac"]]


def get_interfaces():
    """Real interface info: Windows via ipconfig, Linux via ip (§2)."""
    windows = _parse_ipconfig(_run_command(["ipconfig", "/all"]) or "")
    if windows:
        return {"interfaces": windows, "source": "ipconfig /all"}
    # ---- Linux fallback: `ip -o addr` + `ip link` ----------------------
    output = _run_command(["ip", "-o", "addr", "show"])
    if output is None:
        return {"interfaces": [], "source": None,
                "error": "Network information is currently unavailable."}
    interfaces = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name, status = parts[1], "up" if "UP" in line else "down"
        entry = interfaces.setdefault(
            name, {"name": name, "ipv4": None, "ipv6": None, "mac": None,
                    "status": status, "subnet": None, "gateway": None}
        )
        if parts[2] == "inet" and _IP_RE.match(parts[3].split("/")[0]):
            entry["ipv4"] = parts[3].split("/")[0]
            entry["subnet"] = parts[3].split("/")[1] if "/" in parts[3] else None
        elif parts[2] == "inet6":
            entry["ipv6"] = entry["ipv6"] or parts[3].split("/")[0]
    link_output = _run_command(["ip", "link", "show"]) or ""
    for line in link_output.splitlines():
        match = _MAC_RE.search(line)
        name_match = re.match(r"\d+:\s+([^:@]+)", line.strip())
        if match and name_match and name_match.group(1) in interfaces:
            interfaces[name_match.group(1)]["mac"] = match.group(1).upper()
    return {"interfaces": list(interfaces.values()), "source": "ip"}


# ======================================================================
# Default gateway (section 3) — CONFIRMED from the routing table
# ======================================================================
def get_gateway():
    """The default gateway + its interface, from the REAL route table."""
    routes = get_routing_table()["routes"]
    for route in routes:
        if route.get("destination") == "0.0.0.0" and route.get("gateway"):
            return {"gateway": route["gateway"], "interface": route.get("interface")}
    return {"gateway": None, "interface": None,
            "message": "Default gateway could not be determined."}


# ======================================================================
# Routing table (section 4) — Windows `route print`
# ======================================================================
def _parse_route_print(output):
    """Parse the 'Active Routes' table of `route print`."""
    routes = []
    in_active = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("Active Routes"):
            in_active = True
            continue
        if in_active and line.startswith("Persistent Routes"):
            break
        if not in_active or not line:
            continue
        parts = line.split()
        if len(parts) == 5 and _IP_RE.match(parts[0]) and _IP_RE.match(parts[1]):
            destination, mask, gateway, interface, metric = parts
            try:
                prefix = bin(int(mask.split(".")[0])).count("1") + \
                         bin(int(mask.split(".")[1])).count("1") + \
                         bin(int(mask.split(".")[2])).count("1") + \
                         bin(int(mask.split(".")[3])).count("1")
            except Exception:
                prefix = None
            routes.append({
                "destination": destination,
                "mask": mask,
                "prefix": prefix,
                "gateway": None if gateway == "On-link" else gateway,
                "interface": interface,
                "metric": int(metric) if metric.isdigit() else None,
            })
    return routes


def _parse_ip_route(output):
    """Parse Linux `ip route show` lines."""
    routes = []
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        destination = parts[0]
        if destination == "default":
            destination, mask = "0.0.0.0", "0.0.0.0"
        elif "/" in destination:
            destination, mask = destination.split("/")[0], f"255.255.255.{255 - (2 ** (32 - int(destination.split('/')[1])) - 1) & 255}"
        else:
            mask = "255.255.255.255"
        gateway = parts[parts.index("via") + 1] if "via" in parts else None
        interface = parts[parts.index("dev") + 1] if "dev" in parts else None
        metric = int(parts[parts.index("metric") + 1]) if "metric" in parts else None
        routes.append({
            "destination": destination,
            "mask": mask,
            "prefix": None,
            "gateway": gateway,
            "interface": interface,
            "metric": metric,
        })
    return routes


def get_routing_table():
    """The OS routing table, real entries only (section 4)."""
    windows = _parse_route_print(_run_command(["route", "print"]) or "")
    if windows:
        return {"routes": windows, "source": "route print"}
    linux = _run_command(["ip", "route", "show"])
    if linux is not None:
        return {"routes": _parse_ip_route(linux), "source": "ip route"}
    return {"routes": [], "source": None,
            "error": "Network information is currently unavailable."}


# ======================================================================
# Traceroute (sections 6-7) — Windows `tracert`
# ======================================================================
_HOP_LINE = re.compile(
    r"^\s*(\d{1,2})\s+"                     # hop number
    r"(?:(\d+)\s*(?:ms|msec)\s*)?"          # rtt 1
    r"(?:([<]\d+\s*ms)|([\d.]+\s*ms))?\s*"  # "<1 ms" or decimal ms
    r"(\*{1,3}\s*)?"                        # asterisks = timeout
    r"([\w.\-:]*)\s*(\[?[\d.]{7,}|\[[0-9a-fA-F:]{2,}\])?\s*$"
)
_IP_IN_HOP = re.compile(r"\[?((?:\d{1,3}(?:\.\d{1,3}){3})|(?:[0-9a-fA-F:]{2,}:[0-9a-fA-F:]+))\]?")


def parse_tracert(output):
    """Turn `tracert` text into structured hops (section 7).

    Every line is tried independently — one weird line can never break
    the whole result. Unparseable/timeout lines become status 'timeout'
    with NO invented IP or RTT.
    """
    hops = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        hop_match = re.match(r"^\s*(\d{1,2})\s+\*?\s*(.*)$", line)
        if not hop_match:
            continue
        hop_number = int(hop_match.group(1))
        rest = hop_match.group(2)

        ip_match = _IP_IN_HOP.search(rest)
        hostname = None
        if ip_match:
            before = rest[:ip_match.start()].strip()
            # Remove the timing tokens ("3 ms", "<1 ms", "*"); whatever
            # ALPHANUMERIC text remains is the reverse-DNS hostname.
            residual = re.sub(r"[<]?\d+(?:\.\d+)?\s*ms", "", before)
            residual = residual.replace("*", "").strip()
            if residual:
                hostname = residual
        rtt_values = [
            float(v.lstrip("<"))    # Windows writes "<1 ms" for sub-ms
            for v in re.findall(r"([<]?\d+(?:\.\d+)?)\s*ms", rest) if v
        ]
        timed_out = ("*" in rest) or (ip_match is None)

        # Tracert lists up to 3 probes per hop; report the minimum RTT.
        rtt = min(rtt_values) if rtt_values else None
        hops.append({
            "hop": hop_number,
            "ip": ip_match.group(1) if ip_match else None,
            "hostname": hostname,
            "rtt_ms": rtt,
            "status": "timeout" if timed_out else "reachable",
        })

    # Keep the FIRST record per hop number (tracert sometimes repeats).
    deduplicated = {}
    for hop in hops:
        deduplicated.setdefault(hop["hop"], hop)
    return [deduplicated[key] for key in sorted(deduplicated)]


def run_traceroute(target):
    """Validate, run and parse a traceroute (sections 6-7, 13-14).

    Returns (result_dict, http_status). The caller (main.py) turns a
    400 into 'Invalid destination.' and a 503 into 'not available'.
    """
    if not validate_target(target):
        return {"error": "Invalid destination."}, 400
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        creation = subprocess.CREATE_NO_WINDOW
    else:
        creation = 0

    arguments = ["tracert", "-d", "-h", str(TRACERT_MAX_HOPS), "-w", "400", target]
    try:
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            timeout=_COMMAND_TIMEOUT_SECONDS,
            creationflags=creation,
        )
        output = completed.stdout or ""
    except FileNotFoundError:
        # Windows has tracert; on Linux try traceroute before giving up.
        linux_output = _run_command(
            ["traceroute", "-n", "-m", str(TRACERT_MAX_HOPS), "-w", "2", target],
            timeout=TRACERT_TIMEOUT_SECONDS,
        )
        if linux_output is None:
            return {"error": "Traceroute is not available on this system."}, 503
        return {
            "target": target,
            "hops": parse_linux_traceroute(linux_output),
            "source": "traceroute",
        }, 200
    except subprocess.TimeoutExpired:
        return {"error": "Traceroute timed out."}, 504
    except Exception:
        return {"error": "Traceroute failed on this system."}, 500

    return {
        "target": target,
        "hops": parse_tracert(output),
        "source": "tracert",
    }, 200


def parse_linux_traceroute(output):
    """Parse `traceroute -n` output (Linux fallback)."""
    hops = []
    for line in output.splitlines():
        hop_match = re.match(r"\s*(\d{1,2})\s+(.*)$", line)
        if not hop_match:
            continue
        rest = hop_match.group(2)
        ip_match = _IP_IN_HOP.search(rest)
        rtt_values = [float(v) for v in re.findall(r"(\d+(?:\.\d+)?)\s*ms", rest)]
        hops.append({
            "hop": int(hop_match.group(1)),
            "ip": ip_match.group(1) if ip_match else None,
            "hostname": None,          # -n skips lookups
            "rtt_ms": min(rtt_values) if rtt_values else None,
            "status": "reachable" if ip_match else "timeout",
        })
    return hops
