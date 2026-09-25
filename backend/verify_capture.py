"""
verify_capture.py — Stage 2 self-test (run this to prove capture works)

WHAT IT DOES
------------
1. Checks whether the terminal has Administrator rights (Windows).
2. Captures up to 50 IP packets (or 20 seconds, whichever comes first).
3. Prints the same metadata NetSense stores for a few packets.

How to run (from the `backend` folder, in an ADMINISTRATOR terminal):
    venv\\Scripts\\activate
    python verify_capture.py

If you see real IPs and packet sizes, capture works — and the
Live Packets page in the browser will show the same data.
"""

import sys

from scapy.all import sniff


def main():
    # ---- 1. Admin check (Windows only) ---------------------------------
    if sys.platform == "win32":
        import ctypes

        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("[FAIL] This terminal is NOT Administrator.")
            print("       Right-click your terminal -> 'Run as administrator',")
            print("       then run this script again.")
            return

    # ---- 2. Capture up to 50 packets, max 20 seconds --------------------
    print("Capturing up to 50 packets (max 20 seconds)...")
    print("Tip: open a website or run `ping localhost` to generate traffic.\n")

    packets = sniff(count=50, timeout=20, filter="ip", store=True)

    # ---- 3. Print the metadata NetSense stores --------------------------
    if len(packets) == 0:
        print("[FAIL] No packets captured. Is Npcap installed?")
        return

    from scapy.layers.inet import IP, IPv6, TCP, UDP

    print(f"[OK] Captured {len(packets)} packets. First 10:\n")
    print(f"{'TIME':<10} {'SOURCE':<28} {'DESTINATION':<28} {'PROTO':<6} {'PORTS':<11} SIZE")
    for packet in packets[:10]:
        network_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if network_layer is None:
            continue

        protocol = "OTHER"
        ports = "-"
        if packet.haslayer(TCP):
            protocol = "TCP"
            ports = f"{packet[TCP].sport}->{packet[TCP].dport}"
        elif packet.haslayer(UDP):
            protocol = "UDP"
            ports = f"{packet[UDP].sport}->{packet[UDP].dport}"

        from datetime import datetime

        clock = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S")
        print(
            f"{clock:<10} {network_layer.src:<28} {network_layer.dst:<28} "
            f"{protocol:<6} {ports:<11} {len(packet)}"
        )

    print("\n[OK] Packet capture is working. Start the backend and click")
    print("     'Start Capture' on the Live Packets page in the browser.")


if __name__ == "__main__":
    main()
