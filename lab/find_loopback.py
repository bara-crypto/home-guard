"""HomeGuard AI - find the loopback capture interface for single-laptop mode.

When the client/victim agent and the attacker run on the SAME laptop, all attack
traffic is loopback (127.0.0.1) and never touches the Wi-Fi NIC. Npcap still
exposes a loopback capture device (usually ``\\Device\\NPF_Loopback``); this helper
finds it so you can pass the exact name to ``--iface``.

Usage:
    python lab/find_loopback.py
"""
import sys

from scapy.all import get_if_list


def find_loopback() -> str | None:
    for name in get_if_list():
        if "loopback" in name.lower():
            return name
    return None


def main() -> int:
    ifaces = get_if_list()
    loop = find_loopback()
    print("scapy interfaces:")
    for name in ifaces:
        print(f"  {name}{'   <-- loopback' if name == loop else ''}")
    print()
    if loop:
        print("Single-laptop mode: use this for --iface (capture) and the agent sniffer:")
        print(f'  --iface "{loop}"')
        return 0
    print("No loopback interface found.")
    print("Install Npcap and enable 'Support loopback traffic ('Npcap Loopback Adapter')',")
    print("then reboot and re-run this helper.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
