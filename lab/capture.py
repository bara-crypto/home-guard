"""HomeGuard AI - Step 5: capture a labelled pcap on Laptop A (victim).

Records traffic on a chosen interface into data/captured/<label>/run<N>.pcap and
writes a sidecar JSON with start/end UTC. Prefers dumpcap (from Wireshark) if
present, else falls back to scapy sniff (needs Npcap + Administrator on Windows).

Run ONE of these per class while Laptop B generates that class of traffic
against this laptop. Loopback traffic is NOT captured by Npcap by default, so
real detection is only exercised across two laptops.

Usage (as Administrator):
    python lab/capture.py --iface "Wi-Fi" --label portscan --run 1 --duration 60
    python lab/capture.py --list-ifaces
"""
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

LABELS = ("benign", "portscan", "bruteforce", "dos")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def which(cmd: str) -> str | None:
    from shutil import which as _which
    return _which(cmd)


def list_ifaces() -> None:
    try:
        from scapy.all import get_if_list  # type: ignore
        print("scapy interfaces:")
        for i in get_if_list():
            print("  ", i)
    except Exception as e:
        print(f"(scapy iface list unavailable: {e})")
    dp = which("dumpcap")
    if dp:
        print("\ndumpcap -D:")
        subprocess.run([dp, "-D"])
    else:
        print("\n(dumpcap not found; install Wireshark for dumpcap, optional)")


def capture_dumpcap(iface: str, out: Path, duration: int) -> bool:
    dp = which("dumpcap")
    if not dp:
        return False
    cmd = [dp, "-i", iface, "-a", f"duration:{duration}", "-w", str(out)]
    print("Running:", " ".join(cmd))
    return subprocess.run(cmd).returncode == 0 and out.exists()


def capture_scapy(iface: str, out: Path, duration: int) -> bool:
    from scapy.all import sniff, wrpcap  # type: ignore

    print(f"scapy sniff on {iface} for {duration}s (Ctrl+C to stop early)...")
    pkts = sniff(iface=iface, timeout=duration)
    wrpcap(str(out), pkts)
    print(f"Captured {len(pkts)} packets.")
    return out.exists()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list-ifaces", action="store_true")
    ap.add_argument("--iface")
    ap.add_argument("--label", choices=LABELS)
    ap.add_argument("--run", type=int)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--engine", choices=("auto", "dumpcap", "scapy"), default="auto")
    args = ap.parse_args()

    if args.list_ifaces:
        list_ifaces()
        return

    if not (args.iface and args.label and args.run is not None):
        ap.error("--iface, --label and --run are required unless --list-ifaces")

    out_dir = Path("data/captured") / args.label
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap = out_dir / f"run{args.run}.pcap"
    sidecar = out_dir / f"run{args.run}.json"

    start = now_utc()
    t0 = time.time()
    use_dumpcap = args.engine == "dumpcap" or (args.engine == "auto" and which("dumpcap"))
    ok = capture_dumpcap(args.iface, pcap, args.duration) if use_dumpcap \
        else capture_scapy(args.iface, pcap, args.duration)
    end = now_utc()

    if not ok:
        print("Capture failed. On Windows: run as Administrator, confirm Npcap is installed,")
        print("and check the interface name with --list-ifaces.")
        sys.exit(2)

    sidecar.write_text(json.dumps({
        "label": args.label, "run": args.run, "iface": args.iface,
        "start_utc": start, "end_utc": end, "seconds": round(time.time() - t0, 1),
        "pcap": str(pcap),
    }, indent=2), encoding="utf-8")
    print(f"Saved {pcap} and {sidecar}")


if __name__ == "__main__":
    main()
