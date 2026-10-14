"""HomeGuard AI - Step 3: learn the LIVE feature names produced by cicflowmeter.

The Python `cicflowmeter` package can emit different feature names/values than
the Java tool that built CIC-IDS2017. This script:
  1. builds a tiny SYNTHETIC pcap with scapy (crafted packets written to a file,
     NO real network traffic is sent),
  2. runs `cicflowmeter -f <pcap> -c <csv>` to get live column names,
  3. normalizes names (lowercase, non-alphanumeric -> underscore),
  4. intersects them with the dataset columns from reports/dataset_columns.txt,
  5. writes reports/cicflowmeter_columns.txt and reports/common_features.json.

Usage:
    python src/03_learn_features.py
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")


def build_synthetic_pcap(pcap_path: Path) -> None:
    """Write a few synthetic TCP flows to a pcap file. Nothing is sent on a network."""
    from scapy.all import IP, TCP, Ether, wrpcap  # type: ignore

    pkts = []
    base_ports = [40001, 40002, 40003]
    for i, sport in enumerate(base_ports):
        src, dst = "10.0.0.5", "10.0.0.9"
        # a minimal 3-way handshake + data + fin so cicflowmeter sees a real flow
        pkts.append(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="S", seq=1000))
        pkts.append(Ether() / IP(src=dst, dst=src) / TCP(sport=80, dport=sport, flags="SA", seq=5000, ack=1001))
        pkts.append(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="A", seq=1001, ack=5001))
        for n in range(3):
            pkts.append(
                Ether() / IP(src=src, dst=dst)
                / TCP(sport=sport, dport=80, flags="PA", seq=1001 + n * 10, ack=5001)
                / (b"GET / HTTP/1.0\r\n\r\n")
            )
        pkts.append(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="FA", seq=2000, ack=5001))
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(pcap_path), pkts)


def run_cicflowmeter(pcap_path: Path, csv_path: Path) -> bool:
    # Use the keyword-correct wrapper (the shipped cicflowmeter CLI is broken; see
    # lab/run_cicflowmeter.py). Invoked via this interpreter so the venv is used.
    wrapper = Path(__file__).resolve().parent.parent / "lab" / "run_cicflowmeter.py"
    cmd = [sys.executable, str(wrapper), "-f", str(pcap_path), "-c", str(csv_path)]
    print("Running:", " ".join(cmd))
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        print("ERROR: wrapper not found. Is the repo layout intact?")
        return False
    except subprocess.TimeoutExpired:
        print("ERROR: cicflowmeter timed out.")
        return False
    if res.returncode != 0:
        print("cicflowmeter stderr:\n", res.stderr)
        print("cicflowmeter stdout:\n", res.stdout)
    return csv_path.exists()


def load_dataset_columns(report: Path) -> list[str]:
    if not report.exists():
        print(f"WARNING: {report} not found. Run src/02_explore.py first for a real overlap.")
        return []
    cols: list[str] = []
    in_cols = False
    for line in report.read_text(encoding="utf-8").splitlines():
        if line.startswith("columns ("):
            in_cols = True
            continue
        if in_cols:
            if not line.startswith("  "):
                break
            name = line.strip().split("::")[0].strip()
            if name:
                cols.append(name)
    return cols


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", default="data/captured/_synthetic/synthetic.pcap")
    ap.add_argument("--csv", default="data/captured/_synthetic/synthetic_flows.csv")
    ap.add_argument("--dataset-report", default="reports/dataset_columns.txt")
    ap.add_argument("--out-cols", default="reports/cicflowmeter_columns.txt")
    ap.add_argument("--out-common", default="reports/common_features.json")
    args = ap.parse_args()

    pcap_path, csv_path = Path(args.pcap), Path(args.csv)
    print("Building synthetic pcap (no network traffic is sent)...")
    build_synthetic_pcap(pcap_path)

    if not run_cicflowmeter(pcap_path, csv_path):
        print("Could not produce live flows. See message above.")
        sys.exit(2)

    import pandas as pd

    live_df = pd.read_csv(csv_path)
    live_cols = list(live_df.columns)
    live_norm = {normalize(c): c for c in live_cols}

    Path(args.out_cols).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_cols).write_text(
        "live cicflowmeter columns (raw :: normalized):\n"
        + "\n".join(f"  {c} :: {normalize(c)}" for c in live_cols),
        encoding="utf-8",
    )

    ds_cols = load_dataset_columns(Path(args.dataset_report))
    ds_norm = {normalize(c): c for c in ds_cols}

    common_norm = sorted(set(live_norm) & set(ds_norm))
    common = {
        "overlap_count": len(common_norm),
        "normalized_common": common_norm,
        "dataset_original": [ds_norm[n] for n in common_norm],
        "live_original": [live_norm[n] for n in common_norm],
    }
    Path(args.out_common).write_text(json.dumps(common, indent=2), encoding="utf-8")

    print(f"\nLive cicflowmeter columns: {len(live_cols)}")
    print(f"Dataset columns: {len(ds_cols)}")
    print(f"Overlap (normalized): {len(common_norm)}")
    print(f"Wrote {args.out_cols} and {args.out_common}")
    if len(common_norm) < 40 and ds_cols:
        print("NOTE: overlap < 40 -> Phase A training will fall back to all numeric columns.")


if __name__ == "__main__":
    main()
