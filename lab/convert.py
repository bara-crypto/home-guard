"""HomeGuard AI - Step 5: convert captured pcaps to labelled flows.

For every data/captured/<label>/run<N>.pcap:
  - run `cicflowmeter -f <pcap> -c <csv>` to extract flows,
  - assign a class label:
      * benign folder          -> every flow is 'benign'
      * attack folder + --attacker-ip -> flows whose src_ip OR dst_ip equals the
        attacker IP get the folder's class; all OTHER flows get 'benign'
        (so background traffic in an attack capture is not mislabelled).
      * attack folder + --single-laptop -> both endpoints are 127.0.0.1, so label
        by destination/source port instead (2121=bruteforce, 8080=dos, 1-1024=portscan).
  - add label, run_id (=<label>/run<N>) and source pcap columns.
Merge everything to data/processed/lab_flows.parquet.

Usage:
    python lab/convert.py --attacker-ip 10.42.0.23      # two-laptop (LAN) capture
    python lab/convert.py --single-laptop               # single-laptop (loopback) capture
    python lab/convert.py --captured data/captured --out data/processed/lab_flows.parquet
"""
import argparse
import subprocess
import sys
from pathlib import Path

LABELS = ("benign", "portscan", "bruteforce", "dos")
WRAPPER = Path(__file__).resolve().parent / "run_cicflowmeter.py"

# Single-laptop mode: attack traffic is all loopback (127.0.0.1), so we separate
# attack flows from background by the service port they hit.
SERVICE_PORTS = {"bruteforce": {2121}, "dos": {8080}}


def label_single_laptop(df, label: str):
    """Label a single-laptop (loopback) attack capture by service port.

    bruteforce -> dst/src port 2121; dos -> 8080; portscan -> a scanned port in
    1-1024 that is not one of the service ports. Everything else is benign.
    """
    import pandas as pd

    def row_label(row) -> str:
        if label == "portscan":
            scanned = False
            for col in ("dst_port", "src_port"):
                v = row.get(col)
                if pd.notna(v) and 1 <= int(v) <= 1024 and int(v) not in (2121, 8080):
                    scanned = True
            return "portscan" if scanned else "benign"
        ports = SERVICE_PORTS[label]
        for col in ("dst_port", "src_port"):
            v = row.get(col)
            if pd.notna(v) and int(v) in ports:
                return label
        return "benign"

    return df.apply(row_label, axis=1)


def convert_pcap(pcap: Path, csv: Path) -> bool:
    # Use the keyword-correct wrapper (shipped cicflowmeter CLI is broken in 0.5.0).
    cmd = [sys.executable, str(WRAPPER), "-f", str(pcap), "-c", str(csv)]
    print("Running:", " ".join(cmd))
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        print("ERROR: wrapper not found (check repo layout).")
        return False
    if res.returncode != 0:
        print("cicflowmeter stderr:", res.stderr[-800:])
    return csv.exists() and csv.stat().st_size > 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--captured", default="data/captured")
    ap.add_argument("--out", default="data/processed/lab_flows.parquet")
    ap.add_argument("--attacker-ip", default=None,
                    help="IP of Laptop B; required to label attack folders correctly")
    ap.add_argument("--single-laptop", action="store_true",
                    help="label loopback captures by service port instead of attacker IP")
    args = ap.parse_args()

    import pandas as pd

    captured = Path(args.captured)
    frames = []
    for label in LABELS:
        folder = captured / label
        if not folder.is_dir():
            continue
        for pcap in sorted(folder.glob("run*.pcap")):
            run_id = f"{label}/{pcap.stem}"
            csv = pcap.with_suffix(".csv")
            # Re-extract if the CSV is missing, empty (a crashed prior run can
            # leave a 0-byte file), or older than the pcap.
            stale = (not csv.exists()) or csv.stat().st_size == 0 or csv.stat().st_mtime < pcap.stat().st_mtime
            if stale:
                if not convert_pcap(pcap, csv):
                    print(f"  skipped {pcap} (no flows)")
                    continue
            try:
                df = pd.read_csv(csv)
            except pd.errors.EmptyDataError:
                print(f"  skipped {pcap} (empty csv)")
                continue
            if df.empty:
                print(f"  {run_id}: 0 flows")
                continue

            if label == "benign":
                df["label"] = "benign"
            elif args.single_laptop:
                df["label"] = label_single_laptop(df, label)
            else:
                if not args.attacker_ip:
                    raise SystemExit(
                        f"Folder '{label}' needs --attacker-ip (or --single-laptop) to label attack flows."
                    )
                ip = args.attacker_ip
                is_attack = (df.get("src_ip") == ip) | (df.get("dst_ip") == ip)
                df["label"] = is_attack.map({True: label, False: "benign"})

            df["run_id"] = run_id
            df["source_pcap"] = str(pcap)
            frames.append(df)
            print(f"  {run_id}: {len(df)} flows ({df['label'].value_counts().to_dict()})")

    if not frames:
        raise SystemExit("No flows produced. Capture pcaps into data/captured/<label>/ first.")

    merged = pd.concat(frames, ignore_index=True)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    merged.to_parquet(out, index=False)
    print(f"\nMerged {len(merged)} flows -> {out}")
    print("label counts:\n", merged["label"].value_counts())
    print("run_ids:", sorted(merged["run_id"].unique()))


if __name__ == "__main__":
    main()
