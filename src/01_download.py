"""HomeGuard AI - Step 2: download the public CIC-IDS2017 Network-Flows parquet.

Public dataset: rdpahalavan/CIC-IDS2017, file Network-Flows/CICIDS_Flow.parquet
(~370 MB, 24 labels). Used for Phase A only (pipeline validation).

Usage:
    python src/01_download.py
    python src/01_download.py --repo rdpahalavan/CIC-IDS2017 --file Network-Flows/CICIDS_Flow.parquet
"""
import argparse
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser(description="Download CIC-IDS2017 Network-Flows parquet from Hugging Face.")
    ap.add_argument("--repo", default="rdpahalavan/CIC-IDS2017")
    ap.add_argument("--file", default="Network-Flows/CICIDS_Flow.parquet")
    ap.add_argument("--out", default="data/raw", help="local_dir to download into")
    args = ap.parse_args()

    from huggingface_hub import hf_hub_download

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {args.repo} :: {args.file} -> {out} (this is ~370 MB, be patient)")
    path = hf_hub_download(
        repo_id=args.repo,
        filename=args.file,
        repo_type="dataset",
        local_dir=str(out),
    )
    p = Path(path)
    size_mb = p.stat().st_size / (1024 * 1024) if p.exists() else 0
    print(f"Done. Saved to: {p}  ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
