"""HomeGuard AI - Step 2: explore the downloaded dataset.

Prints columns, dtypes and label counts, and saves a column report to
reports/dataset_columns.txt so later steps never have to guess column names.

Usage:
    python src/02_explore.py
    python src/02_explore.py --path data/raw/Network-Flows/CICIDS_Flow.parquet
"""
import argparse
from pathlib import Path


def find_parquet(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    candidates = sorted(Path("data/raw").rglob("*.parquet"))
    if not candidates:
        raise SystemExit("No parquet found under data/raw. Run src/01_download.py first.")
    return candidates[0]


def main() -> None:
    ap = argparse.ArgumentParser(description="Explore the CIC-IDS2017 parquet.")
    ap.add_argument("--path", default=None, help="explicit parquet path (optional)")
    ap.add_argument("--report", default="reports/dataset_columns.txt")
    args = ap.parse_args()

    import pandas as pd

    path = find_parquet(args.path)
    print(f"Reading {path} ...")
    df = pd.read_parquet(path)
    print(f"Shape: {df.shape[0]:,} rows x {df.shape[1]} cols")

    label_col = next((c for c in df.columns if c.lower() == "label"), None)
    lines: list[str] = []
    lines.append(f"file: {path}")
    lines.append(f"shape: {df.shape[0]} rows x {df.shape[1]} cols")
    lines.append(f"label_column: {label_col}")
    lines.append("")
    lines.append("columns (name :: dtype):")
    for c in df.columns:
        lines.append(f"  {c} :: {df[c].dtype}")

    if label_col is not None:
        lines.append("")
        lines.append("label value counts:")
        for val, cnt in df[label_col].value_counts().items():
            lines.append(f"  {val} :: {cnt}")

    report = Path(args.report)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("\n".join(lines), encoding="utf-8")

    print("\n".join(lines[:60]))
    print(f"\nFull report written to {report}")


if __name__ == "__main__":
    main()
