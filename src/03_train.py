"""HomeGuard AI - Step 4: Phase A training on the public CIC-IDS2017 dataset.

Phase A PROVES THE PIPELINE. The model it produces is trained on Java-CICFlowMeter
features and may NOT match the Python cicflowmeter output that runs live, so it is
NOT the deployed model. The deployed model comes from Phase B (src/04_train_lab.py).

What it does:
  - map raw labels to {benign, portscan, bruteforce, dos}
  - downsample benign to ~200k, class_weight="balanced"
  - drop identifier columns (IPs, flow id, timestamp, source port)
  - train WITH and WITHOUT destination port and compare macro-F1
  - use common features if overlap >= 40 (reports/common_features.json), else all numeric
  - save per-class report + confusion matrix, models/rf_phaseA.joblib, models/features_phaseA.json

Usage:
    python src/03_train.py
    python src/03_train.py --path data/raw/Network-Flows/CICIDS_Flow.parquet --benign-cap 200000
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import trainer  # noqa: E402


def find_parquet(explicit):
    if explicit:
        return Path(explicit)
    cands = sorted(Path("data/raw").rglob("*.parquet"))
    if not cands:
        raise SystemExit("No parquet under data/raw. Run src/01_download.py first.")
    return cands[0]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=None)
    ap.add_argument("--benign-cap", type=int, default=200_000)
    ap.add_argument("--common", default="reports/common_features.json")
    ap.add_argument("--reports", default="reports")
    args = ap.parse_args()

    import pandas as pd

    path = find_parquet(args.path)
    print(f"Loading {path} ...")
    df = pd.read_parquet(path)

    label_col = next((c for c in df.columns if c.lower() == "label"), None)
    if label_col is None:
        raise SystemExit("No 'label' column found. Check reports/dataset_columns.txt.")

    df["cls"] = df[label_col].map(trainer.map_label)
    before = len(df)
    df = df.dropna(subset=["cls"])
    print(f"Rows kept after label mapping: {len(df):,} / {before:,}")
    print("Class distribution:\n", df["cls"].value_counts())

    benign = df[df.cls == "benign"]
    if len(benign) > args.benign_cap:
        benign = benign.sample(args.benign_cap, random_state=42)
    df = pd.concat([benign, df[df.cls != "benign"]]).reset_index(drop=True)
    print(f"After benign downsample: {len(df):,} rows")

    common = None
    cpath = Path(args.common)
    if cpath.exists():
        common = json.loads(cpath.read_text()).get("normalized_common")

    results = {}
    best = None
    for include_dst in (True, False):
        tag = "with_dstport" if include_dst else "no_dstport"
        feats = trainer.select_feature_columns(df, common, include_dst_port=include_dst)
        print(f"\n=== Phase A [{tag}] : {len(feats)} features ===")
        X = trainer.clean_X(df, feats)
        model, text, macro_f1 = trainer.train_and_report(
            X, df["cls"], report_prefix=f"phaseA_{tag}", reports_dir=Path(args.reports)
        )
        results[tag] = {"features": len(feats), "macro_f1": round(float(macro_f1), 4)}
        if best is None or macro_f1 >= best[0]:
            best = (macro_f1, feats, model, tag)

    print("\n=== destination-port comparison (macro-F1) ===")
    print(json.dumps(results, indent=2))
    Path(args.reports, "phaseA_dstport_comparison.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )

    # Deploy the WITH-dstport variant as the canonical Phase A model (full feature set),
    # but report both so a port-only shallow model is visible.
    _, feats, model, tag = best
    trainer.save_model(
        model, feats, Path("models/rf_phaseA.joblib"), Path("models/features_phaseA.json")
    )
    print(f"\nSaved best Phase A variant: {tag}")
    print("REMINDER: Phase A is pipeline validation only. Deploy Phase B (rf_v1) live.")


if __name__ == "__main__":
    main()
