"""HomeGuard AI - Step 7: minimal offline inference. CSV in, JSON out.

Loads models/rf_v1.joblib (+features.json), falls back to Phase A model, aligns
the CSV columns to the saved feature list and prints a JSON verdict per row.

Usage:
    python agent/infer.py flows.csv
    python agent/infer.py flows.csv --model-dir models
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def resolve(model_dir: Path):
    for m, f in [(model_dir / "rf_v1.joblib", model_dir / "features.json"),
                 (model_dir / "rf_phaseA.joblib", model_dir / "features_phaseA.json")]:
        if m.exists() and f.exists():
            return m, f
    raise SystemExit(f"No model found in {model_dir}. Train Phase B (--demo ok) or Phase A first.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--model-dir", default=str(ROOT / "models"))
    args = ap.parse_args()

    import joblib
    import numpy as np
    import pandas as pd

    mfile, ffile = resolve(Path(args.model_dir))
    model = joblib.load(mfile)
    feats = json.loads(Path(ffile).read_text())

    df = pd.read_csv(args.csv)
    X = df.reindex(columns=feats).apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], 0).fillna(0)
    proba = model.predict_proba(X)
    classes = list(model.classes_)

    out = []
    for i, row in enumerate(proba):
        j = int(row.argmax())
        out.append({
            "label": str(classes[j]),
            "confidence": round(float(row[j]), 3),
            "src_ip": df.iloc[i].get("src_ip") if "src_ip" in df.columns else None,
            "dst_ip": df.iloc[i].get("dst_ip") if "dst_ip" in df.columns else None,
        })
    json.dump(out, sys.stdout, indent=2, default=str)
    print()


if __name__ == "__main__":
    main()
