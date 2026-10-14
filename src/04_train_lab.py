"""HomeGuard AI - Step 6: Phase B training on OWN lab flows. THIS IS THE LIVE MODEL.

Trained on flows captured in the lab with the SAME extractor (Python cicflowmeter)
that runs live, so its features match the agent's input.

Split policy: train on run 1-2, test on run 3 (split by run_id, NEVER by random
rows) so near-duplicate flows from one capture session cannot inflate the score.

Outputs: per-class report + confusion matrix, models/rf_v1.joblib, models/features.json.

Usage:
    python src/04_train_lab.py                      # real lab data
    python src/04_train_lab.py --demo               # synthetic rows, clearly labelled DEMO
    python src/04_train_lab.py --data data/processed/lab_flows.parquet --test-run run3
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import trainer  # noqa: E402


def make_demo_frame():
    """Build a tiny clearly-synthetic dataset so the pipeline is testable with no captures.

    NOT a real model. Each class gets separable synthetic flow features across 3 runs.
    """
    import numpy as np
    import pandas as pd

    rng = np.random.default_rng(42)
    rows = []
    # (class, dst_port, duration_scale, pkts_scale, bytes_scale)
    profiles = {
        "benign":     (443, 5.0, 40, 3000),
        "portscan":   (0,   0.02, 2, 60),
        "bruteforce": (2121, 0.5, 12, 400),
        "dos":        (8080, 0.05, 300, 9000),
    }
    for cls, (port, dur, pk, by) in profiles.items():
        for run in (1, 2, 3):
            for _ in range(250):
                rows.append({
                    "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9",
                    "src_port": int(rng.integers(1024, 65535)),
                    "dst_port": port if port else int(rng.integers(1, 1024)),
                    "protocol": 6,
                    "timestamp": "2026-01-01 00:00:00",
                    "flow_duration": float(abs(rng.normal(dur, dur * 0.2 + 0.01))),
                    "tot_fwd_pkts": int(abs(rng.normal(pk, pk * 0.2 + 1))),
                    "tot_bwd_pkts": int(abs(rng.normal(pk * 0.5, pk * 0.1 + 1))),
                    "totlen_fwd_pkts": float(abs(rng.normal(by, by * 0.2 + 1))),
                    "totlen_bwd_pkts": float(abs(rng.normal(by * 0.4, by * 0.1 + 1))),
                    "flow_pkts_s": float(abs(rng.normal(pk / (dur + 0.01), 5))),
                    "flow_byts_s": float(abs(rng.normal(by / (dur + 0.01), 50))),
                    "label": cls,
                    "run_id": f"{cls}/run{run}",
                })
    return pd.DataFrame(rows)


def split_by_run(df, test_run: str):
    test_mask = df["run_id"].str.endswith("/" + test_run) | df["run_id"].str.endswith(test_run)
    return df[~test_mask], df[test_mask]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true", help="train on synthetic rows (DEMO only)")
    ap.add_argument("--data", default="data/processed/lab_flows.parquet")
    ap.add_argument("--test-run", default="run3")
    ap.add_argument("--reports", default="reports")
    args = ap.parse_args()

    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report, f1_score

    if args.demo:
        print("*** DEMO MODE: synthetic data, NOT a real detector. ***")
        df = make_demo_frame()
    else:
        p = Path(args.data)
        if not p.exists():
            raise SystemExit(f"{p} not found. Run lab/convert.py first, or use --demo.")
        df = pd.read_parquet(p)

    if "label" not in df.columns:
        raise SystemExit("No 'label' column in lab flows.")
    df["cls"] = df["label"].map(trainer.map_label)
    df = df.dropna(subset=["cls"])
    print("Class distribution:\n", df["cls"].value_counts())

    if "run_id" not in df.columns:
        raise SystemExit("No 'run_id' column; re-run lab/convert.py.")
    train_df, test_df = split_by_run(df, args.test_run)
    if train_df.empty or test_df.empty:
        raise SystemExit(
            f"Run split produced empty set (train={len(train_df)}, test={len(test_df)}). "
            f"Need runs other than {args.test_run} for training and {args.test_run} for test."
        )
    print(f"Train rows: {len(train_df)}  Test rows ({args.test_run}): {len(test_df)}")

    feats = trainer.select_feature_columns(df, common_features=None, include_dst_port=True)
    print(f"Features ({len(feats)}): {feats}")

    Xtr = trainer.clean_X(train_df, feats)
    Xte = trainer.clean_X(test_df, feats)
    model = RandomForestClassifier(
        n_estimators=200, n_jobs=-1, class_weight="balanced", random_state=42
    ).fit(Xtr, train_df["cls"])

    pred = model.predict(Xte)
    print(classification_report(test_df["cls"], pred, digits=3))
    macro_f1 = f1_score(test_df["cls"], pred, average="macro")

    labels = sorted(df["cls"].unique())
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(test_df["cls"], pred, labels=labels)
    prefix = "phaseB_demo" if args.demo else "phaseB"
    trainer._save_confusion(cm, labels, Path(args.reports) / f"{prefix}_confusion.png",
                            Path(args.reports) / f"{prefix}_confusion.txt")

    trainer.save_model(model, feats, Path("models/rf_v1.joblib"), Path("models/features.json"))

    # Isolation Forest: train on BENIGN flows from the train split only. The agent
    # uses it to verify low-confidence / benign-labelled flows (anomaly => unknown threat).
    benign_train = train_df[train_df["cls"] == "benign"]
    if len(benign_train) >= 20:
        if_X = trainer.clean_X(benign_train, feats)
        iforest = trainer.train_isolation_forest(if_X)
        trainer.save_iforest(iforest, feats, Path("models/iforest.joblib"),
                             Path("models/iforest_features.json"))
        # quick sanity: anomaly rate on held-out attack rows should be higher than on benign
        try:
            atk = test_df[test_df["cls"] != "benign"]
            ben = test_df[test_df["cls"] == "benign"]
            if len(atk) and len(ben):
                ar = (iforest.predict(trainer.clean_X(atk, feats)) == -1).mean()
                br = (iforest.predict(trainer.clean_X(ben, feats)) == -1).mean()
                print(f"Isolation Forest anomaly rate — attacks: {ar:.2f}, benign: {br:.2f}")
        except Exception as e:
            print(f"(IF sanity check skipped: {e})")
    else:
        print("Not enough benign rows to train an Isolation Forest (need >=20); skipped.")

    print(f"\nPhase B macro-F1 ({args.test_run} held out): {macro_f1:.3f}")
    if args.demo:
        print("*** DEMO model saved as rf_v1. Replace with a real capture before any demo. ***")
    else:
        print("rf_v1 is the LIVE model. Deploy it with the agent on Laptop A.")


if __name__ == "__main__":
    main()
