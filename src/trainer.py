"""Shared training helpers for HomeGuard AI (Phase A and Phase B).

Keeps label mapping, identifier dropping, feature selection and reporting in one
place so Phase A (public dataset) and Phase B (own lab flows) behave identically.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

CLASSES = ("benign", "portscan", "bruteforce", "dos")

# Identifier-like columns that must never be features (would leak lab topology).
IDENTIFIER_NAMES = {
    "flow_id", "flowid", "fid",
    "source_ip", "destination_ip", "src_ip", "dst_ip", "sourceip", "destinationip",
    "source_port", "src_port", "sourceport",   # dst port handled separately (optional feature)
    "timestamp", "time", "date",
    "protocol_name", "label", "cls",
}


def normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def map_label(raw: str) -> str | None:
    """Map a raw dataset/lab label to one of the 4 HomeGuard classes (case-insensitive)."""
    l = str(raw).strip().lower()
    if l == "benign":
        return "benign"
    if "portscan" in l or "port scan" in l:
        return "portscan"
    if "patator" in l or "bruteforce" in l or "brute force" in l or "brute_force" in l:
        return "bruteforce"
    if l.startswith("dos") or "denial" in l or "hulk" in l or "goldeneye" in l or "slowloris" in l or "slowhttp" in l:
        return "dos"
    return None


def select_feature_columns(df, common_features: list[str] | None, include_dst_port: bool):
    """Return the list of numeric feature column names to train on."""
    norm_to_orig = {normalize(c): c for c in df.columns}
    drop = set(IDENTIFIER_NAMES)
    if not include_dst_port:
        drop |= {"destination_port", "dst_port", "destinationport"}

    numeric = df.select_dtypes("number").columns.tolist()
    candidates = [c for c in numeric if normalize(c) not in drop]

    if common_features and len(common_features) >= 40:
        keep = {normalize(c) for c in common_features}
        narrowed = [c for c in candidates if normalize(c) in keep]
        if len(narrowed) >= 40:
            return narrowed
    return candidates


def clean_X(df, feature_cols):
    import numpy as np

    X = df.reindex(columns=feature_cols).apply(
        lambda s: s if s.dtype.kind in "fiu" else s
    )
    X = X.replace([np.inf, -np.inf], 0).fillna(0)
    return X


def train_and_report(X, y, report_prefix: str, reports_dir: Path):
    """Train a RandomForest, print a per-class report, save a confusion matrix.

    Returns (model, text_report, macro_f1).
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.model_selection import train_test_split

    Xtr, Xte, ytr, yte = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(
        n_estimators=200, n_jobs=-1, class_weight="balanced", random_state=42
    ).fit(Xtr, ytr)
    pred = model.predict(Xte)
    text = classification_report(yte, pred, digits=3)
    print(text)

    reports_dir.mkdir(parents=True, exist_ok=True)
    labels = sorted(set(y))
    cm = confusion_matrix(yte, pred, labels=labels)
    _save_confusion(cm, labels, reports_dir / f"{report_prefix}_confusion.png",
                    reports_dir / f"{report_prefix}_confusion.txt")

    from sklearn.metrics import f1_score
    macro_f1 = f1_score(yte, pred, average="macro")
    return model, text, macro_f1


def _save_confusion(cm, labels, png_path: Path, txt_path: Path) -> None:
    # Always write a text version; PNG only if matplotlib is importable.
    header = "pred->  " + "  ".join(f"{l[:8]:>8}" for l in labels)
    rows = [header]
    for i, l in enumerate(labels):
        rows.append(f"{l[:7]:>7}  " + "  ".join(f"{cm[i][j]:>8}" for j in range(len(labels))))
    txt_path.write_text("\n".join(rows), encoding="utf-8")
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(5, 4))
        im = ax.imshow(cm, cmap="Blues")
        ax.set_xticks(range(len(labels)), labels, rotation=45, ha="right")
        ax.set_yticks(range(len(labels)), labels)
        ax.set_xlabel("predicted")
        ax.set_ylabel("true")
        for i in range(len(labels)):
            for j in range(len(labels)):
                ax.text(j, i, str(cm[i][j]), ha="center", va="center",
                        color="white" if cm[i][j] > cm.max() / 2 else "black")
        fig.colorbar(im)
        fig.tight_layout()
        fig.savefig(png_path, dpi=120)
        plt.close(fig)
    except Exception as e:  # matplotlib optional
        print(f"(confusion PNG skipped: {e}; text version at {txt_path})")


def save_model(model, feature_cols, model_path: Path, features_path: Path) -> None:
    import joblib

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    features_path.write_text(json.dumps(list(feature_cols), indent=2), encoding="utf-8")
    print(f"Saved model -> {model_path}")
    print(f"Saved features -> {features_path}")
