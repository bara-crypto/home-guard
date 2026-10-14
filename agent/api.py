"""HomeGuard AI - Step 7: FastAPI inference agent (runs on Laptop A).

Endpoints:
  GET  /health   -> {status, model, features, loaded}
  POST /predict  -> accepts ONE flow dict (the shape cicflowmeter's HttpWriter POSTs:
                    json=<single flow dict>) OR a JSON list of flow dicts.
                    Returns [{label, confidence, src_ip, dst_ip, ts}].
                    Appends every verdict to logs/verdicts.jsonl.

Model dir resolves models/rf_v1.joblib + models/features.json (Phase B / live) and
falls back to models/rf_phaseA.joblib + models/features_phaseA.json if that is all
that exists. Set HOMEGUARD_MODEL_DIR to override.

Run standalone:
    uvicorn agent.api:app --host 127.0.0.1 --port 8001
(run_agent.py launches this for you.)
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request

ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = Path(os.environ.get("HOMEGUARD_MODEL_DIR", ROOT / "models"))
LOG_PATH = Path(os.environ.get("HOMEGUARD_VERDICT_LOG", ROOT / "logs" / "verdicts.jsonl"))

app = FastAPI(title="HomeGuard AI agent")

_STATE: dict[str, Any] = {"model": None, "features": None, "model_file": None}


def _resolve_model() -> tuple[Path, Path] | None:
    pairs = [
        (MODEL_DIR / "rf_v1.joblib", MODEL_DIR / "features.json"),
        (MODEL_DIR / "rf_phaseA.joblib", MODEL_DIR / "features_phaseA.json"),
    ]
    for model_file, feat_file in pairs:
        if model_file.exists() and feat_file.exists():
            return model_file, feat_file
    return None


def load_model() -> None:
    import joblib

    resolved = _resolve_model()
    if resolved is None:
        print(f"[agent] WARNING: no model found in {MODEL_DIR}. /predict will error until one exists.")
        return
    model_file, feat_file = resolved
    _STATE["model"] = joblib.load(model_file)
    _STATE["features"] = json.loads(feat_file.read_text())
    _STATE["model_file"] = str(model_file)
    print(f"[agent] loaded {model_file} with {len(_STATE['features'])} features")


@app.on_event("startup")
def _startup() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    load_model()


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "model": _STATE.get("model_file"),
        "features": len(_STATE["features"]) if _STATE.get("features") else 0,
        "loaded": _STATE.get("model") is not None,
    }


def _predict_rows(flows: list[dict]) -> list[dict]:
    import numpy as np
    import pandas as pd

    model = _STATE.get("model")
    feats = _STATE.get("features")
    if model is None or feats is None:
        raise RuntimeError("No model loaded. Train Phase B (rf_v1) or Phase A first.")

    df = pd.DataFrame(flows)
    X = df.reindex(columns=feats)
    X = X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], 0).fillna(0)

    proba = model.predict_proba(X)
    classes = list(model.classes_)
    ts = datetime.now(timezone.utc).isoformat()
    out = []
    for i, row in enumerate(proba):
        j = int(row.argmax())
        out.append({
            "label": str(classes[j]),
            "confidence": round(float(row[j]), 3),
            "src_ip": flows[i].get("src_ip"),
            "dst_ip": flows[i].get("dst_ip"),
            "ts": ts,
        })
    return out


@app.post("/predict")
async def predict(request: Request):
    payload = await request.json()
    if isinstance(payload, dict):
        flows = [payload]
    elif isinstance(payload, list):
        flows = payload
    else:
        return {"error": "payload must be a flow dict or a list of flow dicts"}

    verdicts = _predict_rows(flows)

    with LOG_PATH.open("a", encoding="utf-8") as fh:
        for v in verdicts:
            fh.write(json.dumps(v) + "\n")
    return verdicts
