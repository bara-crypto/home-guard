"""HomeGuard AI - FastAPI inference + decision agent (runs on Laptop A).

Endpoints:
  GET  /health            model + isolation-forest + channel status
  POST /predict           one flow dict (cicflowmeter's POST shape) or a list.
                          Classifies, runs the decision engine (notify / confirm /
                          remediate / isolation-forest), logs verdicts, returns
                          [{label, confidence, src_ip, dst_ip, ts, outcome}].
  GET  /confirm?token=..&action=yes|no   confirm-link target (email buttons).
  GET  /pending           current pending confirmations.

A background reaper expires pending confirmations after confirm_timeout_seconds
(auto-remediating if configured). If Telegram is enabled, a background poller
handles the inline Yes/No button callbacks.

Model: models/rf_v1.joblib + features.json (Phase B / live), else rf_phaseA.*.
Isolation forest: models/iforest.joblib (+ iforest_features.json or features.json).
Set HOMEGUARD_MODEL_DIR to override the models directory.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from agent.decision import DecisionEngine
from agent.notify import Notifier
from agent.settings import load_settings

ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = Path(os.environ.get("HOMEGUARD_MODEL_DIR", ROOT / "models"))
LOG_PATH = Path(os.environ.get("HOMEGUARD_VERDICT_LOG", ROOT / "logs" / "verdicts.jsonl"))

app = FastAPI(title="HomeGuard AI agent")

_STATE: dict[str, Any] = {"model": None, "features": None, "model_file": None,
                          "settings": None, "notifier": None, "engine": None,
                          "trigger_gate": False, "alert_window_secs": 300.0,
                          "armed_until": float("inf")}


def _armed() -> bool:
    """True when detection/alerting is active.

    With the lure-trigger gate OFF (the default, e.g. tests / 2-laptop), the agent
    is always armed. With it ON, the agent stays quiet until POST /arm is called
    (run_agent.py calls it when the lure website is actually triggered)."""
    if not _STATE.get("trigger_gate"):
        return True
    return time.time() <= float(_STATE.get("armed_until", 0.0))


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


def _reaper_loop() -> None:
    engine: DecisionEngine = _STATE["engine"]
    while True:
        time.sleep(5)
        try:
            acted = engine.reap_expired()
            for a in acted:
                print("[agent] timeout -> " + json.dumps(a))
        except Exception as e:
            print(f"[agent] reaper error: {e}")


def _telegram_poll_loop() -> None:
    """Handle inline Yes/No callbacks. No inbound server needed."""
    engine: DecisionEngine = _STATE["engine"]
    tg = _STATE["settings"]["telegram"]
    token = tg["bot_token"]
    base = f"https://api.telegram.org/bot{token}"
    offset = None
    print("[agent] telegram poller started")
    while True:
        try:
            params = {"timeout": 30}
            if offset is not None:
                params["offset"] = offset
            r = requests.get(base + "/getUpdates", params=params, timeout=40)
            for upd in r.json().get("result", []):
                offset = upd["update_id"] + 1
                cq = upd.get("callback_query")
                if not cq:
                    continue
                data = cq.get("data", "")
                approve = data.startswith("confirm:")
                tok = data.split(":", 1)[1] if ":" in data else ""
                res = engine.confirm(tok, approve)
                answer = ("Dropping traffic from %s" % res.get("ip")) if approve else "Ignored"
                try:
                    requests.post(base + "/answerCallbackQuery",
                                  json={"callback_query_id": cq["id"], "text": answer}, timeout=10)
                    msg = cq.get("message", {})
                    if msg:
                        requests.post(base + "/editMessageText", json={
                            "chat_id": msg["chat"]["id"], "message_id": msg["message_id"],
                            "text": msg.get("text", "") + f"\n\n— {answer} ({res.get('status')})"},
                            timeout=10)
                except Exception:
                    pass
        except Exception as e:
            print(f"[agent] telegram poll error: {e}")
            time.sleep(5)


@app.on_event("startup")
def _startup() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    load_model()
    settings = load_settings()
    notifier = Notifier(settings)
    engine = DecisionEngine(settings, notifier, MODEL_DIR)
    gate = bool(settings.get("trigger_gate", False))
    _STATE.update(settings=settings, notifier=notifier, engine=engine,
                  trigger_gate=gate,
                  alert_window_secs=float(settings.get("alert_window_seconds", 300)),
                  armed_until=0.0 if gate else float("inf"))
    if gate:
        print("[agent] lure-trigger gate ON: staying quiet until the lure is triggered.")

    threading.Thread(target=_reaper_loop, daemon=True).start()
    if notifier.telegram_enabled():
        threading.Thread(target=_telegram_poll_loop, daemon=True).start()


@app.get("/health")
def health() -> dict:
    eng: DecisionEngine | None = _STATE.get("engine")
    notifier: Notifier | None = _STATE.get("notifier")
    return {
        "status": "ok",
        "model": _STATE.get("model_file"),
        "features": len(_STATE["features"]) if _STATE.get("features") else 0,
        "loaded": _STATE.get("model") is not None,
        "isolation_forest": bool(eng and eng.iforest is not None),
        "confirm_threshold": eng.threshold if eng else None,
        "trigger_gate": bool(_STATE.get("trigger_gate")),
        "armed": _armed(),
        "channels": {
            "email": bool(notifier and notifier.email_enabled()),
            "telegram": bool(notifier and notifier.telegram_enabled()),
        },
        "remediation": _STATE["settings"]["remediation"] if _STATE.get("settings") else None,
    }


def _predict_rows(flows: list[dict]) -> list[dict]:
    import numpy as np
    import pandas as pd

    model = _STATE.get("model")
    feats = _STATE.get("features")
    if model is None or feats is None:
        raise RuntimeError("No model loaded. Train Phase B (rf_v1) or Phase A first.")

    df = pd.DataFrame(flows)
    X = df.reindex(columns=feats).apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], 0).fillna(0)

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


def _confirm_base(request: Request) -> str:
    pub = (_STATE.get("settings") or {}).get("api_public_base") or ""
    if pub:
        return pub.rstrip("/")
    return str(request.base_url).rstrip("/")


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
    engine: DecisionEngine | None = _STATE.get("engine")
    base = _confirm_base(request)
    armed = _armed()

    with LOG_PATH.open("a", encoding="utf-8") as fh:
        for v, flow in zip(verdicts, flows):
            if engine is not None and armed:
                decision = engine.handle(flow, v["label"], v["confidence"], base)
                v["outcome"] = decision.get("outcome")
                if decision.get("token"):
                    v["token"] = decision["token"]
                if decision.get("if_result"):
                    v["if_result"] = decision["if_result"]
                if decision.get("cloud"):
                    v["cloud"] = decision["cloud"]
            else:
                # Lure-trigger gate: not armed yet -> record quietly, no action.
                v["outcome"] = "quiet_until_trigger"
            fh.write(json.dumps(v) + "\n")
    return verdicts


@app.post("/arm")
def arm(window: float | None = None):
    """Arm detection for the next `window` seconds (called when the lure triggers).

    No-op effect when the trigger gate is disabled (the agent is always armed)."""
    win = float(window) if window is not None else float(_STATE.get("alert_window_secs", 300))
    _STATE["armed_until"] = time.time() + win
    print(f"[agent] armed for {int(win)}s (lure trigger)")
    return {"armed": True, "armed_until": _STATE["armed_until"], "window": win,
            "trigger_gate": bool(_STATE.get("trigger_gate"))}


@app.get("/confirm", response_class=HTMLResponse)
def confirm(token: str, action: str = "yes"):
    engine: DecisionEngine | None = _STATE.get("engine")
    if engine is None:
        return HTMLResponse("<h3>Agent not ready</h3>", status_code=503)
    approve = str(action).lower() in ("yes", "y", "true", "1", "confirm")
    res = engine.confirm(token, approve)
    status = res.get("status")
    color = "#c0392b" if approve else "#7f8c8d"
    msg = {
        "confirmed": f"Confirmed. Blocking traffic from {res.get('ip')}.",
        "ignored": "Ignored. No action taken.",
        "not_found": "This confirmation link is unknown or has expired.",
    }.get(status, f"Status: {status}")
    rem = res.get("remediation")
    detail = f"<pre>{json.dumps(rem, indent=2)}</pre>" if rem else ""
    return HTMLResponse(
        f"<html><body style='font-family:sans-serif'>"
        f"<h2 style='color:{color}'>HomeGuard</h2><p>{msg}</p>{detail}</body></html>")


@app.get("/pending")
def pending() -> dict:
    engine: DecisionEngine | None = _STATE.get("engine")
    if engine is None:
        return {"pending": []}
    return {"pending": [
        {k: v for k, v in p.items() if k != "created"} for p in engine.pending.values()
    ]}
