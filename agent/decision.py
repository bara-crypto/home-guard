"""HomeGuard AI - decision engine.

For each flow the RF classifies, decide what to do:

  label == benign?
    -> Isolation Forest verifies: anomaly => UNKNOWN THREAT (notify);
       normal => benign, silent.
  label is an attack (portscan/bruteforce/dos)?
    confidence >= confirm_threshold -> KNOWN THREAT: ask to confirm (email/telegram).
       "Yes" (or timeout auto-remediate) -> block the attacker IP ("drop the packet").
    confidence <  confirm_threshold -> Isolation Forest verifies:
       anomaly => UNKNOWN THREAT (notify); normal => benign, silent.

A per-(ip, category) cooldown stops an attack's many flows from sending a flood of
alerts. Pending confirmations expire after confirm_timeout_seconds; if
auto_remediate_on_timeout is set, they are then remediated automatically.

No data leaves the machine (no cloud) - unknown threats are only reported locally
and by email/telegram, as requested.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import remediate

ROOT = Path(__file__).resolve().parent.parent
DECISION_LOG = ROOT / "logs" / "decisions.jsonl"

ATTACK_DESCRIPTIONS = {
    "portscan": "Port scan — many connection attempts across different ports in a short time.",
    "bruteforce": "Brute-force login attempts — repeated password guesses (e.g. FTP/SSH).",
    "dos": "Denial-of-service — a flood of requests intended to overwhelm a service.",
    "unknown": "Anomalous traffic that does not match learned normal behaviour.",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DecisionEngine:
    def __init__(self, settings: dict, notifier, model_dir: Path):
        self.s = settings
        self.notifier = notifier
        self.model_dir = Path(model_dir)
        self.threshold = float(settings.get("confirm_threshold", 0.80))
        self.cooldown = float(settings.get("notify_cooldown_seconds", 300))
        self.confirm_timeout = float(settings.get("confirm_timeout_seconds", 120))
        self.auto_remediate = bool(settings.get("auto_remediate_on_timeout", False))
        self.remediation = settings.get("remediation", {"enabled": True, "dry_run": True})

        self._lock = threading.Lock()
        self._cooldowns: dict[tuple, float] = {}     # (ip, category) -> last notify monotonic
        self.pending: dict[str, dict] = {}           # token -> record
        self.iforest = None
        self.iforest_features: list[str] | None = None
        self._load_iforest()

    # ---------------- isolation forest ----------------
    def _load_iforest(self) -> None:
        import joblib

        mfile = self.model_dir / "iforest.joblib"
        ffile = self.model_dir / "iforest_features.json"
        # fall back to the RF feature list (same features used at train time)
        if not ffile.exists():
            ffile = self.model_dir / "features.json"
        if mfile.exists() and ffile.exists():
            try:
                self.iforest = joblib.load(mfile)
                self.iforest_features = json.loads(ffile.read_text())
                print(f"[decision] loaded isolation forest ({len(self.iforest_features)} features)")
            except Exception as e:
                print(f"[decision] WARNING: could not load isolation forest: {e}")
        else:
            print("[decision] no isolation forest model; uncertain flows -> reported as unknown")

    def _is_anomaly(self, flow: dict) -> bool | None:
        """True=anomaly, False=normal, None=IF unavailable."""
        if self.iforest is None or not self.iforest_features:
            return None
        import numpy as np
        import pandas as pd

        X = pd.DataFrame([flow]).reindex(columns=self.iforest_features)
        X = X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], 0).fillna(0)
        try:
            return int(self.iforest.predict(X)[0]) == -1
        except Exception as e:
            print(f"[decision] IF predict error: {e}")
            return None

    # ---------------- helpers ----------------
    def _cooled_down(self, ip: str, category: str) -> bool:
        """Return True if we should SUPPRESS (still within cooldown window)."""
        key = (ip, category)
        now = time.monotonic()
        last = self._cooldowns.get(key)
        if last is not None and (now - last) < self.cooldown:
            return True
        self._cooldowns[key] = now
        return False

    def _log(self, rec: dict) -> None:
        DECISION_LOG.parent.mkdir(parents=True, exist_ok=True)
        with DECISION_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")

    # ---------------- main entry ----------------
    def handle(self, flow: dict, label: str, confidence: float, confirm_base: str) -> dict:
        src = flow.get("src_ip")
        dst = flow.get("dst_ip")
        rec = {"ts": _now_iso(), "src_ip": src, "dst_ip": dst,
               "rf_label": label, "confidence": round(float(confidence), 3)}

        with self._lock:
            if label == "benign":
                anomaly = self._is_anomaly(flow)
                if anomaly:
                    outcome = self._emit_unknown(flow, rec, reason="benign-labelled but IF flagged anomaly")
                else:
                    outcome = {"outcome": "benign_silent",
                               "note": "benign (IF normal)" if anomaly is False else "benign (IF n/a)"}
            else:
                if confidence >= self.threshold:
                    outcome = self._emit_confirm(flow, label, confidence, rec, confirm_base)
                else:
                    anomaly = self._is_anomaly(flow)
                    if anomaly is False:
                        outcome = {"outcome": "benign_silent",
                                   "note": f"{label}<{self.threshold:.0%} and IF says normal"}
                    else:  # anomaly True, or IF unavailable -> report as unknown
                        why = "low-confidence attack, IF anomaly" if anomaly else \
                              "low-confidence attack, IF unavailable"
                        outcome = self._emit_unknown(flow, rec, reason=why)

        rec.update(outcome)
        self._log(rec)
        return rec

    def _emit_confirm(self, flow, label, confidence, rec, confirm_base) -> dict:
        src = flow.get("src_ip")
        if self._cooled_down(src, label):
            return {"outcome": "known_threat_confirm", "notified": False,
                    "note": "suppressed by cooldown (already alerted for this source)"}
        token = secrets.token_urlsafe(8)
        self.pending[token] = {
            "token": token, "src_ip": src, "dst_ip": flow.get("dst_ip"),
            "label": label, "confidence": round(float(confidence), 3),
            "created": time.monotonic(), "created_iso": _now_iso(), "status": "pending",
        }
        desc = ATTACK_DESCRIPTIONS.get(label, label)
        subject = f"[HomeGuard] {label.upper()} detected ({confidence:.0%} confidence)"
        body = (f"HomeGuard detected a likely {label.upper()} attack.\n\n"
                f"Attacker IP : {src}\nTarget IP   : {flow.get('dst_ip')}\n"
                f"Confidence  : {confidence:.1%}\nWhat it is  : {desc}\n\n"
                f"Approve to DROP all traffic from {src} (block its IP). "
                f"If you don't respond within {int(self.confirm_timeout)}s, "
                f"{'the system will auto-remediate.' if self.auto_remediate else 'no action is taken.'}")
        confirm_url = f"{confirm_base}/confirm?token={token}&action=yes"
        ignore_url = f"{confirm_base}/confirm?token={token}&action=no"
        self.notifier.send_telegram(
            f"<b>{subject}</b>\n\nAttacker: <code>{src}</code>\nTarget: <code>{flow.get('dst_ip')}</code>\n"
            f"Confidence: {confidence:.1%}\n{desc}\n\nApprove to drop traffic from {src}.",
            token=token,
        )
        self.notifier.send_email(subject, body, confirm_url=confirm_url, ignore_url=ignore_url)
        return {"outcome": "known_threat_confirm", "notified": True, "token": token}

    def _emit_unknown(self, flow, rec, reason: str) -> dict:
        src = flow.get("src_ip")
        if self._cooled_down(src, "unknown"):
            return {"outcome": "unknown_threat", "notified": False,
                    "note": "suppressed by cooldown", "reason": reason}
        subject = "[HomeGuard] UNKNOWN THREAT detected"
        body = (f"HomeGuard saw traffic it cannot classify as a known attack, but it is "
                f"NOT normal.\n\nSource IP : {src}\nTarget IP : {flow.get('dst_ip')}\n"
                f"Reason    : {reason}\n\n{ATTACK_DESCRIPTIONS['unknown']}\n\n"
                f"No automatic action taken. This is informational only "
                f"(not sent to the cloud).")
        self.notifier.send_telegram(
            f"<b>{subject}</b>\n\nSource: <code>{src}</code>\nTarget: <code>{flow.get('dst_ip')}</code>\n"
            f"Reason: {reason}\nUnknown/anomalous traffic. No auto-action.")
        self.notifier.send_email(subject, body)
        return {"outcome": "unknown_threat", "notified": True, "reason": reason}

    # ---------------- confirmation + timeout ----------------
    def confirm(self, token: str, approve: bool) -> dict:
        with self._lock:
            p = self.pending.get(token)
            if p is None:
                return {"status": "not_found", "token": token}
            if p["status"] != "pending":
                return {"status": "already_" + p["status"], "token": token, "ip": p["src_ip"]}
            if not approve:
                p["status"] = "ignored"
                return {"status": "ignored", "token": token, "ip": p["src_ip"]}
            p["status"] = "confirmed"
            ip = p["src_ip"]
        result = remediate.block_ip(ip, dry_run=self.remediation.get("dry_run", True),
                                    enabled=self.remediation.get("enabled", True))
        return {"status": "confirmed", "token": token, "ip": ip, "remediation": result}

    def reap_expired(self) -> list[dict]:
        """Expire pending confirmations past the timeout; auto-remediate if configured."""
        out = []
        now = time.monotonic()
        to_act = []
        with self._lock:
            for token, p in self.pending.items():
                if p["status"] == "pending" and (now - p["created"]) >= self.confirm_timeout:
                    p["status"] = "auto_remediated" if self.auto_remediate else "expired"
                    to_act.append((token, dict(p)))
        for token, p in to_act:
            if self.auto_remediate:
                res = remediate.block_ip(p["src_ip"], dry_run=self.remediation.get("dry_run", True),
                                         enabled=self.remediation.get("enabled", True))
                out.append({"token": token, "ip": p["src_ip"], "status": "auto_remediated",
                            "remediation": res})
            else:
                out.append({"token": token, "ip": p["src_ip"], "status": "expired"})
        return out
