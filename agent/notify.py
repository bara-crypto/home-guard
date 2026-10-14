"""HomeGuard AI - notifications (email + Telegram).

Both channels are optional and config-driven (see agent/settings.py). When a
channel is not configured, its send() returns False and the message is logged to
logs/notifications.jsonl, so the whole pipeline is testable with no secrets.

Telegram is the recommended CONFIRM channel: a message with inline [Yes, drop it]
/ [No, ignore] buttons, handled by a polling loop (no inbound server needed).
Email includes clickable Confirm/Ignore links that hit the agent's /confirm
endpoint (requires the agent reachable from where you read mail; see docs).
"""
from __future__ import annotations

import json
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
LOG = ROOT / "logs" / "notifications.jsonl"
TG_API = "https://api.telegram.org"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(rec: dict) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


class Notifier:
    def __init__(self, settings: dict):
        self.s = settings
        self.email_cfg = settings.get("email", {})
        self.tg_cfg = settings.get("telegram", {})

    # ---------------- email ----------------
    def email_enabled(self) -> bool:
        c = self.email_cfg
        return bool(c.get("enabled") and c.get("user") and c.get("password") and c.get("to"))

    def send_email(self, subject: str, body: str, confirm_url: str | None = None,
                   ignore_url: str | None = None) -> bool:
        html = body.replace("\n", "<br>")
        if confirm_url:
            html += (f'<br><br><a href="{confirm_url}" '
                     'style="padding:10px 16px;background:#c0392b;color:#fff;'
                     'text-decoration:none;border-radius:6px">Yes, drop it</a>&nbsp;&nbsp;')
            if ignore_url:
                html += (f'<a href="{ignore_url}" '
                         'style="padding:10px 16px;background:#7f8c8d;color:#fff;'
                         'text-decoration:none;border-radius:6px">No, ignore</a>')
        rec = {"ts": _now(), "channel": "email", "subject": subject,
               "to": self.email_cfg.get("to"), "has_confirm": bool(confirm_url)}
        if not self.email_enabled():
            rec.update(status="log_only", body=body)
            _log(rec)
            print(f"[notify:email:log-only] {subject}")
            return False
        try:
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = self.email_cfg.get("from") or self.email_cfg["user"]
            msg["To"] = self.email_cfg["to"]
            msg.set_content(body)
            msg.add_alternative(f"<html><body>{html}</body></html>", subtype="html")
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.email_cfg["smtp_host"],
                                  int(self.email_cfg["smtp_port"]), context=ctx, timeout=15) as srv:
                srv.login(self.email_cfg["user"], self.email_cfg["password"])
                srv.send_message(msg)
            rec.update(status="sent")
            _log(rec)
            print(f"[notify:email] sent: {subject}")
            return True
        except Exception as e:
            rec.update(status="error", error=str(e))
            _log(rec)
            print(f"[notify:email] ERROR: {e}")
            return False

    # ---------------- telegram ----------------
    def telegram_enabled(self) -> bool:
        c = self.tg_cfg
        return bool(c.get("enabled") and c.get("bot_token") and c.get("chat_id"))

    def send_telegram(self, text: str, token: str | None = None) -> bool:
        """Send a Telegram message. If `token` is given, attach Yes/No inline buttons."""
        rec = {"ts": _now(), "channel": "telegram", "has_confirm": bool(token)}
        if not self.telegram_enabled():
            rec.update(status="log_only", text=text)
            _log(rec)
            print("[notify:telegram:log-only] " + text.splitlines()[0])
            return False
        url = f"{TG_API}/bot{self.tg_cfg['bot_token']}/sendMessage"
        payload: dict = {"chat_id": self.tg_cfg["chat_id"], "text": text, "parse_mode": "HTML"}
        if token:
            payload["reply_markup"] = {"inline_keyboard": [[
                {"text": "✅ Yes, drop it", "callback_data": f"confirm:{token}"},
                {"text": "🚫 No, ignore", "callback_data": f"deny:{token}"},
            ]]}
        try:
            r = requests.post(url, json=payload, timeout=10)
            ok = r.ok and r.json().get("ok", False)
            rec.update(status="sent" if ok else "error", resp=r.status_code)
            _log(rec)
            print(f"[notify:telegram] {'sent' if ok else 'error'}")
            return ok
        except Exception as e:
            rec.update(status="error", error=str(e))
            _log(rec)
            print(f"[notify:telegram] ERROR: {e}")
            return False
