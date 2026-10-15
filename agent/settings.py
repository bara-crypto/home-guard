"""HomeGuard AI - agent configuration loader.

Merge order (later wins): built-in defaults <- agent/config.json <- environment vars.

Nothing here contains real secrets. Copy agent/config.example.json to
agent/config.json (gitignored) and fill in SMTP / Telegram credentials, or set
the HOMEGUARD_* environment variables. With nothing configured, the notifier
runs in log-only mode so the pipeline is fully testable without any secrets.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("HOMEGUARD_CONFIG", HERE / "config.json"))

DEFAULTS = {
    "confirm_threshold": 0.80,          # RF confidence at/above which we ask to confirm+drop
    "notify_cooldown_seconds": 300,     # suppress repeat alerts for same (ip, category)
    "confirm_timeout_seconds": 120,     # wait this long for a Yes before auto-remediating
    "auto_remediate_on_timeout": False, # product vision: confirm-first, auto-fix on timeout
    "remediation": {"enabled": True, "dry_run": True},  # dry_run=True -> log only, never block
    # Local dashboard UI (auto-started by run_agent.py). Login is username-only:
    # the username must equal this machine's router (default-gateway) IP.
    "dashboard": {"enabled": True, "host": "127.0.0.1", "port": 8010},
    # Lure-trigger gate (single-laptop demo). When enabled, the agent stays QUIET
    # (no alerts / notifications / dashboard entries) until the lure website is
    # actually triggered by the user. run_agent.py enables this for its API child.
    "trigger_gate": False,
    "alert_window_seconds": 300,        # how long after a lure trigger detection stays active
    "lure_log": str(HERE.parent / "hacker" / "lure_log.jsonl"),  # watched for "attack_launched"
    "email": {
        "enabled": False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 465,               # SSL
        "user": "",
        "password": "",                 # Gmail: use an App Password, not your login password
        "from": "",
        "to": "balac6796@gmail.com",    # sample alert recipient
    },
    "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
    # Public base URL the agent is reachable at, used in email confirm links
    # (e.g. http://192.168.1.50:8001). Empty -> links use the request's own base.
    "api_public_base": "",
}


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _env_overrides() -> dict:
    e = os.environ
    o: dict = {"email": {}, "telegram": {}, "remediation": {}, "dashboard": {}}

    def setif(key, cast=str):
        if key in e and e[key] != "":
            return cast(e[key])
        return None

    def _bool(s): return str(s).strip().lower() in ("1", "true", "yes", "on")

    for env_key, (section, field, cast) in {
        "HOMEGUARD_CONFIRM_THRESHOLD": (None, "confirm_threshold", float),
        "HOMEGUARD_AUTO_REMEDIATE": (None, "auto_remediate_on_timeout", _bool),
        "HOMEGUARD_REMEDIATE_DRYRUN": ("remediation", "dry_run", _bool),
        "HOMEGUARD_REMEDIATE_ENABLED": ("remediation", "enabled", _bool),
        "HOMEGUARD_EMAIL_ENABLED": ("email", "enabled", _bool),
        "HOMEGUARD_SMTP_HOST": ("email", "smtp_host", str),
        "HOMEGUARD_SMTP_PORT": ("email", "smtp_port", int),
        "HOMEGUARD_SMTP_USER": ("email", "user", str),
        "HOMEGUARD_SMTP_PASS": ("email", "password", str),
        "HOMEGUARD_EMAIL_FROM": ("email", "from", str),
        "HOMEGUARD_EMAIL_TO": ("email", "to", str),
        "HOMEGUARD_TELEGRAM_ENABLED": ("telegram", "enabled", _bool),
        "HOMEGUARD_TELEGRAM_TOKEN": ("telegram", "bot_token", str),
        "HOMEGUARD_TELEGRAM_CHAT": ("telegram", "chat_id", str),
        "HOMEGUARD_API_PUBLIC_BASE": (None, "api_public_base", str),
        "HOMEGUARD_DASHBOARD_ENABLED": ("dashboard", "enabled", _bool),
        "HOMEGUARD_DASHBOARD_HOST": ("dashboard", "host", str),
        "HOMEGUARD_DASHBOARD_PORT": ("dashboard", "port", int),
        "HOMEGUARD_TRIGGER_GATE": (None, "trigger_gate", _bool),
        "HOMEGUARD_ALERT_WINDOW_SECS": (None, "alert_window_seconds", float),
        "HOMEGUARD_LURE_LOG": (None, "lure_log", str),
    }.items():
        val = setif(env_key, cast)
        if val is None:
            continue
        if section is None:
            o[field] = val
        else:
            o[section][field] = val
    # auto-enable a channel if its credentials arrive via env
    if o["telegram"].get("bot_token") and "enabled" not in o["telegram"]:
        o["telegram"]["enabled"] = True
    if o["email"].get("user") and o["email"].get("password") and "enabled" not in o["email"]:
        o["email"]["enabled"] = True
    return o


def load_settings() -> dict:
    cfg = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        try:
            cfg = _deep_merge(cfg, json.loads(CONFIG_PATH.read_text()))
        except Exception as e:  # malformed config must not crash the agent
            print(f"[settings] WARNING: could not read {CONFIG_PATH}: {e}")
    cfg = _deep_merge(cfg, _env_overrides())
    return cfg


if __name__ == "__main__":
    # Print the effective config with secrets masked.
    s = load_settings()
    red = json.loads(json.dumps(s))
    if red["email"].get("password"):
        red["email"]["password"] = "***"
    if red["telegram"].get("bot_token"):
        red["telegram"]["bot_token"] = "***"
    print(json.dumps(red, indent=2))
