# HomeGuard AI — detection → notify → confirm → remediate pipeline

This is what the agent does with every flow after the Random Forest classifies it.

## Flow of decisions

```
RF classifies a flow → (label, confidence)

┌── label == benign ────────────────────────────────────────────────┐
│   Isolation Forest verifies the flow:                              │
│     anomaly  → UNKNOWN THREAT  → email/telegram "unknown threat"   │
│     normal   → benign, SILENT (normal process, no alert)           │
└────────────────────────────────────────────────────────────────────┘

┌── label is an attack (portscan / bruteforce / dos) ───────────────┐
│   confidence ≥ 80%  → KNOWN THREAT                                 │
│        → send confirm email + telegram (Yes / No)                  │
│        → "Yes"  → identify + DROP (block attacker IP)              │
│        → timeout → auto-remediate IF enabled, else no action       │
│   confidence < 80%  → uncertain → Isolation Forest verifies:       │
│        anomaly → UNKNOWN THREAT → email/telegram "unknown threat"  │
│        normal  → benign, SILENT                                    │
└────────────────────────────────────────────────────────────────────┘
```

- **Benign verified by Isolation Forest → no email, normal process.**
- **Known threat → confirm email; on "Yes" the packet source is dropped.**
- **Unknown threat → informational email only.** Nothing is sent to the cloud (by
  design, for now): the agent just identifies it and tells you.

The `confirm_threshold` (default 0.80) and every other knob live in
`agent/config.json` (copy from `agent/config.example.json`).

## Notifications

Two channels, both optional and config-driven. With neither configured, the agent
runs **log-only** (writes `logs/notifications.jsonl`) so everything is testable
without secrets.

| Channel | Confirm action | Needs |
|---|---|---|
| **Telegram** (recommended) | inline **Yes / No** buttons, handled by a built-in poller — no inbound server | a bot token + chat id from `@BotFather` |
| **Email** | **Confirm / Ignore** links that hit the agent's `/confirm` endpoint | SMTP (Gmail App Password); agent reachable from where you read mail (run with `--api-host 0.0.0.0` and set `api_public_base`) |

Alert contents: attack label, **confidence score**, attacker/target IP, and a
plain-language description of the attack.

## Remediation = "drop the packet"

On confirm (or timeout auto-remediate), the agent blocks the attacker's IP at the OS
firewall — `netsh advfirewall` on Windows, `iptables` on Linux. This drops all
packets from that source.

- **Default is `dry_run: true`** — the agent logs the exact command to
  `logs/remediations.jsonl` and changes nothing. Set `remediation.dry_run: false`
  in `agent/config.json` to actually block (needs Administrator / root).
- Only **loopback / RFC1918 private** IPs are ever eligible — it will never block a
  public IP.
- True per-packet inline drop (vs. host firewall) needs gateway mode — roadmap.

## Isolation Forest (unknown-threat detector)

Trained unsupervised on **benign** lab flows during Phase B
(`src/04_train_lab.py` → `models/iforest.joblib`). The agent uses it to second-guess
low-confidence and benign-labelled flows: `predict()` returns `1` for normal and
`-1` for an anomaly (a possible unknown threat).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | model, IF, channels, remediation status |
| POST | `/predict` | classify + run the decision pipeline |
| GET | `/confirm?token=…&action=yes\|no` | email-link / manual confirm target |
| GET | `/pending` | pending confirmations |

## Logs

| File | What |
|---|---|
| `logs/verdicts.jsonl` | every classification + outcome |
| `logs/decisions.jsonl` | the decision taken per flow |
| `logs/notifications.jsonl` | every email/telegram (or log-only) |
| `logs/remediations.jsonl` | every block/unblock (incl. dry-run) |

## Tuning for a demo

- Lower `notify_cooldown_seconds` if you want more frequent alerts while testing
  (default 300 s suppresses repeat alerts for the same source so an attack's many
  flows don't flood your inbox).
- Set `auto_remediate_on_timeout: true` to show the "confirm-first, auto-fix on
  timeout" product behaviour; keep `dry_run: true` until you're ready to block for real.
