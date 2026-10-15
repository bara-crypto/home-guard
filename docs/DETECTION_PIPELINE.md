# HomeGuard AI — detection → notify → confirm → remediate pipeline

This is what the agent does with every flow after the Random Forest classifies it.

## Flow of decisions

```
RF classifies a flow → (label, confidence)

┌── label == benign ────────────────────────────────────────────────┐
│   Isolation Forest verifies the flow:                              │
│     anomaly  → UNKNOWN THREAT  → email "threat detected" (once/run)│
│     normal   → benign, SILENT (normal process, no alert)           │
└────────────────────────────────────────────────────────────────────┘

┌── label is an attack (portscan / bruteforce / dos) ───────────────┐
│   confidence ≥ 80%  → KNOWN THREAT                                 │
│        → pending token (manual /confirm can DROP the attacker IP)  │
│        → "Yes"  → identify + DROP (block attacker IP)              │
│        → timeout → auto-remediate IF enabled, else no action       │
│   confidence < 80%  → uncertain → Isolation Forest verifies:       │
│        anomaly → UNKNOWN THREAT → email "threat detected" (once)   │
│        normal  → benign, SILENT                                    │
└────────────────────────────────────────────────────────────────────┘
```

- **Notification policy: exactly ONE small heads-up email per agent run** — sent on
  the *first* threat detected (known **or** unknown), addressed to the configured
  `email.to`. No confirm links, no Telegram. Restarting the agent starts a new run
  (and a new email). Everything is still appended to `logs/decisions.jsonl`.
- **Benign verified by Isolation Forest → no email, normal process.**
- **Known threat → pending token; on "Yes" (via `/confirm`) the source is dropped.**
- **Unknown threat → informational email only, plus a terminal verdict.** For every
  unknown threat the agent prints the **Isolation Forest verdict** — e.g.
  `[decision] Isolation Forest: new threat (anomaly) | rf=dos conf=0.55`. When the
  verdict is an **anomaly** (or the IF is **unavailable**), it also prints
  `[decision] Sending to cloud for help` and records `"cloud": "sending_for_help"`;
  a verdict of *benign (normal)* is the ordinary path and prints nothing. The verdict
  is saved as `"if_result"` (`anomaly` / `normal` / `unavailable`) and the cloud flag
  as `"cloud"` in `logs/decisions.jsonl`.
  This is a **placeholder for a future cloud lookup — nothing is actually sent to the
  cloud** (by design, for now): the agent just identifies it and tells you.
- **Dashboard:** unknown threats appear in **Recent attacks** with an `unknown` badge
  (in the **Type** column) and their Isolation Forest result in the **IF** column.
  Counters: **Unknown threats** and **Cloud help** (both count every unknown threat),
  an **Emails sent** card, and a **Notifications** panel showing the recipient
  (`email.to`), emails sent this session, and the last email's subject/time/status.

The `confirm_threshold` (default 0.80) and every other knob live in
`agent/config.json` (copy from `agent/config.example.json`).

## Notifications

Optional and config-driven. With it unconfigured, the agent runs **log-only** (writes
`logs/notifications.jsonl`) so everything is testable without secrets.

| Channel | What it does | Needs |
|---|---|---|
| **Email** | **one small "Threat detected" heads-up per agent run** (first known *or* unknown threat); no confirm links | SMTP (Gmail App Password) in `agent/config.json`; `email.to` is the recipient |
| **Telegram** | *(optional, disabled in the demo)* inline **Yes / No** buttons via a built-in poller | a bot token + chat id from `@BotFather` |

Alert contents: attack label (or UNKNOWN), attacker/target IP, **confidence score**
(known threats), and a one-line reason (unknown threats). The email is sent at most
once per run; further detections in the same run are logged but do not email.

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

## Trigger gate (wait for the lure)

In the single-laptop demo the agent would otherwise classify *all* loopback traffic
(the client's benign traffic and the agent's own dashboard/API traffic) and could
alert before you do anything. To keep the demo clean, `run_agent.py` enables a
**lure-trigger gate**: the agent keeps sniffing (so the sub-second port-scan burst is
never missed) but stays **quiet** — no `ALERT`, no notifications, nothing logged to
the dashboard — until the lure actually launches an attack.

- `run_agent.py` watches `hacker/lure_log.jsonl` for an `{"action": "attack_launched"}`
  line, then calls the agent's `POST /arm` endpoint, which opens a detection window
  (`alert_window_seconds`, default 300). Each new lure visit re-arms it.
- While un-armed, `POST /predict` records each flow with
  `outcome: "quiet_until_trigger"` and takes no action; the dashboard ignores those
  and only shows the current session (since the agent started).
- Off by default in `agent/config.json` (`trigger_gate: false`) so tests and the
  2-laptop setup are unchanged; the single-laptop launcher turns it on. Disable with
  `--no-trigger-gate`.

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
