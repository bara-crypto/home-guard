# HomeGuard AI — from-scratch runbook for Laptop A and Laptop B

Assumes **both laptops have cloned/pulled the same updated repo**. Laptop A = client
/ victim + agent. Laptop B = attacker / lure host. (A dedicated Laptop C is optional;
if you have one, do the training there — otherwise do it on A.)

Legend: 🅰 = run on Laptop A, 🅱 = run on Laptop B, 🅰+🅱 = coordinated.

> **Single-laptop option:** A and B can be the *same* laptop. Target the attacks at
> `127.0.0.1` and sniff the Npcap loopback device (`python lab\find_loopback.py`), use
> `python lab\convert.py --single-laptop`, and skip §0's hotspot/firewall steps. Full
> sequence: `docs\ATTACKER_PLAYBOOK.md` → "Single-laptop mode".

---

## 0. One-time setup on each laptop

🅰 (Administrator PowerShell):
```powershell
cd homeguard
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
# install Npcap (WinPcap-compatible mode) — see docs\CLIENT_SETUP.md §2
```
🅱:
```powershell
cd homeguard
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-hacker.txt      # hacker + lure only need this
# optional: install Nmap for a faster port scan
```
🅰+🅱: put both on the same hotspot, set profiles to **Private**, confirm
`ping <other_ip>` works (see docs\MALICIOUS_SITE_LAB.md for firewall rules and
client-isolation notes).

---

## 1. (Optional) Phase A — prove the pipeline on public data

Do this on A or C, where the internet is reachable. It validates the code; it is
**not** the deployed model.
```powershell
python src\01_download.py          # CIC-IDS2017 Network-Flows (~370 MB)
python src\02_explore.py
python src\03_learn_features.py
python src\03_train.py             # writes models\rf_phaseA.* + reports\
```

## 2. Phase B — the model you actually deploy (needs A+B)

### 2a. Capture labelled traffic  🅰+🅱
🅰 start the target services and keep them running:
```powershell
python client\client_intent.py serve        # note A's LAN IP it prints
```
Then, for each class, 🅰 records while 🅱 attacks A (do **3 runs** of each so run 3
can be the test set). Note B's IP too.

| Class | 🅰 capture | 🅱 attack A |
|---|---|---|
| benign | `python lab\capture.py --iface "Wi-Fi" --label benign --run 1 --duration 900` (browse normally) | — |
| portscan | `...--label portscan --run N --duration 120` | `python hacker\hacker_intent.py portscan --target <A_IP> --confirm-lab` |
| bruteforce | `...--label bruteforce --run N --duration 120` | `python hacker\hacker_intent.py bruteforce --target <A_IP> --confirm-lab` |
| dos | `...--label dos --run N --duration 120` | `python hacker\hacker_intent.py dos --target <A_IP> --confirm-lab --duration 60` |

### 2b. Convert + train  🅰 (or C)
```powershell
python lab\convert.py --attacker-ip <B_IP>   # -> data\processed\lab_flows.parquet
python src\04_train_lab.py                    # -> models\rf_v1.joblib, features.json, iforest.joblib
```
`04_train_lab.py` trains the Random Forest (run1-2 train, run3 test) **and** the
Isolation Forest on benign flows. Review the per-class report in `reports\`.

> No time to capture yet? `python src\04_train_lab.py --demo` writes a clearly-labelled
> synthetic `rf_v1` so you can exercise the agent end to end — replace it before any
> real demo.

## 3. Configure notifications  🅰

```powershell
copy agent\config.example.json agent\config.json
```
Edit `agent\config.json`:
- **Telegram (easiest):** set `telegram.enabled=true`, `bot_token`, `chat_id`.
- **Email:** set `email.enabled=true`, Gmail + 16-char App Password, `to` recipient.
  For the email "Confirm" link to work from your phone, run the agent with
  `--api-host 0.0.0.0` and set `api_public_base` to `http://<A_IP>:8001`.
- Keep `remediation.dry_run=true` until you want real IP blocking.

(No config = log-only; the agent still works, writing `logs\notifications.jsonl`.)

## 4. Run the agent  🅰 (Administrator)

```powershell
python agent\run_agent.py --iface "Wi-Fi" --threshold 0.7
# add  --api-host 0.0.0.0  if you use email confirm links from another device
```
`/health` on `127.0.0.1:8001` should show `loaded=true` and `isolation_forest=true`.

## 5. Live test  🅰+🅱

Two ways for 🅱 to attack, pick either:
```powershell
# direct
python hacker\hacker_intent.py all --target <A_IP> --confirm-lab

# or the lure: 🅱 hosts a page, 🅰 opens http://<B_IP>:8090/ in a browser
python hacker\lure_server.py --port 8090 --arm --confirm-lab --duration 20
```
On 🅰 you should see, within a few seconds:
- the agent print `ALERT {...}` for each detected attack,
- a Telegram/email alert with the **confidence score** and attack description,
- for ≥80% confidence, a **confirm** message — tap **Yes** (or click the email link)
  → the agent runs the firewall block (dry-run logs it; live actually blocks B),
- low-confidence / odd traffic reported as **unknown threat**,
- normal browsing stays silent.

Check the record in `logs\` (`verdicts`, `decisions`, `notifications`, `remediations`).

## 6. Pass criteria

- Each attack labelled correctly within a few seconds.
- ≤ 2 false alarms per 10 minutes of normal use.
- Confirm → remediation fires (dry-run or live).
- Keep a recorded pcap per attack as a stage fallback.

## Who does what — quick table

| Order | Where | What |
|---|---|---|
| 1 | 🅰 & 🅱 | setup venv + installs (§0) |
| 2 | 🅰+🅱 | capture 3 runs per class (§2a) |
| 3 | 🅰/C | convert + train Phase B (§2b) |
| 4 | 🅰 | configure `config.json`, run agent (§3–4) |
| 5 | 🅰+🅱 | live attack + confirm + remediate (§5) |
