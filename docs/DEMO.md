# HomeGuard AI — Single-laptop demo (client + attacker + agent on one PC)

This is the fastest way to demo HomeGuard: everything runs on **one** laptop.
The victim client, the malicious "lure" website, and the detector all run locally,
and the attack traffic is loopback (`127.0.0.1`), so there is **no hotspot, no
`Private` network profile, and no firewall rules** to set up. The only requirement
is Npcap with the loopback device (already working on this machine).

---

## Where is the "malicious website"? (it was NOT removed)

- There is **no separate HTML file**. The fake page is embedded in
  `hacker\lure_server.py` (lines ~42-51) and looks like a "Guest Portal / Free WiFi
  Speed Test" page.
- You **view it in a browser** at `http://127.0.0.1:8090/`.
- There are two different sites in this demo:
  - **Benign/victim target site** (the thing being attacked):
    `client\client_intent.py serve` → `http://127.0.0.1:8080/` (+ FTP on `2121`).
  - **Lure/malicious site** (the trap): `hacker\lure_server.py` →
    `http://127.0.0.1:8090/`.

## How visiting the page triggers the attack

A web page cannot, by itself, make the server attack you (browser sandbox). The
realistic lab version is: when your browser loads the lure page, the server reads
the **visitor's IP** from the request, and — only when armed — launches the bounded
lab attacks (`portscan → bruteforce → dos`) back at that IP using
`hacker\hacker_intent.py` (`lure_server.py:78-121`). Visiting the page reveals your
IP to the attacker host, which then attacks it. No exploit, no payload.

---

## Ports used (all local)

| Service | Port | Started by |
|---|---|---|
| Agent API | 8001 | `agent\run_agent.py` |
| Agent dashboard UI | 8010 | `agent\run_agent.py` (auto) |
| Victim HTTP (target) | 8080 | `client\client_intent.py serve` |
| Victim FTP (target) | 2121 | `client\client_intent.py serve` |
| Lure website (trap) | 8090 | `hacker\run_attacker.ps1` / `lure_server.py` |
| Npcap loopback iface | `\Device\NPF_Loopback` | (capture interface) |

---

## Demo — step by step

Open 3 PowerShell terminals in the repo root
(`D:\Users\balac\Chennai Hack\Home Guard V2\home_gaurd`) plus a browser.

### 0. One-time (skip if already done)
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```
The model (`models\rf_v1.joblib`) is already trained. (If missing, see
`docs\ATTACKER_PLAYBOOK.md` → capture + train.)

### 1. Terminal 1 — victim services
```powershell
.\.venv\Scripts\python.exe client\client_intent.py serve
```
Serves the benign target at `http://127.0.0.1:8080/` and FTP on `2121`.

### 2. Terminal 2 — HomeGuard agent (the detector)
```powershell
$env:HOMEGUARD_FLOW_IDLE_SECS="8"
.\.venv\Scripts\python.exe agent\run_agent.py --iface "\Device\NPF_Loopback" --threshold 0.7
```
Wait for `[agent] health: {...}`. This is the screen where `ALERT {...}` lines appear.
`HOMEGUARD_FLOW_IDLE_SECS=8` makes alerts show within ~10 s instead of ~4 min
(see "Latency" below). This window must inherit this variable, so run it in the
same shell right after setting it.

**The agent now waits for the lure.** By default it stays **quiet** — no `ALERT`
lines, no notifications, nothing on the dashboard — until the lure website is
actually triggered. You'll see:
```
[agent] trigger gate ON — detection stays QUIET until the lure is triggered.
[agent] watching ...\hacker\lure_log.jsonl for 'attack_launched' (armed for 300s per trigger; ...).
```
Each time the lure launches an attack (i.e. you open the page), the agent prints
`[agent] lure triggered -> detection ARMED for 300s` and then detects normally for
that window. To disable this and detect immediately (or for 2-laptop use), add
`--no-trigger-gate`. Change the window with `--alert-window <secs>`.

**One-time email alert.** On the first threat detected in a run (a known attack
*or* an unknown/anomalous flow), the agent emails a short "Threat detected"
message to `email.to` and then stays quiet for the rest of the run — one email per
run, no confirm links. Credentials live in the gitignored `agent/config.json`
(recipient defaults to `balac6796@gmail.com`); without them the agent is log-only.
You'll see `[notify:email] sent: [HomeGuard] Threat detected: ...` in Terminal 2.

### 3. Terminal 3 — attacker + lure host
```powershell
powershell -ExecutionPolicy Bypass -File hacker\run_attacker.ps1 -Mode SingleLaptop -Port 8090 -Duration 40
```
This runs the attacker guard self-check, then hosts the **armed** lure at
`http://127.0.0.1:8090/`.

> Safe preview only (serves the page, attacks nobody): `-Mode Serve`.

### 4. Browser — the trigger
Open:
```
http://127.0.0.1:8090/
```
Loading the page fires the attack at `127.0.0.1`.

### 5. What you should see
- **Terminal 3**: `[lure] {"action": "attack_launched", ...}` then per-phase logs.
  Files: `hacker\lure_log.jsonl` (visit + action) and `hacker\hacker_log.jsonl`.
- **Terminal 2**: `ALERT {...}` lines for non-benign verdicts; the first threat
  produces a `[notify:email] sent: [HomeGuard] Threat detected: ...` line (one email
  per run). For an unknown threat you also see its Isolation Forest verdict, e.g.:
  ```
  [decision] Sending to cloud for help
  [decision] Isolation Forest: new threat (anomaly) | rf=dos conf=0.55
  ```
  Telegram is disabled in this demo.
- **Email**: `balac6796@gmail.com` receives one small "Threat detected" message for
  the run.
- **Files**: `logs\verdicts.jsonl` (every verdict), `logs\notifications.jsonl`,
  `logs\decisions.jsonl`, `logs\remediations.jsonl`.

### 5b. Dashboard (agent web UI)
Terminal 2 starts the dashboard automatically at **`http://127.0.0.1:8010`**.
Open it in a browser and sign in with a **username only** (no password): the
username must equal this machine's **router (default-gateway) IP**, which the login
page displays as a hint and the agent also prints at startup, e.g.:

```
[agent] dashboard ready at http://127.0.0.1:8010  (login username = router IP 10.134.112.203)
```

It shows an attack summary — counters for port scan / brute force / DoS / **unknown
threats** / **cloud help** / **emails sent** — an attacks-per-minute sparkline, top
source IPs, and the **last 20 attacks** with confidence, outcome, and each row's
**IF** (Isolation Forest) result. Unknown threats are shown with an `unknown` **badge**
in the **Type** column (including anomalies the RF called *benign*). A **Notifications**
panel reports the email recipient (`email.to`), emails sent this session, and the last
email's subject/time/status. It refreshes every 3 s and reads the same
`logs\verdicts.jsonl` / `logs\decisions.jsonl` / `logs\notifications.jsonl` the agent
writes, so it lights up live. It binds to `127.0.0.1` only. Disable with
`--no-dashboard` or change the port with `--dashboard-port 8010`. Override router
detection with `HOMEGUARD_ROUTER_IP`.

**The dashboard shows only the current session** — events since the agent started
(effectively since the lure was triggered). It stays empty until you trigger the
lure, and never replays attacks from earlier runs.

### 6. Cleanup
```powershell
.\.venv\Scripts\python.exe client\client_intent.py stop
```
Then `Ctrl+C` in Terminal 3 (lure) and Terminal 2 (agent).

---

## Latency (why alerts are not instant)

cicflowmeter only *emits* a flow after it has been idle for `EXPIRED_UPDATE`
seconds (240 by default) or has lasted >= 90 s. With the default, a short attack
burst shows up ~2–4 minutes later. Setting `HOMEGUARD_FLOW_IDLE_SECS=8` in the
agent's shell lowers the idle threshold so the 1-second background collector flushes
flows within ~10 s of the traffic stopping. Use a larger value (or unset it) for the
upstream default. Keep the same value when you re-run `lab\convert.py` so training
and live behavior match.

---

## Troubleshooting

- **No ALERT**: confirm `$env:HOMEGUARD_FLOW_IDLE_SECS` is set in the agent shell;
  confirm the interface is `\Device\NPF_Loopback` (`lab\find_loopback.py`); confirm
  `models\rf_v1.joblib` + `models\features.json` exist; wait ~10–20 s after the attack.
- **Lure page won't load**: Terminal 3 must still be running; the URL is
  `http://127.0.0.1:8090/` (single-laptop).
- **Browser warns "not secure"**: expected for the plain-HTTP lab page; proceed.
- **Ports already in use**: `.\.venv\Scripts\python.exe client\client_intent.py stop`
  and close any old agent/lure windows.
- **Want to reset the attack without reopening the browser**: just reload the page
  (there is a 60 s per-visitor cooldown between attacks).

---

## Direct-attack fallback (no lure / no browser)

```powershell
.\.venv\Scripts\python.exe hacker\hacker_intent.py portscan   --target 127.0.0.1 --confirm-lab --duration 20
.\.venv\Scripts\python.exe hacker\hacker_intent.py bruteforce --target 127.0.0.1 --confirm-lab --duration 20
.\.venv\Scripts\python.exe hacker\hacker_intent.py dos        --target 127.0.0.1 --confirm-lab --duration 20
```

All generators are lab-only: private/loopback target only, `--confirm-lab`
required, duration capped at 120 s, dummy FTP wordlist (the real password is
excluded), bounded DoS.
