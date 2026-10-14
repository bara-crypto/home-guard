# HomeGuard AI — Two-laptop test plan

Ordered checklist to capture lab data, train the live model (Phase B) and run a
live detection test. Laptop A = victim/agent, Laptop B = hacker, Laptop C = dev/trainer
(C can be the same person's main machine; A and B must be separate laptops).

Keep **all** attack traffic on your own three laptops and the hotspot.

## 0. Before you start

- A and B on the same hotspot; `ping` works both ways (see setup docs for client isolation).
- On A: `client_intent serve` is running and you have noted A's LAN IP.
- On A: record both A's IP and B's IP for this session (hotspot IPs can change).

## 1. Capture benign traffic (10–15 min)

On **A** (Administrator):
```powershell
python lab\capture.py --iface "Wi-Fi" --label benign --run 1 --duration 900
```
During capture, use A normally (browse, stream, download, copy files) and optionally run
`python client\client_intent.py benign --duration 900`.

## 2. Capture each attack — 3 runs each

For each attack, start the capture on **A**, then run the matching generator on **B**
against A's IP. Do **3 runs** of each (so you can train on runs 1–2 and test on run 3).

| Class       | On A (capture)                                                        | On B (attack A only)                                                        |
|-------------|-----------------------------------------------------------------------|------------------------------------------------------------------------------|
| portscan    | `python lab\capture.py --iface "Wi-Fi" --label portscan --run N --duration 120`   | `python hacker\hacker_intent.py portscan --target <A_IP> --confirm-lab`      |
| bruteforce  | `python lab\capture.py --iface "Wi-Fi" --label bruteforce --run N --duration 120` | `python hacker\hacker_intent.py bruteforce --target <A_IP> --confirm-lab`    |
| dos         | `python lab\capture.py --iface "Wi-Fi" --label dos --run N --duration 120`        | `python hacker\hacker_intent.py dos --target <A_IP> --confirm-lab --duration 60` |

Vary `--speed` across the 3 runs (slow/normal/fast) for portscan and dos so the model
sees a range. Capture files land in `data\captured\<label>\run<N>.pcap`.

## 3. Convert captures to labelled flows

On the machine with the venv (A or C), pass **B's IP** so attack flows are labelled
correctly (flows to/from B in an attack folder get that class; everything else is benign):

```powershell
python lab\convert.py --attacker-ip <B_IP>
```
Produces `data\processed\lab_flows.parquet` with a `run_id` per capture.

## 4. Train Phase B (the live model)

```powershell
python src\04_train_lab.py            # trains on run1-2, tests on run3
```
Outputs `models\rf_v1.joblib` + `models\features.json` and a per-class report +
confusion matrix in `reports\`. Review per-class recall; if a class is weak, capture
more runs of it and retrain.

> Do **not** deploy the Phase A model (`rf_phaseA`) live — it is trained on a different
> extractor's features. `rf_v1` (Phase B) is the live model.

## 5. Deploy on A and live-test

Copy `models\rf_v1.joblib` + `models\features.json` to **A** (if trained on C).

On **A** (Administrator):
```powershell
python agent\run_agent.py --iface "Wi-Fi" --threshold 0.7
```
Then from **B**, run each attack against A and watch A's agent print `ALERT {...}`.
Also browse normally on A to check for false alarms.

## 6. Pass criteria

- Each of portscan / bruteforce / dos is labelled correctly within a few seconds of the
  attack starting.
- Normal use produces **no more than 2 false alarms per 10 minutes**.
- Keep a recorded pcap of each attack (`data\captured\...`) as a stage fallback — you can
  replay detection offline with `python lab\convert.py` + `python agent\infer.py <csv>`.

## 7. Notes / limitations

- On a plain Wi-Fi hotspot a laptop only sees its own traffic, so the agent runs **on the
  victim (A)** — "device-agent mode". Gateway mode (sniffing all hotspot traffic) is a
  roadmap item; you can approximate it by sharing the hotspot *from* A.
- Loopback is not captured by Npcap by default, so single-laptop tests only check the
  plumbing — real detection is this two-laptop flow.
