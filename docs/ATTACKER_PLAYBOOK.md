# HomeGuard AI — Attacker playbook (Laptop B) with client checklist (Laptop A)

End-to-end runbook for the **lure-website** demo, with a **full Phase B capture +
train** so Laptop A actually detects the attacks. Laptop A = client/victim + agent.
Laptop B = attacker/lure host. Both on the **same phone hotspot**.

Legend: 🅰 = run on Laptop A, 🅱 = run on Laptop B, 🅰+🅱 = coordinated.

> Lab-only. `hacker_intent.py` refuses any non-private target, requires
> `--confirm-lab`, caps duration at 120 s, uses a dummy FTP wordlist that excludes the
> real password, and bounds the DoS load. Point it only at your own lab.

---

## Single-laptop mode (client + attacker on one PC)

Everything can run on **one** laptop. All attack traffic is loopback (`127.0.0.1`),
so there is **no hotspot, no `Private` profile, and no inbound firewall rules**
(loopback bypasses Windows Firewall). The one requirement is that the agent sniffer
captures the **Npcap loopback** interface instead of Wi-Fi.

1. Find the loopback capture device:
   ```powershell
   python lab\find_loopback.py        # prints e.g. \Device\NPF_Loopback
   ```
2. Capture + train on loopback (attacker target is `127.0.0.1`):
   ```powershell
   python client\client_intent.py serve
   python lab\capture.py --iface "\Device\NPF_Loopback" --label portscan --run 1 --duration 120
   python hacker\hacker_intent.py portscan --target 127.0.0.1 --confirm-lab
   # ...repeat for benign / bruteforce / dos, 3 runs each
   python lab\convert.py --single-laptop
   python src\04_train_lab.py
   ```
3. Run the agent on loopback:
   ```powershell
   python agent\run_agent.py --iface "\Device\NPF_Loopback" --threshold 0.7
   ```
4. Lure demo:
   ```powershell
   powershell -ExecutionPolicy Bypass -File hacker\run_attacker.ps1 -Mode SingleLaptop -Port 8090 -Duration 60
   # then browse to http://127.0.0.1:8090/
   ```

Notes:
- `lab\convert.py --single-laptop` labels attack folders by port
  (2121 = bruteforce, 8080 = dos, 1-1024 = portscan) because on loopback **both**
  endpoints are `127.0.0.1`, so the attacker-IP rule cannot separate attack flows.
- The lure visitor is `127.0.0.1`, which `lure_server.py` accepts (loopback is allowed).
- Port map on one PC: API `8001`, HTTP target `8080`, FTP `2121`, lure `8090`.

---

## 0. One-time setup

🅱 (Laptop B):
```powershell
cd home_gaurd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-hacker.txt
# optional: install Nmap (nmap.org) for a fast portscan; otherwise the bounded
# Python TCP-connect scan is used.
```
Or just use the launcher (does venv + install for you):
```powershell
powershell -ExecutionPolicy Bypass -File hacker\run_attacker.ps1 -Mode Verify
```

🅰 (Laptop A, Administrator PowerShell) — see `docs\CLIENT_SETUP.md`:
```powershell
cd home_gaurd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
# install Npcap with "WinPcap API-compatible mode" checked
```

🅰 Windows network + firewall:
```powershell
Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private
New-NetFirewallRule -DisplayName "HomeGuard HTTP 8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
New-NetFirewallRule -DisplayName "HomeGuard FTP 2121"  -Direction Inbound -Protocol TCP -LocalPort 2121 -Action Allow
```

🅱 Windows network + firewall (allow A to reach the lure):
```powershell
Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private
New-NetFirewallRule -DisplayName "HomeGuard Lure 8090" -Direction Inbound -Protocol TCP -LocalPort 8090 -Action Allow
```

🅰+🅱 Reachability:
- Same hotspot. Turn **off client isolation / AP isolation** on the phone (or share a
  Windows Mobile Hotspot from A, or use a travel router).
- Note each laptop's LAN IP (`ipconfig`; A's is also printed by `client_intent.py serve`).
- Confirm `ping <other_ip>` works **both ways**.

---

## 1. Verify the attacker on B (sends nothing)

🅱:
```powershell
powershell -ExecutionPolicy Bypass -File hacker\run_attacker.ps1 -Mode Verify
# or directly:
python hacker\hacker_intent.py all --target 127.0.0.1 --confirm-lab --dry-run
python hacker\hacker_intent.py portscan --target 8.8.8.8 --confirm-lab       # must REFUSE
python hacker\hacker_intent.py portscan --target 127.0.0.1                   # must REFUSE (no --confirm-lab)
python hacker\hacker_intent.py dos --target 127.0.0.1 --confirm-lab --duration 999  # must REFUSE
```

Expected: the dry-run prints the plan; every guard command exits non-zero with a
`REFUSED:` message. Optional full plumbing test (needs full `requirements.txt` because
it starts a local target): `python tests\verify_hacker.py`.

---

## 2. Phase B capture — labelled traffic (A captures, B attacks)

🅰 start the target services and note A's LAN IP:
```powershell
python client\client_intent.py serve
```

Do **3 runs of each class** (runs 1–2 train, run 3 tests). Vary `--speed` across the
runs of portscan/dos. For each class: start the capture on A, then run B's attack.

| Class | 🅰 capture (Admin) | 🅱 attack A |
|---|---|---|
| benign | `python lab\capture.py --iface "Wi-Fi" --label benign --run N --duration 900` (browse normally) | — |
| portscan | `python lab\capture.py --iface "Wi-Fi" --label portscan --run N --duration 120` | `python hacker\hacker_intent.py portscan --target <A_IP> --confirm-lab --speed slow\|normal\|fast` |
| bruteforce | `python lab\capture.py --iface "Wi-Fi" --label bruteforce --run N --duration 120` | `python hacker\hacker_intent.py bruteforce --target <A_IP> --confirm-lab` |
| dos | `python lab\capture.py --iface "Wi-Fi" --label dos --run N --duration 120` | `python hacker\hacker_intent.py dos --target <A_IP> --confirm-lab --duration 60` |

Captures land in `data\captured\<label>\run<N>.pcap`.

---

## 3. Convert + train (Laptop A)

🅰 pass **B's IP** so attack flows are labelled correctly:
```powershell
python lab\convert.py --attacker-ip <B_IP>      # -> data\processed\lab_flows.parquet
python src\04_train_lab.py                      # -> models\rf_v1.joblib + features.json + iforest.joblib
```
Review the per-class report + confusion matrix in `reports\`. If a class is weak,
capture more runs of it and retrain.

> No time to capture? `python src\04_train_lab.py --demo` writes a clearly-labelled
> synthetic model so you can exercise the pipeline — replace it before a real demo.

---

## 4. Run the agent on A

🅰:
```powershell
copy agent\config.example.json agent\config.json
# edit config.json: leave remediation.dry_run=true; optionally enable Telegram (easiest confirm)
python agent\run_agent.py --iface "Wi-Fi" --threshold 0.7
```
`/health` on `127.0.0.1:8001` should show `loaded=true` and `isolation_forest=true`.

---

## 5. Host the lure (B) + client triggers (A) → attack + confirm

🅱 host the page (armed = attack every private-IP visitor):
```powershell
powershell -ExecutionPolicy Bypass -File hacker\run_attacker.ps1 -Mode Arm -Port 8090 -Duration 20
# or directly:
python hacker\lure_server.py --port 8090 --arm --confirm-lab --duration 20
```
Safe first run (serve only, attack nobody): `-Mode Serve`.

🅰 open the page in a browser (accept the SmartScreen / "insecure site" prompt):
```
http://<B_IP>:8090/
```
B reads A's IP from the visit and runs portscan → bruteforce → dos back at A.

Expected on 🅰: the agent prints `ALERT {...}`, a Telegram/email alert with the
**confidence score**, a **confirm** message (tap **Yes**) → dry-run firewall block
logged. Normal browsing stays silent.

🅱 logs: `hacker\lure_log.jsonl` (visits) and `hacker\hacker_log.jsonl` (each phase).
🅰 logs: `logs\verdicts.jsonl`, `logs\decisions.jsonl`, `logs\notifications.jsonl`,
`logs\remediations.jsonl`.

Direct-attack fallback (no lure):
```powershell
python hacker\hacker_intent.py all --target <A_IP> --confirm-lab
```

---

## 6. Pass criteria

- Each of portscan / bruteforce / dos labelled correctly within a few seconds.
- ≤ 2 false alarms per 10 minutes of normal use.
- Confirm → remediation fires (dry-run or live).
- Keep a recorded pcap per attack as a fallback.

---

## 7. Cleanup

🅰+🅱:
```powershell
Remove-NetFirewallRule -DisplayName "HomeGuard*"
```
🅰: `python client\client_intent.py stop`; Ctrl+C the agent; keep `dry_run=true` unless
you intended a real block.

---

## Client-side (A) — quick checklist

1. Same hotspot as B; profile **Private**; `ping <B_IP>` works.
2. Npcap installed (WinPcap-compatible) + `pip install -r requirements.txt`.
3. Inbound rules for TCP 8080 and 2121.
4. `python client\client_intent.py serve` → share A's LAN IP with B.
5. Capture with `lab\capture.py` while B attacks; then `lab\convert.py --attacker-ip <B_IP>` + `src\04_train_lab.py`.
6. Run the agent as **Administrator** with `--iface "Wi-Fi"`; keep `dry_run=true`.
7. Open `http://<B_IP>:8090/` to trigger the lure; tap **Yes** on the alert.
8. Cleanup firewall rules and stop the servers.
