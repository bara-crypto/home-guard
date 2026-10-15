# HomeGuard AI — Client / Victim setup (Laptop A, Windows 10/11)

Laptop A runs the **target services** the hacker laptop attacks, **plus** the
HomeGuard agent (sniffer + model). It never attacks anything.

> Loopback note: on Windows, Npcap exposes a loopback capture device
> (`\Device\NPF_Loopback`). A one-laptop (single-PC) test is now supported by
> pointing the attacker at `127.0.0.1` and sniffing that device instead of Wi-Fi —
> see the "Single-laptop mode" section in `docs/ATTACKER_PLAYBOOK.md`. The classic
> two-laptop flow (agent sniffs Wi-Fi) still applies in `docs/TEST_PLAN.md`.

## 1. What to copy to Laptop A

From the repo, copy:

- `client/`  — target servers + benign traffic
- `agent/`   — FastAPI inference API + sniffer launcher
- `lab/`     — `run_cicflowmeter.py` (the flow extractor wrapper) and capture tools
- `src/`     — `trainer.py` (imported by training), `infer.py` not required but handy
- `models/`  — **`rf_v1.joblib` + `features.json`** (the Phase B model) once trained
- `requirements.txt`

## 2. Installs

1. **Python 3.10+** from python.org. Check "Add python to PATH".
2. **Npcap** from npcap.com. During install **check "Install Npcap in WinPcap API-compatible mode"**.
   (Installing Nmap also installs Npcap — Npcap is part of the Nmap project.)
3. *(optional)* **Nmap** from nmap.org — only needed on the *hacker* laptop, not here.

```powershell
cd homeguard
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Windows network + firewall

- Set the Wi-Fi/hotspot network profile to **Private**:
  ```powershell
  Get-NetConnectionProfile
  Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private
  ```
- Allow the two target ports inbound (run PowerShell **as Administrator**):
  ```powershell
  New-NetFirewallRule -DisplayName "HomeGuard HTTP 8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
  New-NetFirewallRule -DisplayName "HomeGuard FTP 2121"  -Direction Inbound -Protocol TCP -LocalPort 2121 -Action Allow
  ```

## 4. Find your Wi-Fi interface name and LAN IP

```powershell
# interface name for the sniffer (e.g. "Wi-Fi")
Get-NetAdapter | Format-Table Name, InterfaceDescription, Status
ipconfig            # note the IPv4 address on the Wi-Fi adapter
```
`client_intent.py serve` also prints the laptop's LAN IPv4 addresses. **Note this IP
each session — it can change on a hotspot.**

## 5. Run order (each in its own Administrator PowerShell, venv activated)

```powershell
# (1) start the target services + print this laptop's LAN IP
python client\client_intent.py serve

# (2) start the agent: API on 127.0.0.1:8001 + live sniffer -> /predict
python agent\run_agent.py --iface "Wi-Fi" --threshold 0.7
#     (API-only, no sniffing:  python agent\run_agent.py --no-sniff)

# (3) optional: generate your own benign client traffic
python client\client_intent.py benign --duration 600
```

The agent prints `ALERT {...}` whenever a non-benign flow is detected at or above
the threshold, and logs every verdict to `logs\verdicts.jsonl`.

## 6. How to stop

- Agent: **Ctrl+C** in its window (it terminates the cicflowmeter child cleanly).
- Servers: `python client\client_intent.py stop` (frees ports 8080/2121).
- Check state anytime: `python client\client_intent.py status`.

## 7. Troubleshooting

- **No flows / agent silent** — the sniffer must run in an **Administrator** shell with
  **Npcap** installed. Confirm the interface name with
  `python lab\capture.py --list-ifaces`.
- **`cicflowmeter` errors on the command line** — the shipped `cicflowmeter` 0.5.0 CLI is
  broken (it mispasses its arguments). HomeGuard calls the library through
  `lab\run_cicflowmeter.py` instead; always use that wrapper, not the bare `cicflowmeter`.
- **Laptops can't reach each other** — the phone hotspot has *client isolation* on. Use a
  Windows Mobile Hotspot shared from Laptop A instead, or a travel router.
- **Port already in use** — run `python client\client_intent.py stop`, then re-serve.
- **Npcap conflicts** — if an old WinPcap is installed, uninstall it; reinstall Npcap with
  WinPcap-compatible mode checked.
- **Firewall blocks the attack traffic** — confirm the two inbound rules above exist and the
  profile is Private.
