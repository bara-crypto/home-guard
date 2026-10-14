# HomeGuard AI — Hacker setup (Laptop B, Windows 10/11)

Laptop B generates the three attack **traffic patterns** against **Laptop A only**,
so HomeGuard has labelled data to learn from. It is deliberately bounded and lab-only.

> This tool contains no exploits, no evasion, and no attack types beyond port scan,
> brute force and a bounded HTTP load. Only ever point it at your own lab (Laptop A).

## 1. What to copy

Copy **only** these to Laptop B:

- `hacker/`  (contains `hacker_intent.py`)
- `requirements-hacker.txt`

Nothing else from the repo is needed here.

## 2. Install

1. **Python 3.10+** (python.org, "Add to PATH").
2. *(optional)* **Nmap** from nmap.org — if present, `portscan` uses it; otherwise a
   bounded Python TCP-connect scan is used instead.

```powershell
cd hacker-laptop
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-hacker.txt
```

## 3. Reach Laptop A

Both laptops on the same phone hotspot. Get Laptop A's LAN IP from its `serve` output
(or `ipconfig` on A), then:

```powershell
ping <A_IP>
```
No reply → the hotspot has *client isolation* on. Use a Windows Mobile Hotspot shared
from Laptop A, or a travel router.

## 4. Commands

`--target` and `--confirm-lab` are always required. `--target` must be a private/lab IP.

```powershell
# port scan (ports 1-1024)
python hacker\hacker_intent.py portscan   --target <A_IP> --confirm-lab --speed normal

# brute force: FTP logins vs A:2121, tiny dummy wordlist (real password excluded)
python hacker\hacker_intent.py bruteforce --target <A_IP> --confirm-lab --duration 30

# bounded HTTP GET load vs A:8080
python hacker\hacker_intent.py dos        --target <A_IP> --confirm-lab --duration 30 --threads 20

# all three in sequence
python hacker\hacker_intent.py all        --target <A_IP> --confirm-lab --duration 30

# see the plan without sending anything
python hacker\hacker_intent.py all        --target <A_IP> --confirm-lab --dry-run
```

Options: `--duration` seconds per phase (hard max **120**), `--speed slow|normal|fast`,
`--threads` for dos (max **50**), `--dry-run`.

## 4b. Lure server (optional — "visit a page, get attacked")

`hacker/lure_server.py` hosts a normal-looking page; when **armed**, each private-IP
visitor is attacked with the same bounded phases above (the server reads the visitor's
IP and attacks back — there is no browser exploit). See `docs/MALICIOUS_SITE_LAB.md`
for how it works and the Windows settings it needs.

```powershell
# serve only, attack nobody (safe default)
python hacker\lure_server.py --port 8090
# armed: attack each private-IP visitor
python hacker\lure_server.py --port 8090 --arm --confirm-lab --duration 20
```
Then open `http://<B_IP>:8090/` on Laptop A. Visits are logged to `hacker\lure_log.jsonl`.

## 5. The log

Every phase appends a JSON line to `hacker\hacker_log.jsonl`:

```json
{"phase": "portscan", "start_utc": "...", "end_utc": "...", "target": "192.168.1.50", "parameters": {...}}
```
Read it with any text editor, or:
```powershell
Get-Content hacker\hacker_log.jsonl
```

## 6. Stop

**Ctrl+C** stops any phase cleanly (the current phase is logged with its end time).

## 7. What the guards refuse (by design)

- `--target` that is not loopback or RFC1918 private (e.g. `8.8.8.8`) → refused, non-zero exit.
- Missing `--confirm-lab` → refused.
- `--duration` greater than 120 → refused.
- brute force can never succeed: the built-in wordlist (≤30 entries) does **not** contain
  the real lab password.

Keep these guards. They are what makes this safe to run.
