# HomeGuard AI — the "client visits a page and gets attacked" lab idea

## Is it possible?

**Not the way it first sounds, but yes in a realistic lab form.**

A web page loaded in a browser **cannot** make the server port-scan, brute-force, or
DoS the visitor. The browser sandbox stops a page from telling a remote server to
send raw attack packets back to your machine, and it blocks scripts from scanning
your ports. So "open a normal page → the page itself attacks you" is not how networks
work.

**What *is* real and is exactly what we build:** the attacker's web server learns the
**visitor's IP** from the incoming HTTP request, and then the *attacker machine*
launches the attack back at that IP. The page is just the trigger/lure; the attack
traffic is still Laptop B → Laptop A, initiated by B, using the same bounded
`hacker_intent.py` phases. This is the honest lab version of a "drive-by": visiting
the page reveals Laptop A to Laptop B, which then attacks it.

`hacker/lure_server.py` implements this:

```powershell
# On Laptop B — serve only, attack nobody (safe default)
python hacker\lure_server.py --port 8090

# Armed: every PRIVATE-IP visitor is attacked with the bounded lab attacks
python hacker\lure_server.py --port 8090 --arm --confirm-lab --duration 20

# Dry-run: show what it would do, send nothing
python hacker\lure_server.py --port 8090 --arm --confirm-lab --dry-run
```

Then on **Laptop A**, open `http://<B_IP>:8090/` in a browser. B reads A's IP from
the visit and runs portscan → bruteforce → dos back at A. HomeGuard on A detects it
like any other attack. All existing guards hold: private/loopback IPs only,
`--confirm-lab` required, duration cap, dummy FTP wordlist, bounded DoS. There is
**no browser exploit and no payload delivered to A** — it is a traffic trigger, not
malware.

> It stays within your three-laptop lab. Don't point the armed lure at any network or
> device you don't own.

## What to turn off / adjust on Windows before this works

You do **not** need to disable Windows Defender antivirus. Make these minimal,
targeted changes on the lab machines, and undo them after:

**Laptop A (victim/agent):**
1. Set the Wi-Fi/hotspot profile to **Private**:
   `Set-NetConnectionProfile -InterfaceAlias "Wi-Fi" -NetworkCategory Private`
2. Allow the target ports inbound (Administrator PowerShell):
   ```powershell
   New-NetFirewallRule -DisplayName "HomeGuard HTTP 8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
   New-NetFirewallRule -DisplayName "HomeGuard FTP 2121"  -Direction Inbound -Protocol TCP -LocalPort 2121 -Action Allow
   ```
   (Npcap captures at the NIC *before* the firewall, so detection works even if the
   firewall drops packets — but the HTTP/FTP services must be reachable to generate
   realistic traffic.)
3. While testing detection, keep `remediation.dry_run: true` so the agent doesn't
   firewall-block Laptop B mid-demo.
4. Browser may show a SmartScreen/"insecure site" notice for the plain-HTTP lure —
   that's expected for a lab page; proceed.

**Laptop B (attacker/lure host):**
1. Set the profile to **Private**.
2. Allow the lure port inbound so A can reach it:
   ```powershell
   New-NetFirewallRule -DisplayName "HomeGuard Lure 8090" -Direction Inbound -Protocol TCP -LocalPort 8090 -Action Allow
   ```

**The hotspot:**
- Turn **off client isolation / AP isolation** on the phone hotspot, or the laptops
  can't reach each other. If the phone won't allow it, share a **Windows Mobile
  Hotspot from Laptop A** (or use a cheap travel router) so B and A are on the same
  reachable subnet.

**After the demo:** remove the firewall rules
(`Remove-NetFirewallRule -DisplayName "HomeGuard*"`) and set `dry_run` back if you
changed it.

## If you'd rather skip the lure

Everything still works with direct attacks — on B run
`python hacker\hacker_intent.py all --target <A_IP> --confirm-lab`. The lure is only a
nicer way to start the same traffic from a browser visit.
