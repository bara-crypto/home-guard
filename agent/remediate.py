"""HomeGuard AI - remediation: "drop the packet" by blocking the attacker IP.

On a host, the practical realization of "drop the attack traffic" is a firewall
rule that drops everything from the attacker's source IP:
  - Windows: netsh advfirewall firewall add rule ... action=block remoteip=<ip>
  - Linux:   iptables -I INPUT -s <ip> -j DROP

Safety:
  - dry_run=True (default) logs the exact command and changes NOTHING.
  - Only loopback / RFC1918 private IPs are ever eligible (never block a public IP).
  - Every action is appended to logs/remediations.jsonl.

True per-packet inline drop (vs. host firewall) needs gateway mode, which is a
roadmap item; on the victim host, blocking the source IP is the correct mitigation.
"""
from __future__ import annotations

import ipaddress
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG = ROOT / "logs" / "remediations.jsonl"
RULE_PREFIX = "HomeGuard block"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _eligible(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and (addr.is_loopback or addr.is_private)


def _log(rec: dict) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def _block_cmd(ip: str) -> list[str]:
    if platform.system() == "Windows":
        return ["netsh", "advfirewall", "firewall", "add", "rule",
                f'name={RULE_PREFIX} {ip}', "dir=in", "action=block", f"remoteip={ip}"]
    return ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]


def _unblock_cmd(ip: str) -> list[str]:
    if platform.system() == "Windows":
        return ["netsh", "advfirewall", "firewall", "delete", "rule", f'name={RULE_PREFIX} {ip}']
    return ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]


def block_ip(ip: str, dry_run: bool = True, enabled: bool = True) -> dict:
    """Block all traffic from `ip`. Returns a record describing what happened."""
    cmd = _block_cmd(ip)
    rec = {"ts": _now(), "action": "block", "ip": ip, "cmd": " ".join(cmd),
           "dry_run": dry_run, "platform": platform.system()}

    if not enabled:
        rec.update(status="skipped", reason="remediation disabled in config")
    elif not _eligible(ip):
        rec.update(status="refused", reason="ip is not loopback/RFC1918 private")
    elif dry_run:
        rec.update(status="dry_run", reason="would run cmd; no change made")
    else:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            rec.update(status="applied" if p.returncode == 0 else "error",
                       returncode=p.returncode, stderr=p.stderr[-300:])
        except FileNotFoundError:
            rec.update(status="error", reason="firewall tool not found (need Administrator/root)")
        except Exception as e:
            rec.update(status="error", reason=str(e))

    _log(rec)
    print("[remediate] " + json.dumps(rec))
    return rec


def unblock_ip(ip: str, dry_run: bool = True, enabled: bool = True) -> dict:
    cmd = _unblock_cmd(ip)
    rec = {"ts": _now(), "action": "unblock", "ip": ip, "cmd": " ".join(cmd),
           "dry_run": dry_run, "platform": platform.system()}
    if not enabled:
        rec.update(status="skipped")
    elif dry_run:
        rec.update(status="dry_run")
    else:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            rec.update(status="applied" if p.returncode == 0 else "error",
                       returncode=p.returncode, stderr=p.stderr[-300:])
        except Exception as e:
            rec.update(status="error", reason=str(e))
    _log(rec)
    print("[remediate] " + json.dumps(rec))
    return rec


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="HomeGuard remediation (manual).")
    ap.add_argument("ip")
    ap.add_argument("--unblock", action="store_true")
    ap.add_argument("--live", action="store_true", help="actually apply (default dry-run)")
    a = ap.parse_args()
    (unblock_ip if a.unblock else block_ip)(a.ip, dry_run=not a.live)
