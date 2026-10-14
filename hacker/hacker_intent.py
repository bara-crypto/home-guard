"""HomeGuard AI - Step 9: lab traffic generator (Laptop B). STANDALONE.

PURPOSE: generate the three attack *traffic patterns* (port scan, brute force,
DoS-style load) against YOUR OWN lab victim (Laptop A) so the HomeGuard model has
labelled training/test data. It is deliberately bounded and lab-only. It contains
no exploits, no evasion, and no attack types beyond these three.

MANDATORY SAFETY GUARDS (do not remove):
  * --target MUST be a loopback or RFC1918 private IPv4 address (checked with the
    `ipaddress` module). Any public/global address is refused with a non-zero exit.
  * --confirm-lab MUST be present, or the tool refuses to run.
  * --duration has a hard maximum of 120 seconds.
  * bruteforce uses a tiny built-in wordlist (<=30 entries) that deliberately does
    NOT contain the real lab password, with a delay between attempts.
  * dos is a bounded HTTP GET load: at most 50 threads, stops at the duration limit.
  * --dry-run prints the plan and sends nothing.

Each phase appends a JSON line to hacker/hacker_log.jsonl.
Dependencies: Python stdlib + requests. nmap is used for portscan if present.

Examples:
    python hacker/hacker_intent.py portscan   --target 192.168.1.50 --confirm-lab
    python hacker/hacker_intent.py bruteforce --target 192.168.1.50 --confirm-lab --duration 30
    python hacker/hacker_intent.py dos        --target 192.168.1.50 --confirm-lab --speed normal
    python hacker/hacker_intent.py all        --target 192.168.1.50 --confirm-lab --dry-run
"""
import argparse
import ipaddress
import json
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOG = HERE / "hacker_log.jsonl"

HTTP_PORT = 8080
FTP_PORT = 2121
FTP_USER = "labuser"

DURATION_DEFAULT = 30
DURATION_MAX = 120  # hard cap
DOS_THREADS_DEFAULT = 20
DOS_THREADS_MAX = 50

# Tiny dummy wordlist. The REAL lab password (labpass123) is intentionally NOT here,
# so brute force always fails. This generates the traffic pattern, not a compromise.
WORDLIST = [
    "password", "123456", "admin", "root", "letmein", "qwerty", "welcome",
    "ftp", "test", "guest", "changeme", "pass123", "login", "user",
    "labuser", "secret", "toor", "default", "1234", "abc123",
    "password1", "iloveyou", "monkey", "dragon", "master", "hello",
    "freedom", "whatever", "trustno1", "sunshine",
]

SPEEDS = {"slow": 1.0, "normal": 0.3, "fast": 0.05}  # inter-action delay (s)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_phase(phase: str, start: str, end: str, target: str, params: dict) -> None:
    rec = {"phase": phase, "start_utc": start, "end_utc": end, "target": target, "parameters": params}
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    print("[log] " + json.dumps(rec))


def validate_target(target: str) -> ipaddress.IPv4Address:
    """Refuse anything that is not a loopback or RFC1918 private IPv4 address."""
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        sys.exit(f"REFUSED: --target '{target}' is not a valid IP address. Lab IPs only.")
    if ip.version != 4:
        sys.exit("REFUSED: only IPv4 lab targets are allowed.")
    if not (ip.is_loopback or ip.is_private):
        sys.exit(f"REFUSED: --target {target} is not loopback/RFC1918 private. "
                 f"This tool only runs against your own lab network.")
    return ip


def guard(args) -> None:
    if not args.confirm_lab:
        sys.exit("REFUSED: --confirm-lab is required. This tool is for your own lab only.")
    validate_target(args.target)
    if args.duration > DURATION_MAX:
        sys.exit(f"REFUSED: --duration {args.duration}s exceeds the hard cap of {DURATION_MAX}s.")
    if args.duration <= 0:
        sys.exit("REFUSED: --duration must be positive.")


# ----------------------------- phases -----------------------------

def phase_portscan(args) -> None:
    start = now_utc()
    ports = list(range(1, 1025))
    used = "nmap"
    if args.dry_run:
        print(f"[dry-run] portscan {args.target} ports 1-1024 (nmap if present, else TCP connect)")
        log_phase("portscan", start, now_utc(), args.target,
                  {"ports": "1-1024", "dry_run": True})
        return

    from shutil import which
    open_ports = []
    if which("nmap"):
        import subprocess
        timing = {"slow": "-T2", "normal": "-T3", "fast": "-T4"}[args.speed]
        cmd = ["nmap", timing, "-p", "1-1024", args.target]
        print("[portscan] running:", " ".join(cmd))
        subprocess.run(cmd)
    else:
        used = "tcp_connect"
        print(f"[portscan] nmap not found; bounded Python TCP-connect scan of {args.target}:1-1024")
        deadline = time.time() + args.duration
        for p in ports:
            if time.time() > deadline:
                print("[portscan] duration limit reached; stopping.")
                break
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                if s.connect_ex((args.target, p)) == 0:
                    open_ports.append(p)
        print(f"[portscan] open ports found: {open_ports}")
    log_phase("portscan", start, now_utc(), args.target,
              {"ports": "1-1024", "tool": used, "speed": args.speed, "open_ports": open_ports})


def phase_bruteforce(args) -> None:
    from ftplib import FTP, error_perm

    start = now_utc()
    delay = SPEEDS[args.speed]
    if args.dry_run:
        print(f"[dry-run] bruteforce FTP {args.target}:{FTP_PORT} user={FTP_USER}, "
              f"{len(WORDLIST)} dummy passwords (real one excluded), delay={delay}s")
        log_phase("bruteforce", start, now_utc(), args.target,
                  {"service": "ftp", "user": FTP_USER, "attempts": len(WORDLIST), "dry_run": True})
        return

    deadline = time.time() + args.duration
    attempts = 0
    succeeded = False
    for pw in WORDLIST:
        if time.time() > deadline:
            print("[bruteforce] duration limit reached; stopping.")
            break
        attempts += 1
        try:
            ftp = FTP()
            ftp.connect(args.target, FTP_PORT, timeout=3)
            ftp.login(FTP_USER, pw)
            succeeded = True
            print(f"[bruteforce] UNEXPECTED success with '{pw}' (dummy list should never work)")
            ftp.quit()
            break
        except error_perm:
            print(f"[bruteforce] {FTP_USER}:{pw} -> rejected")
        except Exception as e:
            print(f"[bruteforce] connection error: {e}")
        time.sleep(delay)
    log_phase("bruteforce", start, now_utc(), args.target,
              {"service": "ftp", "user": FTP_USER, "attempts": attempts,
               "speed": args.speed, "succeeded": succeeded})


def phase_dos(args) -> None:
    import requests

    start = now_utc()
    threads = min(args.threads, DOS_THREADS_MAX)
    url = f"http://{args.target}:{HTTP_PORT}/"
    if args.dry_run:
        print(f"[dry-run] dos bounded HTTP GET load on {url}, {threads} threads, {args.duration}s")
        log_phase("dos", start, now_utc(), args.target,
                  {"url": url, "threads": threads, "duration": args.duration, "dry_run": True})
        return

    deadline = time.time() + args.duration
    counter = {"n": 0}
    lock = threading.Lock()
    stop = threading.Event()

    def worker():
        sess = requests.Session()
        while not stop.is_set() and time.time() < deadline:
            try:
                sess.get(url, timeout=3)
                with lock:
                    counter["n"] += 1
            except Exception:
                pass

    print(f"[dos] bounded HTTP GET load on {url} with {threads} threads for {args.duration}s")
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in ts:
        t.start()
    try:
        while time.time() < deadline and any(t.is_alive() for t in ts):
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    stop.set()
    for t in ts:
        t.join(timeout=2)
    print(f"[dos] sent ~{counter['n']} requests")
    log_phase("dos", start, now_utc(), args.target,
              {"url": url, "threads": threads, "duration": args.duration, "requests": counter["n"]})


def main() -> None:
    ap = argparse.ArgumentParser(description="HomeGuard lab traffic generator (Laptop B). Lab-only.")
    ap.add_argument("phase", choices=("portscan", "bruteforce", "dos", "all"))
    ap.add_argument("--target", required=True, help="lab victim IP (loopback or RFC1918 only)")
    ap.add_argument("--confirm-lab", action="store_true", required=False,
                    help="REQUIRED acknowledgement that the target is your own lab")
    ap.add_argument("--duration", type=int, default=DURATION_DEFAULT,
                    help=f"seconds per phase (hard max {DURATION_MAX})")
    ap.add_argument("--speed", choices=tuple(SPEEDS), default="normal")
    ap.add_argument("--threads", type=int, default=DOS_THREADS_DEFAULT,
                    help=f"dos threads (max {DOS_THREADS_MAX})")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and send nothing")
    args = ap.parse_args()

    # Guards run even for --dry-run (except we still refuse bad targets / missing flag).
    guard(args)

    print(f"Target {args.target} accepted (lab/private). confirm-lab={args.confirm_lab} "
          f"dry_run={args.dry_run} duration={args.duration}s speed={args.speed}")

    try:
        if args.phase in ("portscan", "all"):
            phase_portscan(args)
        if args.phase in ("bruteforce", "all"):
            phase_bruteforce(args)
        if args.phase in ("dos", "all"):
            phase_dos(args)
    except KeyboardInterrupt:
        print("\n[hacker] interrupted; stopping cleanly.")
        sys.exit(130)


if __name__ == "__main__":
    main()
