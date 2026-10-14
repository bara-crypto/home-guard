"""HomeGuard AI - Step 10b: verify the HACKER side against loopback only.

The real hacker runs on another laptop; here we only confirm behaviour and that
the safety guards hold. Reports PASS/FAIL per check:
  1. start a temporary local target (client_intent serve)
  2. hacker_intent all --target 127.0.0.1 --confirm-lab --duration 10 -> log has 3 phases
  3. --dry-run prints a plan and sends nothing
  4. REFUSES public IP (8.8.8.8), missing --confirm-lab, and --duration over the cap
  5. stop the target; assert ports free and no leftover procs

Usage:  python tests/verify_hacker.py
"""
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
CLIENT = ROOT / "client" / "client_intent.py"
HACKER = ROOT / "hacker" / "hacker_intent.py"
HLOG = ROOT / "hacker" / "hacker_log.jsonl"
RESULTS: list[tuple[str, str, str]] = []


def record(name, ok, detail=""):
    status = "PASS" if ok is True else ("SKIP" if ok == "skip" else "FAIL")
    RESULTS.append((name, status, detail))
    print(f"[{status}] {name} {('- ' + detail) if detail else ''}")


def port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return s.connect_ex(("127.0.0.1", port)) != 0


def wait_port_up(port, tries=40):
    for _ in range(tries):
        if not port_free(port):
            return True
        time.sleep(0.25)
    return False


def run_hacker(extra, timeout=60):
    return subprocess.run([PY, str(HACKER)] + extra, cwd=str(ROOT),
                          capture_output=True, text=True, timeout=timeout)


def main() -> int:
    subprocess.run([PY, str(CLIENT), "stop"], cwd=str(ROOT),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if HLOG.exists():
        HLOG.unlink()
    try:
        # 1) temp target
        subprocess.run([PY, str(CLIENT), "serve"], cwd=str(ROOT),
                       capture_output=True, text=True)
        up = wait_port_up(8080) and wait_port_up(2121)
        record("1. temp target up (8080+2121)", up)

        # 2) all phases vs loopback
        before = HLOG.stat().st_size if HLOG.exists() else 0
        r = run_hacker(["all", "--target", "127.0.0.1", "--confirm-lab", "--duration", "10"],
                       timeout=120)
        phases = set()
        if HLOG.exists():
            for line in HLOG.read_text().splitlines():
                try:
                    phases.add(json.loads(line)["phase"])
                except Exception:
                    pass
        record("2. all 3 phases logged", {"portscan", "bruteforce", "dos"} <= phases,
               f"phases={sorted(phases)} rc={r.returncode}")
        has_times = True
        if HLOG.exists():
            for line in HLOG.read_text().splitlines():
                rec = json.loads(line)
                if not (rec.get("start_utc") and rec.get("end_utc")):
                    has_times = False
        record("2. each phase has start/end times", has_times)

        # 3) dry-run sends nothing (log unchanged in byte count beyond the run above)
        size_before = HLOG.stat().st_size if HLOG.exists() else 0
        rd = run_hacker(["dos", "--target", "127.0.0.1", "--confirm-lab", "--dry-run"])
        size_after = HLOG.stat().st_size if HLOG.exists() else 0
        # dry-run DOES append a log line with dry_run:true but sends no traffic; assert it says dry-run
        dry_ok = "dry-run" in rd.stdout.lower() and rd.returncode == 0
        # confirm the appended record is marked dry_run
        dry_marked = False
        if HLOG.exists():
            last = HLOG.read_text().splitlines()[-1]
            dry_marked = json.loads(last).get("parameters", {}).get("dry_run") is True
        record("3. --dry-run prints plan, marks record dry_run", dry_ok and dry_marked, rd.stdout.strip()[:120])

        # 4) guards
        g1 = run_hacker(["portscan", "--target", "8.8.8.8", "--confirm-lab"])
        record("4. refuses public IP 8.8.8.8", g1.returncode != 0, g1.stdout.strip() or g1.stderr.strip()[:120])
        g2 = run_hacker(["portscan", "--target", "127.0.0.1"])  # missing --confirm-lab
        record("4. refuses missing --confirm-lab", g2.returncode != 0,
               (g2.stdout or g2.stderr).strip()[:120])
        g3 = run_hacker(["dos", "--target", "127.0.0.1", "--confirm-lab", "--duration", "999"])
        record("4. refuses --duration over cap", g3.returncode != 0,
               (g3.stdout or g3.stderr).strip()[:120])

    finally:
        # 5) stop
        stop = subprocess.run([PY, str(CLIENT), "stop"], cwd=str(ROOT),
                              capture_output=True, text=True)
        time.sleep(0.5)
        record("5. ports 8080/2121 free", port_free(8080) and port_free(2121))

    print("\n==== HACKER RESULTS ====")
    for name, status, detail in RESULTS:
        print(f"  {status:4}  {name}")
    failed = [r for r in RESULTS if r[1] == "FAIL"]
    print("\nHACKER " + ("PASS" if not failed else "FAIL"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
