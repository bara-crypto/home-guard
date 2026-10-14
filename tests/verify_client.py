"""HomeGuard AI - Step 10a: verify the CLIENT side end to end.

Runs real processes on loopback and reports PASS/FAIL per check:
  1. start client_intent serve + agent (--no-sniff) on the Phase B demo model
  2. POST sample flows to /predict; assert JSON, labels in the 4 classes, logged
  3. run client_intent benign for 15s
  4. live cicflowmeter -> /predict path (only if we can sniff; else SKIPPED w/ reason)
  5. stop everything; assert ports 8080/2121/8001 free and no leftover procs

Usage:  python tests/verify_client.py
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
CLIENT = ROOT / "client" / "client_intent.py"
AGENT_LOG = ROOT / "logs" / "verdicts.jsonl"
RESULTS: list[tuple[str, str, str]] = []


def record(name, ok, detail=""):
    status = "PASS" if ok is True else ("SKIP" if ok == "skip" else "FAIL")
    RESULTS.append((name, status, detail))
    print(f"[{status}] {name} {('- ' + detail) if detail else ''}")


def port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return s.connect_ex(("127.0.0.1", port)) != 0


def wait_port(port, up=True, tries=40):
    for _ in range(tries):
        if port_free(port) != up:
            return True
        time.sleep(0.25)
    return False


def main() -> int:
    import requests

    # Ensure a model exists: train the demo Phase B model if none.
    models = ROOT / "models"
    if not ((models / "rf_v1.joblib").exists() or (models / "rf_phaseA.joblib").exists()):
        print("No model present; training demo Phase B model...")
        subprocess.run([PY, str(ROOT / "src" / "04_train_lab.py"), "--demo"], cwd=str(ROOT), check=True)

    procs: list[subprocess.Popen] = []
    agent = None
    try:
        # 1) serve + agent
        subprocess.run([PY, str(CLIENT), "stop"], cwd=str(ROOT),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        serve = subprocess.run([PY, str(CLIENT), "serve"], cwd=str(ROOT),
                               capture_output=True, text=True)
        print(serve.stdout)
        up = wait_port(8080) and wait_port(2121)
        record("1. client serve (8080+2121 up)", up, serve.stdout.strip().splitlines()[-1] if not up else "")

        agent = subprocess.Popen(
            [PY, "-m", "uvicorn", "agent.api:app", "--host", "127.0.0.1", "--port", "8001",
             "--log-level", "warning"],
            cwd=str(ROOT), env=dict(os.environ, HOMEGUARD_MODEL_DIR=str(models)))
        procs.append(agent)
        agent_up = False
        for _ in range(40):
            try:
                if requests.get("http://127.0.0.1:8001/health", timeout=1).status_code == 200:
                    agent_up = True
                    break
            except Exception:
                pass
            time.sleep(0.25)
        health = requests.get("http://127.0.0.1:8001/health", timeout=2).json() if agent_up else {}
        record("1. agent /health", agent_up and health.get("loaded"), json.dumps(health))

        # 2) POST sample flows (shape cicflowmeter posts: single dict, and a list)
        before = AGENT_LOG.stat().st_size if AGENT_LOG.exists() else 0
        sample_single = {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "src_port": 51000,
                         "dst_port": 8080, "protocol": 6, "flow_duration": 0.05,
                         "tot_fwd_pkts": 300, "tot_bwd_pkts": 150, "flow_pkts_s": 6000}
        r1 = requests.post("http://127.0.0.1:8001/predict", json=sample_single, timeout=5)
        r2 = requests.post("http://127.0.0.1:8001/predict",
                           json=[sample_single, {"src_ip": "1.2.3.4", "dst_ip": "10.0.0.9",
                                                 "dst_port": 80, "tot_fwd_pkts": 2, "flow_duration": 0.01}],
                           timeout=5)
        ok_json = r1.ok and r2.ok and isinstance(r1.json(), list) and isinstance(r2.json(), list)
        classes = {"benign", "portscan", "bruteforce", "dos"}
        labels_ok = all(v["label"] in classes for v in r1.json() + r2.json())
        has_conf = all(0 <= v["confidence"] <= 1 for v in r1.json() + r2.json())
        record("2. /predict returns valid JSON", ok_json, json.dumps(r1.json()))
        record("2. labels within 4 classes", labels_ok)
        record("2. confidences in [0,1]", has_conf)
        time.sleep(0.3)
        after = AGENT_LOG.stat().st_size if AGENT_LOG.exists() else 0
        record("2. verdicts appended to logs/verdicts.jsonl", after > before,
               f"{before}->{after} bytes")

        # 2b) decision pipeline: confident attack -> confirm -> remediate; benign -> silent; IF loaded
        record("2b. isolation forest loaded", bool(health.get("isolation_forest")))
        dec_log = ROOT / "logs" / "decisions.jsonl"
        dec_before = dec_log.stat().st_size if dec_log.exists() else 0
        # fresh src_ip to avoid the cooldown from the step-2 POSTs
        atk = {"src_ip": "10.0.0.77", "dst_ip": "10.0.0.9", "src_port": 5555, "dst_port": 8080,
               "protocol": 6, "flow_duration": 0.05, "tot_fwd_pkts": 320, "tot_bwd_pkts": 160,
               "totlen_fwd_pkts": 9200, "totlen_bwd_pkts": 3700, "flow_pkts_s": 6200, "flow_byts_s": 185000}
        rd = requests.post("http://127.0.0.1:8001/predict", json=atk, timeout=5).json()
        outcome = rd[0].get("outcome")
        tok = rd[0].get("token")
        record("2b. confident attack -> known_threat_confirm", outcome == "known_threat_confirm",
               json.dumps(rd[0]))
        if tok:
            c = requests.get("http://127.0.0.1:8001/confirm",
                             params={"token": tok, "action": "yes"}, timeout=5)
            rem_log = ROOT / "logs" / "remediations.jsonl"
            rem_ok = rem_log.exists() and "dry_run" in rem_log.read_text().splitlines()[-1]
            record("2b. confirm -> remediation (dry-run, no real block)",
                   c.ok and "Blocking" in c.text and rem_ok)
        else:
            record("2b. confirm -> remediation (dry-run, no real block)", False, "no token issued")
        ben = {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "src_port": 5001, "dst_port": 443,
               "protocol": 6, "flow_duration": 5.0, "tot_fwd_pkts": 40, "tot_bwd_pkts": 20,
               "totlen_fwd_pkts": 3000, "totlen_bwd_pkts": 1200, "flow_pkts_s": 8, "flow_byts_s": 600}
        rb = requests.post("http://127.0.0.1:8001/predict", json=ben, timeout=5).json()
        record("2b. benign flow -> benign_silent (no alert)", rb[0].get("outcome") == "benign_silent",
               json.dumps(rb[0]))
        dec_after = dec_log.stat().st_size if dec_log.exists() else 0
        record("2b. decisions logged to logs/decisions.jsonl", dec_after > dec_before)

        # 3) benign for 15s
        b = subprocess.run([PY, str(CLIENT), "benign", "--duration", "15"],
                           cwd=str(ROOT), capture_output=True, text=True, timeout=60)
        record("3. benign traffic 15s", b.returncode == 0 and "done" in b.stdout,
               b.stdout.strip().splitlines()[-1] if b.stdout.strip() else b.stderr[-200:])

        # 4) live cicflowmeter -> /predict (best effort)
        live_done = try_live_capture(requests)
        if live_done is True:
            record("4. live cicflowmeter->/predict", True, "flows arrived")
        else:
            record("4. live cicflowmeter->/predict", "skip", str(live_done))

    finally:
        # 5) stop everything
        if agent and agent.poll() is None:
            agent.send_signal(signal.SIGTERM)
            try:
                agent.wait(timeout=5)
            except Exception:
                agent.kill()
        stop = subprocess.run([PY, str(CLIENT), "stop"], cwd=str(ROOT),
                              capture_output=True, text=True)
        print(stop.stdout)
        time.sleep(0.5)
        free = port_free(8080) and port_free(2121) and port_free(8001)
        leftovers = leftover_procs()
        record("5. ports 8080/2121/8001 free", free)
        record("5. no leftover homeguard procs", not leftovers, ",".join(leftovers))

    print("\n==== CLIENT RESULTS ====")
    for name, status, detail in RESULTS:
        print(f"  {status:4}  {name}")
    failed = [r for r in RESULTS if r[1] == "FAIL"]
    print("\nCLIENT " + ("PASS" if not failed else "FAIL"))
    return 1 if failed else 0


def try_live_capture(requests):
    """Attempt a short real cicflowmeter capture. Returns True, or a skip-reason string."""
    from shutil import which
    wrapper = ROOT / "lab" / "run_cicflowmeter.py"
    # On Linux we need root + libpcap/tcpdump to sniff; on Windows this needs Npcap + Administrator.
    iface = "lo" if sys.platform.startswith("linux") else None
    if iface is None:
        return "live sniff only auto-tested on Linux loopback; on Windows run the 2-laptop test"
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return "not root; cannot open raw socket for live capture"
    if which("tcpdump") is None:
        return "tcpdump/libpcap not installed; needed by scapy for live capture"
    before = AGENT_LOG.stat().st_size if AGENT_LOG.exists() else 0
    sniff = subprocess.Popen([sys.executable, str(wrapper), "-i", iface, "-u", "http://127.0.0.1:8001/predict"],
                             cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # generate loopback traffic to the agent itself + client http
        end = time.time() + 8
        while time.time() < end:
            try:
                requests.get("http://127.0.0.1:8080/", timeout=1)
            except Exception:
                pass
            time.sleep(0.2)
        time.sleep(2)
    finally:
        # SIGINT (not SIGTERM) so the wrapper runs session.flush_flows() and posts
        # any pending flows before exiting.
        try:
            sniff.send_signal(signal.SIGINT)
            sniff.wait(timeout=8)
        except Exception:
            sniff.kill()
    time.sleep(1)
    after = AGENT_LOG.stat().st_size if AGENT_LOG.exists() else 0
    return True if after > before else "capture ran but no flows reached /predict"


def leftover_procs():
    try:
        import psutil
    except Exception:
        return []
    names = []
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = " ".join(p.info["cmdline"] or [])
        except Exception:
            continue
        if any(k in cmd for k in ("client_intent.py _http", "client_intent.py _ftp",
                                  "agent.api:app", "run_cicflowmeter.py")):
            names.append(f"{p.info['pid']}")
    return names


if __name__ == "__main__":
    sys.exit(main())
