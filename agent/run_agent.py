"""HomeGuard AI - Step 7: agent launcher (runs on Laptop A).

Starts the FastAPI inference API (uvicorn) and, unless --no-sniff, launches
cicflowmeter to sniff a live interface and POST flows to the agent:

    cicflowmeter -i <iface> -u http://127.0.0.1:8001/predict

It then tails logs/verdicts.jsonl and prints a JSON alert line whenever a
non-benign verdict has confidence >= threshold. Ctrl+C terminates uvicorn and
the cicflowmeter child cleanly.

Usage (as Administrator for live sniffing on Windows):
    python agent/run_agent.py --iface "Wi-Fi"
    python agent/run_agent.py --no-sniff              # API only (for tests/local)
    python agent/run_agent.py --iface "Wi-Fi" --threshold 0.8 --model-dir models
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOST, PORT = "127.0.0.1", 8001


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None, help="capture interface (e.g. 'Wi-Fi')")
    ap.add_argument("--model-dir", default=str(ROOT / "models"))
    ap.add_argument("--threshold", type=float, default=0.7)
    ap.add_argument("--no-sniff", action="store_true", help="API only; do not launch cicflowmeter")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--dashboard-port", type=int,
                    default=int(os.environ.get("HOMEGUARD_DASHBOARD_PORT", "8010")),
                    help="port for the local dashboard UI (default 8010)")
    ap.add_argument("--dashboard-host", default=os.environ.get("HOMEGUARD_DASHBOARD_HOST", "127.0.0.1"),
                    help="interface the dashboard binds (default 127.0.0.1)")
    ap.add_argument("--no-dashboard", action="store_true", help="do not start the dashboard UI")
    ap.add_argument("--api-host", default=HOST,
                    help="interface uvicorn binds (default 127.0.0.1; use 0.0.0.0 so email "
                         "'Confirm' links work from your phone/other LAN devices)")
    ap.add_argument("--no-trigger-gate", action="store_true",
                    help="do NOT wait for the lure trigger: start detecting immediately "
                         "(default for the live sniffer is to stay quiet until the lure runs)")
    ap.add_argument("--lure-log", default=os.environ.get("HOMEGUARD_LURE_LOG",
                    str(ROOT / "hacker" / "lure_log.jsonl")),
                    help="lure server log watched for an 'attack_launched' trigger")
    ap.add_argument("--alert-window", type=float,
                    default=float(os.environ.get("HOMEGUARD_ALERT_WINDOW_SECS", "300")),
                    help="seconds detection stays armed after each lure trigger (default 300)")
    args = ap.parse_args()

    if not args.no_sniff and not args.iface:
        ap.error("--iface is required unless --no-sniff is set")

    # Lure-trigger gate: only meaningful while live-sniffing (single-laptop demo).
    trigger_gate = (not args.no_sniff) and (not args.no_trigger_gate)
    lure_log = Path(args.lure_log)

    env = dict(os.environ, HOMEGUARD_MODEL_DIR=str(Path(args.model_dir).resolve()))
    if trigger_gate:
        env["HOMEGUARD_TRIGGER_GATE"] = "1"
        env["HOMEGUARD_ALERT_WINDOW_SECS"] = str(args.alert_window)
        env["HOMEGUARD_LURE_LOG"] = str(lure_log)
    log_path = ROOT / "logs" / "verdicts.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    children: list[subprocess.Popen] = []

    # 1) uvicorn API
    api_cmd = [sys.executable, "-m", "uvicorn", "agent.api:app",
               "--host", args.api_host, "--port", str(args.port), "--log-level", "warning"]
    print("[agent] starting API:", " ".join(api_cmd))
    api = subprocess.Popen(api_cmd, cwd=str(ROOT), env=env)
    children.append(api)

    # wait for /health
    import requests
    base = f"http://{HOST}:{args.port}"

    # 1a) lure-trigger watcher: keep the agent QUIET until the lure is triggered.
    # Started BEFORE the API is ready so its baseline file position is taken as
    # early as possible (a trigger is never missed due to startup timing).
    if trigger_gate:
        print("[agent] trigger gate ON - detection stays QUIET until the lure is triggered.")
        print(f"[agent] watching {lure_log} for 'attack_launched' "
              f"(armed for {int(args.alert_window)}s per trigger; disable with --no-trigger-gate).")

        # Baseline captured here (in the main thread, before the API is up) so a
        # trigger can never be missed due to thread-start timing.
        lure_start_pos = lure_log.stat().st_size if lure_log.exists() else 0

        def _watch_lure(stop_evt: threading.Event, pos: int) -> None:
            while not stop_evt.is_set():
                try:
                    if lure_log.exists():
                        with lure_log.open("r", encoding="utf-8", errors="replace") as fh:
                            fh.seek(pos)
                            for line in fh:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    rec = json.loads(line)
                                except json.JSONDecodeError:
                                    continue
                                if rec.get("action") == "attack_launched":
                                    try:
                                        requests.post(base + "/arm",
                                                      params={"window": args.alert_window}, timeout=3)
                                        print(f"[agent] lure triggered -> detection ARMED "
                                              f"for {int(args.alert_window)}s")
                                    except Exception as e:
                                        print(f"[agent] could not arm detection: {e}")
                            pos = fh.tell()
                except Exception as e:
                    print(f"[agent] lure watcher error: {e}")
                stop_evt.wait(0.5)

        _lure_stop = threading.Event()
        threading.Thread(target=_watch_lure, args=(_lure_stop, lure_start_pos), daemon=True).start()

    for _ in range(40):
        try:
            if requests.get(base + "/health", timeout=1).status_code == 200:
                break
        except Exception:
            pass
        if api.poll() is not None:
            print("[agent] API process exited early."); sys.exit(2)
        time.sleep(0.25)
    try:
        print("[agent] health:", requests.get(base + "/health", timeout=2).json())
    except Exception as e:
        print(f"[agent] health check failed: {e}")

    # 1b) dashboard UI (starts automatically with the agent)
    if not args.no_dashboard:
        dash_base = f"http://{args.dashboard_host}:{args.dashboard_port}"
        dash_cmd = [sys.executable, "-m", "uvicorn", "agent.dashboard:app",
                    "--host", args.dashboard_host, "--port", str(args.dashboard_port),
                    "--log-level", "warning"]
        print("[agent] starting dashboard:", " ".join(dash_cmd))
        dash = subprocess.Popen(dash_cmd, cwd=str(ROOT), env=env)
        children.append(dash)
        router_ip = None
        for _ in range(40):
            try:
                r = requests.get(dash_base + "/health", timeout=1)
                if r.status_code == 200:
                    router_ip = r.json().get("router_ip")
                    break
            except Exception:
                pass
            if dash.poll() is not None:
                print("[agent] dashboard process exited early."); break
            time.sleep(0.25)
        who = f"(login username = router IP {router_ip})" if router_ip else \
              "(login username = this machine's router IP)"
        print(f"[agent] dashboard ready at {dash_base}  {who}")

    # 2) cicflowmeter sniffer -> POST to /predict
    sniffer = None
    if not args.no_sniff:
        # Use the keyword-correct wrapper (the shipped cicflowmeter CLI is broken in 0.5.0).
        wrapper = ROOT / "lab" / "run_cicflowmeter.py"
        cf = [sys.executable, str(wrapper), "-i", args.iface, "-u", base + "/predict"]
        print("[agent] starting sniffer:", " ".join(cf))
        print("[agent] (Windows: must be an Administrator shell with Npcap installed)")
        try:
            sniffer = subprocess.Popen(cf, cwd=str(ROOT))
            children.append(sniffer)
        except FileNotFoundError:
            print("[agent] sniffer wrapper not found; running API-only.")

    # 3) tail verdicts and alert
    def shutdown(*_a):
        print("\n[agent] shutting down children...")
        for c in reversed(children):
            if c.poll() is None:
                try:
                    c.terminate()
                except Exception:
                    pass
        t0 = time.time()
        for c in reversed(children):
            try:
                c.wait(timeout=max(0.1, 5 - (time.time() - t0)))
            except Exception:
                try:
                    c.kill()
                except Exception:
                    pass
        print("[agent] done.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"[agent] watching {log_path} for non-benign verdicts (threshold={args.threshold}). Ctrl+C to stop.")
    pos = log_path.stat().st_size if log_path.exists() else 0
    try:
        while True:
            if api.poll() is not None:
                print("[agent] API exited; stopping."); shutdown()
            if log_path.exists():
                with log_path.open("r", encoding="utf-8") as fh:
                    fh.seek(pos)
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            v = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if v.get("outcome") == "quiet_until_trigger":
                            continue  # lure not triggered yet -> stay quiet
                        if v.get("label") != "benign" and float(v.get("confidence", 0)) >= args.threshold:
                            print("ALERT " + json.dumps(v))
                    pos = fh.tell()
            time.sleep(0.5)
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
