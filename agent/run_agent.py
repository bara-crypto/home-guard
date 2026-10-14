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
    ap.add_argument("--api-host", default=HOST,
                    help="interface uvicorn binds (default 127.0.0.1; use 0.0.0.0 so email "
                         "'Confirm' links work from your phone/other LAN devices)")
    args = ap.parse_args()

    if not args.no_sniff and not args.iface:
        ap.error("--iface is required unless --no-sniff is set")

    env = dict(os.environ, HOMEGUARD_MODEL_DIR=str(Path(args.model_dir).resolve()))
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
                        if v.get("label") != "benign" and float(v.get("confidence", 0)) >= args.threshold:
                            print("ALERT " + json.dumps(v))
                    pos = fh.tell()
            time.sleep(0.5)
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
