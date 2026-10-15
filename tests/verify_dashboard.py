"""HomeGuard AI - verify the agent dashboard (agent/dashboard.py).

Starts the dashboard on a free loopback port and checks, with a cookie-preserving
session:
  1. GET  /health         -> status ok (router IP detected or overridden)
  2. GET  /               -> login page shows the router-IP hint
  3. POST /login (wrong)  -> refused (redirect with ?error=1, no session)
  4. POST /login (right)  -> session cookie set, redirect to /dashboard
  5. GET  /dashboard      -> dashboard HTML (auth required)
  6. GET  /api/summary    -> valid JSON summary with the expected keys/shapes
  7. GET  /api/summary    -> 401 without a session
  8. teardown: dashboard process stopped, port free

Usage:  python tests/verify_dashboard.py
"""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
RESULTS: list[tuple[str, str, str]] = []

# Deterministic login value for the test (override real gateway detection).
TEST_ROUTER_IP = "10.99.0.1"


def record(name, ok, detail=""):
    status = "PASS" if ok is True else ("SKIP" if ok == "skip" else "FAIL")
    RESULTS.append((name, status, detail))
    print(f"[{status}] {name} {('- ' + detail) if detail else ''}")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_health(base, tries=40):
    import requests
    for _ in range(tries):
        try:
            r = requests.get(base + "/health", timeout=1)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        time.sleep(0.25)
    return None


def main() -> int:
    import requests

    # real detection must at least not crash (value may be None off-network)
    try:
        sys.path.insert(0, str(ROOT))
        from agent.dashboard import detect_router_ip
        detected = detect_router_ip()
        record("0. detect_router_ip() runs", True, str(detected))
    except Exception as e:
        record("0. detect_router_ip() runs", False, str(e))

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = dict(os.environ,
               HOMEGUARD_ROUTER_IP=TEST_ROUTER_IP,
               HOMEGUARD_MODEL_DIR=str(ROOT / "models"),
               HOMEGUARD_DASHBOARD_WINDOW_MINUTES="30")
    proc = subprocess.Popen(
        [PY, "-m", "uvicorn", "agent.dashboard:app", "--host", "127.0.0.1",
         "--port", str(port), "--log-level", "warning"],
        cwd=str(ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        health = wait_health(base)
        up = health is not None
        record("1. dashboard /health up", up, json.dumps(health))
        if not up:
            return 1

        anon = requests.get(base + "/dashboard", allow_redirects=False, timeout=5)
        record("2. /dashboard blocked when anonymous",
               anon.status_code in (302, 307) or anon.status_code == 401,
               f"status={anon.status_code}")

        page = requests.get(base + "/", timeout=5)
        record("3. login page shows router-IP hint",
               page.ok and TEST_ROUTER_IP in page.text, f"status={page.status_code}")

        bad = requests.post(base + "/login", data={"username": "1.2.3.4"},
                            allow_redirects=False, timeout=5)
        record("4. wrong username refused",
               bad.status_code in (302, 307) and "error=1" in bad.headers.get("location", "")
               and not bad.cookies)

        s = requests.Session()
        good = s.post(base + "/login", data={"username": TEST_ROUTER_IP},
                      allow_redirects=False, timeout=5)
        got_cookie = any(c.name == "hg_session" for c in s.cookies)
        record("5. correct username logs in",
               good.status_code in (302, 307) and good.headers.get("location", "").endswith("/dashboard")
               and got_cookie,
               f"status={good.status_code} cookie={got_cookie}")

        dash = s.get(base + "/dashboard", timeout=5)
        record("6. /dashboard served when authed",
               dash.ok and "Recent attacks" in dash.text, f"status={dash.status_code}")

        summ = s.get(base + "/api/summary", timeout=5)
        data = summ.json() if summ.ok else {}
        keys = {"generated_at", "window_minutes", "totals", "by_source", "timeseries",
                "recent", "status"}
        shape_ok = (summ.ok and keys.issubset(data.keys())
                    and isinstance(data.get("timeseries"), list)
                    and len(data["timeseries"]) == data.get("window_minutes")
                    and isinstance(data.get("recent"), list)
                    and isinstance(data.get("by_source"), list)
                    and isinstance(data["totals"].get("attacks"), int))
        record("7. /api/summary valid JSON summary", shape_ok,
               json.dumps(data.get("totals", {})) if summary_ok(data) else f"status={summ.status_code}")

        anon2 = requests.get(base + "/api/summary", timeout=5)
        record("8. /api/summary 401 without session", anon2.status_code == 401,
               f"status={anon2.status_code}")

        out = s.get(base + "/logout", allow_redirects=False, timeout=5)
        after = s.get(base + "/api/summary", timeout=5)
        record("9. logout invalidates session",
               out.status_code in (302, 307) and after.status_code == 401)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        time.sleep(0.5)
        free = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            free = s.connect_ex(("127.0.0.1", port)) != 0
        record("10. teardown: dashboard port free", free)

    print("\n==== DASHBOARD RESULTS ====")
    for name, status, _ in RESULTS:
        print(f"  {status:4}  {name}")
    failed = [r for r in RESULTS if r[1] == "FAIL"]
    print("\nDASHBOARD " + ("PASS" if not failed else "FAIL"))
    return 1 if failed else 0


def summary_ok(data) -> bool:
    try:
        return set(("generated_at", "window_minutes", "totals", "by_source",
                    "timeseries", "recent", "status")).issubset(data.keys())
    except Exception:
        return False


if __name__ == "__main__":
    sys.exit(main())
