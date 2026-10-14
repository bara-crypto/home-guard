"""HomeGuard AI - Step 8: client/victim tooling (Laptop A). STANDALONE.

This laptop runs the target services the hacker laptop attacks, plus benign
client traffic. It never attacks anything.

Subcommands:
  serve    start an HTTP server on 0.0.0.0:8080 and an FTP server on 0.0.0.0:2121
           (pyftpdlib, one DUMMY account labuser/labpass123, no anonymous).
           Prints this laptop's LAN IPv4 addresses. Writes child PIDs to client/.pids.
  benign   loop of normal-looking HTTP client traffic against the local server
           (and optional --urls file) with random pauses; --duration seconds.
  status   show HomeGuard-owned processes and whether ports 8080/2121 are in use.
  stop     terminate everything in client/.pids and confirm 8080/2121 are free.

Dependencies: pyftpdlib, psutil, requests (all in requirements.txt).

Examples:
    python client/client_intent.py serve
    python client/client_intent.py benign --duration 60
    python client/client_intent.py status
    python client/client_intent.py stop
"""
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PIDS_FILE = HERE / ".pids"
HTTP_PORT = 8080
FTP_PORT = 2121
FTP_USER = "labuser"
FTP_PASS = "labpass123"  # DUMMY lab account. Not a secret; lab-only.


# ----------------------------- helpers -----------------------------

def lan_ipv4s() -> list[str]:
    ips = set()
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no packets sent; just picks the egress iface
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return sorted(i for i in ips if not i.startswith("127."))


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def read_pids() -> list[int]:
    if not PIDS_FILE.exists():
        return []
    out = []
    for line in PIDS_FILE.read_text().splitlines():
        line = line.strip()
        if line.isdigit():
            out.append(int(line))
    return out


def write_pids(pids: list[int]) -> None:
    PIDS_FILE.write_text("\n".join(str(p) for p in pids) + "\n")


# ----------------------------- servers (internal subcommands) -----------------------------

def _run_http() -> None:
    import http.server
    import socketserver

    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            body = (
                b"<!doctype html><html><head><title>HomeGuard Lab Target</title></head>"
                b"<body><h1>HomeGuard lab target</h1>"
                b"<p>This is a dummy web service for lab testing only.</p></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # quiet
            pass

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("0.0.0.0", HTTP_PORT), Handler) as httpd:
        print(f"[http] serving on 0.0.0.0:{HTTP_PORT}", flush=True)
        httpd.serve_forever()


def _run_ftp() -> None:
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer

    root = HERE / "_ftproot"
    root.mkdir(exist_ok=True)
    (root / "README.txt").write_text("HomeGuard lab FTP target. Dummy account only.\n")

    authorizer = DummyAuthorizer()
    authorizer.add_user(FTP_USER, FTP_PASS, str(root), perm="elr")  # read-only dummy account
    # No anonymous access.
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = "HomeGuard lab FTP (test only)"
    server = FTPServer(("0.0.0.0", FTP_PORT), handler)
    print(f"[ftp] serving on 0.0.0.0:{FTP_PORT} (user={FTP_USER})", flush=True)
    server.serve_forever()


# ----------------------------- user subcommands -----------------------------

def cmd_serve(_args) -> None:
    if port_in_use(HTTP_PORT) or port_in_use(FTP_PORT):
        print(f"Port {HTTP_PORT} or {FTP_PORT} already in use. Run 'stop' first.")
        sys.exit(1)

    # Detach the servers' stdio to a log file. If they inherited this process's
    # stdout, a caller using subprocess.run(capture_output=True) would block forever
    # waiting for EOF on a pipe the long-lived servers keep open.
    log = (HERE / "servers.log").open("a")
    http_p = subprocess.Popen([sys.executable, __file__, "_http"], cwd=str(HERE.parent),
                              stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    ftp_p = subprocess.Popen([sys.executable, __file__, "_ftp"], cwd=str(HERE.parent),
                             stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    write_pids([http_p.pid, ftp_p.pid])

    # wait for both ports
    ok = False
    for _ in range(40):
        if port_in_use(HTTP_PORT) and port_in_use(FTP_PORT):
            ok = True
            break
        time.sleep(0.25)

    ips = lan_ipv4s()
    print(json.dumps({
        "http": f"0.0.0.0:{HTTP_PORT}", "ftp": f"0.0.0.0:{FTP_PORT}",
        "ftp_user": FTP_USER, "lan_ipv4": ips, "pids": [http_p.pid, ftp_p.pid],
        "ready": ok,
    }, indent=2))
    if ips:
        print(f"\nTell Laptop B to target one of: {', '.join(ips)}")
    else:
        print("\nNo LAN IPv4 found yet; check your Wi-Fi/hotspot connection.")
    if not ok:
        print("WARNING: servers did not come up in time; check 'status'.")


def cmd_benign(args) -> None:
    import random
    import requests

    urls = [f"http://127.0.0.1:{HTTP_PORT}/"]
    if args.urls:
        extra = [u.strip() for u in Path(args.urls).read_text().splitlines() if u.strip()]
        urls.extend(extra)

    print(f"[benign] generating client traffic to {len(urls)} url(s) for {args.duration}s")
    end = time.time() + args.duration
    n = 0
    sess = requests.Session()
    while time.time() < end:
        url = random.choice(urls)
        try:
            sess.get(url, timeout=3)
            n += 1
        except Exception as e:
            print(f"[benign] {url} -> {e}")
        time.sleep(random.uniform(0.2, 1.5))
    print(f"[benign] done; {n} requests sent")


def cmd_status(_args) -> None:
    import psutil

    print(json.dumps({
        "port_8080_in_use": port_in_use(HTTP_PORT),
        "port_2121_in_use": port_in_use(FTP_PORT),
        "pids_file": str(PIDS_FILE),
        "recorded_pids": read_pids(),
    }, indent=2))
    print("\nRecorded processes:")
    for pid in read_pids():
        try:
            p = psutil.Process(pid)
            print(f"  pid {pid}: {p.name()} {' '.join(p.cmdline()[-2:])} ({p.status()})")
        except Exception:
            print(f"  pid {pid}: not running")


def _is_our_server(proc) -> bool:
    """True only if the process really is one of our _http/_ftp servers.

    Guards against PID reuse: a recorded PID may have been recycled by the OS to
    an unrelated process (even this test harness), which we must never kill.
    """
    try:
        cmd = " ".join(proc.cmdline())
    except Exception:
        return False
    return ("client_intent.py" in cmd) and (" _http" in cmd or " _ftp" in cmd)


def cmd_stop(_args) -> None:
    import psutil

    pids = read_pids()
    targets = []
    for pid in pids:
        try:
            p = psutil.Process(pid)
        except Exception:
            continue
        if _is_our_server(p):
            targets.append(p)
            try:
                p.terminate()
            except Exception:
                pass
    _gone, alive = psutil.wait_procs(targets, timeout=5)
    for p in alive:
        try:
            p.kill()
        except Exception:
            pass
    if PIDS_FILE.exists():
        PIDS_FILE.unlink()

    time.sleep(0.5)
    http_free = not port_in_use(HTTP_PORT)
    ftp_free = not port_in_use(FTP_PORT)
    print(json.dumps({
        "terminated_pids": pids,
        "port_8080_free": http_free,
        "port_2121_free": ftp_free,
    }, indent=2))
    if not (http_free and ftp_free):
        print("WARNING: a port is still in use. Check 'status' / kill leftover python processes.")
        sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser(description="HomeGuard client/victim tooling (Laptop A).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve")
    b = sub.add_parser("benign")
    b.add_argument("--duration", type=int, default=60)
    b.add_argument("--urls", default=None, help="optional file with extra URLs, one per line")
    sub.add_parser("status")
    sub.add_parser("stop")
    # internal (not advertised)
    sub.add_parser("_http")
    sub.add_parser("_ftp")

    args = ap.parse_args()
    if args.cmd == "_http":
        _run_http()
    elif args.cmd == "_ftp":
        _run_ftp()
    elif args.cmd == "serve":
        cmd_serve(args)
    elif args.cmd == "benign":
        cmd_benign(args)
    elif args.cmd == "status":
        cmd_status(args)
    elif args.cmd == "stop":
        cmd_stop(args)


if __name__ == "__main__":
    main()
