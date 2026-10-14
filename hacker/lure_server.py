"""HomeGuard AI - lab "lure" web server (Laptop B). STANDALONE, lab-only.

HONEST MECHANISM (read this): a web page a browser loads cannot, by itself, make
the server attack the visitor. What this does instead is the realistic lab version:
the server serves a normal-looking page, reads the VISITOR'S IP from the incoming
request, and -- only when explicitly armed -- launches the SAME bounded lab attacks
from hacker_intent.py back at that visitor IP. There is no browser exploit and no
payload delivered to the client; it is a convenience trigger so that "Laptop A
visits a page -> attack traffic appears at Laptop A" without B knowing A's IP ahead
of time.

All of hacker_intent.py's guards still apply (loopback/RFC1918 only, duration cap,
dummy wordlist, bounded DoS). The server is NOT armed by default.

Examples:
    # serve only, log visits, attack nobody (safe default)
    python hacker/lure_server.py --port 8090

    # armed: each private-IP visitor is attacked with the bounded lab attacks
    python hacker/lure_server.py --port 8090 --arm --confirm-lab --duration 20

    # see what it WOULD do without sending anything
    python hacker/lure_server.py --port 8090 --arm --confirm-lab --dry-run
"""
import argparse
import ipaddress
import json
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import hacker_intent  # reuse the exact guarded attack phases  # noqa: E402

LOG = HERE / "lure_log.jsonl"

PAGE = b"""<!doctype html><html><head><meta charset="utf-8">
<title>Free WiFi Speed Test</title>
<style>body{font-family:sans-serif;max-width:640px;margin:48px auto;color:#222}
.btn{display:inline-block;padding:10px 18px;background:#2d7;color:#fff;border-radius:6px}</style>
</head><body>
<h1>Welcome to the Guest Portal</h1>
<p>Run a quick connection speed test before you continue browsing.</p>
<p><span class="btn">Start speed test</span></p>
<p style="color:#888;font-size:12px">Lab demo page (HomeGuard). No real service.</p>
</body></html>"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log(rec: dict) -> None:
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    print("[lure] " + json.dumps(rec))


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and (a.is_loopback or a.is_private)


class Lure:
    def __init__(self, opts):
        self.opts = opts
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def on_visit(self, visitor_ip: str) -> None:
        rec = {"ts": now(), "visitor": visitor_ip, "armed": self.opts.arm}
        if not self.opts.arm:
            rec["action"] = "served_only"
            log(rec)
            return
        if not is_private(visitor_ip):
            rec["action"] = "refused_public_visitor"
            log(rec)
            return
        with self._lock:
            last = self._last.get(visitor_ip, 0)
            if time.time() - last < self.opts.cooldown:
                rec["action"] = "cooldown_skip"
                log(rec)
                return
            self._last[visitor_ip] = time.time()
        rec["action"] = "attack_launched"
        rec["phases"] = self.opts.attacks
        rec["dry_run"] = self.opts.dry_run
        log(rec)
        threading.Thread(target=self._attack, args=(visitor_ip,), daemon=True).start()

    def _attack(self, target_ip: str) -> None:
        # Build the same args object hacker_intent expects, then reuse its guarded phases.
        args = SimpleNamespace(
            target=target_ip, confirm_lab=True, duration=self.opts.duration,
            speed=self.opts.speed, threads=self.opts.threads, dry_run=self.opts.dry_run,
        )
        try:
            hacker_intent.guard(args)  # enforces private-IP + confirm-lab + duration cap
        except SystemExit as e:
            log({"ts": now(), "visitor": target_ip, "action": "guard_refused", "detail": str(e)})
            return
        phases = {"portscan": hacker_intent.phase_portscan,
                  "bruteforce": hacker_intent.phase_bruteforce,
                  "dos": hacker_intent.phase_dos}
        for name in self.opts.attacks:
            fn = phases.get(name)
            if fn:
                try:
                    fn(args)
                except Exception as e:
                    log({"ts": now(), "visitor": target_ip, "phase": name, "error": str(e)})


def make_handler(lure: Lure):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            visitor = self.client_address[0]
            lure.on_visit(visitor)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(PAGE)))
            self.end_headers()
            self.wfile.write(PAGE)

        def log_message(self, *a):
            pass
    return Handler


def main() -> None:
    ap = argparse.ArgumentParser(description="HomeGuard lab lure server (Laptop B). Lab-only.")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--arm", action="store_true",
                    help="attack each private-IP visitor (default: serve only, attack nobody)")
    ap.add_argument("--confirm-lab", action="store_true",
                    help="required with --arm; acknowledges visitors are your own lab")
    ap.add_argument("--attacks", default="portscan,bruteforce,dos",
                    help="comma list of phases to launch per visit")
    ap.add_argument("--duration", type=int, default=hacker_intent.DURATION_DEFAULT)
    ap.add_argument("--speed", choices=tuple(hacker_intent.SPEEDS), default="normal")
    ap.add_argument("--threads", type=int, default=hacker_intent.DOS_THREADS_DEFAULT)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--cooldown", type=int, default=60,
                    help="min seconds between attacks on the same visitor IP")
    args = ap.parse_args()

    if args.arm and not args.confirm_lab:
        sys.exit("REFUSED: --arm requires --confirm-lab (visitors must be your own lab).")
    args.attacks = [a.strip() for a in args.attacks.split(",") if a.strip()]

    lure = Lure(args)
    httpd = ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(lure))
    mode = "ARMED — private-IP visitors will be attacked" if args.arm else "serve-only (safe)"
    print(f"[lure] http://0.0.0.0:{args.port}  [{mode}]  dry_run={args.dry_run}")
    print("[lure] Point Laptop A's browser here. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[lure] stopped.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
