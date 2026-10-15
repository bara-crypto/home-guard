"""HomeGuard AI - local agent dashboard (auto-started by agent/run_agent.py).

A small, offline web UI for the agent. It is intentionally dependency-free
(inline HTML/CSS/JS, no CDN) and binds to 127.0.0.1 only.

Login: username-only (no password). The username MUST equal this machine's
default-gateway (router) IP, which is detected automatically:

    python -m uvicorn agent.dashboard:app --host 127.0.0.1 --port 8010

Set HOMEGUARD_ROUTER_IP to override detection. Tunables:
    HOMEGUARD_DASHBOARD_WINDOW_MINUTES  rolling window for the summary (default 30)
    HOMEGUARD_DASHBOARD_RECENT          number of recent attacks listed (default 20)
    HOMEGUARD_LOG_DIR                   directory holding the agent *.jsonl logs
    HOMEGUARD_MODEL_DIR                 models directory (features.json)

Data source: logs/verdicts.jsonl (one JSON per classified flow) plus counts from
logs/decisions.jsonl and logs/remediations.jsonl. Nothing is sent off the machine.
"""
from __future__ import annotations

import html
import ipaddress
import json
import os
import platform
import re
import secrets
import subprocess
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = Path(os.environ.get("HOMEGUARD_LOG_DIR", ROOT / "logs"))
VERDICT_LOG = LOG_DIR / "verdicts.jsonl"
DECISION_LOG = LOG_DIR / "decisions.jsonl"
REMEDIATION_LOG = LOG_DIR / "remediations.jsonl"
NOTIFICATION_LOG = LOG_DIR / "notifications.jsonl"
MODEL_DIR = Path(os.environ.get("HOMEGUARD_MODEL_DIR", ROOT / "models"))

WINDOW_MINUTES = int(os.environ.get("HOMEGUARD_DASHBOARD_WINDOW_MINUTES", "30"))
RECENT_LIMIT = int(os.environ.get("HOMEGUARD_DASHBOARD_RECENT", "20"))
COOKIE_NAME = "hg_session"
ATTACK_LABELS = ("portscan", "bruteforce", "dos")
# The dashboard only shows what happened since the agent (this process) started,
# so earlier runs never look like "attacks fired on their own". Override for tests.
_SESSION_START = float(os.environ.get("HOMEGUARD_SESSION_START", time.time()))
QUIET_OUTCOME = "quiet_until_trigger"
UNKNOWN_OUTCOME = "unknown_threat"

app = FastAPI(title="HomeGuard AI dashboard")
_SESSIONS: set[str] = set()


# --------------------------------------------------------------------------- #
# Router / default-gateway detection (the login "username")
# --------------------------------------------------------------------------- #
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _valid_ipv4(s: str) -> bool:
    try:
        return ipaddress.ip_address(s).version == 4 and s != "0.0.0.0"
    except ValueError:
        return False


def _gateway_windows() -> str | None:
    # `route print -4` prints the IPv4 table:  dest  mask  gateway  iface  metric
    try:
        out = subprocess.run(["route", "print", "-4"], capture_output=True,
                             text=True, timeout=10).stdout
        for line in out.splitlines():
            m = re.match(r"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\b", line)
            if m and _valid_ipv4(m.group(1)):
                return m.group(1)
    except Exception:
        pass
    # Fallback: ipconfig "Default Gateway" (IPv4 may be on the following line).
    try:
        lines = subprocess.run(["ipconfig"], capture_output=True, text=True,
                               timeout=10).stdout.splitlines()
        for i, line in enumerate(lines):
            if "Default Gateway" in line:
                for j in range(i, min(i + 3, len(lines))):
                    m = _IPV4.search(lines[j])
                    if m and _valid_ipv4(m.group(1)):
                        return m.group(1)
    except Exception:
        pass
    return None


def _gateway_linux() -> str | None:
    try:
        p = Path("/proc/net/route")
        if not p.exists():
            return None
        for line in p.read_text().splitlines()[1:]:
            f = line.split()
            if len(f) >= 3 and f[1] == "00000000":  # default route (dest 0.0.0.0)
                gw_hex = f[2]
                ip = ".".join(str(int(gw_hex[i:i + 2], 16)) for i in (6, 4, 2, 0))
                if _valid_ipv4(ip):
                    return ip
    except Exception:
        pass
    return None


def detect_router_ip() -> str | None:
    override = os.environ.get("HOMEGUARD_ROUTER_IP", "").strip()
    if override:
        return override
    if platform.system() == "Windows":
        return _gateway_windows()
    return _gateway_linux()


ROUTER_IP = detect_router_ip()


# --------------------------------------------------------------------------- #
# Auth helpers (username-only, in-memory sessions; 127.0.0.1 bind only)
# --------------------------------------------------------------------------- #
def _authed(request: Request) -> bool:
    tok = request.cookies.get(COOKIE_NAME)
    return bool(tok and tok in _SESSIONS)


def _set_session(resp) -> None:
    tok = secrets.token_urlsafe(24)
    _SESSIONS.add(tok)
    resp.set_cookie(COOKIE_NAME, tok, httponly=True, samesite="lax", path="/")


# --------------------------------------------------------------------------- #
# Log reading (cached by file signature so a 3s poll is cheap)
# --------------------------------------------------------------------------- #
_JSONL_CACHE: dict[str, tuple[tuple[int, float], list[dict]]] = {}


def _sig(path: Path):
    try:
        st = path.stat()
        return (st.st_size, st.st_mtime)
    except OSError:
        return None


def load_jsonl(path: Path) -> list[dict]:
    sig = _sig(path)
    if sig is None:
        return []
    hit = _JSONL_CACHE.get(str(path))
    if hit and hit[0] == sig:
        return hit[1]
    recs: list[dict] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    recs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        recs = []
    _JSONL_CACHE[str(path)] = (sig, recs)
    return recs


def _parse_ts(value) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def build_summary() -> dict:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=WINDOW_MINUTES)
    session_cutoff = datetime.fromtimestamp(_SESSION_START, tz=timezone.utc)
    cutoff = max(window_start, session_cutoff)
    start_min = window_start.replace(second=0, microsecond=0)

    by_label: Counter = Counter()
    by_source: dict[str, dict] = {}
    attacks: list[dict] = []
    recent_src: list[dict] = []          # known attacks + unknown threats (any RF label)
    if_counts: Counter = Counter()       # isolation-forest verdicts among unknowns

    for v in load_jsonl(VERDICT_LOG):
        t = _parse_ts(v.get("ts"))
        if t is None or t < cutoff:
            continue
        outcome = v.get("outcome")
        if outcome == QUIET_OUTCOME:
            continue  # lure not triggered yet -> ignore
        label = v.get("label")
        by_label[label] += 1
        is_unknown = outcome == UNKNOWN_OUTCOME
        if is_unknown:
            if_counts[v.get("if_result") or "unknown"] += 1
        if label == "benign":
            if is_unknown:
                recent_src.append(v)   # benign-labelled IF anomaly -> show it
            continue
        attacks.append(v)
        recent_src.append(v)
        src = v.get("src_ip") or "?"
        entry = by_source.setdefault(src, {"ip": src, "count": 0,
                                           "last_label": label, "last_ts": v.get("ts")})
        entry["count"] += 1
        if str(v.get("ts", "")) >= str(entry["last_ts"] or ""):
            entry["last_label"] = label
            entry["last_ts"] = v.get("ts")

    # attacks-per-minute buckets across the window
    buckets = [0] * WINDOW_MINUTES
    for v in attacks:
        t = _parse_ts(v.get("ts"))
        if t is None:
            continue
        idx = int((t - start_min).total_seconds() // 60)
        if 0 <= idx < WINDOW_MINUTES:
            buckets[idx] += 1
    timeseries = [
        {"t": (start_min + timedelta(minutes=i)).isoformat(), "count": buckets[i]}
        for i in range(WINDOW_MINUTES)
    ]

    recent = sorted(recent_src, key=lambda v: str(v.get("ts", "")), reverse=True)[:RECENT_LIMIT]
    recent = [{
        "ts": r.get("ts"),
        "label": r.get("label"),
        "confidence": r.get("confidence"),
        "src_ip": r.get("src_ip"),
        "dst_ip": r.get("dst_ip"),
        "outcome": r.get("outcome"),
        "is_unknown": r.get("outcome") == UNKNOWN_OUTCOME,
        "if_result": r.get("if_result"),
    } for r in recent]

    # outcome + remediation counts from the window
    outcomes: Counter = Counter()
    cloud_help = 0
    for d in load_jsonl(DECISION_LOG):
        t = _parse_ts(d.get("ts"))
        if t is None or t < cutoff:
            continue
        if d.get("outcome") == QUIET_OUTCOME:
            continue  # lure not triggered yet -> ignore
        outcomes[d.get("outcome")] += 1
        if d.get("cloud") == "sending_for_help":
            cloud_help += 1

    remediations = load_jsonl(REMEDIATION_LOG)
    remediation_status: Counter = Counter(r.get("status") for r in remediations)

    # email notifications within the window/session (one "heads-up" email per run)
    emails_sent = 0
    email_total = 0
    last_email: dict | None = None
    for n in load_jsonl(NOTIFICATION_LOG):
        if n.get("channel") != "email":
            continue
        t = _parse_ts(n.get("ts"))
        if t is None or t < cutoff:
            continue
        email_total += 1
        if n.get("status") == "sent":
            emails_sent += 1
        if last_email is None or str(n.get("ts", "")) >= str(last_email.get("ts") or ""):
            last_email = {"ts": n.get("ts"), "subject": n.get("subject"),
                          "status": n.get("status"), "to": n.get("to")}

    feature_count = 0
    feat_file = MODEL_DIR / "features.json"
    if not feat_file.exists():
        feat_file = MODEL_DIR / "features_phaseA.json"
    if feat_file.exists():
        try:
            feature_count = len(json.loads(feat_file.read_text()))
        except Exception:
            feature_count = 0
    model_file = None
    for name in ("rf_v1.joblib", "rf_phaseA.joblib"):
        if (MODEL_DIR / name).exists():
            model_file = name
            break

    channels = {}
    email_to = ""
    try:
        from agent.settings import load_settings
        s = load_settings()
        channels = {"email": bool(s["email"].get("enabled")),
                    "telegram": bool(s["telegram"].get("enabled"))}
        email_to = s["email"].get("to") or ""
    except Exception:
        pass

    sources = sorted(by_source.values(), key=lambda e: e["count"], reverse=True)

    return {
        "generated_at": now.isoformat(),
        "window_minutes": WINDOW_MINUTES,
        "router_ip": ROUTER_IP,
        "totals": {
            "flows": sum(by_label.values()),
            "attacks": len(attacks),
            "portscan": by_label.get("portscan", 0),
            "bruteforce": by_label.get("bruteforce", 0),
            "dos": by_label.get("dos", 0),
            "benign": by_label.get("benign", 0),
            "unknown": outcomes.get("unknown_threat", 0),
            "cloud_help": cloud_help,
            "emails_sent": emails_sent,
        },
        "by_type": {k: by_label.get(k, 0) for k in ATTACK_LABELS},
        "by_source": sources,
        "timeseries": timeseries,
        "recent": recent,
        "iforest": {
            "anomaly": if_counts.get("anomaly", 0),
            "normal": if_counts.get("normal", 0),
            "unavailable": if_counts.get("unavailable", 0),
        },
        "notifications": {
            "email_to": email_to,
            "sent": emails_sent,
            "total": email_total,
            "last": last_email,
        },
        "outcomes": dict(outcomes),
        "remediations": {
            "total": len(remediations),
            "by_status": dict(remediation_status),
        },
        "status": {
            "model": model_file,
            "features": feature_count,
            "channels": channels,
        },
    }


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
_STYLE = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#0f1420;color:#e6ebf2}
a{color:#6cf}
.wrap{max-width:1080px;margin:0 auto;padding:24px}
header{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
h1{font-size:20px;margin:0}
.muted{color:#8a97ab;font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.card{background:#171d2b;border:1px solid #232c3e;border-radius:10px;padding:14px}
.card .num{font-size:28px;font-weight:700}
.card .lbl{font-size:12px;color:#8a97ab;text-transform:uppercase;letter-spacing:.04em}
.card.atk{border-color:#5a2530}
.card.atk .num{color:#ff6b6b}
.card.ps .num{color:#ffd166}
.card.bf .num{color:#c792ea}
.card.dos .num{color:#ff9f43}
.card.unk .num{color:#4dd0e1}
.card.cloud .num{color:#8ab4f8}
.card.mail .num{color:#7ee787}
.panel{background:#171d2b;border:1px solid #232c3e;border-radius:10px;padding:16px;margin:14px 0}
.panel h2{font-size:14px;margin:0 0 12px;color:#a9b6c9;text-transform:uppercase;letter-spacing:.05em}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #222b3c}
th{color:#8a97ab;font-weight:600}
.tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}
.tag.portscan{background:#4a3d10;color:#ffd166}
.tag.bruteforce{background:#3a2350;color:#c792ea}
.tag.dos{background:#4a2c12;color:#ff9f43}
.tag.unknown{background:#0e3b40;color:#4dd0e1}
.spark{display:flex;align-items:flex-end;gap:3px;height:90px}
.spark .bar{flex:1;background:#2d7;border-radius:3px 3px 0 0;min-height:2px;opacity:.85}
.grid2{display:grid;grid-template-columns:1.4fr 1fr;gap:14px}
@media(max-width:760px){.grid2{grid-template-columns:1fr}}
.login{max-width:380px;margin:9vh auto;background:#171d2b;border:1px solid #232c3e;border-radius:12px;padding:28px}
.login h1{margin-bottom:6px}
input{width:100%;padding:11px 12px;border-radius:8px;border:1px solid #2b3550;background:#0f1420;color:#e6ebf2;font-size:15px;margin:8px 0}
button{width:100%;padding:11px;border:0;border-radius:8px;background:#2d7;color:#04150c;font-weight:700;font-size:15px;cursor:pointer}
.hint{background:#0f1420;border:1px dashed #2b3550;border-radius:8px;padding:10px;margin:6px 0 14px;font-size:13px;color:#9fb}
.err{color:#ff6b6b;font-size:13px;margin-top:8px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
"""


def _login_page(error: bool = False) -> str:
    hint = html.escape(ROUTER_IP) if ROUTER_IP else "unavailable"
    note = ("<div class='hint'>Login username (this machine's router IP): "
            f"<b>{hint}</b></div>") if ROUTER_IP else \
           ("<div class='hint err'>Router IP could not be detected. "
            "Set HOMEGUARD_ROUTER_IP or restart on a networked machine.</div>")
    err = "<div class='err'>Incorrect username. Enter the router IP shown above.</div>" if error else ""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HomeGuard sign in</title><style>{_STYLE}</style></head><body>
<form class="login" method="post" action="/login">
  <h1>HomeGuard</h1>
  <div class="muted">Agent dashboard — sign in</div>
  {note}
  <label class="muted" for="username">Username</label>
  <input id="username" name="username" autocomplete="off" autofocus
         placeholder="router IP address">
  <button type="submit">Sign in</button>
  {err}
</form></body></html>"""


def _dashboard_page() -> str:
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HomeGuard dashboard</title><style>{_STYLE}</style></head><body>
<div class="wrap">
  <header>
    <div><h1>HomeGuard&nbsp;AI</h1>
      <div class="muted" id="statusline">loading…</div></div>
    <div class="muted"><a href="/logout">Sign out</a></div>
  </header>

  <div class="cards">
    <div class="card atk"><div class="num" id="c-atk">–</div><div class="lbl">Attacks (window)</div></div>
    <div class="card ps"><div class="num" id="c-ps">–</div><div class="lbl">Port scan</div></div>
    <div class="card bf"><div class="num" id="c-bf">–</div><div class="lbl">Brute force</div></div>
    <div class="card dos"><div class="num" id="c-dos">–</div><div class="lbl">DoS</div></div>
    <div class="card unk"><div class="num" id="c-unk">–</div><div class="lbl">Unknown threats</div></div>
    <div class="card cloud"><div class="num" id="c-cloud">–</div><div class="lbl">Cloud help</div></div>
    <div class="card mail"><div class="num" id="c-mail">–</div><div class="lbl">Emails sent</div></div>
    <div class="card"><div class="num" id="c-flow">–</div><div class="lbl">Flows seen</div></div>
  </div>
  <div class="muted" id="ifline" style="margin:-6px 0 14px"></div>

  <div class="panel">
    <h2>Attacks per minute — last <span id="win">30</span> min</h2>
    <div class="spark" id="spark"></div>
  </div>

  <div class="grid2">
    <div class="panel">
      <h2>Recent attacks</h2>
      <table><thead><tr><th>Time (UTC)</th><th>Type</th><th>Confidence</th>
      <th>Source</th><th>Target</th><th>Outcome</th><th>IF</th></tr></thead>
      <tbody id="recent"><tr><td colspan="7" class="muted">no attacks yet</td></tr></tbody></table>
    </div>
    <div class="panel">
      <h2>Top sources</h2>
      <table><thead><tr><th>Source IP</th><th>Count</th><th>Last type</th></tr></thead>
      <tbody id="sources"><tr><td colspan="3" class="muted">—</td></tr></tbody></table>
      <div class="muted" id="remline" style="margin-top:10px"></div>
    </div>
  </div>

  <div class="panel">
    <h2>Notifications</h2>
    <div id="notif"><span class="muted">no email sent yet</span></div>
  </div>
</div>
<script>
const ATT = ['portscan','bruteforce','dos'];
function tag(l){{return '<span class="tag '+l+'">'+l+'</span>';}}
function conf(v){{return (v===null||v===undefined)?'–':(Math.round(v*100)+'%');}}
function esc(s){{return (s===null||s===undefined)?'–':String(s).replace(/[&<>]/g,
  c=>({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c]));}}
async function refresh(){{
  let r;
  try{{ r = await fetch('/api/summary',{{cache:'no-store'}}); }}
  catch(e){{ document.getElementById('statusline').textContent='connection lost — retrying…'; return; }}
  if(r.status===401){{ location.href='/'; return; }}
  const d = await r.json();
  const t = d.totals;
  document.getElementById('c-atk').textContent=t.attacks;
  document.getElementById('c-ps').textContent=t.portscan;
  document.getElementById('c-bf').textContent=t.bruteforce;
  document.getElementById('c-dos').textContent=t.dos;
  document.getElementById('c-unk').textContent=t.unknown;
  document.getElementById('c-cloud').textContent=(t.cloud_help===undefined?'–':t.cloud_help);
  document.getElementById('c-mail').textContent=(t.emails_sent===undefined?'–':t.emails_sent);
  document.getElementById('c-flow').textContent=t.flows;
  document.getElementById('win').textContent=d.window_minutes;
  const ifo=d.iforest||{{}};
  document.getElementById('ifline').textContent =
    'Isolation Forest — new threats: '+(ifo.anomaly||0)+
    ' · normal: '+(ifo.normal||0)+' · unavailable: '+(ifo.unavailable||0);
  const ch=d.status.channels||{{}};
  document.getElementById('statusline').innerHTML =
    'model: '+esc(d.status.model)+' · features: '+d.status.features+
    ' · channels: email '+(ch.email?'on':'off')+', telegram '+(ch.telegram?'on':'off')+
    ' · updated '+new Date(d.generated_at).toLocaleTimeString();
  // sparkline
  const ts=d.timeseries, mx=Math.max(1,...ts.map(x=>x.count));
  document.getElementById('spark').innerHTML = ts.map(x=>
    '<div class="bar" title="'+x.t.slice(11,16)+' — '+x.count+'" style="height:'+
    (x.count/mx*100)+'%"></div>').join('');
  // recent
  document.getElementById('recent').innerHTML = d.recent.length ? d.recent.map(r=>
    '<tr><td>'+esc((r.ts||'').slice(11,19))+'</td><td>'+
    (r.is_unknown ? tag('unknown') : (ATT.includes(r.label)?tag(r.label):esc(r.label))) +
    '</td><td>'+conf(r.confidence)+'</td><td>'+esc(r.src_ip)+'</td><td>'+esc(r.dst_ip)+
    '</td><td class="muted">'+esc(r.outcome)+'</td><td class="muted">'+esc(r.if_result||'–')+'</td></tr>').join('')
    : '<tr><td colspan="7" class="muted">no attacks yet</td></tr>';
  // sources
  document.getElementById('sources').innerHTML = d.by_source.length ? d.by_source.map(s=>
    '<tr><td>'+esc(s.ip)+'</td><td>'+s.count+'</td><td>'+
    (ATT.includes(s.last_label)?tag(s.last_label):esc(s.last_label))+'</td></tr>').join('')
    : '<tr><td colspan="3" class="muted">—</td></tr>';
  const rem=d.remediations||{{}};
  const by=rem.by_status||{{}};
  document.getElementById('remline').textContent =
    'Remediations logged: '+(rem.total||0)+
    (Object.keys(by).length? ' ('+Object.entries(by).map(([k,v])=>k+': '+v).join(', ')+')':'');
  // notifications (email)
  const nt=d.notifications||{{}};
  const to=nt.email_to||'—';
  const last=nt.last;
  document.getElementById('notif').innerHTML =
    'Email alerts go to: <b>'+esc(to)+'</b> &nbsp;·&nbsp; sent this session: <b>'+(nt.sent||0)+'</b>'+
    (last ? '<div class="muted" style="margin-top:6px">last: '+esc(last.subject)+
            ' — '+esc(last.status)+' — '+esc((last.ts||'').slice(11,19))+' UTC</div>'
          : '<div class="muted" style="margin-top:6px">no email sent yet</div>');
}}
refresh(); setInterval(refresh, 3000);
</script></body></html>"""


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if _authed(request):
        return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse(_login_page(error=request.query_params.get("error") == "1"))


@app.post("/login")
async def login(request: Request):
    body = (await request.body()).decode("utf-8", "replace")
    data = parse_qs(body)
    username = (data.get("username", [""])[0] or body).strip()
    if not ROUTER_IP or username != ROUTER_IP:
        return RedirectResponse("/?error=1", status_code=302)
    resp = RedirectResponse("/dashboard", status_code=302)
    _set_session(resp)
    return resp


@app.get("/logout")
def logout(request: Request):
    tok = request.cookies.get(COOKIE_NAME)
    _SESSIONS.discard(tok)
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    if not _authed(request):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(_dashboard_page())


@app.get("/api/summary")
def api_summary(request: Request):
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse(build_summary())


@app.get("/health")
def health():
    return {"status": "ok", "router_ip": ROUTER_IP,
            "window_minutes": WINDOW_MINUTES, "recent": RECENT_LIMIT}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1",
                port=int(os.environ.get("HOMEGUARD_DASHBOARD_PORT", "8010")))
