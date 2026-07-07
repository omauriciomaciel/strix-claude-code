"""Mobile-first PWA dashboard for Strix hunter sessions.

Self-contained, additive module. It only *reads from* and *calls into* the
existing CLI code (``db`` and ``scan_manager``) plus ``screen`` — it does not
modify any CLI behaviour. Running it has zero effect on the CLI.

Design priorities (per use):
  - Running screen sessions are the source of truth via ``screen -list``,
    NOT the scan-metadata DB (hunters started manually have no metadata).
  - Latest findings come from ~/.strix/strix.db.
  - "Peek" works on ANY session via ``screen -X hardcopy`` (no -L needed).

Look & feel: OwlDataLab theme (deep green/navy accents, cool-gray surface,
dark terminal-window session cards), Space Grotesk + DM Sans + JetBrains
Mono. Mobile bottom-nav shell with a desktop sidebar variant above 880px.

Run:
    .venv/bin/python -m strix_cli_claude.webapp            # 0.0.0.0:8800

Auth (single shared password):
    env STRIX_WEB_PASSWORD  or  file ~/.strix/web_password (first line).
    Edits apply immediately (re-read per request).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles

from strix_cli_claude import db, scan_manager, verifier

STATIC_DIR = Path(__file__).parent / "web_static"
SELF_SCREEN = os.getenv("STRIX_WEB_SELF_SCREEN", "strix-app")

# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #

_PW_FILE = Path.home() / ".strix" / "web_password"
_COOKIE = "strix_auth"


def _load_password() -> str:
    env = os.getenv("STRIX_WEB_PASSWORD")
    if env:
        return env
    if _PW_FILE.exists():
        lines = _PW_FILE.read_text(encoding="utf-8").splitlines()
        if lines and lines[0].strip():
            return lines[0].strip()
    _PW_FILE.parent.mkdir(mode=0o700, exist_ok=True)
    _PW_FILE.write_text("changeme\n", encoding="utf-8")
    try:
        _PW_FILE.chmod(0o600)
    except OSError:
        pass
    return "changeme"


def _token(password: str) -> str:
    return hmac.new(password.encode(), b"strix-web-authed", hashlib.sha256).hexdigest()


def _is_authed(request: Request) -> bool:
    got = request.cookies.get(_COOKIE, "")
    return bool(got) and hmac.compare_digest(got, _token(_load_password()))


# --------------------------------------------------------------------------- #
# Data: sessions (screen -list), findings, scope
# --------------------------------------------------------------------------- #

_SCREEN_RE = re.compile(r"^\s*(\d+)\.(\S+)\s+\(([^)]+)\)\s+\(([^)]+)\)\s*$")


def _age_from_dt(dt: datetime) -> str:
    secs = (datetime.now() - dt).total_seconds()
    if secs < 0:
        return ""
    if secs < 60:
        return f"{int(secs)}s"
    if secs < 3600:
        return f"{int(secs // 60)}m"
    if secs < 86400:
        return f"{int(secs // 3600)}h"
    return f"{int(secs // 86400)}d"


def _age_epoch(ts: object) -> str:
    try:
        return _age_from_dt(datetime.fromtimestamp(float(ts)))  # type: ignore[arg-type]
    except Exception:
        return ""


def list_screens() -> list[dict]:
    """Ground truth of running screen sessions, enriched with metadata if any."""
    try:
        out = subprocess.run(
            ["screen", "-list"], capture_output=True, text=True, timeout=10
        ).stdout
    except Exception:
        return []
    sessions: list[dict] = []
    for line in out.splitlines():
        m = _SCREEN_RE.match(line)
        if not m:
            continue
        pid, label, started, state = (
            m.group(1), m.group(2), m.group(3).strip(), m.group(4).strip(),
        )
        if label == SELF_SCREEN:
            continue
        target = mode = None
        if label.startswith("strix-"):
            try:
                meta = scan_manager.load_scan_metadata(label[len("strix-"):])
            except Exception:
                meta = None
            if meta:
                tg = meta.get("targets") or []
                target = ", ".join(tg) if isinstance(tg, list) else str(tg)
                mode = meta.get("scan_mode")
        age = ""
        try:
            age = _age_from_dt(datetime.strptime(started, "%m/%d/%Y %I:%M:%S %p"))
        except Exception:
            pass
        sessions.append({
            "name": f"{pid}.{label}",
            "label": label,
            "pid": pid,
            "state": state,
            "attached": "attached" in state.lower(),
            "started": started,
            "age": age,
            "target": target,
            "mode": mode,
            "is_strix": label.startswith("strix"),
        })
    sessions.sort(key=lambda s: (not s["is_strix"], s["label"]))
    return sessions


def findings_json(status: str | None = None, limit: int = 200) -> list[dict]:
    try:
        items = db.list_findings(status=status or None, limit=limit)
    except Exception:
        return []
    out = []
    for f in items:
        out.append({
            "id": f.get("id"),
            "title": f.get("title"),
            "severity": (f.get("severity") or "").lower(),
            "status": (f.get("status") or "").lower(),
            "program": f.get("program_handle"),
            "asset": f.get("asset") or f.get("target_identifier") or "",
            "vuln_type": f.get("vuln_type") or "",
            "asset_type": (f.get("asset_type") or "").upper(),
            "age": _age_epoch(f.get("created_at")),
            "notes": (f.get("notes") or "")[:1500],
            "verify_status": (f.get("verify_status") or "unverified"),
            "verify_verdict": f.get("verify_verdict") or "",
            "recording": bool(f.get("verify_recording")),
        })
    return out


def summary_json() -> dict:
    finds = []
    try:
        finds = db.list_findings(limit=2000)
    except Exception:
        pass
    confirmed = sum(1 for f in finds if (f.get("status") or "") == "confirmed")
    candidate = sum(1 for f in finds if (f.get("status") or "") == "candidate")
    return {
        "running": len(list_screens()),
        "findings": len(finds),
        "confirmed": confirmed,
        "candidate": candidate,
    }


def scope_json() -> dict:
    try:
        return {"counts": db.scan_status_counts(), "programs": db.scope_summary()}
    except Exception as e:
        return {"counts": {}, "programs": [], "error": str(e)}


def _screen_name_ok(name: str) -> bool:
    # "pid.label" — keep it strict to avoid shell/identifier abuse.
    return bool(re.fullmatch(r"\d+\.[\w.\-]+", name or ""))


# --------------------------------------------------------------------------- #
# PWA assets
# --------------------------------------------------------------------------- #

_MANIFEST = {
    "name": "Strix",
    "short_name": "Strix",
    "description": "Strix hunter dashboard",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "orientation": "portrait-primary",
    "background_color": "#F7F8FA",
    "theme_color": "#F7F8FA",
    "icons": [
        {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
        {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
        {"src": "/static/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
    ],
}

_SW = """
const CACHE='strix-v3';
const SHELL=['/static/icon-192.png','/static/icon-512.png','/static/favicon-32.png'];
self.addEventListener('install',e=>{self.skipWaiting();e.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL).catch(()=>{})));});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));});
self.addEventListener('fetch',e=>{
  const req=e.request; if(req.method!=='GET') return;
  const url=new URL(req.url);
  if(url.pathname.startsWith('/api/')||url.pathname==='/login') return;       // live data: always network
  if(req.mode==='navigate'){ e.respondWith(fetch(req).catch(()=>caches.match('/'))); return; }
  if(url.pathname.startsWith('/static/')){
    e.respondWith(caches.match(req).then(r=>r||fetch(req).then(resp=>{const c=resp.clone();caches.open(CACHE).then(cc=>cc.put(req,c));return resp;})));
  }
});
"""

# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #

_HEAD = """<meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover,maximum-scale=1">
<meta name=theme-color content="#F7F8FA">
<meta name=apple-mobile-web-app-capable content=yes>
<meta name=mobile-web-app-capable content=yes>
<meta name=apple-mobile-web-app-status-bar-style content=default>
<meta name=apple-mobile-web-app-title content=Strix>
<link rel=manifest href=/manifest.webmanifest>
<link rel=icon href=/static/favicon-32.png>
<link rel=apple-touch-icon href=/static/apple-touch-icon.png>
<link rel=preconnect href=https://fonts.googleapis.com>
<link rel=preconnect href=https://fonts.gstatic.com crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel=stylesheet>"""

# Owl mark used inline wherever the brand icon appears (header, sidebar, login).
# fill="currentColor" picks up the surrounding text color; eyes/beak/mouth are
# fixed off-white so the face reads on both light and dark tiles.
_OWL = ('<svg viewBox="0 0 120 120" fill="none" style="display:block;width:100%;height:100%">'
        '<path d="M60 10C30 10 14 30 14 60C14 80 26 96 40 104C48 108 54 110 60 110C66 110 72 108 80 104'
        'C94 96 106 80 106 60C106 30 90 10 60 10Z" fill="currentColor"/>'
        '<path d="M26 24 L34 40 L22 38 Z" fill="currentColor"/>'
        '<path d="M94 24 L86 40 L98 38 Z" fill="currentColor"/>'
        '<circle cx="42" cy="54" r="16" fill="#F7F8FA"/><circle cx="42" cy="54" r="8" fill="currentColor"/>'
        '<circle cx="44" cy="52" r="2.6" fill="#F7F8FA"/>'
        '<circle cx="78" cy="54" r="16" fill="#F7F8FA"/><circle cx="78" cy="54" r="8" fill="currentColor"/>'
        '<circle cx="80" cy="52" r="2.6" fill="#F7F8FA"/>'
        '<path d="M60 66 L66 74 L60 82 L54 74 Z" fill="#F7F8FA"/>'
        '<path d="M48 92 L60 100 L72 92" stroke="#F7F8FA" stroke-width="2.5" '
        'stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>')

_LOGIN = """<!doctype html><html lang=en><head>""" + _HEAD + """
<title>Strix · login</title><style>
*{box-sizing:border-box}
body{font-family:'DM Sans',system-ui,sans-serif;background:#F7F8FA;color:#141922;
margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
overflow:hidden;position:relative}
body::before{content:'';position:absolute;width:520px;height:520px;border-radius:50%;
background:radial-gradient(circle,rgba(42,138,109,.20),transparent 62%);top:-120px;left:-120px}
body::after{content:'';position:absolute;width:520px;height:520px;border-radius:50%;
background:radial-gradient(circle,rgba(26,62,122,.18),transparent 62%);bottom:-160px;right:-140px}
form{position:relative;width:100%;max-width:320px;text-align:center}
.mark{width:74px;height:74px;border-radius:20px;background:linear-gradient(150deg,#0D3B2E,#0A1F3F);
display:flex;align-items:center;justify-content:center;box-shadow:0 12px 30px rgba(10,31,63,.28);
margin:0 auto 22px;color:#6BC2A6;padding:16px}
input{width:100%;padding:13px 15px;margin:8px 0;border-radius:9px;border:1px solid #D9DDE4;
background:#fff;color:#141922;font-size:15px;font-family:inherit;outline:0;
text-align:center;letter-spacing:.14em}
input:focus{border-color:#0D3B2E;box-shadow:0 0 0 3px rgba(13,59,46,.14)}
button{width:100%;padding:13px;margin-top:10px;border:0;border-radius:9px;
background:#0D3B2E;color:#fff;font-size:15px;font-weight:600;font-family:inherit;cursor:pointer;
transition:background .15s}
button:active{transform:scale(.98)}
.err{display:flex;align-items:center;gap:7px;justify-content:center;color:#A02222;font-size:12.5px;
background:#FEF3F3;border:1px solid #FBDCDC;border-radius:8px;padding:8px 10px;margin:0 0 10px}
</style></head><body><form method=post action=/login>
<div class=mark>""" + _OWL + """</div>
__ERR__
<input type=password name=password placeholder=Password autofocus autocomplete=current-password>
<button type=submit>Enter</button></form></body></html>"""


_ERR_ICON = ('<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
             'stroke-width="2" stroke-linecap="round"><path d="M12 8v5M12 16h.01"></path>'
             '<circle cx="12" cy="12" r="9"></circle></svg>')


def _icon(path: str, w: int = 20, h: int = 20, sw: float = 1.85, fill: str = "none") -> str:
    stroke = "" if fill != "none" else (
        f' stroke="currentColor" stroke-width="{sw}" stroke-linecap="round" stroke-linejoin="round"'
    )
    return f'<svg width="{w}" height="{h}" viewBox="0 0 24 24" fill="{fill}"{stroke}>{path}</svg>'


_ICO_LIVE = _icon('<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"></path>')
_ICO_FINDINGS = _icon(
    '<path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6M12 20v-9'
    'M9 7V6a3 3 0 0 1 6 0v1M6 13H2M22 13h-4M5 8 3 6M21 6l-2 2M6 18l-3 2M18 18l3 2"></path>'
)
_ICO_SCOPE = _icon(
    '<path d="M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10z'
    'M13 12a1 1 0 1 0-2 0 1 1 0 0 0 2 0z"></path>'
)
_ICO_MORE = _icon('<path d="M4 12h16M4 6h16M4 18h16"></path>')
_ICO_LOGOUT = _icon('<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"></path>', w=17, h=17)
_ICO_REFRESH = _icon(
    '<path d="M23 4v6h-6M1 20v-6h6M3.5 9a9 9 0 0 1 14.8-3.4L23 10M1 14l4.7 4.4A9 9 0 0 0 20.5 15"></path>',
    w=16, h=16,
)
_ICO_CLOSE = _icon('<path d="M18 6 6 18M6 6l12 12"></path>', w=16, h=16, sw=2)
_ICO_EYE = _icon('<path d="M2 12s3-8 10-8 10 8 10 8-3 8-10 8-10-8-10-8z"></path><circle cx="12" cy="12" r="3"></circle>', w=15, h=15, sw=1.9)
_ICO_SEND = _icon('<path d="M22 2 11 13M22 2l-7 20-4-9-9-4 20-7z"></path>', w=15, h=15, sw=1.9)
_ICO_STOP = _icon('<rect x="5" y="5" width="14" height="14" rx="2"></rect>', w=14, h=14, fill="currentColor")
_ICO_SHIELD = _icon('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>', w=14, h=14, sw=1.9)
_ICO_LOG = _icon('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><path d="M14 2v6h6M9 13h6M9 17h6"></path>', w=14, h=14, sw=1.8)
_ICO_REC = _icon('<path d="m22 8-6 4 6 4V8z"></path><rect x="2" y="6" width="14" height="12" rx="2"></rect>', w=14, h=14, sw=1.8)
_ICO_DETAILS = _icon('<path d="M9 18l6-6-6-6"></path>', w=14, h=14, sw=1.8)
_ICO_CHECK = _icon('<path d="M20 6 9 17l-5-5"></path>', w=15, h=15, sw=2.3)
_ICO_REJECT = _icon('<path d="M18 6 6 18M6 6l12 12"></path>', w=15, h=15, sw=2.3)
_ICO_DOWNLOAD = _icon('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"></path>', w=15, h=15, sw=1.9)
_ICO_TRASH = _icon('<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"></path>', w=15, h=15, sw=1.9)
_ICO_LAUNCH = _icon('<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"></path>', w=16, h=16, sw=2)
_ICO_BELL = _icon('<path d="M12 3a6 6 0 0 0-6 6v2a6 6 0 0 0 12 0V9a6 6 0 0 0-6-6z"></path>', w=26, h=26, sw=1.6)
_ICO_SEARCH = _icon('<circle cx="11" cy="11" r="7"></circle><path d="M21 21l-4.3-4.3"></path>', w=26, h=26, sw=1.6)


def login_page(error: bool = False) -> str:
    err = f'<div class=err>{_ERR_ICON}Wrong password</div>' if error else ""
    return _LOGIN.replace("__ERR__", err)


_PAGE = """<!doctype html><html lang=en><head>""" + _HEAD + """
<title>Strix</title><style>
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
:root{
 --bg:#F7F8FA;--card:#ffffff;--ink:#141922;--muted:#4A5362;--muted2:#6B7484;
 --line:#E7EAEF;--line2:#D9DDE4;
 --pc:#0D3B2E;--pc2:#14523F;--pc-light:#6BC2A6;--pc-tint:#9BD6C3;
 --navy:#1A3E7A;--navy2:#112C58;
 --term:#0A0E14;--term2:#141922;--term-ink:#B8BEC8;--term-muted:#6B7484;--term-line:#1F2530;
 --r:#DC3D3D;--y:#E09400;--g:#18B07F;
 --crit-c:#A02222;--crit-bg:#FBDCDC;--crit-fg:#5E1414;
 --high-c:#DC3D3D;--high-bg:#FBDCDC;--high-fg:#A02222;
 --med-c:#E09400;--med-bg:#FBEBC2;--med-fg:#A36B00;
 --low-c:#3A72C2;--low-bg:#E1EAF7;--low-fg:#1A3E7A;
 --info-c:#8F97A5;--info-bg:#F1F3F6;--info-fg:#4A5362;
 --st-candidate-bg:#FBEBC2;--st-candidate-fg:#A36B00;
 --st-confirmed-bg:#D6F3E6;--st-confirmed-fg:#117A5B;
 --st-rejected-bg:#FBDCDC;--st-rejected-fg:#A02222;
 --st-submitted-bg:#E1EAF7;--st-submitted-fg:#1A3E7A;
 --heading:'Space Grotesk',system-ui,sans-serif;--sans:'DM Sans',system-ui,-apple-system,sans-serif;
 --mono:'JetBrains Mono',ui-monospace,Menlo,monospace;
 --sh:0 1px 3px rgba(10,31,63,.06);--sh-lg:0 4px 14px rgba(10,31,63,.16)}
html,body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
font-size:15px;overscroll-behavior-y:contain;-webkit-font-smoothing:antialiased}
body{padding-bottom:calc(76px + env(safe-area-inset-bottom))}
@keyframes fu{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.72)}}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
@keyframes scan{0%{transform:translateY(-100%)}100%{transform:translateY(2000%)}}
header{position:sticky;top:0;z-index:20;background:rgba(247,248,250,.86);backdrop-filter:blur(12px);
border-bottom:1px solid var(--line);display:flex;align-items:center;gap:9px;
padding:calc(env(safe-area-inset-top) + 11px) 16px 11px}
header .mark{width:20px;height:20px;color:var(--pc);flex:none}
header h1{font-family:var(--heading);font-size:16px;font-weight:700;letter-spacing:.03em;margin:0;flex:1}
#desktitle{display:none;flex-direction:column;flex:1;min-width:0}
#desktitle b{font-family:var(--heading);font-weight:600;font-size:19px;letter-spacing:-.01em;color:var(--ink)}
#desktitle span{font-size:12px;color:var(--muted2)}
header .upd{font-family:var(--mono);font-size:11px;color:var(--muted2)}
header button{background:#fff;border:1px solid var(--line2);color:var(--muted);
border-radius:8px;width:34px;height:34px;display:flex;align-items:center;justify-content:center}
header button:active{transform:scale(.94)}
.spin{animation:sp .7s linear infinite;transform-origin:center;display:inline-flex}
@keyframes sp{to{transform:rotate(360deg)}}
main{padding:18px 16px 28px;max-width:680px;margin:0 auto}
section[data-view]{animation:fu .25s ease}
.h2{font-family:var(--heading);font-size:18px;font-weight:600;letter-spacing:-.01em;
color:var(--ink);margin:20px 0 12px;display:flex;align-items:baseline;gap:9px}
.h2:first-child{margin-top:2px}
.h2 .n{font-family:var(--mono);font-size:13px;color:var(--muted2);font-weight:400}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:2px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;box-shadow:var(--sh)}
.stat b{display:block;font-family:var(--heading);font-size:27px;font-weight:700;line-height:1.1}
.stat span{font-family:var(--mono);font-size:10px;color:var(--muted2);text-transform:uppercase;letter-spacing:.12em;display:block}
.stat.accent{background:linear-gradient(150deg,#0D3B2E,#14523F);border-color:transparent;box-shadow:0 6px 16px rgba(10,31,63,.14)}
.stat.accent b,.stat.accent span{color:#fff}.stat.accent span{opacity:.75}
.stat.navy{background:linear-gradient(150deg,#112C58,#1A3E7A);border-color:transparent}
.stat.navy b,.stat.navy span{color:#fff}.stat.navy span{opacity:.75}
.stat.confirmed b{color:#117A5B}

/* terminal-window session card */
.term{background:var(--term);border:1px solid var(--term-line);border-radius:12px;
margin-bottom:14px;overflow:hidden;box-shadow:var(--sh-lg)}
.termbar{display:flex;align-items:center;gap:8px;padding:10px 13px;background:var(--term2);
border-bottom:1px solid var(--term-line)}
.tl{width:10px;height:10px;border-radius:50%;flex:none}
.tl.r{background:var(--r)}.tl.y{background:var(--y)}.tl.g{background:var(--g)}
.termname{font-family:var(--mono);font-size:12px;color:#B8BEC8;margin-left:4px;word-break:break-all}
.termbar .sp{flex:1}
.live{display:inline-flex;align-items:center;gap:5px;font-family:var(--mono);font-size:10px;color:var(--pc-light)}
.live .dot{width:7px;height:7px;border-radius:50%;background:var(--g);animation:pulse 1.4s infinite}
.termbar .age{font-family:var(--mono);font-size:11px;color:var(--term-muted);margin-left:8px}
.termbody{padding:13px 14px;font-family:var(--mono);font-size:12.5px;color:#9BD6C3;
word-break:break-word;line-height:1.5}
.termbody .pr{color:#3DA886;margin-right:7px}
.termbody .meta{color:var(--term-muted)}
.termbody .mode{color:#6895D6}
.termbody .st{color:var(--y)}
.termbody .cur{display:inline-block;width:8px;height:15px;background:#3DA886;vertical-align:-2px;margin-left:2px;animation:blink 1.1s step-end infinite}
.term .actions{display:flex;gap:8px;padding:0 13px 13px;margin-top:14px}
.term .actions button{flex:1;min-height:44px;display:flex;align-items:center;justify-content:center;gap:6px;
padding:9px;border-radius:8px;border:1px solid #2D3540;
background:#1F2530;color:#C4E7DB;font-size:13px;font-weight:500;font-family:var(--sans)}
.term .actions button:active{transform:scale(.96)}
.term .actions .danger{color:#F08484;border-color:#5E1414;background:rgba(220,61,61,.12)}
.term .actions svg{flex:none}

/* finding card */
.fcard{position:relative;background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:15px 16px;margin-bottom:12px;box-shadow:var(--sh);overflow:hidden}
.fcard::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--muted2)}
.fcard.sev-critical::before{background:var(--crit-c)}.fcard.sev-high::before{background:var(--high-c)}
.fcard.sev-medium::before{background:var(--med-c)}.fcard.sev-low::before{background:var(--low-c)}
.fcard.sev-info::before,.fcard.sev-informational::before{background:var(--info-c)}
.crow{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:9px}.crow .sp{flex:1}
.age{font-family:var(--mono);font-size:11px;color:var(--muted2);flex:none}
.chip{font-family:var(--mono);font-size:9.5px;font-weight:600;border-radius:5px;
padding:3px 7px;text-transform:uppercase;letter-spacing:.08em}
.pill{font-family:var(--sans);font-size:11px;font-weight:500;border-radius:999px;padding:3px 8px}
.c-critical{background:var(--crit-bg);color:var(--crit-fg)}.c-high{background:var(--high-bg);color:var(--high-fg)}
.c-medium{background:var(--med-bg);color:var(--med-fg)}.c-low{background:var(--low-bg);color:var(--low-fg)}
.c-info{background:var(--info-bg);color:var(--info-fg)}
.s-confirmed{background:var(--st-confirmed-bg);color:var(--st-confirmed-fg)}
.s-candidate{background:var(--st-candidate-bg);color:var(--st-candidate-fg)}
.s-rejected{background:var(--st-rejected-bg);color:var(--st-rejected-fg)}
.s-submitted{background:var(--st-submitted-bg);color:var(--st-submitted-fg)}
.s-duplicate{background:var(--info-bg);color:var(--info-fg)}.gray{background:var(--info-bg);color:var(--info-fg)}
.src-h1{background:#EEFAF3;color:#117A5B}.src-intigriti{background:#FBEBC2;color:#A36B00}.src-bugcrowd{background:#E1EAF7;color:#1A3E7A}
.title{font-family:var(--heading);font-weight:600;font-size:14.5px;line-height:1.4;margin:1px 0 5px}
.sub{font-size:12.5px;color:var(--muted2);word-break:break-word;margin-top:2px}
.fcard .actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:13px}
.fcard .actions button{flex:1;min-height:44px;display:flex;align-items:center;justify-content:center;gap:6px;
padding:8px 10px;border-radius:8px;border:1px solid var(--line2);
background:#fff;color:var(--muted);font-size:12.5px;font-weight:500;font-family:var(--sans)}
.fcard .actions button:active{transform:scale(.96)}
.fcard .actions .go{background:var(--pc);color:#fff;border-color:var(--pc2);font-weight:600}
.fcard .actions .danger{color:var(--crit-fg);border-color:#F08484;background:var(--crit-bg)}
.fcard .actions.confirm-row{padding-top:12px;margin-top:11px;border-top:1px solid #F1F3F6}
.fcard .actions.confirm-row .go{background:#EEFAF3;color:#117A5B;border-color:#6AD4AF}
.fcard .actions svg{flex:none}

.empty{color:var(--muted2);text-align:center;padding:34px 16px;background:var(--card);
border:1px dashed var(--line2);border-radius:12px;font-size:14px}
.empty svg{display:block;margin:0 auto 8px}
.notes{white-space:pre-wrap;background:var(--term);color:#9BD6C3;border-radius:8px;
padding:12px;margin-top:12px;font-family:var(--mono);font-size:11.5px;max-height:240px;overflow-y:auto;
-webkit-overflow-scrolling:touch;overscroll-behavior:contain;touch-action:pan-y}

form.launch label{font-size:11px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;
color:var(--muted2);display:block;margin:14px 0 7px}
form.launch label:first-of-type{margin-top:0}
form.launch input,form.launch select{width:100%;padding:12px 14px;border-radius:9px;
border:1px solid var(--line2);background:#F7F8FA;color:var(--ink);font-size:14px;font-family:inherit}
form.launch input:focus{outline:0;border-color:var(--pc);box-shadow:0 0 0 3px rgba(13,59,46,.14)}
form.launch button{width:100%;padding:13px;border:0;border-radius:9px;background:var(--pc);
color:#fff;font-weight:600;font-size:14.5px;margin-top:16px;font-family:inherit;
display:flex;align-items:center;justify-content:center;gap:8px}
.launch-card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;
box-shadow:var(--sh);max-width:560px}
.launch-card .h2{margin-top:0}
.launch-card .lede{font-size:13px;color:var(--muted2);margin:0 0 16px}
.seg{display:flex;gap:8px}.seg label{flex:1;margin:0}.seg input{display:none}
.seg span{display:block;text-align:center;padding:10px;border-radius:9px;border:1px solid var(--line2);
background:#fff;font-size:13px;font-weight:600;font-family:var(--sans)}
.seg input:checked+span{background:var(--pc);border-color:var(--pc);color:#fff}
.linkbtn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;text-align:center;
padding:12px;border-radius:9px;border:1px solid var(--line2);background:#fff;color:var(--muted);
margin-top:8px;text-decoration:none;font-weight:500;font-size:13.5px}

/* mobile bottom nav */
nav#bottomnav{position:fixed;bottom:0;left:0;right:0;z-index:20;display:flex;
background:rgba(247,248,250,.9);backdrop-filter:blur(14px);border-top:1px solid var(--line);
padding:8px 6px calc(6px + env(safe-area-inset-bottom))}
nav#bottomnav button{flex:1;background:none;border:0;color:var(--muted2);padding:6px 2px;
display:flex;flex-direction:column;align-items:center;gap:4px;transition:color .15s;font-family:var(--sans)}
nav#bottomnav button .lbl{font-size:10.5px;font-weight:500}
nav#bottomnav button.active{color:var(--pc)}
nav#bottomnub button.active .lbl,nav#bottomnav button.active .lbl{font-weight:700}

/* desktop sidebar (hidden on mobile) */
aside#sidebar{display:none}
@media(min-width:880px){
 body{margin-left:230px;padding-bottom:0}
 nav#bottomnav{display:none}
 header{padding:0 24px;height:62px}
 header .mark{display:none}
 header h1{display:none}
 #desktitle{display:flex}
 main{max-width:1080px;padding:26px 28px 40px}
 .term,.fcard{margin-bottom:0}
 #sessions,#home_findings,#findings,#scope_progs{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px}
 .sheet{position:relative!important;left:auto!important;right:auto!important;bottom:auto!important;
  width:520px;max-width:92%;max-height:80%;border-radius:16px!important}
 .overlay{display:flex!important;align-items:center;justify-content:center}
 .overlay:not(.show){display:none!important}
 aside#sidebar{display:flex;flex-direction:column;position:fixed;top:0;left:0;bottom:0;width:230px;
  background:linear-gradient(185deg,#051D16,#050E1F);color:#fff;z-index:30}
 aside#sidebar .brand{padding:20px 18px 16px;display:flex;align-items:center;gap:10px}
 aside#sidebar .brand .mark{width:26px;height:26px;color:var(--pc-light)}
 aside#sidebar .brand b{font-family:var(--heading);font-weight:700;font-size:17px;letter-spacing:.03em}
 aside#sidebar nav{flex:1;overflow:auto;padding:6px 12px;display:flex;flex-direction:column;gap:3px}
 aside#sidebar nav button{display:flex;align-items:center;gap:11px;padding:9px 12px;border-radius:8px;
  border:0;cursor:pointer;width:100%;font-family:var(--sans);font-size:13.5px;background:transparent;
  color:rgba(255,255,255,.72);font-weight:500;text-align:left}
 aside#sidebar nav button.active{background:rgba(107,194,166,.14);color:var(--pc-tint);font-weight:600}
 aside#sidebar nav button .lbl{flex:1}
 aside#sidebar nav button .badge{background:var(--y);color:#051D16;font-size:10px;font-weight:700;
  padding:1px 7px;border-radius:999px;font-family:var(--mono)}
 aside#sidebar .logout{margin:12px;padding:9px 12px;border-radius:8px;border:0;background:transparent;
  color:rgba(255,255,255,.6);cursor:pointer;font-family:var(--sans);font-size:13.5px;font-weight:500;
  display:flex;align-items:center;gap:9px;text-decoration:none}
}

#toast{position:fixed;left:50%;bottom:calc(86px + env(safe-area-inset-bottom));
transform:translateX(-50%) translateY(20px);background:#141922;border-left:3px solid var(--navy);
color:#fff;padding:11px 15px;border-radius:10px;box-shadow:0 10px 30px rgba(10,31,63,.3);
font-size:13px;font-weight:500;opacity:0;pointer-events:none;transition:.26s;z-index:60;max-width:88vw;
display:flex;align-items:center;gap:9px}
#toast .dot{width:8px;height:8px;border-radius:50%;background:var(--navy);flex:none}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
#toast.err{border-left-color:var(--r)}#toast.err .dot{background:var(--r)}
#toast.ok{border-left-color:var(--g)}#toast.ok .dot{background:var(--g)}
@media(min-width:880px){#toast{left:calc(230px + (100% - 230px)/2);bottom:28px}}

.overlay{position:fixed;inset:0;z-index:50;background:rgba(10,31,63,.48);display:none}
.overlay.show{display:block;animation:fade .2s}@keyframes fade{from{opacity:0}to{opacity:1}}
.sheet{position:absolute;left:0;right:0;bottom:0;background:var(--card);border-radius:20px 20px 0 0;
padding:0;max-height:88vh;overflow:hidden;display:flex;flex-direction:column;
animation:up .28s cubic-bezier(.22,1,.36,1)}
body.locked{position:fixed;left:0;right:0;width:100%;overflow:hidden}
@keyframes up{from{transform:translateY(100%)}to{transform:none}}
.sheet.dark{background:var(--term);color:var(--term-ink)}
.sheethead{display:flex;align-items:center;gap:10px;padding:16px 18px;border-bottom:1px solid var(--line);flex-shrink:0}
.sheet.dark .sheethead{border-color:var(--term-line)}
.sheethead .tt{flex:1;min-width:0}
.sheethead h3{margin:0;font-family:var(--heading);font-size:16px;font-weight:600;color:var(--ink)}
.sheet.dark .sheethead h3{color:#F7F8FA}
.sheethead .tt .sub{font-family:var(--mono);font-size:11px;color:var(--muted2);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sheet.dark .sheethead .tt .sub{color:var(--term-muted)}
.sheethead .x{font-size:0;width:32px;height:32px;flex:none;display:flex;align-items:center;justify-content:center;
border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--muted2)}
.sheet.dark .sheethead .x{background:#1F2530;border-color:#2D3540;color:#B8BEC8}
.sheetbody{padding:18px;overflow-y:auto;-webkit-overflow-scrolling:touch;flex:1}
.quick{display:flex;flex-wrap:wrap;gap:8px}
.quick .lbl{font-size:11px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted2);
margin-bottom:10px;width:100%}
.quick button{background:#F7F8FA;border:1px solid var(--line2);color:var(--pc2);
border-radius:8px;padding:8px 13px;font-size:12.5px;font-family:var(--mono)}
.quick button:active{transform:scale(.95)}
.sheet input{width:100%;padding:11px 13px;border-radius:9px;border:1px solid var(--line2);
background:#F7F8FA;color:var(--ink);font-size:16px;font-family:var(--mono)}
.sheet .send{padding:11px 18px;border:0;border-radius:9px;
background:var(--pc);color:#fff;font-weight:600;font-size:13.5px;font-family:var(--sans)}
#peekbox,#recbox,#verbox{white-space:pre-wrap;font-family:var(--mono);font-size:12px;color:#9BD6C3;
padding:0;line-height:1.7;-webkit-overflow-scrolling:touch;touch-action:pan-y}
#verbox{color:#B8BEC8;font-size:11.5px;line-height:1.75}
#recbox video{width:100%;border-radius:8px;background:#000}

/* verification status panel (status / verdict / sandbox) */
#verstat{display:flex;gap:10px;flex-wrap:wrap;padding:14px 18px;border-bottom:1px solid var(--term-line);flex-shrink:0}
#verstat .col{flex:1;min-width:90px}
#verstat .col .k{font-family:var(--mono);font-size:9.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--term-muted)}
#verstat .col .v{font-family:var(--mono);font-size:13px;color:#9BD6C3;margin-top:3px;display:flex;align-items:center;gap:6px}
#verstat .col .v .dot{width:8px;height:8px;border-radius:50%;background:var(--g);animation:pulse 1.4s infinite}
#verstat .col .v.off .dot{background:var(--term-muted);animation:none}
#verstat.loading{display:block;padding:14px 18px;color:var(--term-muted);font-size:12px}

/* recording preview chrome */
#recstage{position:relative;background:#000;border-radius:10px;aspect-ratio:16/10;overflow:hidden;
display:flex;align-items:center;justify-content:center;border:1px solid var(--term-line);margin-bottom:14px}
#recstage .grid{position:absolute;inset:0;background:repeating-linear-gradient(0deg,rgba(107,194,166,.04) 0,rgba(107,194,166,.04) 1px,transparent 1px,transparent 3px);pointer-events:none}
#recstage .scanline{position:absolute;top:0;left:0;right:0;height:14px;background:linear-gradient(180deg,rgba(107,194,166,.5),transparent);animation:scan 3.5s linear infinite;pointer-events:none}
#recstage .badge{position:absolute;top:10px;left:12px;font-family:var(--mono);font-size:10px;color:var(--pc-light);display:flex;align-items:center;gap:6px}
#recstage .badge .dot{width:7px;height:7px;border-radius:50%;background:var(--r);animation:pulse 1.4s infinite}
#recstage img,#recstage video{width:100%;height:100%;object-fit:contain}
#recmeta{font-family:var(--mono);font-size:11px;color:var(--term-muted);margin-bottom:14px}
</style></head><body>
<aside id=sidebar>
 <div class=brand><span class=mark>""" + _OWL + """</span><b>STRIX</b></div>
 <nav>
  <button class=navbtn data-tab=home onclick="show('home')">""" + _ICO_LIVE + """<span class=lbl>Live</span></button>
  <button class=navbtn data-tab=findings onclick="show('findings')">""" + _ICO_FINDINGS + """<span class=lbl>Findings</span></button>
  <button class=navbtn data-tab=scope onclick="show('scope')">""" + _ICO_SCOPE + """<span class=lbl>Scope</span></button>
  <button class=navbtn data-tab=more onclick="show('more')">""" + _ICO_MORE + """<span class=lbl>More</span></button>
 </nav>
 <a class=logout href=/logout>""" + _ICO_LOGOUT + """Log out</a>
</aside>

<header><span class=mark>""" + _OWL + """</span><h1>STRIX</h1>
<div id=desktitle><b id=desktitle_t>Live</b><span id=desktitle_s>real-time sessions and findings</span></div>
<span class=upd><span id=updlbl>atualizado</span> <span id=upd>–</span></span>
<button onclick=refresh() id=refbtn>""" + _ICO_REFRESH + """</button></header>

<main>
 <section data-view=home>
  <div class=stats>
   <div class="stat accent"><b id=s_run>–</b><span>running</span></div>
   <div class=stat><b id=s_cand>–</b><span>candidates</span></div>
   <div class="stat confirmed"><b id=s_conf>–</b><span>confirmed</span></div>
  </div>
  <h2 class=h2>Running sessions <span class=n id=sess_n>0</span></h2>
  <div id=sessions></div>
  <h2 class=h2>Latest findings</h2>
  <div id=home_findings></div>
 </section>

 <section data-view=findings hidden>
  <h2 class=h2>Findings</h2>
  <div class=quick id=fpills></div>
  <div id=findings></div>
 </section>

 <section data-view=scope hidden>
  <h2 class=h2>Targets</h2>
  <div class=stats id=scope_stats></div>
  <h2 class=h2>Programs</h2>
  <div id=scope_progs></div>
 </section>

 <section data-view=more hidden>
  <div class=launch-card>
   <h2 class=h2>Launch scan</h2>
   <p class=lede>Point the owl at a new target.</p>
   <form class=launch onsubmit="return doLaunch(event)">
    <label>Target</label>
    <input name=targets placeholder="url / repo / path" required>
    <label>Mode</label>
    <div class=seg>
     <label><input type=radio name=scan_mode value=deep checked><span>deep</span></label>
     <label><input type=radio name=scan_mode value=standard><span>standard</span></label>
     <label><input type=radio name=scan_mode value=quick><span>quick</span></label>
    </div>
    <label>Agent</label>
    <div class=seg>
     <label><input type=radio name=agent value=claude checked><span>claude</span></label>
     <label><input type=radio name=agent value=opencode><span>opencode</span></label>
    </div>
    <label>Instruction (optional)</label>
    <input name=instruction placeholder="e.g. focus on auth and IDOR">
    <button type=submit>""" + _ICO_LAUNCH + """Start scan</button>
   </form>
  </div>
  <a class=linkbtn href=/logout>""" + _ICO_LOGOUT + """Log out</a>
  <p class=sub style="text-align:center;margin-top:16px">sessions from <code>screen -list</code> · findings from strix.db</p>
 </section>
</main>

<nav id=bottomnav>
 <button class=navbtn data-tab=home onclick="show('home')">""" + _ICO_LIVE + """<span class=lbl>Live</span></button>
 <button class=navbtn data-tab=findings onclick="show('findings')">""" + _ICO_FINDINGS + """<span class=lbl>Findings</span></button>
 <button class=navbtn data-tab=scope onclick="show('scope')">""" + _ICO_SCOPE + """<span class=lbl>Scope</span></button>
 <button class=navbtn data-tab=more onclick="show('more')">""" + _ICO_MORE + """<span class=lbl>More</span></button>
</nav>

<div id=toast></div>

<div class=overlay id=sendov onclick="if(event.target===this)close_('sendov')">
 <div class=sheet><div class=sheethead><div class=tt><h3>Send command</h3><div class=sub id=sendtitle></div></div><button class=x onclick="close_('sendov')">""" + _ICO_CLOSE + """</button></div>
  <div class=sheetbody>
   <div class=quick>
    <div class=lbl>Quick commands</div>
    <button onclick="qsend('work')">work</button>
    <button onclick="qsend('go')">go</button>
    <button onclick="qsend('sync h1')">sync h1</button>
    <button onclick="qsend('sync intigriti')">sync intigriti</button>
    <button onclick="qsend('sync bugcrowd')">sync bugcrowd</button>
    <button onclick="qsend('status')">status</button>
    <button onclick="qsend('continue')">continue</button>
   </div>
   <div class=lbl style="margin-top:18px;width:100%">Custom command</div>
   <div style="display:flex;gap:8px">
    <input id=sendinput placeholder="custom command…" autocomplete=off style="flex:1">
    <button class=send onclick="sendCustom()">Send</button>
   </div>
  </div>
 </div>
</div>

<div class=overlay id=peekov onclick="if(event.target===this)close_('peekov')">
 <div class="sheet dark"><div class=sheethead><div class=tt><h3>Peek</h3><div class=sub id=peektitle></div></div>
  <button class=send style="padding:7px 12px;font-size:12.5px;background:#1F2530;color:#C4E7DB" onclick=peekRefresh()>Refresh</button>
  <button class=x onclick="close_('peekov')">""" + _ICO_CLOSE + """</button></div>
  <div id=peekbox class=sheetbody>loading…</div>
 </div>
</div>

<div class=overlay id=verov onclick="if(event.target===this)close_('verov')">
 <div class="sheet dark"><div class=sheethead><div class=tt><h3>Verification</h3><div class=sub id=vertitle></div></div><button class=x onclick="close_('verov')">""" + _ICO_CLOSE + """</button></div>
  <div id=verstat class=loading>loading…</div>
  <div id=verbox class=sheetbody>…</div>
  <div style="display:flex;gap:8px;padding:14px 18px;border-top:1px solid var(--term-line)">
   <button class=send style="display:flex;align-items:center;gap:6px;background:rgba(220,61,61,.12);color:#F08484" onclick="stopVer()">""" + _ICO_STOP + """Stop</button>
   <button class=send style="flex:1;background:#1F2530;color:#C4E7DB" onclick="close_('verov')">Close</button>
  </div></div>
</div>

<div class=overlay id=recov onclick="if(event.target===this)close_('recov')">
 <div class="sheet dark"><div class=sheethead><div class=tt><h3>PoC recording</h3><div class=sub id=rectitle></div></div><button class=x onclick="close_('recov')">""" + _ICO_CLOSE + """</button></div>
  <div class=sheetbody>
   <div id=recstage><div class=grid></div><div class=scanline></div><div class=badge><span class=dot></span><span id=rectime>REC</span></div><div id=recbox></div></div>
   <div id=recmeta></div>
  </div>
  <div style="display:flex;gap:8px;padding:14px 18px;border-top:1px solid var(--term-line)">
   <a id=recdl class=send style="flex:1;display:flex;align-items:center;justify-content:center;gap:6px;text-decoration:none;background:#1F2530;color:#C4E7DB" download>""" + _ICO_DOWNLOAD + """Download</a>
   <button class=send style="display:flex;align-items:center;gap:6px;background:rgba(220,61,61,.12);color:#F08484" onclick="deleteRec()">""" + _ICO_TRASH + """Delete</button>
   <button class=send style="background:#1F2530;color:#C4E7DB" onclick="close_('recov')">Close</button>
  </div>
 </div>
</div>

<script>
let activeTab='home', findingFilter='', sendTarget='', peekTarget='';
let lastHome='', lastFind='', lastScope='';
const $=id=>document.getElementById(id);
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
async function api(u,o){const r=await fetch(u,o);if(r.status===401){location.href='/login';throw 0;}return r;}
const getJSON=async u=>(await api(u)).json();
const post=(u,b)=>api(u,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(b).toString()});

const ICO_REFRESH='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6M1 20v-6h6M3.5 9a9 9 0 0 1 14.8-3.4L23 10M1 14l4.7 4.4A9 9 0 0 0 20.5 15"></path></svg>';
const ICO_EYE='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-8 10-8 10 8 10 8-3 8-10 8-10-8-10-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
const ICO_SEND='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2 11 13M22 2l-7 20-4-9-9-4 20-7z"></path></svg>';
const ICO_STOP='<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><rect x="5" y="5" width="14" height="14" rx="2"></rect></svg>';
const ICO_SHIELD='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>';
const ICO_LOG='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><path d="M14 2v6h6M9 13h6M9 17h6"></path></svg>';
const ICO_REC='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m22 8-6 4 6 4V8z"></path><rect x="2" y="6" width="14" height="12" rx="2"></rect></svg>';
const ICO_DETAILS='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18l6-6-6-6"></path></svg>';
const ICO_CHECK='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"></path></svg>';
const ICO_REJECT='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"></path></svg>';
const ICO_BELL='<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#B8BEC8" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0-6 6v2a6 6 0 0 0 12 0V9a6 6 0 0 0-6-6z"></path></svg>';
const ICO_SEARCH='<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#B8BEC8" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"></circle><path d="M21 21l-4.3-4.3"></path></svg>';
const ICO_TARGET='<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#B8BEC8" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><circle cx="12" cy="12" r="5"></circle><circle cx="12" cy="12" r="1"></circle></svg>';

const TAB_TITLES={home:['Live','real-time sessions and findings'],findings:['Findings','vulnerability triage'],scope:['Scope','programs and targets'],more:['Settings','launch a scan and account']};

function toast(m,k){const t=$('toast');t.innerHTML='<span class=dot></span>'+esc(m);t.className='show '+(k||'');setTimeout(()=>t.className='',2300);}
function setBusy(b){$('refbtn').innerHTML=b?'<span class=spin>'+ICO_REFRESH+'</span>':ICO_REFRESH;}
function stamp(){const d=new Date();$('upd').textContent=d.toTimeString().slice(0,8);}

function sevChip(s){const k=({critical:'c-critical',high:'c-high',medium:'c-medium',low:'c-low',info:'c-info',informational:'c-info'}[s])||'c-info';return `<span class="chip ${k}">${esc(s||'?')}</span>`;}
function stChip(s){const k=({confirmed:'s-confirmed',candidate:'s-candidate',rejected:'s-rejected',submitted:'s-submitted',duplicate:'s-duplicate'}[s])||'gray';return `<span class="pill ${k}">${esc(s||'?')}</span>`;}
function srcChip(s){const k=({h1:'src-h1',intigriti:'src-intigriti',bugcrowd:'src-bugcrowd'}[s])||'gray';return `<span class="chip ${k}">${esc(s||'?')}</span>`;}

function sessionCard(s){
 const tgt = s.target ? esc(s.target) : (s.is_strix?'strix hunter':'manual session');
 return `<div class=term>
  <div class=termbar><span class="tl r"></span><span class="tl y"></span><span class="tl g"></span>
   <span class=termname>${esc(s.label)}</span><span class=sp></span>
   <span class=live><span class=dot></span>live</span><span class=age>up ${esc(s.age||'?')}</span></div>
  <div class=termbody><span class=pr>$</span>${tgt}${s.mode?(' <span class=meta>· </span><span class=mode>'+esc(s.mode)+'</span>'):''}
   <span class=meta>&nbsp;(</span><span class=st>${esc(s.state)}</span><span class=meta>)</span><span class=cur></span></div>
  <div class=actions>
   <button onclick="peek('${esc(s.name)}','${esc(s.label)}')">${ICO_EYE}Peek</button>
   <button onclick="openSend('${esc(s.name)}','${esc(s.label)}')">${ICO_SEND}Send</button>
   <button class=danger onclick="stopSession('${esc(s.name)}','${esc(s.label)}')">${ICO_STOP}Stop</button>
  </div></div>`;
}
function vChip(vs,verdict){
 const map={passed:'c-low',failed:'c-critical',inconclusive:'c-info',running:'c-medium',queued:'c-medium',error:'gray'};
 const cls=map[vs]||'gray';
 const label = vs==='passed'?('✓ '+(verdict||'VALID')) : vs==='failed'?(verdict||'FALSE POSITIVE') : ('verify: '+vs);
 return `<span class="pill ${cls}">${esc(label)}</span>`;
}
function findingCard(f){
 const vs=f.verify_status||'unverified';
 const busy=(vs==='queued'||vs==='running');
 const vbadge=(vs && vs!=='unverified')?`<span onclick="openVerify(${f.id})" style="cursor:pointer">${vChip(vs,f.verify_verdict)}</span>`:'';
 const atype=f.asset_type?`<span class=badge>${esc(f.asset_type)}</span>`:'';
 return `<div class="fcard sev-${esc(f.severity)}">
  <div class=crow>${sevChip(f.severity)} ${stChip(f.status)} ${vbadge}<span class=sp></span><span class=age>${esc(f.age)}</span></div>
  <div class=title>${esc(f.title)}</div>
  <div class=sub>${esc(f.program||'—')}${f.asset?(' · '+esc(f.asset)):''} ${atype}</div>
  <div class=actions>
   <button onclick="${busy?`openVerify(${f.id})`:`verifyF(${f.id})`}">${busy?'⏳ Progress':(ICO_SHIELD+(vs==='unverified'?'Verify':'Re-verify'))}</button>
   ${(vs&&vs!=='unverified'&&!busy)?`<button onclick="openVerify(${f.id})">${ICO_LOG}Log</button>`:''}
   ${f.recording?`<button class=go onclick="openRec(${f.id})">${ICO_REC}Recording</button>`:''}
   ${f.notes?`<button onclick="this.closest('.fcard').querySelector('.notes').hidden^=1">${ICO_DETAILS}Details</button>`:''}
  </div>
  <div class="actions confirm-row">
   <button class=go onclick="setF(${f.id},'confirmed')">${ICO_CHECK}Confirm</button>
   <button class=danger onclick="setF(${f.id},'rejected')">${ICO_REJECT}Reject</button>
  </div>
  ${f.notes?`<div class=notes hidden>${esc(f.notes)}</div>`:''}</div>`;
}

async function renderHome(){
 const d=await getJSON('/api/home');
 $('s_run').textContent=d.summary.running; $('s_cand').textContent=d.summary.candidate; $('s_conf').textContent=d.summary.confirmed;
 $('sess_n').textContent=d.sessions.length;
 const k=JSON.stringify([d.sessions,d.findings]);if(k===lastHome)return;lastHome=k;
 $('sessions').innerHTML=d.sessions.length?d.sessions.map(sessionCard).join(''):`<div class=empty>${ICO_BELL}No running sessions</div>`;
 $('home_findings').innerHTML=d.findings.length?d.findings.map(findingCard).join(''):`<div class=empty>${ICO_SEARCH}No findings yet</div>`;
}
const FILTERS=['','candidate','confirmed','rejected','submitted'];
async function renderFindings(){
 $('fpills').innerHTML=FILTERS.map(f=>`<button onclick="findingFilter='${f}';renderFindings()" style="${f===findingFilter?'background:var(--pc);color:#fff;border-color:transparent':''}">${f||'all'}</button>`).join('');
 const d=await getJSON('/api/findings?status='+encodeURIComponent(findingFilter));
 const k=findingFilter+'|'+JSON.stringify(d);if(k===lastFind)return;lastFind=k;
 $('findings').innerHTML=d.length?d.map(findingCard).join(''):`<div class=empty>${ICO_SEARCH}Nothing matches this filter</div>`;
}
async function renderScope(){
 const d=await getJSON('/api/scope');const c=d.counts||{};
 const k=JSON.stringify(d);if(k===lastScope)return;lastScope=k;
 $('scope_stats').innerHTML=[['pending',c.pending||0,''],['running',c.in_progress||0,'navy'],['done',c.done||0,'confirmed']]
   .map(([k,v,cls])=>`<div class="stat ${cls}"><b>${v}</b><span>${k}</span></div>`).join('');
 $('scope_progs').innerHTML=(d.programs||[]).length?d.programs.map(p=>{
   const tot=p.total||0,done=p.done||0,pct=tot?Math.round(done/tot*100):0;
   return `<div class=fcard><div class=crow><span class=title style="margin:0;font-size:14px">${esc(p.program_handle)}</span><span class=sp></span>${srcChip(p.source)}</div>
   <div class=sub>${esc(p.asset_type)} · ${done}/${tot} done · ${p.pending||0} pending</div>
   <div style="height:8px;background:var(--info-bg);border-radius:999px;margin-top:11px;overflow:hidden"><div style="height:100%;width:${pct}%;background:linear-gradient(90deg,var(--pc),#3DA886);border-radius:999px;transition:width .4s"></div></div>
   <div style="text-align:right;font-family:var(--mono);font-size:11px;color:var(--muted2);margin-top:6px">${pct}%</div></div>`;
 }).join(''):`<div class=empty>${ICO_TARGET}No programs synced</div>`;
}
async function refresh(){if(document.querySelector('.overlay.show'))return;setBusy(true);const y=window.scrollY;try{
  if(activeTab==='home')await renderHome();
  else if(activeTab==='findings')await renderFindings();
  else if(activeTab==='scope')await renderScope();
  stamp();
 }catch(e){toast('refresh failed — showing last known data','err');}
 finally{setBusy(false);window.scrollTo(0,y);}}
function show(t){activeTab=t;document.querySelectorAll('[data-view]').forEach(e=>e.hidden=e.dataset.view!==t);
 document.querySelectorAll('.navbtn').forEach(b=>b.classList.toggle('active',b.dataset.tab===t));
 const tt=TAB_TITLES[t]; if(tt){$('desktitle_t').textContent=tt[0];$('desktitle_s').textContent=tt[1];}
 window.scrollTo(0,0);refresh();}

// actions
async function setF(id,st){try{await post('/api/finding',{id,status:st});toast(st==='confirmed'?'Confirmed ✓':'Rejected','ok');refresh();}catch(e){toast('failed','err');}}
async function verifyF(id){try{await post('/api/verify',{id});toast('verification queued — isolated repro running','ok');refresh();setTimeout(()=>openVerify(id),400);}catch(e){toast('verify failed','err');}}
let verId=0, verTimer=null;
async function openVerify(id){
 verId=id; $('vertitle').textContent='#'+id+' · verification log';
 $('verstat').className='loading'; $('verstat').textContent='loading…'; $('verbox').textContent='';
 $('verov').classList.add('show'); lockBody();
 await verPoll(); clearInterval(verTimer); verTimer=setInterval(verPoll,3000);
}
async function verPoll(){
 if(!$('verov').classList.contains('show')){clearInterval(verTimer);return;}
 try{
  const d=await getJSON('/api/verify-log/'+verId);
  const alive=!!d.container;
  const verdict=d.verdict||'—';
  $('verstat').className='';
  $('verstat').innerHTML=
   `<div class=col><div class=k>status</div><div class=v>${esc(d.status||'?')}</div></div>`+
   `<div class=col><div class=k>verdict</div><div class=v>${esc(verdict)}</div></div>`+
   `<div class=col><div class=k>sandbox</div><div class=v${alive?'':' off'}><span class=dot></span>${alive?esc(d.container):'off'}</div></div>`;
  const box=$('verbox'); const bottom=box.scrollTop+box.clientHeight>=box.scrollHeight-40;
  box.textContent=d.log||'(no log yet — starting…)';
  if(bottom) box.scrollTop=box.scrollHeight;
 }catch(e){}
}
async function stopVer(){ if(!confirm('Force-stop this verification? (destroys its sandbox)'))return;
 try{await post('/api/verify-stop',{id:verId});toast('stopping…','ok');verPoll();refresh();}catch(e){toast('stop failed','err');}}
let recId=0;
async function deleteRec(){
 if(!recId||!confirm('Delete this recording? The verdict stays; only the file is removed.'))return;
 try{await post('/api/recording/delete',{id:recId});toast('recording deleted','ok');close_('recov');refresh();}
 catch(e){toast('delete failed','err');}
}
async function openRec(id){
 recId=id;
 const box=$('recbox'); $('rectitle').textContent='#'+id; $('recmeta').textContent='';
 $('recdl').href='/recordings/'+id+'?download=1';
 box.innerHTML=''; $('recov').classList.add('show'); lockBody();
 try{
  const r=await api('/recordings/'+id);
  const ct=(r.headers.get('content-type')||'').toLowerCase();
  const cl=r.headers.get('content-length')||'';
  let media='';
  if(ct.indexOf('video')===0) media='<video controls autoplay playsinline><source src="/recordings/'+id+'"></video>';
  else if(ct.indexOf('image')===0) media='<img src="/recordings/'+id+'" alt="PoC recording">';
  else {const t=await r.text(); media='<pre style="margin:0;padding:18px;color:#9BD6C3;font-family:var(--mono);font-size:12px;white-space:pre-wrap">'+esc(t||'(empty recording)')+'</pre>';}
  box.innerHTML=media;
  const ext=ct.split('/')[1]||'bin';
  const size=cl?Math.round(parseInt(cl)/1024)+' KB':'—';
  $('recmeta').textContent='poc_'+id+'.'+ext+' · '+size;
 }catch(e){ box.innerHTML='<pre style="margin:0;padding:18px;color:#F08484;font-family:var(--mono);font-size:12px">could not load recording</pre>'; }
}
let _sy=0;
function lockBody(){_sy=window.scrollY;document.body.style.top=(-_sy)+'px';document.body.classList.add('locked');}
function unlockBody(){document.body.classList.remove('locked');document.body.style.top='';window.scrollTo(0,_sy);}
function openSend(name,label){sendTarget=name;$('sendtitle').textContent=label;$('sendinput').value='';$('sendov').classList.add('show');lockBody();}
function close_(id){$(id).classList.remove('show');if(!document.querySelector('.overlay.show'))unlockBody();}
async function qsend(c){await doSend(c);}
async function sendCustom(){const c=$('sendinput').value.trim();if(c)await doSend(c);}
async function doSend(cmd){try{await post('/api/send',{name:sendTarget,cmd});toast('sent: '+cmd,'ok');close_('sendov');}catch(e){toast('send failed','err');}}
async function stopSession(name,label){if(!confirm('Stop session '+label+'?'))return;
 try{await post('/api/stop',{name});toast('stopped '+label,'ok');refresh();}catch(e){toast('stop failed','err');}}
async function peek(name,label){peekTarget=name;$('peektitle').textContent=label;$('peekbox').textContent='loading…';$('peekov').classList.add('show');lockBody();peekRefresh();}
async function peekRefresh(){try{const r=await api('/api/peek?name='+encodeURIComponent(peekTarget));const t=await r.text();
 const b=$('peekbox');b.textContent=t||'(empty)';b.scrollTop=b.scrollHeight;}catch(e){$('peekbox').textContent='peek failed';}}
async function doLaunch(ev){ev.preventDefault();const f=ev.target;
 try{await post('/api/launch',Object.fromEntries(new FormData(f)));toast('scan started','ok');f.reset();show('home');}
 catch(e){toast('launch failed','err');}return false;}

setInterval(()=>{if(!document.hidden)refresh();},5000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
if('serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js').catch(()=>{});
show('home');
</script></body></html>"""


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #

app = FastAPI(title="Strix Dashboard")

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.on_event("startup")
def _startup() -> None:
    try:
        db.init_db()
    except Exception:
        pass
    # Heal verifies orphaned by a restart (leaked containers + stuck 'running').
    try:
        verifier.reconcile_stale_startup()
    except Exception:
        pass


async def _form(request: Request) -> dict[str, str]:
    raw = (await request.body()).decode("utf-8", "replace")
    return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}


_PUBLIC = ("/login", "/sw.js", "/manifest.webmanifest")


@app.middleware("http")
async def _auth_gate(request: Request, call_next):
    path = request.url.path
    if path in _PUBLIC or path.startswith("/static") or _is_authed(request):
        return await call_next(request)
    if path.startswith("/api") or path.startswith("/screens"):
        return PlainTextResponse("unauthorized", status_code=401)
    return RedirectResponse("/login", status_code=303)


# ---- PWA assets ----------------------------------------------------------- #

@app.get("/manifest.webmanifest")
async def manifest():
    return JSONResponse(_MANIFEST, media_type="application/manifest+json")


@app.get("/sw.js")
async def service_worker():
    return Response(_SW, media_type="application/javascript")


# ---- auth ----------------------------------------------------------------- #

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    if _is_authed(request):
        return RedirectResponse("/", status_code=303)
    return HTMLResponse(login_page())


@app.post("/login")
async def login_post(request: Request):
    form = await _form(request)
    if hmac.compare_digest(form.get("password", ""), _load_password()):
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(_COOKIE, _token(_load_password()),
                        httponly=True, samesite="lax", max_age=30 * 24 * 3600)
        return resp
    return HTMLResponse(login_page(error=True), status_code=401)


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(_COOKIE)
    return resp


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(_PAGE)


# ---- JSON APIs ------------------------------------------------------------ #

@app.get("/api/home")
async def api_home():
    return JSONResponse({
        "summary": summary_json(),
        "sessions": list_screens(),
        "findings": findings_json(limit=8),
    })


@app.get("/api/findings")
async def api_findings(status: str | None = None):
    return JSONResponse(findings_json(status=status, limit=200))


@app.get("/api/scope")
async def api_scope():
    return JSONResponse(scope_json())


# ---- session actions (by screen name) ------------------------------------- #

@app.get("/api/peek", response_class=PlainTextResponse)
def api_peek(name: str):
    if not _screen_name_ok(name):
        return PlainTextResponse("bad name", status_code=400)
    path = f"/tmp/strix_peek_{os.getpid()}_{int(time.time() * 1000)}.txt"
    try:
        subprocess.run(["screen", "-S", name, "-X", "hardcopy", "-h", path],
                       capture_output=True, timeout=10)
        for _ in range(10):
            if os.path.exists(path):
                break
            time.sleep(0.05)
        data = Path(path).read_bytes()[-40000:] if os.path.exists(path) else b"(no output)"
    except Exception as e:
        data = f"(peek error: {e})".encode()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    return PlainTextResponse(data.decode("utf-8", "replace"))


@app.post("/api/send")
async def api_send(request: Request):
    form = await _form(request)
    name, cmd = form.get("name", ""), form.get("cmd", "")
    if not _screen_name_ok(name) or not cmd:
        return PlainTextResponse("bad request", status_code=400)
    try:
        subprocess.run(["screen", "-S", name, "-X", "stuff", cmd + "\n"],
                       capture_output=True, timeout=10)
    except Exception as e:
        return PlainTextResponse(f"send failed: {e}", status_code=500)
    return PlainTextResponse("ok")


@app.post("/api/stop")
async def api_stop(request: Request):
    form = await _form(request)
    name = form.get("name", "")
    if not _screen_name_ok(name):
        return PlainTextResponse("bad name", status_code=400)
    try:
        subprocess.run(["screen", "-S", name, "-X", "quit"], capture_output=True, timeout=10)
    except Exception as e:
        return PlainTextResponse(f"stop failed: {e}", status_code=500)
    return PlainTextResponse("ok")


# ---- findings + launch ---------------------------------------------------- #

@app.post("/api/finding")
async def api_finding(request: Request):
    form = await _form(request)
    try:
        fid = int(form.get("id", ""))
    except ValueError:
        return PlainTextResponse("bad id", status_code=400)
    status = form.get("status", "")
    if status not in ("candidate", "confirmed", "rejected", "submitted", "duplicate"):
        return PlainTextResponse("bad status", status_code=400)
    try:
        db.update_finding_status(fid, status)
    except Exception as e:
        return PlainTextResponse(f"failed: {e}", status_code=500)
    return PlainTextResponse("ok")


@app.post("/api/verify")
async def api_verify(request: Request):
    form = await _form(request)
    try:
        fid = int(form.get("id", ""))
    except ValueError:
        return PlainTextResponse("bad id", status_code=400)
    if not db.get_finding(fid):
        return PlainTextResponse("no such finding", status_code=404)
    try:
        verifier.launch_verification(fid)
    except Exception as e:
        return PlainTextResponse(f"launch failed: {e}", status_code=500)
    return PlainTextResponse("ok")


@app.get("/recordings/{finding_id}")
def api_recording(finding_id: int, download: bool = False):
    f = db.get_finding(finding_id)
    rec = f.get("verify_recording") if f else None
    if not rec or not Path(rec).exists():
        return PlainTextResponse("no recording", status_code=404)
    if download:
        return FileResponse(rec, filename=Path(rec).name, content_disposition_type="attachment")
    # Serve INLINE (no attachment) so it renders in the sheet — video plays,
    # text/cast transcripts display.
    return FileResponse(rec, content_disposition_type="inline")


@app.get("/api/verify-log/{finding_id}")
def api_verify_log(finding_id: int):
    f = db.get_finding(finding_id)
    if not f:
        return JSONResponse({"error": "no finding"}, status_code=404)
    status = f.get("verify_status") or "unverified"
    log, log_age = "", None
    p = verifier.verify_log_path(finding_id)
    if p.exists():
        try:
            log = p.read_text(errors="replace")[-16000:]
            log_age = _age_epoch(p.stat().st_mtime)
        except Exception:
            pass
    container = ""
    try:
        out = subprocess.run(["docker", "ps", "--format", "{{.Names}} {{.Status}}"],
                             capture_output=True, text=True, timeout=8).stdout
        pref = verifier.verify_container_prefix(finding_id)
        for ln in out.splitlines():
            if ln.startswith(pref):
                container = ln.strip()
                break
    except Exception:
        pass

    # Self-heal: if the DB says it's running but no sandbox is alive, the run
    # died (crash / restart). Mark it so the UI tells the truth.
    if status in ("queued", "running") and not container:
        db.set_verify_status(
            finding_id, "error",
            log_append="interrupted — no sandbox running (the run died or the dashboard restarted). Re-verify to retry.")
        status = "error"
        log = (log + "\n[!] no sandbox running — marked interrupted").strip()

    verdict = f.get("verify_verdict") or ""
    evidence = (f.get("verify_evidence") or "")[:2000]
    last_line = next((l.strip() for l in reversed(log.splitlines()) if l.strip()), "")
    if status == "passed":
        detail = "✅ Verified VALID — reproduced on pristine source." + (f" {evidence}" if evidence else "")
    elif status == "failed":
        detail = "❌ Could not reproduce — likely false positive." + (f" {evidence}" if evidence else "")
    elif status == "inconclusive":
        detail = "➖ Inconclusive (e.g. out of scope / needs input)." + (f" {evidence}" if evidence else "")
    elif status == "running":
        detail = f"⏳ Reproducing in an isolated sandbox. Sandbox {('alive — ' + container) if container else 'starting'}. Last log activity {log_age or '?'} ago."
    elif status == "queued":
        detail = "⏳ Queued — sandbox is starting…"
    elif status == "error":
        detail = "⚠️ " + (last_line or evidence or "Interrupted/failed — re-verify to retry.")
    else:
        detail = "Not verified yet. Tap Verify to reproduce it in an isolated sandbox."

    return JSONResponse({
        "status": status, "verdict": verdict, "evidence": evidence, "detail": detail,
        "updated_age": _age_epoch(f.get("updated_at")), "log_age": log_age,
        "container": container, "recording": bool(f.get("verify_recording")), "log": log,
    })


@app.post("/api/verify-stop")
async def api_verify_stop(request: Request):
    form = await _form(request)
    try:
        fid = int(form.get("id", ""))
    except ValueError:
        return PlainTextResponse("bad id", status_code=400)
    try:
        verifier.stop_verification(fid)
    except Exception as e:
        return PlainTextResponse(f"stop failed: {e}", status_code=500)
    return PlainTextResponse("ok")


@app.post("/api/recording/delete")
async def api_recording_delete(request: Request):
    form = await _form(request)
    try:
        fid = int(form.get("id", ""))
    except ValueError:
        return PlainTextResponse("bad id", status_code=400)
    f = db.get_finding(fid)
    rec = f.get("verify_recording") if f else None
    if rec:
        try:
            Path(rec).unlink(missing_ok=True)
        except Exception:
            pass
    db.clear_recording(fid)
    return PlainTextResponse("ok")


@app.post("/api/launch")
async def api_launch(request: Request):
    form = await _form(request)
    targets = [t.strip() for t in form.get("targets", "").split(",") if t.strip()]
    if not targets:
        return PlainTextResponse("no target", status_code=400)
    try:
        scan_manager.start_scan(
            targets=targets,
            scan_mode=form.get("scan_mode", "deep"),
            instruction=form.get("instruction") or None,
            agent=form.get("agent", "claude"),
        )
    except Exception as e:
        return PlainTextResponse(f"start failed: {e}", status_code=500)
    return PlainTextResponse("ok")


def main() -> None:
    import uvicorn

    host = os.getenv("STRIX_WEB_HOST", "0.0.0.0")
    port = int(os.getenv("STRIX_WEB_PORT", "8800"))
    print(f"Strix dashboard on http://{host}:{port}  (password file: {_PW_FILE})")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
