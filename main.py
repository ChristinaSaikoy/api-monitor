#!/usr/bin/env python3
"""API Monitor — Full SaaS: auto-checks, response time tracking, SSL alerts."""
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
import asyncio, sqlite3, os, json, time, socket, ssl
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import URLError

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitors.db")

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS monitors (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT DEFAULT 'demo',
        url TEXT NOT NULL, name TEXT, check_interval INTEGER DEFAULT 60,
        created_at TEXT DEFAULT (datetime('now')))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, monitor_id INTEGER NOT NULL,
        status_code INTEGER, response_ms REAL, error TEXT, ssl_days_left INTEGER,
        checked_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (monitor_id) REFERENCES monitors(id))""")
    conn.commit()
    conn.close()

async def check_one(url: str) -> dict:
    result = {"status": 0, "ms": 0, "error": None, "ssl_days": None}
    start = time.time()
    try:
        req = Request(url, headers={"User-Agent": "APIMonitor/1.0"})
        resp = urlopen(req, timeout=15)
        result["status"] = resp.status
        result["ms"] = round((time.time() - start) * 1000, 1)
    except URLError as e:
        result["error"] = str(e.reason)[:200] if e.reason else str(e)[:200]
    except Exception as e:
        result["error"] = str(e)[:200]
    # SSL cert check
    if url.startswith("https://"):
        try:
            host = url.split("/")[2].split(":")[0]
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    result["ssl_days"] = (not_after - datetime.now()).days
        except Exception:
            pass
    return result

async def check_all_monitors():
    conn = sqlite3.connect(DB)
    monitors = conn.execute("SELECT id, url FROM monitors").fetchall()
    for mid, url in monitors:
        r = await check_one(url)
        conn.execute("INSERT INTO checks (monitor_id,status_code,response_ms,error,ssl_days_left) VALUES (?,?,?,?,?)",
                     (mid, r["status"], r["ms"], r["error"], r["ssl_days"]))
    conn.commit()
    conn.close()

async def monitor_loop():
    while True:
        try:
            await check_all_monitors()
        except Exception:
            pass
        await asyncio.sleep(60)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task = asyncio.create_task(monitor_loop())
    yield
    task.cancel()

app = FastAPI(title="API Monitor", version="1.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/api/health")
def health():
    conn = sqlite3.connect(DB)
    m = conn.execute("SELECT COUNT(*) FROM monitors").fetchone()[0]
    c = conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
    conn.close()
    return {"status": "ok", "version": "1.1.0", "monitors": m, "checks": c}

@app.post("/api/monitors")
def create_monitor(url: str, name: str = "", user_id: str = "demo"):
    conn = sqlite3.connect(DB)
    cur = conn.execute("INSERT INTO monitors (user_id,url,name) VALUES (?,?,?)", (user_id, url, name))
    mid = cur.lastrowid
    conn.commit()
    conn.close()
    return {"id": mid, "url": url, "name": name}

@app.get("/api/monitors")
def list_monitors(user_id: str = "demo"):
    rows = sqlite3.connect(DB).execute(
        "SELECT id,url,name,created_at FROM monitors WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()
    return [{"id": r[0], "url": r[1], "name": r[2], "created": r[3]} for r in rows]

@app.delete("/api/monitors/{mid}")
def delete_monitor(mid: int):
    conn = sqlite3.connect(DB)
    conn.execute("DELETE FROM monitors WHERE id=?", (mid,))
    conn.execute("DELETE FROM checks WHERE monitor_id=?", (mid,))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.get("/api/monitors/{mid}/checks")
def get_checks(mid: int, limit: int = 20):
    rows = sqlite3.connect(DB).execute(
        "SELECT status_code,response_ms,error,ssl_days_left,checked_at FROM checks WHERE monitor_id=? ORDER BY id DESC LIMIT ?",
        (mid, limit)).fetchall()
    return [{"status": r[0], "ms": r[1], "error": r[2], "ssl_days": r[3], "at": r[4]} for r in rows]

@app.get("/api/stats")
def get_stats(user_id: str = "demo"):
    conn = sqlite3.connect(DB)
    monitors = conn.execute("SELECT id,url,name FROM monitors WHERE user_id=?", (user_id,)).fetchall()
    result = []
    for m in monitors:
        avg = conn.execute("SELECT AVG(response_ms) FROM checks WHERE monitor_id=? AND response_ms>0 AND checked_at >= datetime('now','-1 day')", (m[0],)).fetchone()
        last = conn.execute("SELECT status_code,checked_at FROM checks WHERE monitor_id=? ORDER BY id DESC LIMIT 1", (m[0],)).fetchone()
        ssl_min = conn.execute("SELECT MIN(ssl_days_left) FROM checks WHERE monitor_id=? AND ssl_days_left IS NOT NULL AND checked_at >= datetime('now','-1 day')", (m[0],)).fetchone()
        result.append({
            "id": m[0], "url": m[1], "name": m[2],
            "avg_ms": round(avg[0], 1) if avg and avg[0] else None,
            "last_status": last[0] if last else None,
            "last_checked": last[1] if last else None,
            "ssl_days": ssl_min[0] if ssl_min and ssl_min[0] else None,
        })
    conn.close()
    return result

@app.get("/")
def dashboard():
    return HTMLResponse("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>API Monitor</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
.header{background:#1e293b;padding:14px 24px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:1.2rem;color:#38bdf8}
.container{max-width:1024px;margin:0 auto;padding:20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.stat{background:#1e293b;border-radius:10px;padding:16px;text-align:center}
.stat .num{font-size:1.8rem;font-weight:700;color:#38bdf8}
.stat .lbl{font-size:.8rem;color:#94a3b8;margin-top:2px}
.card{background:#1e293b;border-radius:10px;padding:20px;margin-bottom:16px}
.card h2{font-size:1.05rem;margin-bottom:12px;color:#38bdf8;border-bottom:1px solid #334155;padding-bottom:8px}
.add-form{display:flex;gap:8px}
.add-form input{flex:1;padding:10px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0}
.add-form input:focus{border-color:#38bdf8;outline:none}
.btn{padding:10px 18px;background:#38bdf8;color:#0f172a;border:none;border-radius:8px;font-weight:600;cursor:pointer;white-space:nowrap}
.btn:hover{opacity:.85}
.btn-sm{padding:5px 12px;font-size:.8rem}
.btn-danger{background:#ef4444;color:#fff}
.status-up{color:#6ee7b7}.status-down{color:#fca5a5}.status-warn{color:#fde047}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #334155}
th{color:#94a3b8;font-size:.8rem}.mono{font-family:monospace;font-size:.85rem}
tr:hover{background:#0f172a}
.chart-bar{display:inline-block;height:20px;border-radius:3px;min-width:2px}
.tabs{display:flex;gap:4px;margin-bottom:12px}
.tab{padding:6px 14px;border-radius:6px;cursor:pointer;font-size:.85rem;background:#0f172a;color:#94a3b8}
.tab.active{background:#38bdf8;color:#0f172a}
</style>
</head>
<body>
<div class="header"><h1>API Monitor</h1><span id="clock" style="color:#94a3b8;font-size:.85rem"></span></div>
<div class="container">
<div class="stats">
<div class="stat"><div class="num" id="monCount">-</div><div class="lbl">Monitors</div></div>
<div class="stat"><div class="num" id="upCount">-</div><div class="lbl">Up</div></div>
<div class="stat"><div class="num" id="downCount">-</div><div class="lbl">Down</div></div>
<div class="stat"><div class="num" id="avgAll">-</div><div class="lbl">Avg ms</div></div>
</div>
<div class="card">
<h2>Add Monitor</h2>
<div class="add-form">
<input id="monUrl" placeholder="https://your-api.com/health">
<input id="monName" placeholder="Name (optional)" style="max-width:180px">
<button class="btn" onclick="addMonitor()">Add</button>
</div>
</div>
<div class="card">
<h2>Monitors</h2>
<table><thead><tr><th>Name</th><th>URL</th><th>Status</th><th>Avg ms</th><th>SSL Days</th><th>Last</th><th></th></tr></thead>
<tbody id="monitors"></tbody></table>
</div>
<div class="card" id="detailCard" style="display:none">
<h2>History — <span id="detailName"></span></h2>
<div class="tabs" id="tabs" style="display:none"><button class="tab active" onclick="loadChecks()">Raw</button></div>
<table><thead><tr><th>Status</th><th>ms</th><th>SSL</th><th>Error</th><th>Time</th></tr></thead>
<tbody id="checks"></tbody></table>
</div>
</div>
<script>
const API='';
async function loadStats(){const r=await fetch(API+'/api/stats');const d=await r.json();
document.getElementById('monCount').textContent=d.length;
const up=d.filter(m=>m.last_status&&m.last_status<400).length;
const down=d.filter(m=>m.last_status&&m.last_status>=400||m.last_status===0).length;
document.getElementById('upCount').textContent=up;
document.getElementById('downCount').textContent=down;
const avgs=d.filter(m=>m.avg_ms).map(m=>m.avg_ms);
document.getElementById('avgAll').textContent=avgs.length?Math.round(avgs.reduce((a,b)=>a+b)/avgs.length)+'ms':'n/a';
const tbody=document.getElementById('monitors');
tbody.innerHTML=d.map(m=>{
let s=m.last_status?m.last_status<400?'<span class="status-up">UP '+m.last_status+'</span>':'<span class="status-down">'+m.last_status+'</span>':'<span class="status-down">DOWN</span>';
let ssl=m.ssl_days!=null?m.ssl_days<0?'<span class="status-down">EXP</span>':m.ssl_days<14?'<span class="status-warn">'+m.ssl_days+'d</span>':'<span class="status-up">'+m.ssl_days+'d</span>':'?';
return `<tr onclick="showDetail(${m.id},'${(m.name||m.url).replace(/'/g,"&#39;")}')" style="cursor:pointer"><td>${m.name||'-'}</td><td class="mono">${m.url.substring(0,50)}</td><td>${s}</td><td>${m.avg_ms||'?'}ms</td><td>${ssl}</td><td class="mono">${(m.last_checked||'').substring(11,19)||'?'}</td><td><button class="btn btn-sm btn-danger" onclick="event.stopPropagation();delMon(${m.id})">X</button></td></tr>`}).join('');}
async function showDetail(id,name){document.getElementById('detailCard').style.display='block';document.getElementById('detailName').textContent=name;window._mid=id;loadChecks();}
async function loadChecks(){const r=await fetch(API+'/api/monitors/'+window._mid+'/checks?limit=30');const d=await r.json();
document.getElementById('checks').innerHTML=d.map(c=>`<tr><td>${c.status||'?'}</td><td>${c.ms||'?'}ms</td><td>${c.ssl_days!=null?c.ssl_days+'d':'?'}</td><td style="color:#fca5a5;font-size:.8rem">${(c.error||'').substring(0,60)}</td><td class="mono">${(c.at||'').substring(11,19)}</td></tr>`).join('');}
async function addMonitor(){const url=document.getElementById('monUrl').value;const name=document.getElementById('monName').value;await fetch(API+'/api/monitors?url='+encodeURIComponent(url)+'&name='+encodeURIComponent(name)+'&user_id=demo',{method:'POST'});document.getElementById('monUrl').value='';document.getElementById('monName').value='';loadStats();}
async function delMon(id){if(confirm('Delete?')){await fetch(API+'/api/monitors/'+id,{method:'DELETE'});loadStats();}}
setInterval(loadStats,15000);setInterval(()=>{if(window._mid)loadChecks()},10000);setInterval(()=>{document.getElementById('clock').textContent=new Date().toLocaleTimeString()},1000);loadStats();
</script>
</body>
</html>""")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
