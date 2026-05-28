#!/usr/bin/env python3
"""API Monitor — HTTP endpoint monitoring with alerts."""
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import sqlite3, os
from datetime import datetime

DB = "monitors.db"

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS monitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            url TEXT NOT NULL,
            name TEXT,
            check_interval INTEGER DEFAULT 300,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            monitor_id INTEGER NOT NULL,
            status_code INTEGER,
            response_ms REAL,
            error TEXT,
            checked_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (monitor_id) REFERENCES monitors(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT,
            stripe_customer_id TEXT,
            plan TEXT DEFAULT 'free',
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="API Monitor", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/")
def dashboard():
    return HTMLResponse("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>API Monitor</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
.header{background:#1e293b;padding:16px 24px;border-bottom:1px solid #334155}
.header h1{font-size:1.3rem;color:#38bdf8}
.container{max-width:960px;margin:0 auto;padding:24px}
.card{background:#1e293b;border-radius:12px;padding:24px;margin-bottom:16px}
.card h2{font-size:1.1rem;margin-bottom:12px;color:#38bdf8}
.status-badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:.85rem;font-weight:600}
.status-up{background:#065f46;color:#6ee7b7}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px}
.stat{background:#0f172a;border-radius:8px;padding:16px;text-align:center}
.stat .num{font-size:2rem;font-weight:700;color:#38bdf8}
.stat .lbl{font-size:.85rem;color:#94a3b8;margin-top:4px}
table{width:100%;border-collapse:collapse}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #334155}
th{color:#94a3b8;font-size:.85rem;font-weight:500}
tr:hover{background:#0f172a}
.add-form{display:flex;gap:8px;margin-top:12px}
.add-form input{flex:1;padding:10px 12px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;outline:none}
.add-form input:focus{border-color:#38bdf8}
.btn{padding:10px 20px;background:#38bdf8;color:#0f172a;border:none;border-radius:8px;font-weight:600;cursor:pointer}
.btn:hover{opacity:.9}
</style>
</head>
<body>
<div class="header"><h1>API Monitor</h1></div>
<div class="container">
<div class="card">
<h2>System Status</h2>
<span class="status-badge status-up">ONLINE</span>
</div>
<div class="stats">
<div class="stat"><div class="num" id="monitorCount">-</div><div class="lbl">Monitors</div></div>
<div class="stat"><div class="num" id="checkCount">-</div><div class="lbl">Total Checks</div></div>
<div class="stat"><div class="num" id="avgMs">-</div><div class="lbl">Avg Response (ms)</div></div>
</div>
<div class="card">
<h2>Monitors</h2>
<div class="add-form">
<input id="monUrl" placeholder="https://your-api.com/health">
<input id="monName" placeholder="Name (optional)" style="max-width:200px">
<button class="btn" onclick="addMonitor()">Add</button>
</div>
<table style="margin-top:16px">
<thead><tr><th>Name</th><th>URL</th><th>Created</th><th>Status</th></tr></thead>
<tbody id="monitors"></tbody>
</table>
</div>
</div>
<script>
const API = '';
async function load(){const r=await fetch(API+'/api/monitors');const d=await r.json();
document.getElementById('monitorCount').textContent=d.length;
const tbody=document.getElementById('monitors');
tbody.innerHTML=d.map(m=>`<tr><td>${m.name||'-'}</td><td>${m.url}</td><td>${m.created||'-'}</td><td><span class="status-badge status-up">active</span></td></tr>`).join('');}
async function addMonitor(){const url=document.getElementById('monUrl').value;const name=document.getElementById('monName').value;
await fetch(API+'/api/monitors?url='+encodeURIComponent(url)+'&name='+encodeURIComponent(name)+'&user_id=demo',{method:'POST'});
document.getElementById('monUrl').value='';document.getElementById('monName').value='';load();}
load();
</script>
</body>
</html>""")

from fastapi.responses import HTMLResponse

@app.get("/api/health")
def health():
    return {"status": "ok", "version": "1.0.0"}

@app.post("/api/monitors")
def create_monitor(url: str, name: str = None, user_id: str = "demo"):
    conn = sqlite3.connect(DB)
    cursor = conn.execute(
        "INSERT INTO monitors (user_id, url, name) VALUES (?, ?, ?)",
        (user_id, url, name))
    mid = cursor.lastrowid
    conn.commit()
    conn.close()
    return {"id": mid, "url": url, "name": name}

@app.get("/api/monitors")
def list_monitors(user_id: str = "demo"):
    conn = sqlite3.connect(DB)
    rows = conn.execute(
        "SELECT id, url, name, created_at FROM monitors WHERE user_id = ?",
        (user_id,)).fetchall()
    conn.close()
    return [{"id": r[0], "url": r[1], "name": r[2], "created": r[3]} for r in rows]

@app.get("/api/monitors/{monitor_id}/checks")
def get_checks(monitor_id: int, limit: int = 10):
    conn = sqlite3.connect(DB)
    rows = conn.execute(
        "SELECT status_code, response_ms, error, checked_at FROM checks WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT ?",
        (monitor_id, limit)).fetchall()
    conn.close()
    return [{"status": r[0], "ms": r[1], "error": r[2], "at": r[3]} for r in rows]

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
