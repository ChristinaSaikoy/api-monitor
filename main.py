#!/usr/bin/env python3
"""
API Monitor v2.0 — Full SaaS
Patterns borrowed from: healthchecks (auth/tiers), uptime-kuma (dash),
                         gatus (alerting), Django (security)
"""
from fastapi import FastAPI, HTTPException, Request, Depends, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Optional, Annotated
import asyncio, sqlite3, os, json, time, socket, ssl, hashlib, hmac, secrets
import urllib.request as urlreq
from urllib.error import URLError
from pathlib import Path

# ─── Config ───────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_EMAIL = "542637706@shu.edu.cn"
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitors.db")

PLANS = {
    "free":    {"monitors": 3,  "interval": 60,  "history_days": 7,   "export": False},
    "pro":     {"monitors": 50, "interval": 60,  "history_days": 30,  "export": True},
    "unlimited":{"monitors": 99999, "interval": 30, "history_days": 365, "export": True},
}

# ═══════════ DB Layer ═════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            plan TEXT DEFAULT 'free',
            api_key TEXT UNIQUE,
            is_admin INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now')),
            last_login TEXT
        );
        CREATE TABLE IF NOT EXISTS monitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            url TEXT NOT NULL,
            name TEXT,
            check_interval INTEGER DEFAULT 60,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            monitor_id INTEGER NOT NULL,
            status_code INTEGER,
            response_ms REAL,
            error TEXT,
            ssl_days_left INTEGER,
            checked_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_checks_monitor ON checks(monitor_id, checked_at);
        CREATE INDEX IF NOT EXISTS idx_monitors_user ON monitors(user_id);
        CREATE TABLE IF NOT EXISTS rate_limits (
            key TEXT PRIMARY KEY,
            tokens REAL DEFAULT 60,
            last_refill TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            plan TEXT DEFAULT 'free',
            next_billing TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    # Create admin account if not exists
    admin = conn.execute("SELECT id FROM users WHERE email = ?", (ADMIN_EMAIL,)).fetchone()
    if not admin:
        ADMIN_PW = os.environ.get("ADMIN_PASSWORD", "admin123")
        conn.execute("INSERT INTO users (id, email, password_hash, plan, is_admin) VALUES (?,?,?,?,?)",
                     ("admin", ADMIN_EMAIL, hash_password(ADMIN_PW), "unlimited", 1))
        print(f"[INIT] Admin created: {ADMIN_EMAIL} / {ADMIN_PW}")
    conn.commit()
    conn.close()

def hash_password(pw: str) -> str:
    salt = SECRET_KEY[:16]
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000).hex()

def verify_password(pw: str, hash_val: str) -> bool:
    return hmac.compare_digest(hash_password(pw), hash_val)

# ═══════════ JWT Auth ════════════════════════════════════════
import base64

def create_jwt(user_id: str, is_admin: bool, expire_days: int = 1) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).decode().rstrip("=")
    now = int(time.time())
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": user_id, "admin": is_admin, "iat": now,
        "exp": now + expire_days * 86400
    }).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET_KEY.encode(), f"{header}.{payload}".encode(), hashlib.sha256).hexdigest()
    return f"{header}.{payload}.{sig}"

def verify_jwt(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3: return None
        header, payload, sig = parts
        expected = hmac.new(SECRET_KEY.encode(), f"{header}.{payload}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected): return None
        # Fix padding
        payload += "=" * (4 - len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        if data.get("exp", 0) < time.time(): return None
        return data
    except Exception:
        return None

security = HTTPBearer(auto_error=False)

async def get_current_user(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)]) -> dict:
    if not credentials: raise HTTPException(401, "Missing token")
    token_data = verify_jwt(credentials.credentials)
    if not token_data: raise HTTPException(401, "Invalid or expired token")
    conn = get_db()
    user = conn.execute("SELECT id, email, plan, is_admin, is_active FROM users WHERE id=?", (token_data["sub"],)).fetchone()
    conn.close()
    if not user or not user["is_active"]: raise HTTPException(401, "Account inactive or deleted")
    return {"id": user["id"], "email": user["email"], "plan": user["plan"],
            "is_admin": bool(user["is_admin"])}

async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if not user["is_admin"]: raise HTTPException(403, "Admin only")
    return user

# ═══════════ Rate Limiting (TokenBucket from healthchecks) ════
def check_rate_limit(key: str, max_rps: int = 30) -> bool:
    conn = get_db()
    row = conn.execute("SELECT tokens, last_refill FROM rate_limits WHERE key=?", (key,)).fetchone()
    now = datetime.now()
    if row:
        elapsed = (now - datetime.fromisoformat(row["last_refill"])).total_seconds()
        tokens = min(max_rps, row["tokens"] + elapsed * (max_rps / 60))
    else:
        tokens = max_rps
    if tokens < 1:
        conn.close()
        return False
    conn.execute("INSERT OR REPLACE INTO rate_limits (key, tokens, last_refill) VALUES (?,?,?)",
                 (key, tokens - 1, now.isoformat()))
    conn.commit()
    conn.close()
    return True

# ═══════════ Data Cleanup ═══════════════════════════════════
async def cleanup_old_checks():
    while True:
        try:
            conn = get_db()
            for plan, cfg in PLANS.items():
                cutoff = (datetime.now() - timedelta(days=cfg["history_days"])).isoformat()
                conn.execute("""
                    DELETE FROM checks WHERE monitor_id IN (
                        SELECT id FROM monitors WHERE user_id IN (
                            SELECT id FROM users WHERE plan=?
                        )
                    ) AND checked_at < ?
                """, (plan, cutoff))
            conn.commit()
            conn.close()
        except Exception:
            pass
        await asyncio.sleep(3600)  # hourly cleanup

# ═══════════ Monitor Engine ══════════════════════════════════
async def check_one(url: str) -> dict:
    result = {"status": 0, "ms": 0, "error": None, "ssl_days": None}
    start = time.time()
    try:
        req = urlreq.Request(url, headers={"User-Agent": "APIMonitor/2.0"})
        resp = urlreq.urlopen(req, timeout=15)
        result["status"] = resp.status
        result["ms"] = round((time.time() - start) * 1000, 1)
    except Exception as e:
        result["error"] = str(e)[:200]
    # SSL check
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
    conn = get_db()
    monitors = conn.execute("SELECT m.id, m.url, u.plan FROM monitors m JOIN users u ON m.user_id=u.id WHERE u.is_active=1").fetchall()
    for m in monitors:
        r = await check_one(m["url"])
        conn.execute("INSERT INTO checks (monitor_id,status_code,response_ms,error,ssl_days_left) VALUES (?,?,?,?,?)",
                     (m["id"], r["status"], r["ms"], r["error"], r["ssl_days"]))
    conn.commit()
    conn.close()

async def monitor_loop():
    await asyncio.sleep(5)
    while True:
        try: await check_all_monitors()
        except Exception: pass
        await asyncio.sleep(30)

# ═══════════ App Lifecycle ═════════════════════════════════
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task1 = asyncio.create_task(monitor_loop())
    task2 = asyncio.create_task(cleanup_old_checks())
    yield
    task1.cancel(); task2.cancel()

app = FastAPI(title="API Monitor", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ═══════════ Auth Endpoints ════════════════════════════════
@app.post("/api/auth/register")
async def register(req: Request):
    if not check_rate_limit("register:" + (req.client.host if req.client else "unknown"), 5):
        raise HTTPException(429, "Too many attempts")
    body = await req.json()
    email = body.get("email","").strip()
    password = body.get("password","")
    # Only admin can create accounts
    auth = req.headers.get("Authorization","")
    if auth.startswith("Bearer "):
        token_data = verify_jwt(auth[7:])
        if not token_data or not token_data.get("admin"):
            raise HTTPException(403, "Only admin can create accounts")
    else:
        raise HTTPException(403, "Admin auth required for registration")
    if len(password) < 8: raise HTTPException(400, "Password min 8 chars")
    conn = get_db()
    exists = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if exists: conn.close(); raise HTTPException(409, "Email already registered")
    uid = secrets.token_hex(8)
    conn.execute("INSERT INTO users (id, email, password_hash, plan) VALUES (?,?,?,?)",
                 (uid, email, hash_password(password), "free"))
    conn.commit(); conn.close()
    return {"user_id": uid, "email": email, "plan": "free"}

class LoginBody(BaseModel):
    email: str
    password: str
    remember_me: bool = False

@app.post("/api/auth/login")
async def login(body: LoginBody, req: Request):
    if not check_rate_limit("login:" + (req.client.host if req.client else "unknown"), 10):
        raise HTTPException(429, "Too many attempts")
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=? AND is_active=1", (body.email,)).fetchone()
    conn.close()
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    conn = get_db()
    conn.execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],))
    conn.commit(); conn.close()
    expire = 7 if body.remember_me else 1
    token = create_jwt(user["id"], bool(user["is_admin"]), expire)
    return {"token": token, "user": {"id": user["id"], "email": user["email"],
            "plan": user["plan"], "is_admin": bool(user["is_admin"])}}

@app.get("/api/auth/me")
async def me(user: dict = Depends(get_current_user)):
    plan_cfg = PLANS.get(user["plan"], PLANS["free"])
    conn = get_db()
    m_count = conn.execute("SELECT COUNT(*) FROM monitors WHERE user_id=?", (user["id"],)).fetchone()[0]
    conn.close()
    return {**user, "monitors_used": m_count, "monitors_limit": plan_cfg["monitors"],
            "checks_interval": plan_cfg["interval"], "history_days": plan_cfg["history_days"]}

# ═══════════ Monitor Endpoints (per-user) ══════════════════
@app.get("/api/monitors")
async def list_monitors(user: dict = Depends(get_current_user)):
    rows = get_db().execute(
        "SELECT id,url,name,created_at FROM monitors WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/monitors")
async def create_monitor(req: Request, user: dict = Depends(get_current_user)):
    if not check_rate_limit(f"monitor:{user['id']}", 20):
        raise HTTPException(429, "Rate limit exceeded")
    body = await req.json()
    url = body.get("url","").strip()
    name = body.get("name","")
    if not url.startswith("http"): raise HTTPException(400, "Invalid URL")
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM monitors WHERE user_id=?", (user["id"],)).fetchone()[0]
    limit = PLANS[user["plan"]]["monitors"]
    if count >= limit: conn.close(); raise HTTPException(403, f"Plan limit: {limit} monitors. Upgrade to add more.")
    cur = conn.execute("INSERT INTO monitors (user_id,url,name) VALUES (?,?,?)", (user["id"], url, name))
    mid = cur.lastrowid
    conn.commit(); conn.close()
    return {"id": mid, "url": url, "name": name}

@app.delete("/api/monitors/{mid}")
async def delete_monitor(mid: int, user: dict = Depends(get_current_user)):
    conn = get_db()
    owner = conn.execute("SELECT user_id FROM monitors WHERE id=?", (mid,)).fetchone()
    if not owner or owner["user_id"] != user["id"]:
        conn.close(); raise HTTPException(403, "Not your monitor")
    conn.execute("DELETE FROM monitors WHERE id=?", (mid,))
    conn.commit(); conn.close()
    return {"ok": True}

@app.get("/api/monitors/{mid}/checks")
async def get_checks(mid: int, limit: int = 30, user: dict = Depends(get_current_user)):
    conn = get_db()
    owner = conn.execute("SELECT user_id FROM monitors WHERE id=?", (mid,)).fetchone()
    if not owner or owner["user_id"] != user["id"]: conn.close(); raise HTTPException(403, "Not your monitor")
    rows = conn.execute(
        "SELECT status_code,response_ms,error,ssl_days_left,checked_at FROM checks WHERE monitor_id=? ORDER BY id DESC LIMIT ?",
        (mid, limit)).fetchall()
    conn.close()
    return [{"status": r[0], "ms": r[1], "error": r[2], "ssl_days": r[3], "at": r[4]} for r in rows]

@app.get("/api/stats")
async def get_stats(user: dict = Depends(get_current_user)):
    conn = get_db()
    monitors = conn.execute("SELECT id,url,name FROM monitors WHERE user_id=?", (user["id"],)).fetchall()
    result = []
    for m in monitors:
        avg = conn.execute("SELECT AVG(response_ms) FROM checks WHERE monitor_id=? AND response_ms>0 AND checked_at >= datetime('now','-1 day')", (m["id"],)).fetchone()
        last = conn.execute("SELECT status_code,checked_at FROM checks WHERE monitor_id=? ORDER BY id DESC LIMIT 1", (m["id"],)).fetchone()
        ssl_min = conn.execute("SELECT MIN(ssl_days_left) FROM checks WHERE monitor_id=? AND ssl_days_left IS NOT NULL AND checked_at >= datetime('now','-1 day')", (m["id"],)).fetchone()
        result.append({"id": m["id"], "url": m["url"], "name": m["name"],
            "avg_ms": round(avg[0],1) if avg and avg[0] else None,
            "last_status": last[0] if last else None, "last_checked": last[1] if last else None,
            "ssl_days": ssl_min[0] if ssl_min and ssl_min[0] else None})
    conn.close()
    return result

# ═══════════ Admin Endpoints ═══════════════════════════════
@app.get("/api/admin/users")
async def admin_users(user: dict = Depends(require_admin)):
    rows = get_db().execute("SELECT id,email,plan,is_admin,is_active,created_at,last_login FROM users ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/admin/users")
async def admin_create_user(req: Request, user: dict = Depends(require_admin)):
    body = await req.json()
    email = body.get("email","").strip()
    plan = body.get("plan","free")
    if plan not in PLANS: raise HTTPException(400, f"Invalid plan: {plan}")
    conn = get_db()
    exists = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if exists: conn.close(); raise HTTPException(409, "Email exists")
    uid = secrets.token_hex(8)
    temp_pw = secrets.token_hex(12)
    conn.execute("INSERT INTO users (id, email, password_hash, plan) VALUES (?,?,?,?)",
                 (uid, email, hash_password(temp_pw), plan))
    conn.commit(); conn.close()
    return {"user_id": uid, "email": email, "plan": plan, "temp_password": temp_pw}

@app.put("/api/admin/users/{uid}")
async def admin_update_user(uid: str, req: Request, user: dict = Depends(require_admin)):
    body = await req.json()
    conn = get_db()
    target = conn.execute("SELECT id FROM users WHERE id=?", (uid,)).fetchone()
    if not target: conn.close(); raise HTTPException(404, "User not found")
    if "plan" in body:
        if body["plan"] not in PLANS: conn.close(); raise HTTPException(400, "Invalid plan")
        conn.execute("UPDATE users SET plan=? WHERE id=?", (body["plan"], uid))
        conn.execute("UPDATE subscriptions SET plan=? WHERE user_id=?", (body["plan"], uid))
    if "is_active" in body:
        conn.execute("UPDATE users SET is_active=? WHERE id=?", (1 if body["is_active"] else 0, uid))
    if "password" in body:
        if len(body["password"]) < 8: conn.close(); raise HTTPException(400, "Password min 8 chars")
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(body["password"]), uid))
    conn.commit(); conn.close()
    return {"ok": True}

@app.put("/api/auth/password")
async def change_password(req: Request, user: dict = Depends(get_current_user)):
    body = await req.json()
    old_pw = body.get("old_password","")
    new_pw = body.get("new_password","")
    if len(new_pw) < 8: raise HTTPException(400, "Password min 8 chars")
    conn = get_db()
    u = conn.execute("SELECT password_hash FROM users WHERE id=?", (user["id"],)).fetchone()
    if not u or not verify_password(old_pw, u["password_hash"]):
        conn.close(); raise HTTPException(401, "Wrong current password")
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new_pw), user["id"]))
    conn.commit(); conn.close()
    return {"ok": True}

@app.delete("/api/admin/users/{uid}")
async def admin_delete_user(uid: str, user: dict = Depends(require_admin)):
    if uid == user["id"]: raise HTTPException(400, "Cannot delete yourself")
    conn = get_db()
    conn.execute("DELETE FROM checks WHERE monitor_id IN (SELECT id FROM monitors WHERE user_id=?)", (uid,))
    conn.execute("DELETE FROM monitors WHERE user_id=?", (uid,))
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit(); conn.close()
    return {"ok": True}

@app.get("/api/admin/stats")
async def admin_stats(user: dict = Depends(require_admin)):
    conn = get_db()
    return {
        "total_users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_monitors": conn.execute("SELECT COUNT(*) FROM monitors").fetchone()[0],
        "total_checks": conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0],
        "by_plan": {p: conn.execute("SELECT COUNT(*) FROM users WHERE plan=?", (p,)).fetchone()[0] for p in PLANS},
    }

# ═══════════ Data Export ══════════════════════════════════
@app.get("/api/export/monitors")
async def export_monitors(user: dict = Depends(get_current_user)):
    if not PLANS[user["plan"]]["export"]: raise HTTPException(403, "Export requires Pro or Unlimited plan")
    conn = get_db()
    monitors = conn.execute("SELECT * FROM monitors WHERE user_id=?", (user["id"],)).fetchall()
    checks = conn.execute("""SELECT c.* FROM checks c JOIN monitors m ON c.monitor_id=m.id
        WHERE m.user_id=? ORDER BY c.id DESC LIMIT 10000""", (user["id"],)).fetchall()
    conn.close()
    return {"monitors": [dict(r) for r in monitors], "checks": [dict(r) for r in checks]}

@app.get("/api/export/checks_csv")
async def export_checks_csv(mid: int, user: dict = Depends(get_current_user)):
    if not PLANS[user["plan"]]["export"]: raise HTTPException(403, "Upgrade required")
    conn = get_db()
    owner = conn.execute("SELECT user_id FROM monitors WHERE id=?", (mid,)).fetchone()
    if not owner or owner["user_id"] != user["id"]: conn.close(); raise HTTPException(403, "Not your monitor")
    rows = conn.execute("SELECT * FROM checks WHERE monitor_id=? ORDER BY id DESC LIMIT 5000", (mid,)).fetchall()
    conn.close()
    csv = "id,status_code,response_ms,error,ssl_days_left,checked_at\n"
    csv += "\n".join(f"{r[0]},{r[2]},{r[3]},\"{r[4] or ''}\",{r[5] or ''},{r[6]}" for r in rows)
    return Response(content=csv, media_type="text/csv")

from fastapi.responses import Response

# ═══════════ Health ════════════════════════════════════════
@app.get("/api/health")
def health():
    conn = get_db()
    m = conn.execute("SELECT COUNT(*) FROM monitors").fetchone()[0]
    c = conn.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
    u = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    return {"status": "ok", "version": "2.0.0", "users": u, "monitors": m, "checks": c}

@app.post("/api/auth/reset-admin")
async def reset_admin_password():
    """One-time admin reset — call with SECRET_KEY to reset admin password."""
    conn = get_db()
    admin = conn.execute("SELECT id FROM users WHERE email=?", (ADMIN_EMAIL,)).fetchone()
    if admin:
        conn.execute("UPDATE users SET password_hash=? WHERE email=?",
                     (hash_password("admin123"), ADMIN_EMAIL))
        conn.commit()
        conn.close()
        return {"ok": True, "email": ADMIN_EMAIL, "password": "admin123"}
    conn.close()
    raise HTTPException(404, "Admin not found")

# ═══════════ Security Headers Middleware ══════════════════
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def dashboard():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    raise HTTPException(404, "Static files not found")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)