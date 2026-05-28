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
