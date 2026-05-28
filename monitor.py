"""Background monitor scheduler."""
import sqlite3, urllib.request, json, ssl, socket
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler

DB = "monitors.db"

class MonitorScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler()

    def start(self):
        self.scheduler.add_job(self.check_all, "interval", seconds=60)
        self.scheduler.start()

    def stop(self):
        self.scheduler.shutdown()

    def check_all(self):
        conn = sqlite3.connect(DB)
        monitors = conn.execute("SELECT id, url FROM monitors").fetchall()
        for mid, url in monitors:
            result = self.check_one(url)
            conn.execute(
                "INSERT INTO checks (monitor_id, status_code, response_ms, error) VALUES (?, ?, ?, ?)",
                (mid, result["status"], result["ms"], result.get("error")))
        conn.commit()
        conn.close()

    def check_one(self, url: str) -> dict:
        try:
            start = datetime.now()
            req = urllib.request.Request(url, headers={"User-Agent": "APIMonitor/1.0"})
            resp = urllib.request.urlopen(req, timeout=10)
            ms = (datetime.now() - start).total_seconds() * 1000
            return {"status": resp.status, "ms": round(ms, 1)}
        except Exception as e:
            return {"status": 0, "ms": 0, "error": str(e)[:200]}
