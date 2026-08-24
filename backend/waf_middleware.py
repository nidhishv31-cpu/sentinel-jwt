import json
from datetime import datetime
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from backend.database import get_connection

BLOCKED_IPS = set()

def reload_blocked_ips(db_path: str):
    global BLOCKED_IPS
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM blocked_ips")
        BLOCKED_IPS = {row["ip_address"] for row in cursor.fetchall()}
    except Exception:
        pass # Tables might not exist yet
    finally:
        conn.close()

class WAFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, db_path: str):
        super().__init__(app)
        self.db_path = db_path
        reload_blocked_ips(self.db_path)

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else ""
        if client_ip in BLOCKED_IPS:
            print(f"[WAF] Blocked request from {client_ip}")
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied: Your IP has been blocked by the WAF."}
            )
        response = await call_next(request)
        return response

def block_ip(ip: str, reason: str, db_path: str):
    global BLOCKED_IPS
    conn = get_connection(db_path)
    cursor = conn.cursor()
    blocked_at = datetime.utcnow().isoformat()
    try:
        cursor.execute(
            "INSERT INTO blocked_ips (ip_address, reason, blocked_at) VALUES (?, ?, ?)",
            (ip, reason, blocked_at)
        )
        conn.commit()
        BLOCKED_IPS.add(ip)
    except Exception as e:
        pass # Handle unique constraint failure
    finally:
        conn.close()

def unblock_ip(ip: str, db_path: str):
    global BLOCKED_IPS
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()
    if ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(ip)

def get_blocked_ips(db_path: str) -> list:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, reason, blocked_at FROM blocked_ips")
    rows = cursor.fetchall()
    conn.close()
    return [{"ip": r["ip_address"], "reason": r["reason"], "blocked_at": r["blocked_at"]} for r in rows]
