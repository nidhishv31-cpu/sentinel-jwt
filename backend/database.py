import sqlite3
import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(DB_DIR, "db", "sentinel.db")

def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str = DEFAULT_DB_PATH):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    # Create security_events table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        details TEXT NOT NULL,
        severity TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)
    
    # Create alerts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_triggered TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        event_ids TEXT NOT NULL,
        explanation TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)
    
    # Create baselines table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS baselines (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        metric_name TEXT NOT NULL,
        source_ip_or_user TEXT NOT NULL,
        mean_rate REAL NOT NULL,
        std_dev REAL NOT NULL,
        computed_at TEXT NOT NULL
    )
    """)
    
    # Create threat_intel_entries table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_intel_entries (
        ip_address TEXT,
        feed_source TEXT,
        category TEXT,
        updated_at TEXT
    )
    """)

    # Create geo_cache table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS geo_cache (
        ip TEXT PRIMARY KEY,
        country TEXT,
        country_code TEXT,
        city TEXT,
        lat REAL,
        lon REAL,
        isp TEXT,
        cached_at TEXT
    )
    """)

    # Create blocked_ips table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        reason TEXT,
        blocked_at TEXT NOT NULL
    )
    """)

    # Create signing_keys table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS signing_keys (
        kid TEXT PRIMARY KEY,
        algorithm TEXT DEFAULT 'RS256',
        private_key TEXT NOT NULL,
        public_key TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        created_at TEXT NOT NULL
    )
    """)
    
    # Indexes for optimization
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON security_events(source_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_baselines_metric ON baselines(metric_name, source_ip_or_user)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_ip ON threat_intel_entries(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_signing_keys_status ON signing_keys(status)")
    
    conn.commit()
    conn.close()

def add_security_event(
    timestamp: str,
    event_type: str,
    source_ip: str,
    details: Dict[str, Any],
    severity: str,
    db_path: str = DEFAULT_DB_PATH
) -> int:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    created_at = datetime.utcnow().isoformat()
    details_str = json.dumps(details)
    
    cursor.execute(
        "INSERT INTO security_events (timestamp, event_type, source_ip, details, severity, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (timestamp, event_type, source_ip, details_str, severity, created_at)
    )
    event_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return event_id

def add_alert(
    rule_triggered: str,
    severity: str,
    source_ip: str,
    event_ids: List[int],
    explanation: str,
    status: str = "open",
    db_path: str = DEFAULT_DB_PATH
) -> int:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    created_at = datetime.utcnow().isoformat()
    event_ids_str = json.dumps(event_ids)
    
    cursor.execute(
        "INSERT INTO alerts (rule_triggered, severity, source_ip, event_ids, explanation, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (rule_triggered, severity, source_ip, event_ids_str, explanation, status, created_at)
    )
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id

def get_alerts(status: Optional[str] = None, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    if status:
        cursor.execute("SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC", (status,))
    else:
        cursor.execute("SELECT * FROM alerts ORDER BY created_at DESC")
        
    rows = cursor.fetchall()
    conn.close()
    
    alerts = []
    for r in rows:
        alert = dict(r)
        alert["event_ids"] = json.loads(alert["event_ids"])
        alerts.append(alert)
    return alerts

def update_alert_status(alert_id: int, status: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated
