import sqlite3
import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(DB_DIR, "db", "sentinel.db")

def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # High-performance WAL mode and memory caching
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA cache_size = 10000;")
        conn.execute("PRAGMA temp_store = MEMORY;")
    except Exception:
        pass
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
    
    # Create scan_findings table for normalized findings and baseline diffing
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        target TEXT NOT NULL,
        finding_hash TEXT NOT NULL,
        module_name TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        cvss_vector TEXT,
        cvss_score REAL DEFAULT 0.0,
        cwe TEXT,
        remediation TEXT,
        raw_evidence TEXT,
        status TEXT DEFAULT 'open',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        consecutive_count INTEGER DEFAULT 1
    )
    """)

    # Create carved_artifacts table for safe inert file extractions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS carved_artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        capture_id TEXT NOT NULL,
        stream_id INTEGER,
        filename TEXT NOT NULL,
        stored_path TEXT NOT NULL,
        file_type TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        md5_hash TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        is_truncated BOOLEAN DEFAULT 0,
        carved_at TEXT NOT NULL
    )
    """)

    # Create scan_reports table for decoupled async reporting
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        target TEXT NOT NULL,
        format TEXT NOT NULL,
        status TEXT NOT NULL,
        file_path TEXT,
        summary_json TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # Additional Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON scan_findings(target)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_hash ON scan_findings(finding_hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings(scan_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_carved_capture ON carved_artifacts(capture_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_id ON scan_reports(report_id)")

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
    # Create scan_findings table for normalized findings and baseline diffing
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        target TEXT NOT NULL,
        finding_hash TEXT NOT NULL,
        module_name TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        cvss_vector TEXT,
        cvss_score REAL DEFAULT 0.0,
        cwe TEXT,
        remediation TEXT,
        raw_evidence TEXT,
        status TEXT DEFAULT 'open',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        consecutive_count INTEGER DEFAULT 1
    )
    """)

    # Create carved_artifacts table for safe inert file extractions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS carved_artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        capture_id TEXT NOT NULL,
        stream_id INTEGER,
        filename TEXT NOT NULL,
        stored_path TEXT NOT NULL,
        file_type TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        md5_hash TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        is_truncated BOOLEAN DEFAULT 0,
        carved_at TEXT NOT NULL
    )
    """)

    # Create scan_reports table for decoupled async reporting
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        target TEXT NOT NULL,
        format TEXT NOT NULL,
        status TEXT NOT NULL,
        file_path TEXT,
        summary_json TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # Additional Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON scan_findings(target)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_hash ON scan_findings(finding_hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings(scan_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_carved_capture ON carved_artifacts(capture_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_id ON scan_reports(report_id)")

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
    # Create scan_findings table for normalized findings and baseline diffing
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        target TEXT NOT NULL,
        finding_hash TEXT NOT NULL,
        module_name TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        cvss_vector TEXT,
        cvss_score REAL DEFAULT 0.0,
        cwe TEXT,
        remediation TEXT,
        raw_evidence TEXT,
        status TEXT DEFAULT 'open',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        consecutive_count INTEGER DEFAULT 1
    )
    """)

    # Create carved_artifacts table for safe inert file extractions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS carved_artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        capture_id TEXT NOT NULL,
        stream_id INTEGER,
        filename TEXT NOT NULL,
        stored_path TEXT NOT NULL,
        file_type TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        md5_hash TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        is_truncated BOOLEAN DEFAULT 0,
        carved_at TEXT NOT NULL
    )
    """)

    # Create scan_reports table for decoupled async reporting
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        target TEXT NOT NULL,
        format TEXT NOT NULL,
        status TEXT NOT NULL,
        file_path TEXT,
        summary_json TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # Additional Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON scan_findings(target)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_hash ON scan_findings(finding_hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings(scan_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_carved_capture ON carved_artifacts(capture_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_id ON scan_reports(report_id)")

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
    # Create scan_findings table for normalized findings and baseline diffing
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        target TEXT NOT NULL,
        finding_hash TEXT NOT NULL,
        module_name TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        cvss_vector TEXT,
        cvss_score REAL DEFAULT 0.0,
        cwe TEXT,
        remediation TEXT,
        raw_evidence TEXT,
        status TEXT DEFAULT 'open',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        consecutive_count INTEGER DEFAULT 1
    )
    """)

    # Create carved_artifacts table for safe inert file extractions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS carved_artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        capture_id TEXT NOT NULL,
        stream_id INTEGER,
        filename TEXT NOT NULL,
        stored_path TEXT NOT NULL,
        file_type TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        md5_hash TEXT NOT NULL,
        sha256_hash TEXT NOT NULL,
        is_truncated BOOLEAN DEFAULT 0,
        carved_at TEXT NOT NULL
    )
    """)

    # Create scan_reports table for decoupled async reporting
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        target TEXT NOT NULL,
        format TEXT NOT NULL,
        status TEXT NOT NULL,
        file_path TEXT,
        summary_json TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # Additional Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON scan_findings(target)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_hash ON scan_findings(finding_hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings(scan_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_carved_capture ON carved_artifacts(capture_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_id ON scan_reports(report_id)")

    conn.commit()
    conn.close()
    return updated
