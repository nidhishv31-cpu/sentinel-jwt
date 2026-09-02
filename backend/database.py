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
        conn.execute("PRAGMA busy_timeout = 5000;")
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

    # --- DevSecOps Pipeline Extension Tables ---
    # Create repos table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS repos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        github_full_name TEXT NOT NULL,
        default_branch TEXT NOT NULL DEFAULT 'main',
        install_token_ref TEXT,
        webhook_secret TEXT,
        local_path TEXT,
        last_synced_at TEXT,
        auto_pr_on_fix BOOLEAN DEFAULT 0
    )
    """)

    # Create pipeline_runs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS pipeline_runs (
        id TEXT PRIMARY KEY,
        repo_id INTEGER,
        status TEXT NOT NULL DEFAULT 'queued',
        current_stage TEXT,
        stages_json TEXT,
        summary_json TEXT,
        sarif_path TEXT,
        markdown_report_path TEXT,
        started_at TEXT,
        completed_at TEXT
    )
    """)

    # Create sbom_components table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sbom_components (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL,
        repo_id INTEGER,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        ecosystem TEXT NOT NULL,
        license TEXT,
        purl TEXT
    )
    """)

    # Create exploit_audit_log table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS exploit_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        target_id INTEGER,
        module_name TEXT NOT NULL,
        finding_id TEXT,
        payload_summary TEXT,
        result TEXT NOT NULL,
        operator TEXT DEFAULT 'system'
    )
    """)

    # Create unified_findings table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS unified_findings (
        id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        tool TEXT NOT NULL,
        repo_id INTEGER,
        run_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        cwe TEXT,
        cve TEXT,
        title TEXT NOT NULL,
        description TEXT,
        file_path TEXT,
        line INTEGER,
        endpoint TEXT,
        evidence TEXT,
        remediation TEXT,
        status TEXT DEFAULT 'open',
        created_at TEXT NOT NULL
    )
    """)

    # Additional Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON scan_findings(target)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_hash ON scan_findings(finding_hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON scan_findings(scan_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_carved_capture ON carved_artifacts(capture_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_id ON scan_reports(report_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_repos_name ON repos(github_full_name)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_repo ON pipeline_runs(repo_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sbom_run ON sbom_components(run_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_exploit_target ON exploit_audit_log(target_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_unified_findings_run ON unified_findings(run_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_unified_findings_severity ON unified_findings(severity)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_unified_findings_source ON unified_findings(source)")

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

# --- DevSecOps Helper Functions ---

def add_repo(github_full_name: str, default_branch: str = 'main', install_token_ref: Optional[str] = None, webhook_secret: Optional[str] = None, local_path: Optional[str] = None, auto_pr_on_fix: bool = False, db_path: str = DEFAULT_DB_PATH) -> int:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    last_synced = datetime.utcnow().isoformat()
    cursor.execute(
        "INSERT INTO repos (github_full_name, default_branch, install_token_ref, webhook_secret, local_path, last_synced_at, auto_pr_on_fix) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (github_full_name, default_branch, install_token_ref, webhook_secret, local_path, last_synced, 1 if auto_pr_on_fix else 0)
    )
    repo_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return repo_id

def get_repos(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM repos ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_repo(repo_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM repos WHERE id = ?", (repo_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def add_pipeline_run(run_id: str, repo_id: Optional[int] = None, status: str = 'queued', current_stage: Optional[str] = None, stages: Optional[Dict[str, Any]] = None, summary: Optional[Dict[str, Any]] = None, sarif_path: Optional[str] = None, markdown_report_path: Optional[str] = None, db_path: str = DEFAULT_DB_PATH) -> str:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    started_at = datetime.utcnow().isoformat()
    stages_str = json.dumps(stages or {})
    summary_str = json.dumps(summary or {})
    cursor.execute(
        "INSERT INTO pipeline_runs (id, repo_id, status, current_stage, stages_json, summary_json, sarif_path, markdown_report_path, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (run_id, repo_id, status, current_stage, stages_str, summary_str, sarif_path, markdown_report_path, started_at)
    )
    conn.commit()
    conn.close()
    return run_id

def update_pipeline_run(run_id: str, status: Optional[str] = None, current_stage: Optional[str] = None, stages: Optional[Dict[str, Any]] = None, summary: Optional[Dict[str, Any]] = None, sarif_path: Optional[str] = None, markdown_report_path: Optional[str] = None, completed: bool = False, db_path: str = DEFAULT_DB_PATH) -> bool:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    updates = []
    params = []
    
    if status is not None:
        updates.append("status = ?")
        params.append(status)
    if current_stage is not None:
        updates.append("current_stage = ?")
        params.append(current_stage)
    if stages is not None:
        updates.append("stages_json = ?")
        params.append(json.dumps(stages))
    if summary is not None:
        updates.append("summary_json = ?")
        params.append(json.dumps(summary))
    if sarif_path is not None:
        updates.append("sarif_path = ?")
        params.append(sarif_path)
    if markdown_report_path is not None:
        updates.append("markdown_report_path = ?")
        params.append(markdown_report_path)
    if completed:
        updates.append("completed_at = ?")
        params.append(datetime.utcnow().isoformat())
        
    if not updates:
        conn.close()
        return False
        
    params.append(run_id)
    query = f"UPDATE pipeline_runs SET {', '.join(updates)} WHERE id = ?"
    cursor.execute(query, tuple(params))
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return updated

def get_pipeline_run(run_id: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pipeline_runs WHERE id = ?", (run_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    res = dict(row)
    res["stages"] = json.loads(res.get("stages_json") or "{}")
    res["summary"] = json.loads(res.get("summary_json") or "{}")
    return res

def list_pipeline_runs(repo_id: Optional[int] = None, limit: int = 50, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    if repo_id is not None:
        cursor.execute("SELECT * FROM pipeline_runs WHERE repo_id = ? ORDER BY started_at DESC LIMIT ?", (repo_id, limit))
    else:
        cursor.execute("SELECT * FROM pipeline_runs ORDER BY started_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for r in rows:
        item = dict(r)
        item["stages"] = json.loads(item.get("stages_json") or "{}")
        item["summary"] = json.loads(item.get("summary_json") or "{}")
        results.append(item)
    return results

def add_unified_finding(finding: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> str:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    created_at = finding.get("created_at") or datetime.utcnow().isoformat()
    cursor.execute("""
        INSERT OR REPLACE INTO unified_findings 
        (id, source, tool, repo_id, run_id, severity, cwe, cve, title, description, file_path, line, endpoint, evidence, remediation, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        finding["id"], finding["source"], finding["tool"], finding.get("repo_id"), finding["run_id"],
        finding["severity"], finding.get("cwe"), finding.get("cve"), finding["title"],
        finding.get("description"), finding.get("file_path"), finding.get("line"),
        finding.get("endpoint"), finding.get("evidence"), finding.get("remediation"),
        finding.get("status", "open"), created_at
    ))
    conn.commit()
    conn.close()
    return finding["id"]

def get_unified_findings(run_id: Optional[str] = None, repo_id: Optional[int] = None, source: Optional[str] = None, severity: Optional[str] = None, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    query = "SELECT * FROM unified_findings WHERE 1=1"
    params = []
    if run_id:
        query += " AND run_id = ?"
        params.append(run_id)
    if repo_id:
        query += " AND repo_id = ?"
        params.append(repo_id)
    if source:
        query += " AND source = ?"
        params.append(source)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, id ASC"
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def add_sbom_components(components: List[Dict[str, Any]], run_id: str, repo_id: Optional[int] = None, db_path: str = DEFAULT_DB_PATH):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    for c in components:
        cursor.execute(
            "INSERT INTO sbom_components (run_id, repo_id, name, version, ecosystem, license, purl) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, repo_id, c.get("name", ""), c.get("version", ""), c.get("ecosystem", ""), c.get("license"), c.get("purl"))
        )
    conn.commit()
    conn.close()

def get_sbom_components(run_id: str, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sbom_components WHERE run_id = ? ORDER BY name ASC", (run_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def add_exploit_audit(target_id: Optional[int], module_name: str, result: str, finding_id: Optional[str] = None, payload_summary: Optional[str] = None, operator: str = "system", db_path: str = DEFAULT_DB_PATH) -> int:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    ts = datetime.utcnow().isoformat()
    cursor.execute(
        "INSERT INTO exploit_audit_log (timestamp, target_id, module_name, finding_id, payload_summary, result, operator) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts, target_id, module_name, finding_id, payload_summary, result, operator)
    )
    entry_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return entry_id

def get_exploit_audits(target_id: Optional[int] = None, limit: int = 100, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    if target_id:
        cursor.execute("SELECT * FROM exploit_audit_log WHERE target_id = ? ORDER BY timestamp DESC LIMIT ?", (target_id, limit))
    else:
        cursor.execute("SELECT * FROM exploit_audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

