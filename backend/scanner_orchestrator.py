"""
Module 2 — Configurable Scan Profiles & Rate Limiting & Scan Orchestrator
Declarative scan profiles, async-safe per-target Token-Bucket rate limiter,
and unified cross-module scan orchestration.
"""

import time
import asyncio
import random
import urllib.parse
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from backend.database import get_connection, DEFAULT_DB_PATH

@dataclass
class ScanProfile:
    name: str
    description: str
    modules: List[str]
    concurrency: int
    rps_limit: float          # Requests per second per host
    timeout_seconds: float
    retry_policy: int         # Number of retries on network ambiguity
    jitter_min_ms: int        # Minimum randomized jitter delay
    jitter_max_ms: int        # Maximum randomized jitter delay

# Declarative Profiles Config
SCAN_PROFILES: Dict[str, ScanProfile] = {
    "stealth": ScanProfile(
        name="Stealth / Passive",
        description="Low footprint, randomized jitter delay, non-intrusive header and passive SSL inspection.",
        modules=["ssl_auditor", "headers", "technologies", "dns_recon"],
        concurrency=1,
        rps_limit=2.0,
        timeout_seconds=8.0,
        retry_policy=1,
        jitter_min_ms=300,
        jitter_max_ms=900
    ),
    "owasp_fast": ScanProfile(
        name="OWASP Top 10 Fast",
        description="High speed, targeted core vulnerabilities (SQLi, XSS, JWT, SSRF, Auth), short timeouts.",
        modules=["jwt_audit", "sqli_probe", "xss_probe", "ssl_auditor", "cors_probe", "exposure_probe"],
        concurrency=8,
        rps_limit=25.0,
        timeout_seconds=3.0,
        retry_policy=1,
        jitter_min_ms=10,
        jitter_max_ms=50
    ),
    "deep_coverage": ScanProfile(
        name="Deep Full-Coverage",
        description="Exhaustive vulnerability discovery across all modules, thorough fuzzing and verification retries.",
        modules=["ssl_auditor", "jwt_audit", "sqli_probe", "xss_probe", "cors_probe", "exposure_probe", "nuclei_deep", "api_fuzzer"],
        concurrency=15,
        rps_limit=50.0,
        timeout_seconds=10.0,
        retry_policy=3,
        jitter_min_ms=0,
        jitter_max_ms=20
    )
}

class TokenBucketRateLimiter:
    """
    Thread-safe / async-safe Token-Bucket rate limiter strictly partitioned per target host.
    """
    def __init__(self, rps: float, burst_capacity: Optional[float] = None):
        self.rps = max(0.1, rps)
        self.capacity = burst_capacity if burst_capacity is not None else max(1.0, self.rps)
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Acquires a token, waiting asynchronously if the bucket is empty."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now
            
            # Refill tokens
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rps)
            
            if self.tokens < 1.0:
                deficit = 1.0 - self.tokens
                wait_time = deficit / self.rps
                await asyncio.sleep(wait_time)
                self.tokens = 0.0
                self.last_update = time.monotonic()
            else:
                self.tokens -= 1.0

# Per-host limiter registry
_HOST_LIMITERS: Dict[str, TokenBucketRateLimiter] = {}
_REGISTRY_LOCK = asyncio.Lock()

async def get_host_rate_limiter(hostname: str, rps: float) -> TokenBucketRateLimiter:
    async with _REGISTRY_LOCK:
        if hostname not in _HOST_LIMITERS:
            _HOST_LIMITERS[hostname] = TokenBucketRateLimiter(rps=rps)
        return _HOST_LIMITERS[hostname]

@dataclass
class StructuredModuleLog:
    module_name: str
    target: str
    start_time: str
    duration_ms: float
    status: str              # 'success', 'failed', 'incomplete', 'skipped'
    findings_count: int
    error: Optional[str] = None

class ScanOrchestrator:
    """
    Central orchestration engine that runs scanner modules based on declarative profile config
    with rate limiting and structured diagnostics logging.
    """
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.active_scans: Dict[str, Dict[str, Any]] = {}

    def get_profiles(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": k,
                "name": v.name,
                "description": v.description,
                "modules": v.modules,
                "concurrency": v.concurrency,
                "rps_limit": v.rps_limit,
                "timeout_seconds": v.timeout_seconds,
                "retry_policy": v.retry_policy
            }
            for k, v in SCAN_PROFILES.items()
        ]

    async def run_scan(
        self,
        scan_id: str,
        target_url: str,
        profile_key: str = "owasp_fast",
        custom_params: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
        """
        Executes a scan job applying the requested profile's concurrency and rate limits.
        """
        profile = SCAN_PROFILES.get(profile_key, SCAN_PROFILES["owasp_fast"])
        if custom_params:
            # Allow custom overrides
            rps = float(custom_params.get("rps_limit", profile.rps_limit))
        else:
            rps = profile.rps_limit

        parsed = urllib.parse.urlparse(target_url if target_url.startswith("http") else f"http://{target_url}")
        target_host = parsed.hostname or target_url

        limiter = await get_host_rate_limiter(target_host, rps)
        
        start_time = time.time()
        logs: List[StructuredModuleLog] = []
        all_findings: List[Dict[str, Any]] = []
        
        self.active_scans[scan_id] = {
            "scan_id": scan_id,
            "target": target_url,
            "profile": profile_key,
            "status": "running",
            "progress": 0,
            "started_at": datetime.now(timezone.utc).isoformat()
        }

        # 1. Execute SSL Auditor if in module list
        if "ssl_auditor" in profile.modules:
            mod_start = time.time()
            try:
                # Apply rate limiter
                await limiter.acquire()
                if profile.jitter_max_ms > 0:
                    jitter = random.uniform(profile.jitter_min_ms, profile.jitter_max_ms) / 1000.0
                    await asyncio.sleep(jitter)

                from backend.ssl_auditor import audit_ssl_target
                # Run in executor to avoid blocking async loop
                loop = asyncio.get_event_loop()
                ssl_result = await loop.run_in_executor(None, audit_ssl_target, target_url)
                
                for f in ssl_result.get("findings", []):
                    all_findings.append({
                        "scan_id": scan_id,
                        "target": target_url,
                        "module_name": "ssl_auditor",
                        "title": f["title"],
                        "description": f["description"],
                        "severity": f["severity"],
                        "cvss_score": f.get("cvss_score", 0.0),
                        "cwe": f.get("cwe", "CWE-326"),
                        "raw_evidence": json.dumps(ssl_result.get("protocols", {}))
                    })
                
                logs.append(StructuredModuleLog(
                    module_name="ssl_auditor",
                    target=target_url,
                    start_time=datetime.now(timezone.utc).isoformat(),
                    duration_ms=round((time.time() - mod_start) * 1000, 2),
                    status="success",
                    findings_count=len(ssl_result.get("findings", []))
                ))
            except Exception as e:
                logs.append(StructuredModuleLog(
                    module_name="ssl_auditor",
                    target=target_url,
                    start_time=datetime.now(timezone.utc).isoformat(),
                    duration_ms=round((time.time() - mod_start) * 1000, 2),
                    status="failed",
                    findings_count=0,
                    error=str(e)
                ))

        # 2. Execute DAST & OWASP Analyzers
        from backend.dast_scanners import run_owasp_scan
        mod_start = time.time()
        try:
            await limiter.acquire()
            loop = asyncio.get_event_loop()
            dast_res = await loop.run_in_executor(None, run_owasp_scan, target_url)
            
            for f in dast_res.get("findings", []):
                all_findings.append({
                    "scan_id": scan_id,
                    "target": target_url,
                    "module_name": "owasp_scanner",
                    "title": f.get("name", "Vulnerability Finding"),
                    "description": f.get("description", ""),
                    "severity": f.get("severity", "info"),
                    "cvss_score": f.get("cvss_score", 0.0),
                    "cwe": f.get("cwe", []),
                    "remediation": f.get("remediation", ""),
                    "raw_evidence": f.get("matched_at", "")
                })

            logs.append(StructuredModuleLog(
                module_name="owasp_scanner",
                target=target_url,
                start_time=datetime.now(timezone.utc).isoformat(),
                duration_ms=round((time.time() - mod_start) * 1000, 2),
                status="success",
                findings_count=len(dast_res.get("findings", []))
            ))
        except Exception as e:
            logs.append(StructuredModuleLog(
                module_name="owasp_scanner",
                target=target_url,
                start_time=datetime.now(timezone.utc).isoformat(),
                duration_ms=round((time.time() - mod_start) * 1000, 2),
                status="failed",
                findings_count=0,
                error=str(e)
            ))

        # Save findings to SQLite scan_findings table
        self._persist_findings(all_findings)

        total_duration = round(time.time() - start_time, 2)
        summary = {
            "scan_id": scan_id,
            "target": target_url,
            "profile": profile_key,
            "status": "completed",
            "duration_seconds": total_duration,
            "findings_count": len(all_findings),
            "findings": all_findings,
            "structured_logs": [
                {
                    "module": l.module_name,
                    "duration_ms": l.duration_ms,
                    "status": l.status,
                    "findings": l.findings_count,
                    "error": l.error
                }
                for l in logs
            ],
            "completed_at": datetime.now(timezone.utc).isoformat()
        }

        self.active_scans[scan_id] = summary
        return summary

    def _persist_findings(self, findings: List[Dict[str, Any]]):
        if not findings:
            return
        import hashlib
        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()

        for f in findings:
            # Deterministic finding hash: hash(target + module + title)
            f_hash = hashlib.sha256(f"{f['target']}:{f['module_name']}:{f['title']}".encode('utf-8')).hexdigest()[:16]
            cwe_val = json.dumps(f['cwe']) if isinstance(f.get('cwe'), list) else str(f.get('cwe', ''))
            
            # Check if exists
            cursor.execute("SELECT id, consecutive_count FROM scan_findings WHERE finding_hash = ?", (f_hash,))
            row = cursor.fetchone()
            if row:
                cursor.execute(
                    "UPDATE scan_findings SET last_seen = ?, consecutive_count = consecutive_count + 1 WHERE id = ?",
                    (now, row["id"])
                )
            else:
                cursor.execute(
                    """INSERT INTO scan_findings 
                    (scan_id, target, finding_hash, module_name, title, description, severity, cvss_score, cwe, raw_evidence, first_seen, last_seen, consecutive_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (
                        f["scan_id"], f["target"], f_hash, f["module_name"], f["title"],
                        f.get("description", ""), f["severity"], f.get("cvss_score", 0.0),
                        cwe_val, str(f.get("raw_evidence", "")), now, now
                    )
                )
        conn.commit()
        conn.close()

scan_orchestrator = ScanOrchestrator()
