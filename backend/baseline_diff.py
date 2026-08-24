"""
Module 9 — Baseline Diff Scanning
Structured comparison across scans using normalized finding fingerprints.
Classifies findings into: New, Resolved, Still-Open, and Changed-Severity with anti-flakiness tracking.
"""

import hashlib
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timezone
from backend.database import get_connection, DEFAULT_DB_PATH

def compute_finding_fingerprint(finding: Dict[str, Any]) -> str:
    """
    Computes a deterministic, stable fingerprint for a finding based on
    (target_host, module_name, vulnerability_title, path/cwe).
    """
    target = finding.get("target") or finding.get("host") or ""
    module = finding.get("module_name") or finding.get("module") or "general"
    title = finding.get("title") or finding.get("name") or "finding"
    cwe = str(finding.get("cwe", ""))
    
    key_str = f"{target.strip().lower()}|{module.strip().lower()}|{title.strip().lower()}|{cwe.strip()}"
    return hashlib.sha256(key_str.encode('utf-8')).hexdigest()[:16]

def perform_baseline_diff(
    baseline_findings: List[Dict[str, Any]],
    current_findings: List[Dict[str, Any]],
    confirmation_threshold: int = 1
) -> Dict[str, Any]:
    """
    Compares baseline findings against current scan findings.
    Returns 4-way classification: New, Resolved, Still-Open, Changed-Severity.
    """
    baseline_map: Dict[str, Dict[str, Any]] = {}
    for f in baseline_findings:
        fp = f.get("finding_hash") or compute_finding_fingerprint(f)
        baseline_map[fp] = f

    current_map: Dict[str, Dict[str, Any]] = {}
    for f in current_findings:
        fp = f.get("finding_hash") or compute_finding_fingerprint(f)
        current_map[fp] = f

    new_findings = []
    resolved_findings = []
    still_open_findings = []
    changed_severity_findings = []

    # 1. Inspect Current Scan against Baseline
    for fp, cur_f in current_map.items():
        if fp not in baseline_map:
            # New Finding
            item = dict(cur_f)
            item["diff_status"] = "new"
            new_findings.append(item)
        else:
            base_f = baseline_map[fp]
            base_sev = base_f.get("severity", "info").lower()
            cur_sev = cur_f.get("severity", "info").lower()
            
            if base_sev != cur_sev:
                # Changed Severity
                item = dict(cur_f)
                item["diff_status"] = "changed_severity"
                item["previous_severity"] = base_sev
                item["new_severity"] = cur_sev
                changed_severity_findings.append(item)
            else:
                # Still-Open (Unchanged)
                item = dict(cur_f)
                item["diff_status"] = "still_open"
                still_open_findings.append(item)

    # 2. Inspect Baseline for Resolved findings
    for fp, base_f in baseline_map.items():
        if fp not in current_map:
            # Resolved Finding
            item = dict(base_f)
            item["diff_status"] = "resolved"
            item["resolved_at"] = datetime.now(timezone.utc).isoformat()
            resolved_findings.append(item)

    return {
        "summary": {
            "total_baseline": len(baseline_findings),
            "total_current": len(current_findings),
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "still_open_count": len(still_open_findings),
            "changed_severity_count": len(changed_severity_findings),
            "net_risk_delta": len(new_findings) - len(resolved_findings)
        },
        "new": new_findings,
        "resolved": resolved_findings,
        "still_open": still_open_findings,
        "changed_severity": changed_severity_findings
    }
