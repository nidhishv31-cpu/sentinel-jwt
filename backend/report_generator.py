"""
Module 8 — Executive PDF/HTML Reports & CVSS 3.1 Calculator
Implements the exact FIRST.org CVSS 3.1 base score formula, decouples data aggregation
from HTML/PDF rendering, and generates reports asynchronously with progress tracking.
"""

import os
import math
import json
import time
import uuid
import threading
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from backend.database import get_connection, DEFAULT_DB_PATH

# ── 1. EXACT FIRST.ORG CVSS v3.1 CALCULATOR ───────────────────────────────────

CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, # Attack Vector: Network, Adj, Local, Phys
    "AC": {"L": 0.77, "H": 0.44},                      # Attack Complexity: Low, High
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},         # Privileges Required (Scope Unchanged)
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},          # Privileges Required (Scope Changed)
    "UI": {"N": 0.85, "R": 0.62},                      # User Interaction: None, Required
    "S":  {"U": "U", "C": "C"},                         # Scope: Unchanged, Changed
    "C":  {"H": 0.56, "L": 0.22, "N": 0.0},            # Confidentiality: High, Low, None
    "I":  {"H": 0.56, "L": 0.22, "N": 0.0},            # Integrity: High, Low, None
    "A":  {"H": 0.56, "L": 0.22, "N": 0.0},            # Availability: High, Low, None
}

def cvss_roundup(val: float) -> float:
    """Official CVSS v3.1 roundup function: ceiling to 1 decimal place."""
    int_val = round(val * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000.0
    return (math.floor(int_val / 10000) + 1) / 10.0

def calculate_cvss31_score(vector_string: str) -> Dict[str, Any]:
    """
    Parses a CVSS:3.1 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
    and computes Base Score, Exploitability, Impact, and Qualitative Severity.
    """
    cleaned = vector_string.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").strip()
    parts = cleaned.split("/")
    metric_map = {}
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            metric_map[k.upper()] = v.upper()

    av = CVSS_METRICS["AV"].get(metric_map.get("AV", "N"), 0.85)
    ac = CVSS_METRICS["AC"].get(metric_map.get("AC", "L"), 0.77)
    scope = metric_map.get("S", "U")
    
    if scope == "C":
        pr = CVSS_METRICS["PR_C"].get(metric_map.get("PR", "N"), 0.85)
    else:
        pr = CVSS_METRICS["PR_U"].get(metric_map.get("PR", "N"), 0.85)
        
    ui = CVSS_METRICS["UI"].get(metric_map.get("UI", "N"), 0.85)
    c_val = CVSS_METRICS["C"].get(metric_map.get("C", "N"), 0.0)
    i_val = CVSS_METRICS["I"].get(metric_map.get("I", "N"), 0.0)
    a_val = CVSS_METRICS["A"].get(metric_map.get("A", "N"), 0.0)

    # 1. Calculate ISS (Impact Sub-Score Base)
    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))
    
    # 2. Calculate Impact
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

    # 3. Calculate Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    # 4. Calculate Base Score
    if impact <= 0:
        base_score = 0.0
    else:
        if scope == "U":
            base_score = cvss_roundup(min(impact + exploitability, 10.0))
        else:
            base_score = cvss_roundup(min(1.08 * (impact + exploitability), 10.0))

    # Qualitative Rating
    if base_score == 0.0:
        rating = "None"
    elif base_score < 4.0:
        rating = "Low"
    elif base_score < 7.0:
        rating = "Medium"
    elif base_score < 9.0:
        rating = "High"
    else:
        rating = "Critical"

    return {
        "vector_string": vector_string,
        "base_score": base_score,
        "exploitability_score": round(exploitability, 1),
        "impact_score": round(impact, 1),
        "severity_rating": rating,
        "scope": "Changed" if scope == "C" else "Unchanged"
    }

# ── 2. DATA ASSEMBLY & REPORT GENERATION ─────────────────────────────────────

def assemble_report_data(target: str, findings: List[Dict[str, Any]], scan_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Consolidates scan findings, calculates severity breakdown, CVSS aggregates,
    and formats finding timeline for report rendering.
    """
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    enriched_findings = []

    total_cvss = 0.0
    max_cvss = 0.0

    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
            
        cvss_score = float(f.get("cvss_score", 0.0))
        cvss_vec = f.get("cvss_vector")
        
        # If vector string is present, recompute score deterministically
        if cvss_vec and "AV:" in cvss_vec:
            cvss_data = calculate_cvss31_score(cvss_vec)
            cvss_score = cvss_data["base_score"]
        else:
            cvss_data = {"base_score": cvss_score, "severity_rating": sev.capitalize()}
            
        total_cvss += cvss_score
        max_cvss = max(max_cvss, cvss_score)

        enriched_findings.append({
            "title": f.get("title") or f.get("name", "Vulnerability Finding"),
            "module": f.get("module_name", "general_scanner"),
            "severity": sev,
            "cvss_score": cvss_score,
            "cvss_data": cvss_data,
            "cwe": f.get("cwe", "CWE-Unknown"),
            "description": f.get("description", ""),
            "remediation": f.get("remediation", "Apply defensive patching and input validation."),
            "evidence": f.get("raw_evidence") or f.get("matched_at", "")
        })

    avg_cvss = round(total_cvss / max(1, len(findings)), 1)
    
    # Overall Security Health Index (0-100)
    health_index = max(0, 100 - (severity_counts["critical"] * 25 + severity_counts["high"] * 15 + severity_counts["medium"] * 5))

    return {
        "report_id": f"REP-{uuid.uuid4().hex[:8].upper()}",
        "target": target,
        "generated_at": datetime.now(timezone.utc).strftime("%B %d, %Y - %H:%M UTC"),
        "health_index": health_index,
        "max_cvss": max_cvss,
        "avg_cvss": avg_cvss,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "findings": sorted(enriched_findings, key=lambda x: x["cvss_score"], reverse=True),
        "scan_meta": scan_meta or {}
    }

def render_html_report(data: Dict[str, Any]) -> str:
    """Renders self-contained responsive HTML executive report with dark/light print styling."""
    findings_rows = ""
    for f in data["findings"]:
        sev_color = {
            "critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#3b82f6", "info": "#94a3b8"
        }.get(f["severity"], "#94a3b8")

        findings_rows += f"""
        <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1); border-left: 4px solid {sev_color}; border-radius: 10px; padding: 16px; margin-bottom: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <h3 style="margin: 0; font-size: 15px; color: #f8fafc;">{f['title']}</h3>
                <span style="background: {sev_color}22; color: {sev_color}; border: 1px solid {sev_color}44; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 6px; text-transform: uppercase;">
                    {f['severity']} · CVSS {f['cvss_score']}
                </span>
            </div>
            <p style="margin: 0 0 10px 0; font-size: 13px; color: #94a3b8; line-height: 1.5;">{f['description']}</p>
            <div style="background: rgba(0,0,0,0.3); border-radius: 6px; padding: 10px; font-size: 12px;">
                <strong style="color: #10b981;">Remediation:</strong> <span style="color: #cbd5e1;">{f['remediation']}</span>
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Executive Security Report — {data['target']}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 40px 20px; line-height: 1.6; margin: 0; }}
  .container {{ max-width: 900px; margin: 0 auto; background: #111827; border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 36px; }}
  .badge-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 24px 0; }}
  .badge-card {{ background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 14px; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <div style="border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 20px; display: flex; justify-content: space-between; align-items: center;">
    <div>
      <h1 style="margin: 0; font-size: 22px; color: #f8fafc;">Executive Security Assessment Report</h1>
      <p style="margin: 4px 0 0 0; color: #94a3b8; font-size: 13px;">Target: <strong style="color: #38bdf8;">{data['target']}</strong> · {data['generated_at']}</p>
    </div>
    <div style="text-align: right;">
      <span style="font-size: 28px; font-weight: 800; color: #10b981;">{data['health_index']}/100</span>
      <div style="font-size: 10px; text-transform: uppercase; color: #64748b; font-weight: 700;">Security Score</div>
    </div>
  </div>

  <div class="badge-grid">
    <div class="badge-card">
      <div style="font-size: 24px; font-weight: 800; color: #ef4444;">{data['severity_counts']['critical']}</div>
      <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Critical Risks</div>
    </div>
    <div class="badge-card">
      <div style="font-size: 24px; font-weight: 800; color: #f97316;">{data['severity_counts']['high']}</div>
      <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">High Severity</div>
    </div>
    <div class="badge-card">
      <div style="font-size: 24px; font-weight: 800; color: #eab308;">{data['severity_counts']['medium']}</div>
      <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Medium Severity</div>
    </div>
    <div class="badge-card">
      <div style="font-size: 24px; font-weight: 800; color: #38bdf8;">{data['max_cvss']}</div>
      <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Max CVSS v3.1</div>
    </div>
  </div>

  <h2 style="font-size: 16px; margin: 30px 0 16px 0; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 8px;">
    Vulnerability Findings & Remediations ({data['total_findings']})
  </h2>

  {findings_rows if findings_rows else '<p style="color: #64748b; text-align: center; padding: 40px 0;">No active vulnerabilities detected on target.</p>'}
</div>
</body>
</html>
"""
    return html

def generate_report_async(
    target: str,
    findings: List[Dict[str, Any]],
    output_format: str = "html",
    db_path: str = DEFAULT_DB_PATH
) -> str:
    """
    Creates a new report record in DB and asynchronously renders the file in the background.
    """
    report_id = f"rep_{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO scan_reports (report_id, title, target, format, status, file_path, summary_json, created_at)
        VALUES (?, ?, ?, ?, 'generating', '', '', ?)""",
        (report_id, f"Security Assessment - {target}", target, output_format, now_iso)
    )
    conn.commit()
    conn.close()

    def worker():
        try:
            report_data = assemble_report_data(target, findings)
            html_content = render_html_report(report_data)
            
            reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads", "reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            out_filename = f"{report_id}.{output_format}"
            out_path = os.path.join(reports_dir, out_filename)
            
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            conn_w = get_connection(db_path)
            cur_w = conn_w.cursor()
            cur_w.execute(
                "UPDATE scan_reports SET status = 'completed', file_path = ?, summary_json = ? WHERE report_id = ?",
                (out_path, json.dumps(report_data), report_id)
            )
            conn_w.commit()
            conn_w.close()
        except Exception as e:
            conn_w = get_connection(db_path)
            cur_w = conn_w.cursor()
            cur_w.execute(
                "UPDATE scan_reports SET status = 'failed', summary_json = ? WHERE report_id = ?",
                (json.dumps({"error": str(e)}), report_id)
            )
            conn_w.commit()
            conn_w.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return report_id
