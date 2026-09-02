from pydantic import BaseModel, Field
from typing import Literal, Optional, List, Dict, Any
from datetime import datetime

class Finding(BaseModel):
    id: str
    source: Literal["sast", "dast", "sca", "iac", "container", "cspm", "proxy", "exploit"]
    tool: str  # "semgrep", "zap", "grype", "checkov", "trivy", "prowler", "mitmproxy", "msfrpcd"
    repo_id: Optional[int] = None
    run_id: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    cwe: Optional[str] = None
    cve: Optional[str] = None
    title: str
    description: str
    file_path: Optional[str] = None
    line: Optional[int] = None
    endpoint: Optional[str] = None  # for DAST/proxy findings
    evidence: Optional[str] = None  # raw snippet/request-response, redacted of secrets
    remediation: Optional[str] = None
    status: Literal["open", "fixed", "false_positive", "accepted_risk"] = "open"
    created_at: Optional[str] = None

class RepoConfig(BaseModel):
    id: Optional[int] = None
    github_full_name: str  # e.g., "user/repo"
    default_branch: str = "main"
    install_token_ref: Optional[str] = None
    webhook_secret: Optional[str] = None
    local_path: Optional[str] = None
    last_synced_at: Optional[str] = None
    auto_pr_on_fix: bool = False

class SBOMComponent(BaseModel):
    id: Optional[int] = None
    run_id: str
    repo_id: Optional[int] = None
    name: str
    version: str
    ecosystem: str
    license: Optional[str] = None
    purl: Optional[str] = None

class ExploitAuditEntry(BaseModel):
    id: Optional[int] = None
    timestamp: str
    target_id: Optional[int] = None
    module_name: str
    finding_id: Optional[str] = None
    payload_summary: Optional[str] = None
    result: str
    operator: str = "system"

class PipelineStageStatus(BaseModel):
    name: str
    status: Literal["pending", "running", "passed", "failed", "skipped"]
    duration_ms: Optional[int] = None
    findings_count: int = 0
    error: Optional[str] = None

class PipelineRun(BaseModel):
    id: str
    repo_id: Optional[int] = None
    status: Literal["queued", "running", "completed", "failed"] = "queued"
    current_stage: Optional[str] = None
    stages: Dict[str, Any] = Field(default_factory=dict)
    summary: Dict[str, Any] = Field(default_factory=dict)
    sarif_path: Optional[str] = None
    markdown_report_path: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
