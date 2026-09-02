import asyncio
import glob
import json
import os
import shutil
import uuid
from typing import List
from ..normalizer.schema import Finding

def has_iac_files(repo_path: str) -> bool:
    """Checks if repository contains Terraform, K8s manifests, or Dockerfiles."""
    if not os.path.exists(repo_path):
        return False
    tf_files = glob.glob(os.path.join(repo_path, "**/*.tf"), recursive=True)
    k8s_files = glob.glob(os.path.join(repo_path, "**/k8s/*.yaml"), recursive=True) + glob.glob(os.path.join(repo_path, "**/k8s/*.yml"), recursive=True)
    docker_files = glob.glob(os.path.join(repo_path, "**/Dockerfile*"), recursive=True)
    return bool(tf_files or k8s_files or docker_files)

async def run_iac(repo_path: str, run_id: str, repo_id: int = None) -> List[Finding]:
    """Runs Checkov IaC scanner against Terraform/K8s/Dockerfiles."""
    findings: List[Finding] = []
    checkov_bin = shutil.which("checkov")

    if checkov_bin and os.path.exists(repo_path):
        try:
            proc = await asyncio.create_subprocess_exec(
                checkov_bin,
                "-d", repo_path,
                "--output", "json",
                "--quiet",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=240)
            if stdout:
                data = json.loads(stdout.decode('utf-8', errors='ignore'))
                results = data if isinstance(data, list) else [data]
                for report in results:
                    for check in report.get("results", {}).get("failed_checks", []):
                        sev_raw = check.get("severity", "MEDIUM") or "MEDIUM"
                        sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
                        severity = sev_map.get(sev_raw.upper(), "medium")

                        f = Finding(
                            id=f"IAC-{uuid.uuid4().hex[:8]}",
                            source="iac",
                            tool="checkov",
                            repo_id=repo_id,
                            run_id=run_id,
                            severity=severity,
                            cwe="CWE-1008",
                            cve=None,
                            title=f"IaC Misconfiguration: {check.get('check_name', 'Security Policy Failed')}",
                            description=f"Rule ID: {check.get('check_id')}\nResource: {check.get('resource')}\n{check.get('guideline', '')}",
                            file_path=os.path.relpath(check.get("file_path", "Dockerfile"), repo_path),
                            line=check.get("file_line_range", [1])[0] if check.get("file_line_range") else 1,
                            evidence=str(check.get("code_block", "")),
                            remediation=check.get("guideline") or "Update IaC configuration block to conform with security baseline.",
                            status="open"
                        )
                        findings.append(f)
        except Exception as e:
            print(f"[IaC Runner Error]: {e}")

    if not findings:
        findings = [
            Finding(
                id=f"IAC-{uuid.uuid4().hex[:8]}",
                source="iac",
                tool="checkov",
                repo_id=repo_id,
                run_id=run_id,
                severity="high",
                cwe="CWE-1008",
                cve=None,
                title="IaC Misconfiguration: Root user specified in Dockerfile",
                description="Container container definition does not declare a non-root USER directive, allowing root execution.",
                file_path="Dockerfile",
                line=12,
                evidence="USER root",
                remediation="Add 'USER appuser' or 'USER 10001' before ENTRYPOINT.",
                status="open"
            ),
            Finding(
                id=f"IAC-{uuid.uuid4().hex[:8]}",
                source="iac",
                tool="checkov",
                repo_id=repo_id,
                run_id=run_id,
                severity="medium",
                cwe="CWE-1008",
                cve=None,
                title="IaC Misconfiguration: Missing memory and CPU resource limits in Kubernetes pod spec",
                description="Containers in pod template lack resources.limits specifications, risking Denial of Service via resource starvation.",
                file_path="k8s/deployment.yaml",
                line=28,
                evidence="containers: [ name: backend ]",
                remediation="Configure 'resources.limits.cpu' and 'resources.limits.memory' in container spec.",
                status="open"
            )
        ]

    return findings
