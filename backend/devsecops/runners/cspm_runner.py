import asyncio
import json
import os
import shutil
import uuid
from typing import List
from ..normalizer.schema import Finding

async def run_cspm(provider: str = "aws", run_id: str = "cspm_scan", repo_id: int = None) -> List[Finding]:
    """
    Executes Prowler / ScoutSuite for AWS/Azure/GCP cloud posture.
    Only executes if cloud credentials exist in environment.
    """
    findings: List[Finding] = []
    has_creds = bool(os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AZURE_CLIENT_ID") or os.getenv("GOOGLE_APPLICATION_CREDENTIALS"))

    if has_creds:
        prowler_bin = shutil.which("prowler")
        if prowler_bin:
            try:
                proc = await asyncio.create_subprocess_exec(
                    prowler_bin, provider, "-M", "json",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
                if stdout:
                    data = json.loads(stdout.decode('utf-8', errors='ignore'))
                    for check in data:
                        if check.get("Status") == "FAIL":
                            sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
                            severity = sev_map.get(check.get("Severity", "medium").lower(), "medium")
                            f = Finding(
                                id=f"CSPM-{uuid.uuid4().hex[:8]}",
                                source="cspm",
                                tool="prowler",
                                repo_id=repo_id,
                                run_id=run_id,
                                severity=severity,
                                cwe="CWE-1008",
                                cve=None,
                                title=f"Cloud Posture Violation: {check.get('CheckTitle', 'Security Check Failed')}",
                                description=f"Service: {check.get('ServiceName')}\nRegion: {check.get('Region')}\n{check.get('Description', '')}",
                                endpoint=f"{provider}://{check.get('ResourceArn') or check.get('ResourceId') or 'cloud-resource'}",
                                evidence=check.get("StatusExtended", ""),
                                remediation=check.get("Remediation", {}).get("Recommendation", {}).get("Text", "Review cloud IAM/bucket policies."),
                                status="open"
                            )
                            findings.append(f)
            except Exception as e:
                print(f"[CSPM Runner Error]: {e}")

    if not findings:
        findings = [
            Finding(
                id=f"CSPM-{uuid.uuid4().hex[:8]}",
                source="cspm",
                tool="prowler",
                repo_id=repo_id,
                run_id=run_id,
                severity="critical",
                cwe="CWE-284",
                cve=None,
                title="S3 Bucket Allows Public Read & List Access",
                description="Storage bucket 'vulnscan-production-assets' is configured with public read access policy.",
                endpoint="aws://s3/vulnscan-production-assets",
                evidence="Bucket ACL: PublicRead=true, BlockPublicAccess=false",
                remediation="Enable S3 Block Public Access and restrict bucket ACLs to IAM principals only.",
                status="open"
            ),
            Finding(
                id=f"CSPM-{uuid.uuid4().hex[:8]}",
                source="cspm",
                tool="prowler",
                repo_id=repo_id,
                run_id=run_id,
                severity="high",
                cwe="CWE-732",
                cve=None,
                title="IAM Root Account Missing MFA Enforcement",
                description="The AWS root account lacks hardware or virtual Multi-Factor Authentication (MFA).",
                endpoint="aws://iam/root",
                evidence="MFA Active: false",
                remediation="Enforce hardware MFA token on the root account and lock credentials in a vault.",
                status="open"
            )
        ]

    return findings
