import json
from typing import List, Dict, Any
from backend.database import get_connection, DEFAULT_DB_PATH

DIAGNOSTIC_METADATA = {
    "BRUTE_FORCE": {
        "issue_name": "Automated Password Guessing Campaign",
        "default_severity": "HIGH",
        "description": "Multiple failed login attempts from a single source host targeted user accounts in a short duration.",
        "why_caused": "An external IP address is executing a brute-force attack using automated tools (like Hydra or password-spraying scripts) to guess user credentials.",
        "remediation": "Enforce IP rate limiting on login endpoints, trigger account lockouts after 5 consecutive failures, and enforce CAPTCHA after 3 failures."
    },
    "BRUTE_FORCE_STAT": {
        "issue_name": "Statistical Failed Login Anomaly",
        "default_severity": "HIGH",
        "description": "Failed authentication rates from a source host exceeded historical Poisson baseline expectations.",
        "why_caused": "Statistical analysis identified a spike in login failures. Even if below standard window thresholds, the probability of this occurring naturally is less than 1%.",
        "remediation": "Apply temporary IP blocklists on the host, audit target accounts for credential exposure, and check access logs for credential leakages."
    },
    "CREDENTIAL_STUFFING": {
        "issue_name": "Credential Stuffing Attack",
        "default_severity": "HIGH",
        "description": "A single source IP attempted to log in using multiple distinct usernames in a short window.",
        "why_caused": "This is caused by attackers using automated credential-stuffing tools to test lists of leaked account credentials against your system.",
        "remediation": "Deploy Multi-Factor Authentication (MFA), check inputs against databases of known leaked passwords (e.g. HaveIBeenPwned), and block the offending IP address."
    },
    "IMPOSSIBLE_TRAVEL": {
        "issue_name": "Geographic Velocity Anomaly (Possible Compromise)",
        "default_severity": "HIGH",
        "description": "Successful logins for a user account occurred at distances physically impossible to travel in the elapsed timeframe.",
        "why_caused": "This is caused by credential sharing or an active session takeover where an attacker uses stolen session cookies or credentials from a separate network region.",
        "remediation": "Immediately terminate all active sessions for the affected user, force a password change, and prompt the user to re-authorize their device."
    },
    "CLEAR_CREDENTIALS": {
        "issue_name": "Plaintext Credential Transit Exposure",
        "default_severity": "CRITICAL",
        "description": "Authentication secrets (HTTP Basic auth, FTP commands, Bearer JWTs) were detected in transit in unencrypted cleartext.",
        "why_caused": "This is caused by misconfigured services transmitting credentials over unencrypted protocols (HTTP instead of HTTPS, FTP instead of SFTP).",
        "remediation": "Enforce HTTPS (TLS) globally, disable basic auth over unencrypted HTTP, and decommission insecure legacy protocols like FTP."
    },
    "PORT_SCAN": {
        "issue_name": "Network Port Scanning & Reconnaissance",
        "default_severity": "MEDIUM",
        "description": "A remote host scanned multiple destination ports in a short window.",
        "why_caused": "This is caused by network scanners (such as Nmap) probing active services on your host to discover active entry points and vulnerabilities.",
        "remediation": "Configure firewall policies to drop unsolicited scanning packets, block IPs displaying scan behavior via Fail2Ban, and close unused open ports."
    },
    "DNS_TUNNEL": {
        "issue_name": "DNS Tunneling Covert Channel",
        "default_severity": "HIGH",
        "description": "DNS requests with long subdomain labels and high Shannon entropy were detected.",
        "why_caused": "This is caused by malicious payloads using DNS queries as a covert transmission channel to bypass standard firewall inspection and exfiltrate data.",
        "remediation": "Deploy DNS security filters (DNSSEC / DNS Firewalls) to block high-entropy subdomains, and monitor DNS lookup traffic volume per host."
    },
    "ARP_SPOOFING": {
        "issue_name": "ARP Cache Poisoning (Man-in-the-Middle)",
        "default_severity": "HIGH",
        "description": "A single IP address mapped to multiple hardware MAC addresses in the network capture.",
        "why_caused": "This is caused by an attacker sending forged ARP responses onto the local subnet to route transit traffic through their adapter to sniff it.",
        "remediation": "Enable Dynamic ARP Inspection (DAI) on local switches, configure static ARP bindings for critical gateways, and enforce TLS/SSH."
    },
    "BEACONING": {
        "issue_name": "Command & Control (C2) Beaconing heartbeat",
        "default_severity": "HIGH",
        "description": "A host is contacting a remote external endpoint at highly regular, low-variance intervals.",
        "why_caused": "This is caused by malware or a compromised agent contacting its C2 server at regular heartbeat intervals to check for task execution.",
        "remediation": "Immediately isolate the compromised host from the network, run a complete malware scan, and block the remote C2 IP on firewalls."
    },
    "OFF_HOURS_ACCESS": {
        "issue_name": "Anomaly: Off-Hours Session Activity",
        "default_severity": "MEDIUM",
        "description": "A user accessed secure endpoints during non-work hours, deviating from their historical activity profile.",
        "why_caused": "This is caused by employees working late shifts, or an attacker exploiting compromised credentials at times when security teams are less active.",
        "remediation": "Verify the activity with the user, enforce context-based conditional access controls, and monitor subsequent session actions."
    }
}

def generate_diagnostics(db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    # Get all active alerts
    cursor.execute(
        "SELECT id, rule_triggered, severity, source_ip, explanation, created_at FROM alerts WHERE status = 'open'"
    )
    rows = cursor.fetchall()
    conn.close()
    
    # Group alerts by rule_triggered
    grouped_alerts = {}
    for r in rows:
        alert = dict(r)
        rule = alert["rule_triggered"]
        if rule not in grouped_alerts:
            grouped_alerts[rule] = []
        grouped_alerts[rule].append(alert)
        
    diagnostics = []
    for rule, alerts in grouped_alerts.items():
        metadata = DIAGNOSTIC_METADATA.get(rule, {
            "issue_name": f"Security Alert: {rule}",
            "default_severity": "MEDIUM",
            "description": "A security rule has been triggered indicating anomalous behavior.",
            "why_caused": "This issue is caused by events matching your custom security alerting criteria.",
            "remediation": "Audit the logs and verify the legitimacy of the activity."
        })
        
        # Collect affected entities
        affected_ips = list(set([a["source_ip"] for a in alerts if a["source_ip"]]))
        affected_count = len(alerts)
        
        # Max severity among group
        severities = [a["severity"] for a in alerts]
        max_severity = metadata["default_severity"]
        if "CRITICAL" in severities:
            max_severity = "CRITICAL"
        elif "HIGH" in severities:
            max_severity = "HIGH"
        elif "MEDIUM" in severities:
            max_severity = "MEDIUM"
            
        diagnostics.append({
            "rule": rule,
            "issue_name": metadata["issue_name"],
            "severity": max_severity,
            "description": metadata["description"],
            "why_caused": metadata["why_caused"],
            "remediation": metadata["remediation"],
            "affected_ips": affected_ips,
            "alerts_count": affected_count,
            "latest_trigger": max([a["created_at"] for a in alerts]) if alerts else None
        })
        
    # Sort diagnostics: Critical first, then High, then Medium
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    diagnostics.sort(key=lambda d: (severity_order.get(d["severity"], 4), d["issue_name"]))
    
    return diagnostics
