"""
Module 3 — Interactive HTTP Repeater (Burp-style)
Accepts raw editable request specs, replays exact headers/body without modification,
enforces SSRF protection against RFC1918 / Cloud Metadata IPs, and caps response streams.
"""

import time
import socket
import ipaddress
import urllib.parse
import urllib.request
import urllib.error
import ssl
from typing import Dict, List, Any, Optional, Tuple

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"), # Link-local / AWS/GCP Metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def check_ssrf_risk(url: str) -> Tuple[bool, str, List[str]]:
    """
    Evaluates whether the destination URL resolves to a private/internal RFC1918 or Cloud Metadata IP.
    Returns (is_private_risk, warning_message, resolved_ips).
    """
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        hostname = parsed.hostname
        if not hostname:
            return True, "Invalid URL hostname", []
        
        # Check cloud metadata hostnames directly
        if hostname.lower() in ["metadata.google.internal", "instance-data", "169.254.169.254"]:
            return True, "Target resolves directly to Cloud Instance Metadata Service (SSRF Risk)", ["169.254.169.254"]

        # Resolve DNS
        resolved_ips = []
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                ip_str = item[4][0]
                if ip_str not in resolved_ips:
                    resolved_ips.append(ip_str)
        except socket.gaierror:
            return False, "Host DNS could not be resolved", []

        for ip_s in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_s)
                for priv_net in PRIVATE_NETWORKS:
                    if ip_obj in priv_net:
                        return True, f"Target resolves to Private Internal Network IP ({ip_s}) - RFC1918/Metadata Guard", resolved_ips
            except ValueError:
                continue

        return False, "Target is on public routable internet", resolved_ips
    except Exception as e:
        return True, f"SSRF validation error: {str(e)}", []

def replay_raw_http_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    allow_private_network: bool = False,
    timeout_seconds: float = 10.0,
    max_response_bytes: int = 524288 # 512 KB preview cap
) -> Dict[str, Any]:
    """
    Replays exact HTTP request spec without silent header modification, returning full response and timing.
    """
    method = method.upper().strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    # SSRF Validation Check
    is_private, warning_msg, resolved_ips = check_ssrf_risk(url)
    if is_private and not allow_private_network:
        return {
            "status": "blocked_ssrf",
            "url": url,
            "resolved_ips": resolved_ips,
            "error": warning_msg,
            "requires_confirmation": True,
            "response_status": None,
            "response_headers": {},
            "response_body": None,
            "duration_ms": 0
        }

    start_time = time.time()
    headers_dict = dict(headers or {})
    
    # Encode body
    data_bytes = body.encode('utf-8') if body else None

    # Custom SSL Context allowing self-signed endpoints for testing
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, data=data_bytes, headers=headers_dict, method=method)
    
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds, context=ctx) as response:
            duration_ms = round((time.time() - start_time) * 1000, 2)
            resp_headers = dict(response.getheaders())
            status_code = response.status
            
            # Read capped response stream
            raw_content = response.read(max_response_bytes + 1)
            is_truncated = len(raw_content) > max_response_bytes
            preview_bytes = raw_content[:max_response_bytes]
            
            try:
                body_text = preview_bytes.decode('utf-8', errors='replace')
            except Exception:
                body_text = f"[Binary payload: {len(preview_bytes)} bytes]"

            return {
                "status": "success",
                "url": url,
                "resolved_ips": resolved_ips,
                "response_status": status_code,
                "response_headers": resp_headers,
                "response_body": body_text,
                "body_bytes_count": len(preview_bytes),
                "is_truncated": is_truncated,
                "duration_ms": duration_ms,
                "is_private_target": is_private,
                "warning": warning_msg if is_private else None
            }
    except urllib.error.HTTPError as e:
        duration_ms = round((time.time() - start_time) * 1000, 2)
        resp_headers = dict(e.headers) if hasattr(e, 'headers') else {}
        try:
            body_text = e.read(max_response_bytes).decode('utf-8', errors='replace')
        except Exception:
            body_text = "[Error response body unreadable]"
            
        return {
            "status": "http_error",
            "url": url,
            "resolved_ips": resolved_ips,
            "response_status": e.code,
            "response_headers": resp_headers,
            "response_body": body_text,
            "duration_ms": duration_ms,
            "is_private_target": is_private,
            "error": f"HTTP {e.code}: {e.reason}"
        }
    except Exception as e:
        duration_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "status": "network_error",
            "url": url,
            "resolved_ips": resolved_ips,
            "response_status": None,
            "response_headers": {},
            "response_body": None,
            "duration_ms": duration_ms,
            "is_private_target": is_private,
            "error": str(e)
        }
