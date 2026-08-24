"""
Module 1 — SSL/TLS Security & Cipher Suite Auditor
Deterministic A+ through F HTTPS grading rubric inspired by SSL Labs methodology.
Utilizes native Python ssl and cryptography for high-speed non-blocking concurrent probes.
"""

import ssl
import socket
import urllib.parse
import time
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

# Deprecated/Weak cipher and protocol definitions
WEAK_CIPHERS = ["RC4", "3DES", "DES", "NULL", "EXP", "EXPORT", "MD5", "CBC", "IDEA", "SEED"]
INSECURE_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]

def parse_target_host_port(target: str) -> Tuple[str, int]:
    """Extract clean hostname and port from a target URL or host:port string."""
    target = target.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
    
    parsed = urllib.parse.urlparse(target)
    hostname = parsed.hostname or target.split(":")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return hostname, port

def probe_tls_protocol(hostname: str, port: int, protocol_version: ssl.TLSVersion) -> Dict[str, Any]:
    """
    Probes whether a target supports a specific TLS protocol version.
    Handles connection resets / anti-scan defense gracefully.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        ctx.minimum_version = protocol_version
        ctx.maximum_version = protocol_version
    except (ValueError, AttributeError):
        return {"supported": False, "error": "Protocol version not supported by local OpenSSL build"}

    try:
        with socket.create_connection((hostname, port), timeout=3.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                negotiated_version = ssock.version()
                cipher_name, proto_ver, secret_bits = ssock.cipher()
                return {
                    "supported": True,
                    "version": negotiated_version,
                    "cipher": cipher_name,
                    "bits": secret_bits,
                    "anti_scan_reset": False
                }
    except ssl.SSLError as e:
        err_msg = str(e).lower()
        if "handshake failure" in err_msg or "protocol version" in err_msg or "wrong version" in err_msg:
            return {"supported": False, "reason": "Protocol rejected by server", "anti_scan_reset": False}
        return {"supported": False, "reason": str(e), "anti_scan_reset": False}
    except (ConnectionResetError, ConnectionAbortedError, socket.timeout):
        # Anti-scan defense detection: connection was forcefully reset or timed out
        return {"supported": False, "reason": "Connection reset by peer (possible anti-scan defense)", "anti_scan_reset": True}
    except Exception as e:
        return {"supported": False, "reason": str(e), "anti_scan_reset": False}

def inspect_certificate_and_ciphers(hostname: str, port: int) -> Dict[str, Any]:
    """
    Connects to the server, extracts the X.509 certificate chain, key sizes, signatures, and cipher info.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    cert_info: Dict[str, Any] = {
        "valid": False,
        "subject": "",
        "issuer": "",
        "san": [],
        "signature_algorithm": "",
        "key_type": "",
        "key_size": 0,
        "is_expired": False,
        "is_self_signed": False,
        "hostname_mismatch": False,
        "days_remaining": 0,
        "chain_length": 0,
        "negotiated_cipher": "",
        "negotiated_protocol": "",
        "cipher_bits": 0,
        "issues": []
    }

    try:
        with socket.create_connection((hostname, port), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cipher_name, proto_ver, bits = ssock.cipher()
                cert_info["negotiated_cipher"] = cipher_name
                cert_info["negotiated_protocol"] = proto_ver
                cert_info["cipher_bits"] = bits
                
                if der_cert:
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    
                    # Subject & Issuer
                    cert_info["subject"] = cert.subject.rfc4514_string()
                    cert_info["issuer"] = cert.issuer.rfc4514_string()
                    
                    # Self-signed check
                    if cert.subject == cert.issuer:
                        cert_info["is_self_signed"] = True
                        cert_info["issues"].append("Certificate is self-signed (untrusted CA)")
                    
                    # Validity
                    now = datetime.now(timezone.utc)
                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc
                    
                    if now < not_before:
                        cert_info["issues"].append("Certificate is not yet valid")
                    elif now > not_after:
                        cert_info["is_expired"] = True
                        cert_info["issues"].append("Certificate is EXPIRED")
                    else:
                        cert_info["days_remaining"] = (not_after - now).days
                        if cert_info["days_remaining"] < 15:
                            cert_info["issues"].append(f"Certificate expires soon ({cert_info['days_remaining']} days left)")
                    
                    # Public Key details
                    pub_key = cert.public_key()
                    if isinstance(pub_key, rsa.RSAPublicKey):
                        cert_info["key_type"] = "RSA"
                        cert_info["key_size"] = pub_key.key_size
                        if pub_key.key_size < 2048:
                            cert_info["issues"].append(f"Weak RSA key size: {pub_key.key_size} bits (minimum recommended is 2048)")
                    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                        cert_info["key_type"] = "ECC"
                        cert_info["key_size"] = pub_key.key_size
                        if pub_key.key_size < 256:
                            cert_info["issues"].append(f"Weak ECC key size: {pub_key.key_size} bits (minimum recommended is 256)")
                    else:
                        cert_info["key_type"] = "Unknown"
                        cert_info["key_size"] = getattr(pub_key, 'key_size', 0)
                        
                    # Signature Algorithm
                    sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
                    cert_info["signature_algorithm"] = sig_alg
                    if sig_alg.lower() in ["sha1", "md5", "md2"]:
                        cert_info["issues"].append(f"Insecure certificate signature algorithm: {sig_alg.upper()}")
                        
                    # SAN check & Hostname Match
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        sans = san_ext.value.get_values_for_type(x509.DNSName)
                        cert_info["san"] = sans
                        
                        # Match verification
                        matched = False
                        host_lower = hostname.lower()
                        for s in sans:
                            s_lower = s.lower()
                            if s_lower == host_lower:
                                matched = True
                                break
                            if s_lower.startswith("*."):
                                domain_suffix = s_lower[2:]
                                if host_lower.endswith("." + domain_suffix) or host_lower == domain_suffix:
                                    matched = True
                                    break
                        if not matched and sans:
                            cert_info["hostname_mismatch"] = True
                            cert_info["issues"].append(f"Hostname mismatch: '{hostname}' does not match SANs {sans[:3]}")
                    except Exception:
                        pass
                    
                    cert_info["valid"] = len(cert_info["issues"]) == 0
    except Exception as e:
        cert_info["issues"].append(f"TLS connection failure: {str(e)}")
        
    return cert_info

def check_hsts_header(hostname: str, port: int) -> Dict[str, Any]:
    """
    Inspects HTTP response headers on HTTPS for Strict-Transport-Security (HSTS).
    """
    import http.client
    hsts_info = {
        "present": False,
        "max_age": 0,
        "include_subdomains": False,
        "preload": False,
        "raw_header": None,
        "issues": []
    }
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        conn = http.client.HTTPSConnection(hostname, port, timeout=4.0, context=ctx)
        conn.request("GET", "/", headers={"User-Agent": "Sentinel-SSLAuditor/1.0", "Host": hostname})
        res = conn.getresponse()
        
        for header, val in res.getheaders():
            if header.lower() == "strict-transport-security":
                hsts_info["present"] = True
                hsts_info["raw_header"] = val
                
                # Parse directives
                parts = [p.strip() for p in val.split(";")]
                for p in parts:
                    if p.lower().startswith("max-age="):
                        try:
                            hsts_info["max_age"] = int(p.split("=")[1])
                        except ValueError:
                            pass
                    elif p.lower() == "includesubdomains":
                        hsts_info["include_subdomains"] = True
                    elif p.lower() == "preload":
                        hsts_info["preload"] = True
                break
        conn.close()
    except Exception as e:
        hsts_info["issues"].append(f"Could not check HSTS: {str(e)}")

    if not hsts_info["present"]:
        hsts_info["issues"].append("Missing HTTP Strict-Transport-Security (HSTS) header")
    else:
        if hsts_info["max_age"] < 15768000: # < 6 months
            hsts_info["issues"].append(f"HSTS max-age too short ({hsts_info['max_age']}s; recommended is at least 15768000s / 6 months)")
        if not hsts_info["include_subdomains"]:
            hsts_info["issues"].append("HSTS does not include 'includeSubDomains'")
            
    return hsts_info

def compute_ssl_grade(
    protocols: Dict[str, Any],
    cert_info: Dict[str, Any],
    hsts_info: Dict[str, Any]
) -> Tuple[str, int, List[str], List[Dict[str, Any]]]:
    """
    Computes deterministic SSL grade (A+, A, B, C, D, F) and score (0-100) based on SSL Labs methodology.
    """
    score = 100
    grade = "A"
    reasons = []
    findings = []
    
    # 1. Protocol Support Evaluation
    has_tls13 = protocols.get("TLSv1.3", {}).get("supported", False)
    has_tls12 = protocols.get("TLSv1.2", {}).get("supported", False)
    has_tls11 = protocols.get("TLSv1.1", {}).get("supported", False)
    has_tls10 = protocols.get("TLSv1.0", {}).get("supported", False)
    has_sslv3 = protocols.get("SSLv3", {}).get("supported", False)
    has_sslv2 = protocols.get("SSLv2", {}).get("supported", False)
    
    if has_sslv2 or has_sslv3:
        score = min(score, 30)
        grade = "F"
        reasons.append("Insecure SSLv2/SSLv3 enabled (Vulnerable to POODLE/DROWN)")
        findings.append({
            "title": "Legacy Insecure Protocol Enabled (SSLv2/SSLv3)",
            "severity": "critical",
            "cvss_score": 9.1,
            "cwe": "CWE-326",
            "description": "The server supports obsolete SSLv2 or SSLv3 protocols which have known critical cryptographic breaks."
        })
        
    if has_tls10 or has_tls11:
        score = min(score, 70)
        if grade in ["A+", "A"]:
            grade = "B"
        reasons.append("Deprecated TLS 1.0 or TLS 1.1 enabled (RFC 8996 deprecated)")
        findings.append({
            "title": "Deprecated TLS 1.0/1.1 Protocol Supported",
            "severity": "medium",
            "cvss_score": 5.3,
            "cwe": "CWE-326",
            "description": "TLS 1.0 and TLS 1.1 lack modern cipher suites and are officially deprecated."
        })

    if not has_tls12 and not has_tls13 and (has_tls10 or has_tls11):
        score = min(score, 50)
        grade = "C"
        reasons.append("Server lacks modern TLS 1.2 or TLS 1.3 support")

    # 2. Certificate Evaluation
    if cert_info.get("is_expired", False):
        score = min(score, 40)
        grade = "F"
        reasons.append("SSL/TLS Certificate is EXPIRED")
        findings.append({
            "title": "Expired SSL/TLS Certificate",
            "severity": "high",
            "cvss_score": 7.5,
            "cwe": "CWE-295",
            "description": "The target certificate has passed its validity expiration date, resulting in browser warnings and MITM exposure."
        })
        
    if cert_info.get("is_self_signed", False):
        score = min(score, 50)
        if grade in ["A+", "A", "B"]:
            grade = "C"
        reasons.append("Self-signed / Untrusted CA certificate")
        findings.append({
            "title": "Self-Signed or Untrusted SSL Certificate",
            "severity": "medium",
            "cvss_score": 6.5,
            "cwe": "CWE-295",
            "description": "Certificate is not signed by a recognized Certificate Authority (CA)."
        })
        
    if cert_info.get("hostname_mismatch", False):
        score = min(score, 50)
        if grade in ["A+", "A", "B"]:
            grade = "C"
        reasons.append("Certificate Subject Alternative Name (SAN) mismatch")
        findings.append({
            "title": "SSL Certificate Name Mismatch",
            "severity": "medium",
            "cvss_score": 5.9,
            "cwe": "CWE-297",
            "description": "The certificate domain does not match the requested hostname."
        })
        
    if cert_info.get("key_size", 0) < 2048 and cert_info.get("key_type") == "RSA":
        score = min(score, 45)
        grade = "D"
        reasons.append(f"Weak RSA key size ({cert_info.get('key_size')} bits)")
        findings.append({
            "title": "Weak RSA Key Length (< 2048 bits)",
            "severity": "high",
            "cvss_score": 7.4,
            "cwe": "CWE-326",
            "description": "RSA key length is below the industry standard minimum of 2048 bits."
        })
        
    if cert_info.get("signature_algorithm", "").lower() in ["sha1", "md5"]:
        score = min(score, 40)
        grade = "D"
        reasons.append("Insecure certificate signature algorithm (SHA-1/MD5)")
        findings.append({
            "title": "Insecure Certificate Signature Hash",
            "severity": "high",
            "cvss_score": 7.1,
            "cwe": "CWE-328",
            "description": "The certificate was signed using a collision-vulnerable hash algorithm."
        })

    # 3. Cipher Suite Evaluation
    negotiated_cipher = cert_info.get("negotiated_cipher", "").upper()
    for weak_c in WEAK_CIPHERS:
        if weak_c in negotiated_cipher:
            score = min(score, 50)
            if grade in ["A+", "A", "B"]:
                grade = "C"
            reasons.append(f"Weak cipher suite in use: {negotiated_cipher}")
            findings.append({
                "title": f"Weak Cipher Suite Negotiated ({weak_c})",
                "severity": "high",
                "cvss_score": 7.5,
                "cwe": "CWE-326",
                "description": f"The connection negotiated a weak cipher suite containing {weak_c}."
            })
            break

    # 4. HSTS Evaluation
    if not hsts_info.get("present", False):
        score = max(0, score - 10)
        if grade == "A+":
            grade = "A"
        reasons.append("Missing HSTS security header")
        findings.append({
            "title": "Missing HTTP Strict-Transport-Security (HSTS) Header",
            "severity": "low",
            "cvss_score": 3.7,
            "cwe": "CWE-319",
            "description": "HSTS is not enforced, leaving users vulnerable to SSL-stripping attacks."
        })
    else:
        if grade == "A" and hsts_info.get("max_age", 0) >= 15768000 and hsts_info.get("include_subdomains", False) and hsts_info.get("preload", False):
            grade = "A+"
            reasons.append("Exceptional TLS configuration with robust HSTS preload enforcement")

    return grade, score, reasons, findings

def audit_ssl_target(target: str) -> Dict[str, Any]:
    """
    Complete audit entry point for Module 1.
    Performs concurrent non-blocking socket probes across protocols and evaluates certificates & HSTS.
    """
    start_time = time.time()
    hostname, port = parse_target_host_port(target)
    
    protocols_to_test = {
        "TLSv1.3": getattr(ssl.TLSVersion, "TLSv1_3", None),
        "TLSv1.2": getattr(ssl.TLSVersion, "TLSv1_2", None),
        "TLSv1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
        "TLSv1.0": getattr(ssl.TLSVersion, "TLSv1", None),
    }

    results_protocols = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_proto = {
            executor.submit(probe_tls_protocol, hostname, port, ver): name
            for name, ver in protocols_to_test.items() if ver is not None
        }
        for future in concurrent.futures.as_completed(future_to_proto):
            proto_name = future_to_proto[future]
            try:
                results_protocols[proto_name] = future.result()
            except Exception as e:
                results_protocols[proto_name] = {"supported": False, "error": str(e), "anti_scan_reset": False}

    cert_info = inspect_certificate_and_ciphers(hostname, port)
    hsts_info = check_hsts_header(hostname, port)
    grade, score, reasons, findings = compute_ssl_grade(results_protocols, cert_info, hsts_info)
    duration = round(time.time() - start_time, 2)
    
    return {
        "target": target,
        "hostname": hostname,
        "port": port,
        "grade": grade,
        "score": score,
        "reasons": reasons,
        "protocols": results_protocols,
        "certificate": cert_info,
        "hsts": hsts_info,
        "findings": findings,
        "duration_seconds": duration,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
