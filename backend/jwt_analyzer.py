import base64
import json
import hmac
import hashlib
import math
from typing import Dict, Any, List, Tuple
from datetime import datetime

COMMON_SECRETS = [
    "secret", "admin", "password", "123456", "jwt", "key", "default",
    "development", "testing", "supersecret", "auth", "sentinel",
    "signature", "welcome", "root", "guest", "12345678", "qwerty",
    "user", "manager", "12345", "security", "master", "private"
]

def base64url_decode(payload: str) -> bytes:
    rem = len(payload) % 4
    if rem > 0:
        payload += "=" * (4 - rem)
    return base64.urlsafe_b64decode(payload)

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    entropy = 0.0
    for x in set(s):
        p_x = s.count(x) / len(s)
        entropy += - p_x * math.log2(p_x)
    return entropy

def verify_hmac_sha256(header_b64: str, payload_b64: str, signature_b64: str, secret: str) -> bool:
    try:
        msg = f"{header_b64}.{payload_b64}".encode("utf-8")
        key = secret.encode("utf-8")
        sig = hmac.new(key, msg, hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").replace("=", "")
        return hmac.compare_digest(signature_b64.replace("=", ""), expected_b64)
    except Exception:
        return False

def analyze_jwt(token: str, test_secret: str = None) -> Dict[str, Any]:
    findings = []
    decoded_header = {}
    decoded_payload = {}
    
    parts = token.strip().split(".")
    if len(parts) < 2 or len(parts) > 3:
        return {
            "decoded_header": {},
            "decoded_payload": {},
            "findings": [{
                "title": "Invalid JWT Structure",
                "description": "JWT must contain a header, payload, and signature separated by dots.",
                "severity": "CRITICAL",
                "category": "structure"
            }],
            "risk_score": 100
        }
    
    header_b64, payload_b64 = parts[0], parts[1]
    signature_b64 = parts[2] if len(parts) == 3 else ""
    
    # 1. Decode Header
    try:
        header_bytes = base64url_decode(header_b64)
        decoded_header = json.loads(header_bytes.decode("utf-8"))
    except Exception as e:
        findings.append({
            "title": "Malformed Header",
            "description": f"Failed to base64url decode or parse JWT Header JSON: {str(e)}",
            "severity": "CRITICAL",
            "category": "structure"
        })
        
    # 2. Decode Payload
    try:
        payload_bytes = base64url_decode(payload_b64)
        decoded_payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        findings.append({
            "title": "Malformed Payload",
            "description": f"Failed to base64url decode or parse JWT Payload JSON: {str(e)}",
            "severity": "CRITICAL",
            "category": "structure"
        })
        
    # If we couldn't decode header/payload, stop further checks
    if not decoded_header or not decoded_payload:
        return {
            "decoded_header": decoded_header,
            "decoded_payload": decoded_payload,
            "findings": findings,
            "risk_score": 100
        }
        
    # 3. Algorithm checks
    alg = decoded_header.get("alg", "").lower()
    
    if alg == "none":
        findings.append({
            "title": "None Algorithm Enabled",
            "description": "The token uses the 'none' algorithm which bypasses signature verification. An attacker can tamper with claims and signature.",
            "severity": "CRITICAL",
            "category": "alg"
        })
    elif alg.startswith("hs"):
        # Brute-force common secrets
        brute_forced = False
        for secret in COMMON_SECRETS:
            if verify_hmac_sha256(header_b64, payload_b64, signature_b64, secret):
                findings.append({
                    "title": "Weak Secret Key Detected",
                    "description": f"The symmetric secret was successfully brute-forced! Token was signed using a weak common secret: '{secret}'",
                    "severity": "CRITICAL",
                    "category": "signature"
                })
                brute_forced = True
                break
        
        # Test custom secret if provided
        if test_secret and not brute_forced:
            if verify_hmac_sha256(header_b64, payload_b64, signature_b64, test_secret):
                findings.append({
                    "title": "Signature Verified",
                    "description": "The signature was successfully verified using the provided test secret.",
                    "severity": "INFO",
                    "category": "signature"
                })
                
                # Check secret key entropy
                entropy = calculate_entropy(test_secret)
                if len(test_secret) < 16 or entropy < 3.5:
                    findings.append({
                        "title": "Low Test Secret Entropy",
                        "description": f"The test secret has low entropy ({entropy:.2f} bits/char) or is too short ({len(test_secret)} chars), making it vulnerable to brute force.",
                        "severity": "MEDIUM",
                        "category": "entropy"
                    })
            else:
                findings.append({
                    "title": "Signature Mismatch",
                    "description": "The signature does not match the provided test secret.",
                    "severity": "HIGH",
                    "category": "signature"
                })
                
        # Symmetric key confusion attack check (public key used as HMAC key)
        if test_secret and ("PUBLIC KEY" in test_secret or "CERTIFICATE" in test_secret):
            findings.append({
                "title": "Symmetric Key Confusion Plausible",
                "description": "The provided secret key appears to be a public key block. This indicates the server may be vulnerable to a key confusion attack, verifying a symmetric HS256 token using a public key.",
                "severity": "CRITICAL",
                "category": "alg"
            })
            
    elif alg.startswith("rs"):
        # Alert about asymmetric key confusion susceptibility
        findings.append({
            "title": "Asymmetric RS256 Key Confusion Threat",
            "description": "An asymmetric algorithm (RS256) is used. Verify that your backend explicitly checks for alg='RS256' to prevent attackers from signing token with HS256 using the RSA public key.",
            "severity": "MEDIUM",
            "category": "alg"
        })
        
    # 4. Expiry validations
    exp = decoded_payload.get("exp")
    iat = decoded_payload.get("iat")
    
    if exp is None:
        findings.append({
            "title": "No Expiration Date",
            "description": "The token does not specify an 'exp' (expiration time) claim. It can be used indefinitely if intercepted.",
            "severity": "HIGH",
            "category": "expiry"
        })
    else:
        # Check if expired
        try:
            now_ts = datetime.utcnow().timestamp()
            if exp < now_ts:
                findings.append({
                    "title": "Token Expired",
                    "description": f"The token expired at {datetime.utcfromtimestamp(exp).isoformat()} UTC.",
                    "severity": "HIGH",
                    "category": "expiry"
                })
            
            # Check excessively long expiry (> 24 hours)
            if iat is not None:
                duration_hrs = (exp - iat) / 3600
                if duration_hrs > 24:
                    findings.append({
                        "title": "Excessive Expiration Window",
                        "description": f"The token expiration window is {duration_hrs:.1f} hours, which exceeds the recommended 24-hour limit for access tokens.",
                        "severity": "MEDIUM",
                        "category": "expiry"
                    })
            else:
                # If iat is missing but exp is far in the future
                if (exp - now_ts) / 3600 > 24:
                    findings.append({
                        "title": "Excessive Expiration Window (Estimated)",
                        "description": "The token expires more than 24 hours from the current time.",
                        "severity": "MEDIUM",
                        "category": "expiry"
                    })
        except Exception:
            pass

    # 5. Missing standard claims
    for claim in ["iat", "sub", "aud"]:
        if claim not in decoded_payload:
            findings.append({
                "title": f"Missing Standard Claim: {claim}",
                "description": f"The standard claim '{claim}' is missing from the payload. Adding it aids context and replay defense.",
                "severity": "LOW",
                "category": "claims"
            })
            
    # Calculate Risk Score
    risk_score = 0
    severity_weights = {
        "CRITICAL": 50,
        "HIGH": 30,
        "MEDIUM": 15,
        "LOW": 5,
        "INFO": 0
    }
    
    # Cap score of each category to avoid inflated scores
    category_risks = {}
    for f in findings:
        cat = f["category"]
        sev = f["severity"]
        weight = severity_weights.get(sev, 0)
        category_risks[cat] = max(category_risks.get(cat, 0), weight)
        
    risk_score = sum(category_risks.values())
    risk_score = min(risk_score, 100)
    
    return {
        "decoded_header": decoded_header,
        "decoded_payload": decoded_payload,
        "findings": findings,
        "risk_score": risk_score
    }
