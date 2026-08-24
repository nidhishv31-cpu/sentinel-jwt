"""
Comprehensive Unit & Integration Test Suite for Advanced Modules 1 - 9
Validates deterministic grading, rate limiting, SSRF guard, file carving,
GeoIP/ASN mapping, beaconing jitter statistics, CVSS 3.1 formula, and baseline diffing.
"""

import pytest
import asyncio
import time
from backend.ssl_auditor import compute_ssl_grade, parse_target_host_port
from backend.scanner_orchestrator import SCAN_PROFILES, TokenBucketRateLimiter
from backend.http_repeater import check_ssrf_risk, replay_raw_http_request
from backend.file_carver import carve_files_from_bytes, FILE_SIGNATURES
from backend.geo_asn_map import resolve_single_ip_geo, batch_aggregate_pcap_geo
from backend.beacon_detector import analyze_traffic_beaconing
from backend.report_generator import calculate_cvss31_score, assemble_report_data, render_html_report
from backend.baseline_diff import perform_baseline_diff, compute_finding_fingerprint

# ── MODULE 1: SSL/TLS AUDITOR TESTS ────────────────────────────────────────────

def test_compute_ssl_grade_a_plus():
    """Verify modern TLS with valid HSTS preload qualifies for A+ grade."""
    protocols = {
        "TLSv1.3": {"supported": True},
        "TLSv1.2": {"supported": True},
        "TLSv1.1": {"supported": False},
        "TLSv1.0": {"supported": False}
    }
    cert_info = {
        "valid": True,
        "is_expired": False,
        "is_self_signed": False,
        "hostname_mismatch": False,
        "key_type": "RSA",
        "key_size": 2048,
        "signature_algorithm": "sha256",
        "negotiated_cipher": "ECDHE-RSA-AES256-GCM-SHA384"
    }
    hsts_info = {
        "present": True,
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": True
    }
    grade, score, reasons, findings = compute_ssl_grade(protocols, cert_info, hsts_info)
    assert grade == "A+"
    assert score >= 90
    assert len(findings) == 0

def test_compute_ssl_grade_insecure_protocols():
    """Verify obsolete SSLv3 protocol support forces grade F."""
    protocols = {
        "TLSv1.3": {"supported": True},
        "SSLv3": {"supported": True}
    }
    cert_info = {"valid": True, "negotiated_cipher": "AES128-GCM"}
    hsts_info = {"present": True, "max_age": 15768000, "include_subdomains": True, "preload": True}
    grade, score, reasons, findings = compute_ssl_grade(protocols, cert_info, hsts_info)
    assert grade == "F"
    assert score <= 30
    assert any("SSLv2/SSLv3" in f["title"] for f in findings)

def test_compute_ssl_grade_expired_cert():
    """Verify expired certificate drops grade to F."""
    protocols = {"TLSv1.3": {"supported": True}, "TLSv1.2": {"supported": True}}
    cert_info = {"valid": False, "is_expired": True, "negotiated_cipher": "AES256-GCM"}
    hsts_info = {"present": False}
    grade, score, reasons, findings = compute_ssl_grade(protocols, cert_info, hsts_info)
    assert grade == "F"
    assert any("Expired" in f["title"] for f in findings)

def test_compute_ssl_grade_weak_ciphers():
    """Verify RC4/3DES ciphers downgrade grade to C."""
    protocols = {"TLSv1.2": {"supported": True}}
    cert_info = {"valid": True, "negotiated_cipher": "ECDHE-RSA-RC4-SHA"}
    hsts_info = {"present": True, "max_age": 15768000, "include_subdomains": True}
    grade, score, reasons, findings = compute_ssl_grade(protocols, cert_info, hsts_info)
    assert grade == "C"
    assert any("RC4" in f["title"] for f in findings)

# ── MODULE 2: RATE LIMITER & PROFILES TESTS ───────────────────────────────────

def test_declarative_profiles_structure():
    """Verify all 3 declarative profiles define required operational parameters."""
    for key in ["stealth", "owasp_fast", "deep_coverage"]:
        assert key in SCAN_PROFILES
        p = SCAN_PROFILES[key]
        assert p.concurrency >= 1
        assert p.rps_limit > 0
        assert p.timeout_seconds > 0
        assert len(p.modules) > 0

@pytest.mark.asyncio
async def test_token_bucket_rate_limiter_concurrency():
    """Verify TokenBucketRateLimiter correctly throttles high concurrency requests."""
    limiter = TokenBucketRateLimiter(rps=20.0, burst_capacity=5.0)
    start = time.monotonic()
    
    async def worker():
        await limiter.acquire()
        
    # Launch 10 concurrent requests
    await asyncio.gather(*[worker() for _ in range(10)])
    elapsed = time.monotonic() - start
    # Burst 5 tokens instantly, remaining 5 tokens take ~0.25s
    assert elapsed >= 0.15

# ── MODULE 3: HTTP REPEATER & SSRF TESTS ───────────────────────────────────────

def test_ssrf_risk_detection():
    """Verify private RFC1918, loopback, and Cloud Metadata IPs are blocked."""
    test_cases = [
        ("http://127.0.0.1:8000", True),
        ("http://localhost:3000", True),
        ("http://10.0.1.5", True),
        ("http://192.168.1.100", True),
        ("http://172.16.0.1", True),
        ("http://169.254.169.254/latest/meta-data", True),
        ("http://metadata.google.internal", True)
    ]
    for url, should_block in test_cases:
        is_priv, msg, _ = check_ssrf_risk(url)
        assert is_priv == should_block, f"Failed for {url}: {msg}"

def test_ssrf_public_domain_allowed():
    """Verify valid public targets pass SSRF check."""
    is_priv, _, _ = check_ssrf_risk("https://example.com")
    assert is_priv is False

# ── MODULE 4: FILE CARVER TESTS ────────────────────────────────────────────────

def test_carve_png_image():
    """Verify PNG header and footer extraction from stream."""
    png_bytes = b"RANDOM_TRAFFIC_DATA\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00IEND\xaeB`\x82TRAILING_BYTES"
    artifacts = carve_files_from_bytes(png_bytes, capture_id="test_cap", stream_id=1)
    assert len(artifacts) >= 1
    assert artifacts[0]["file_type"] == "PNG Image"
    assert artifacts[0]["mime_type"] == "image/png"
    assert artifacts[0]["is_truncated"] is False

def test_carve_pdf_document():
    """Verify PDF document extraction."""
    pdf_bytes = b"HEADER%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOFPOSTAMBLE"
    artifacts = carve_files_from_bytes(pdf_bytes, capture_id="test_cap", stream_id=2)
    assert len(artifacts) >= 1
    assert artifacts[0]["file_type"] == "PDF Document"
    assert artifacts[0]["is_truncated"] is False

def test_carve_truncated_stream():
    """Verify truncated file without footer is flagged as incomplete."""
    truncated_png = b"HEADER\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR_TRUNCATED_NO_FOOTER"
    artifacts = carve_files_from_bytes(truncated_png, capture_id="test_cap", stream_id=3)
    assert len(artifacts) >= 1
    assert artifacts[0]["is_truncated"] is True
    assert artifacts[0]["status"] == "partial_truncated"

# ── MODULE 5: GEO THREAT MAP TESTS ─────────────────────────────────────────────

def test_resolve_private_ip_geo():
    """Verify internal IPs resolve to LAN coordinates."""
    res = resolve_single_ip_geo("192.168.1.1")
    assert res["is_private"] is True
    assert res["country_code"] == "LAN"

def test_batch_aggregate_pcap_geo():
    """Verify batch aggregation de-duplicates repeated flows."""
    flows = [
        {"src_ip": "8.8.8.8", "dst_ip": "1.1.1.1", "packet_count": 50},
        {"src_ip": "8.8.8.8", "dst_ip": "1.1.1.1", "packet_count": 30},
        {"src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "packet_count": 10},
    ]
    res = batch_aggregate_pcap_geo(flows)
    assert res["unique_ips_count"] == 3
    assert len(res["arcs"]) >= 1

# ── MODULE 6: BEACONING DETECTOR TESTS ─────────────────────────────────────────

def test_periodic_beacon_detection():
    """Verify periodic flow with low jitter is detected as beacon indicator."""
    # Synthetic flow with 5.0s delta +- 0.05s jitter
    base_ts = 1700000000.0
    packets = []
    for i in range(12):
        ts = base_ts + (i * 5.0) + (0.02 if i % 2 == 0 else -0.02)
        packets.append({
            "timestamp": ts,
            "src_ip": "10.0.0.5",
            "dst_ip": "198.51.100.20",
            "dst_port": 443,
            "protocol": "TCP"
        })
    
    indicators = analyze_traffic_beaconing(packets, min_packets=4, cv_threshold=0.25)
    assert len(indicators) == 1
    ind = indicators[0]
    assert ind["mean_interval_seconds"] == pytest.approx(5.0, abs=0.1)
    assert ind["coefficient_of_variation"] < 0.10
    assert ind["periodicity_confidence"] == "High"

def test_random_traffic_not_flagged():
    """Verify random inter-arrival intervals are not flagged as beacons."""
    intervals = [0.2, 8.5, 1.1, 14.2, 0.4, 22.0, 3.1]
    base_ts = 1700000000.0
    cur_ts = base_ts
    packets = []
    for dt in intervals:
        cur_ts += dt
        packets.append({
            "timestamp": cur_ts,
            "src_ip": "10.0.0.5",
            "dst_ip": "198.51.100.20",
            "dst_port": 80,
            "protocol": "TCP"
        })
        
    indicators = analyze_traffic_beaconing(packets, min_packets=4, cv_threshold=0.25)
    assert len(indicators) == 0

# ── MODULE 8: CVSS 3.1 CALCULATOR & REPORTS TESTS ─────────────────────────────

def test_official_cvss31_formula():
    """Verify exact FIRST.org Base Score calculation against official benchmark."""
    # Benchmark 1: Critical 9.8
    v1 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    res1 = calculate_cvss31_score(v1)
    assert res1["base_score"] == 9.8
    assert res1["severity_rating"] == "Critical"

    # Benchmark 2: Scope Changed (XSS style) 6.1
    v2 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    res2 = calculate_cvss31_score(v2)
    assert res2["base_score"] == 6.1
    assert res2["severity_rating"] == "Medium"
    assert res2["scope"] == "Changed"

def test_report_data_assembly():
    """Verify report health index and severity matrix calculation."""
    findings = [
        {"title": "SQLi Injection", "severity": "critical", "cvss_score": 9.8},
        {"title": "Missing HSTS", "severity": "low", "cvss_score": 3.7}
    ]
    report = assemble_report_data("example.com", findings)
    assert report["total_findings"] == 2
    assert report["severity_counts"]["critical"] == 1
    assert report["severity_counts"]["low"] == 1
    assert report["max_cvss"] == 9.8
    assert report["health_index"] < 100

# ── MODULE 9: BASELINE DIFF TESTS ──────────────────────────────────────────────

def test_baseline_diff_classification():
    """Verify 4-way classification: New, Resolved, Still-Open, Changed-Severity."""
    baseline = [
        {"title": "SQL Injection", "target": "site.com", "module_name": "sqli", "severity": "high", "cwe": "CWE-89"},
        {"title": "Weak Cipher", "target": "site.com", "module_name": "ssl", "severity": "medium", "cwe": "CWE-326"},
        {"title": "Old Bug (Fixed)", "target": "site.com", "module_name": "xss", "severity": "low", "cwe": "CWE-79"}
    ]
    current = [
        # Still-Open (unchanged)
        {"title": "SQL Injection", "target": "site.com", "module_name": "sqli", "severity": "high", "cwe": "CWE-89"},
        # Changed-Severity (upgraded from medium to critical)
        {"title": "Weak Cipher", "target": "site.com", "module_name": "ssl", "severity": "critical", "cwe": "CWE-326"},
        # New Finding
        {"title": "Exposed .env Credentials", "target": "site.com", "module_name": "exposure", "severity": "critical", "cwe": "CWE-200"}
    ]
    diff_res = perform_baseline_diff(baseline, current)
    summary = diff_res["summary"]
    
    assert summary["new_count"] == 1
    assert summary["resolved_count"] == 1
    assert summary["still_open_count"] == 1
    assert summary["changed_severity_count"] == 1
    assert diff_res["new"][0]["title"] == "Exposed .env Credentials"
    assert diff_res["resolved"][0]["title"] == "Old Bug (Fixed)"
    assert diff_res["changed_severity"][0]["new_severity"] == "critical"
