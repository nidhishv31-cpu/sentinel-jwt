import os
import sys

# Add parent directory to path to allow importing modules correctly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import init_db, get_alerts, DEFAULT_DB_PATH
from backend.demo import seed_demo_data
from backend.jwt_analyzer import analyze_jwt
from backend.log_parser import parse_log_line

def test_jwt_analyzer():
    print("[TEST] Running JWT Analyzer checks...")
    # Test none algorithm
    token_none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    res = analyze_jwt(token_none)
    assert res["risk_score"] >= 50, "Risk score for 'none' algorithm should be high"
    assert any(f["category"] == "alg" for f in res["findings"]), "None algorithm finding should be present"
    print("  -> JWT Analyzer 'none' algorithm test passed.")

    # Test expired token
    token_expired = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTE2MjM5MDIyfQ.signature"
    res_expired = analyze_jwt(token_expired)
    assert any(f["title"] == "Token Expired" for f in res_expired["findings"]), "Expired finding should be present"
    print("  -> JWT Analyzer expiration test passed.")

def test_log_parser():
    print("[TEST] Running Log Parser checks...")
    log_line = '127.0.0.1 - admin [10/Oct/2000:13:55:36 -0700] "POST /api/login HTTP/1.1" 401 2326'
    parsed = parse_log_line(log_line)
    assert parsed is not None, "Failed to parse combined Nginx log line"
    assert parsed["source_ip"] == "127.0.0.1"
    assert parsed["status_code"] == 401
    assert parsed["details"]["username"] == "admin"
    print("  -> Log Parser combined format test passed.")

    json_line = '{"timestamp": "2026-08-17T12:00:00Z", "source_ip": "10.0.0.1", "endpoint": "/api/v1/auth", "status_code": 200}'
    parsed_json = parse_log_line(json_line)
    assert parsed_json is not None, "Failed to parse JSON log line"
    assert parsed_json["source_ip"] == "10.0.0.1"
    assert parsed_json["status_code"] == 200
    print("  -> Log Parser JSON lines test passed.")

def test_database_and_rules():
    print("[TEST] Running DB and Rules engine checks...")
    test_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db", "test_sentinel.db")
    if os.path.exists(test_db):
        os.remove(test_db)

    # Initialize DB
    init_db(test_db)
    
    # Seed data
    seed_demo_data(test_db)
    
    # Verify alerts generated
    alerts = get_alerts(db_path=test_db)
    assert len(alerts) > 0, "Detections should have generated alerts in database"
    
    # Verify specific alert rules triggered
    rules_triggered = [a["rule_triggered"] for a in alerts]
    print(f"  -> Rules triggered in test seed: {rules_triggered}")
    assert "BRUTE_FORCE" in rules_triggered or "BRUTE_FORCE_STAT" in rules_triggered, "Brute force alert should be triggered"
    assert "CREDENTIAL_STUFFING" in rules_triggered, "Credential stuffing alert should be triggered"
    assert "IMPOSSIBLE_TRAVEL" in rules_triggered, "Impossible travel alert should be triggered"
    assert "PORT_SCAN" in rules_triggered, "PCAP Port Scan alert should be triggered"
    assert "CLEAR_CREDENTIALS" in rules_triggered, "PCAP Clear credentials alert should be triggered"
    assert "DNS_TUNNEL" in rules_triggered, "PCAP DNS Tunnel alert should be triggered"
    
    # Clean up test database
    if os.path.exists(test_db):
        os.remove(test_db)
    print("  -> DB and Rules engine test passed.")

def test_wireshark_engine():
    print("[TEST] Running Wireshark Engine checks...")
    from backend.pcap_analyzer import get_network_interfaces, evaluate_filter
    
    # 1. Test interface listing
    ifaces = get_network_interfaces()
    assert len(ifaces) > 0, "Should return at least loopback fallback interface"
    print(f"  -> Found {len(ifaces)} network interfaces.")
    
    # 2. Test filter evaluations
    details = {
        "source_ip": "192.168.1.100",
        "dst_ip": "192.168.1.5",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "TCP",
        "bytes": 60,
        "http_info": {
            "request_method": "POST"
        }
    }
    
    assert evaluate_filter(details, "tcp"), "Filter 'tcp' should match"
    assert not evaluate_filter(details, "udp"), "Filter 'udp' should not match"
    assert evaluate_filter(details, "ip.src == 192.168.1.100"), "Filter 'ip.src' should match"
    assert not evaluate_filter(details, "ip.dst == 10.0.0.1"), "Filter 'ip.dst' should not match"
    assert evaluate_filter(details, "ip.src == 192.168.1.100 && tcp.port == 80"), "Filter composite should match"
    assert not evaluate_filter(details, "ip.src == 192.168.1.100 && tcp.port == 443"), "Filter composite port mismatch should not match"
    print("  -> Wireshark display filter evaluator checks passed.")

def test_diagnostics():
    print("[TEST] Running Security Diagnostics checks...")
    import tempfile
    import os
    from backend.database import init_db, add_alert
    from backend.diagnostics import generate_diagnostics
    
    fd, temp_db = tempfile.mkstemp()
    os.close(fd)
    try:
        init_db(temp_db)
        add_alert(
            rule_triggered="PORT_SCAN",
            severity="MEDIUM",
            source_ip="10.0.0.1",
            event_ids=[1, 2],
            explanation="Recon scan",
            db_path=temp_db
        )
        add_alert(
            rule_triggered="IMPOSSIBLE_TRAVEL",
            severity="HIGH",
            source_ip="192.168.1.10",
            event_ids=[3, 4],
            explanation="Geographic anomaly",
            db_path=temp_db
        )
        
        diags = generate_diagnostics(temp_db)
        assert len(diags) == 2, "Diagnostics should yield 2 entries"
        assert diags[0]["rule"] == "IMPOSSIBLE_TRAVEL", "First entry should be IMPOSSIBLE_TRAVEL (HIGH)"
        assert diags[1]["rule"] == "PORT_SCAN", "Second entry should be PORT_SCAN (MEDIUM)"
        assert diags[0]["issue_name"] == "Geographic Velocity Anomaly (Possible Compromise)", "Mismatch in issue name"
        assert "192.168.1.10" in diags[0]["affected_ips"], "Source IP not recorded in diagnostics"
        
        print("  -> Diagnostics compiler checks passed.")
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)

if __name__ == "__main__":
    print("="*40)
    print("STARTING SENTINELJWT BACKEND AUTOMATED TESTS")
    print("="*40)
    try:
        test_jwt_analyzer()
        test_log_parser()
        test_database_and_rules()
        test_wireshark_engine()
        test_diagnostics()
        print("="*40)
        print("ALL TESTS PASSED SUCCESSFULLY!")
        print("="*40)
        sys.exit(0)
    except AssertionError as e:
        print(f"[TEST FAILURE] Assertion failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[TEST ERROR] Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)
