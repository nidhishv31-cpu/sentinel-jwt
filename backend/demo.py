import sqlite3
import json
import jwt
import math
from datetime import datetime, timedelta
from backend.database import get_connection, add_security_event, add_alert
from backend.jwt_analyzer import analyze_jwt
from backend.detection_rules import run_siem_rules

def seed_demo_data(db_path: str):
    # Clear database first
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM security_events")
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM baselines")
    conn.commit()
    conn.close()
    
    now = datetime.utcnow()
    
    # 1. SEED NORMAL AUTH LOGS
    # Seed 20 successful logins spread over the last 12 hours from standard user IPs during normal work hours
    for i in range(20):
        # alternate between 10:00 and 15:00 hours to stay in normal hours
        time_offset = timedelta(hours=i % 12, minutes=i * 7)
        timestamp = (now - time_offset).isoformat() + "Z"
        ip = f"192.168.1.{100 + (i % 5)}"
        username = f"user_{i % 4}"
        
        details = {
            "method": "POST",
            "username": username,
            "bytes_sent": 412,
            "referer": "https://sentinel.jwt/login",
            "status_code": 200,
            "endpoint": "/api/auth/login",
            "user_agent": "Mozilla/5.0",
            "raw_line": f'{ip} - - [{timestamp}] "POST /api/auth/login HTTP/1.1" 200 412 "https://sentinel.jwt/login" "Mozilla/5.0"'
        }
        
        add_security_event(
            timestamp=timestamp,
            event_type="auth_log",
            source_ip=ip,
            details=details,
            severity="INFO",
            db_path=db_path
        )
        
    # 2. SEED BRUTE FORCE ATTACK (IP: 198.51.100.1)
    # 10 failed login attempts in a 2 minute window, 5 minutes ago
    bf_ip = "198.51.100.1"
    for i in range(10):
        timestamp = (now - timedelta(minutes=5) + timedelta(seconds=i * 10)).isoformat() + "Z"
        details = {
            "method": "POST",
            "username": "admin",
            "bytes_sent": 180,
            "referer": "https://sentinel.jwt/login",
            "status_code": 401,
            "endpoint": "/api/auth/login",
            "user_agent": "Mozilla/5.0",
            "raw_line": f'{bf_ip} - - [{timestamp}] "POST /api/auth/login HTTP/1.1" 401 180 "https://sentinel.jwt/login" "Mozilla/5.0"'
        }
        add_security_event(
            timestamp=timestamp,
            event_type="auth_log",
            source_ip=bf_ip,
            details=details,
            severity="INFO",
            db_path=db_path
        )
        
    # 3. SEED CREDENTIAL STUFFING (IP: 203.0.113.2)
    # 8 failed attempts on 8 distinct usernames, 15 minutes ago
    cs_ip = "203.0.113.2"
    usernames = ["root", "administrator", "guest", "support", "test", "user1", "oracle", "dbadmin"]
    for i, user in enumerate(usernames):
        timestamp = (now - timedelta(minutes=15) + timedelta(seconds=i * 15)).isoformat() + "Z"
        details = {
            "method": "POST",
            "username": user,
            "bytes_sent": 180,
            "referer": "https://sentinel.jwt/login",
            "status_code": 401,
            "endpoint": "/api/auth/login",
            "user_agent": "Mozilla/5.0",
            "raw_line": f'{cs_ip} - - [{timestamp}] "POST /api/auth/login HTTP/1.1" 401 180 "https://sentinel.jwt/login" "Mozilla/5.0"'
        }
        add_security_event(
            timestamp=timestamp,
            event_type="auth_log",
            source_ip=cs_ip,
            details=details,
            severity="INFO",
            db_path=db_path
        )
        
    # 4. SEED IMPOSSIBLE TRAVEL EVENT (User: john_doe)
    # New York IP (198.51.100.1) at 30 minutes ago, London IP (203.0.113.2) at 15 minutes ago
    base_time = now - timedelta(minutes=30)
    t1 = base_time.isoformat() + "Z"
    t2 = (base_time + timedelta(minutes=15)).isoformat() + "Z"
    
    details_ny = {
        "method": "POST",
        "username": "john_doe",
        "bytes_sent": 280,
        "status_code": 200,
        "endpoint": "/api/auth/login",
        "user_agent": "Mozilla/5.0",
        "raw_line": f'198.51.100.1 - - [{t1}] "POST /api/auth/login HTTP/1.1" 200 280 "-" "Mozilla/5.0"'
    }
    details_lon = {
        "method": "POST",
        "username": "john_doe",
        "bytes_sent": 280,
        "status_code": 200,
        "endpoint": "/api/auth/login",
        "user_agent": "Mozilla/5.0",
        "raw_line": f'203.0.113.2 - - [{t2}] "POST /api/auth/login HTTP/1.1" 200 280 "-" "Mozilla/5.0"'
    }
    
    add_security_event(
        timestamp=t1,
        event_type="auth_log",
        source_ip="198.51.100.1",
        details=details_ny,
        severity="INFO",
        db_path=db_path
    )
    add_security_event(
        timestamp=t2,
        event_type="auth_log",
        source_ip="203.0.113.2",
        details=details_lon,
        severity="INFO",
        db_path=db_path
    )
    
    # 5. SEED WEAK JWT FINDINGS
    # We will generate a few actual JWT tokens and run them through analysis to seed rich JSON findings
    
    # JWT 1: 'none' algorithm
    token_none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    r1 = analyze_jwt(token_none)
    add_security_event(
        timestamp=(now - timedelta(minutes=18)).isoformat() + "Z",
        event_type="jwt_finding",
        source_ip="198.51.100.1",
        details={
            "token": token_none,
            "findings": r1["findings"],
            "risk_score": r1["risk_score"],
            "header": r1["decoded_header"],
            "payload": r1["decoded_payload"]
        },
        severity="CRITICAL",
        db_path=db_path
    )
    
    # JWT 2: signed with weak secret "secret"
    token_weak = jwt.encode(
        {"sub": "superadmin", "iat": int((now - timedelta(hours=2)).timestamp()), "aud": "sentinel-app"},
        "secret",
        algorithm="HS256"
    )
    r2 = analyze_jwt(token_weak)
    add_security_event(
        timestamp=(now - timedelta(minutes=12)).isoformat() + "Z",
        event_type="jwt_finding",
        source_ip="198.51.100.1",
        details={
            "token": token_weak,
            "findings": r2["findings"],
            "risk_score": r2["risk_score"],
            "header": r2["decoded_header"],
            "payload": r2["decoded_payload"]
        },
        severity="CRITICAL",
        db_path=db_path
    )
    
    # JWT 3: expired token
    token_expired = jwt.encode(
        {"sub": "regular_user", "iat": int((now - timedelta(days=2)).timestamp()), "exp": int((now - timedelta(days=1)).timestamp())},
        "strong_secret_key_1234567890",
        algorithm="HS256"
    )
    r3 = analyze_jwt(token_expired)
    add_security_event(
        timestamp=(now - timedelta(minutes=8)).isoformat() + "Z",
        event_type="jwt_finding",
        source_ip="192.168.1.10",
        details={
            "token": token_expired,
            "findings": r3["findings"],
            "risk_score": r3["risk_score"],
            "header": r3["decoded_header"],
            "payload": r3["decoded_payload"]
        },
        severity="HIGH",
        db_path=db_path
    )

    # 6. SEED MOCK PACKET EVENTS
    # A. Port Scan (192.0.2.3 scanning ports 20-45 on 192.168.1.5)
    scan_ip = "192.0.2.3"
    scan_evs = []
    for port in range(20, 45):
        timestamp = (now - timedelta(minutes=22) + timedelta(milliseconds=port * 20)).isoformat() + "Z"
        details = {
            "dst_ip": "192.168.1.5",
            "src_port": 54321 + port,
            "dst_port": port,
            "protocol": "TCP",
            "packet_summary": f"SYN packet to port {port}",
            "flags": {"syn": True, "ack": False, "fin": False, "rst": False, "psh": False},
            "bytes": 60
        }
        ev_id = add_security_event(
            timestamp=timestamp,
            event_type="packet_event",
            source_ip=scan_ip,
            details=details,
            severity="INFO",
            db_path=db_path
        )
        scan_evs.append(ev_id)
        
    # Standard rule trigger for Port Scan (we manually insert here so it runs correctly)
    add_alert(
        rule_triggered="PORT_SCAN",
        severity="HIGH",
        source_ip=scan_ip,
        event_ids=scan_evs[:10],
        explanation=(
            f"Port scan pattern detected: Source IP {scan_ip} sent SYN packets to "
            f"25 distinct ports on destination 192.168.1.5 within a 10-second rolling window."
        ),
        db_path=db_path
    )
    
    # B. Cleartext Credentials
    # HTTP Authorization Basic
    timestamp_basic = (now - timedelta(minutes=24)).isoformat() + "Z"
    details_basic = {
        "dst_ip": "192.168.1.5",
        "src_port": 49123,
        "dst_port": 80,
        "protocol": "HTTP",
        "packet_summary": "POST /api/v1/login HTTP/1.1",
        "http_info": {
            "request_method": "POST",
            "request_uri": "/api/v1/login",
            "user_agent": "Mozilla/5.0",
            "authorization": "Basic YWRtaW46cGFzc3dvcmQxMjM=", # admin:password123
            "content_type": "application/json"
        },
        "bytes": 280
    }
    ev_basic = add_security_event(
        timestamp=timestamp_basic,
        event_type="packet_event",
        source_ip="192.168.1.100",
        details=details_basic,
        severity="INFO",
        db_path=db_path
    )
    add_alert(
        rule_triggered="CLEAR_CREDENTIALS",
        severity="HIGH",
        source_ip="192.168.1.100",
        event_ids=[ev_basic],
        explanation="Unencrypted basic credentials detected in HTTP request header: Username: 'admin', Password: 'password123'.",
        db_path=db_path
    )
    
    # C. DNS Tunneling Query
    timestamp_dns = (now - timedelta(minutes=26)).isoformat() + "Z"
    details_dns = {
        "dst_ip": "8.8.8.8",
        "src_port": 53531,
        "dst_port": 53,
        "protocol": "DNS",
        "packet_summary": "Standard query 0x1234 A a1b2c3d4e5f6g7h8i9j0.tunnel.maliciousdomain.com",
        "dns_info": {
            "qry_name": "a1b2c3d4e5f6g7h8i9j0.tunnel.maliciousdomain.com",
            "qry_type": "A",
            "flags": "0x0100"
        },
        "bytes": 85
    }
    ev_dns = add_security_event(
        timestamp=timestamp_dns,
        event_type="packet_event",
        source_ip="192.168.1.120",
        details=details_dns,
        severity="INFO",
        db_path=db_path
    )
    add_alert(
        rule_triggered="DNS_TUNNEL",
        severity="MEDIUM",
        source_ip="192.168.1.120",
        event_ids=[ev_dns],
        explanation="DNS Tunneling indicator detected: High entropy in DNS subdomain label (4.38 bits/char): 'a1b2c3d4e5f6g7h8i9j0'.",
        db_path=db_path
    )
    
    # D. ARP Spoofing
    timestamp_arp1 = (now - timedelta(minutes=30)).isoformat() + "Z"
    timestamp_arp2 = (now - timedelta(minutes=29)).isoformat() + "Z"
    
    arp_details1 = {
        "dst_ip": "192.168.1.5",
        "protocol": "ARP",
        "packet_summary": "ARP Reply 192.168.1.1 is at 00:11:22:33:44:55",
        "arp_info": {
            "opcode": "reply",
            "src_mac": "00:11:22:33:44:55",
            "src_ip": "192.168.1.1",
            "dst_mac": "FF:FF:FF:FF:FF:FF",
            "dst_ip": "192.168.1.5"
        },
        "bytes": 42
    }
    arp_details2 = {
        "dst_ip": "192.168.1.5",
        "protocol": "ARP",
        "packet_summary": "ARP Reply 192.168.1.1 is at AA:BB:CC:DD:EE:FF",
        "arp_info": {
            "opcode": "reply",
            "src_mac": "AA:BB:CC:DD:EE:FF",
            "src_ip": "192.168.1.1",
            "dst_mac": "FF:FF:FF:FF:FF:FF",
            "dst_ip": "192.168.1.5"
        },
        "bytes": 42
    }
    ev_arp1 = add_security_event(timestamp=timestamp_arp1, event_type="packet_event", source_ip="192.168.1.1", details=arp_details1, severity="INFO", db_path=db_path)
    ev_arp2 = add_security_event(timestamp=timestamp_arp2, event_type="packet_event", source_ip="192.168.1.1", details=arp_details2, severity="INFO", db_path=db_path)
    
    add_alert(
        rule_triggered="ARP_SPOOFING",
        severity="HIGH",
        source_ip="192.168.1.1",
        event_ids=[ev_arp1, ev_arp2],
        explanation="ARP Spoofing detected! The IP address 192.168.1.1 was claimed by multiple distinct MAC addresses: 00:11:22:33:44:55, AA:BB:CC:DD:EE:FF.",
        db_path=db_path
    )
    
    # E. Beaconing (10 connections from 192.168.1.15 to 203.0.113.10 exactly 5.0 seconds apart)
    beacon_ip = "192.168.1.15"
    beacon_evs = []
    for k in range(10):
        timestamp = (now - timedelta(minutes=40) + timedelta(seconds=k * 5)).isoformat() + "Z"
        details = {
            "dst_ip": "203.0.113.10",
            "src_port": 40321 + k,
            "dst_port": 443,
            "protocol": "TCP",
            "packet_summary": f"TCP connection handshake {k}",
            "bytes": 74
        }
        ev_id = add_security_event(
            timestamp=timestamp,
            event_type="packet_event",
            source_ip=beacon_ip,
            details=details,
            severity="INFO",
            db_path=db_path
        )
        beacon_evs.append(ev_id)
        
    add_alert(
        rule_triggered="BEACONING",
        severity="HIGH",
        source_ip=beacon_ip,
        event_ids=beacon_evs,
        explanation=(
            f"Beaconing behavior detected: Source {beacon_ip} is contacting destination 203.0.113.10 "
            f"at suspiciously regular intervals of ~5.00s (Standard Deviation: 0.002s, CV: 0.000)."
        ),
        db_path=db_path
    )

    # 7. RUN RULES ENGINE to correlate attacks & generate log-based alerts!
    run_siem_rules(db_path)
    print("[SUCCESS] Demo seed complete.")
