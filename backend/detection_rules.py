import sqlite3
import json
import math
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from backend.database import get_connection, add_alert, add_security_event

# Mock IP Geolocation for demo impossible travel rules
MOCK_GEO_DB = {
    "198.51.100.1": {"city": "New York", "lat": 40.7128, "lon": -74.0060},
    "203.0.113.2": {"city": "London", "lat": 51.5074, "lon": -0.1278},
    "192.0.2.3": {"city": "Tokyo", "lat": 35.6762, "lon": 139.6503},
    "198.51.100.10": {"city": "Paris", "lat": 48.8566, "lon": 2.3522},
    "127.0.0.1": {"city": "San Francisco", "lat": 37.7749, "lon": -122.4194},
    "localhost": {"city": "San Francisco", "lat": 37.7749, "lon": -122.4194}
}

def get_ip_geo(ip: str) -> Dict[str, Any]:
    # Fallback default location if not in mock database
    if ip in MOCK_GEO_DB:
        return MOCK_GEO_DB[ip]
    
    # Generate a deterministic mock city/coords based on IP hash to keep it consistent
    h = hash(ip)
    lat = 30.0 + (h % 30) # 30 to 60 deg lat
    lon = -100.0 + ((h * 17) % 180) # -100 to 80 deg lon
    return {"city": f"Mock City ({ip})", "lat": lat, "lon": lon}

def calculate_great_circle_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    # Haversine / Great-Circle distance formula (km)
    R = 6371.0 # Earth's radius in km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.asin(math.sqrt(a))
    return R * c

def poisson_cumulative_probability(k: int, lmbda: float) -> float:
    """
    Returns P(X >= k) for a Poisson distribution with expected rate lambda.
    P(X >= k) = 1 - Sum_{i=0}^{k-1} (lmbda^i * e^-lmbda) / i!
    """
    if lmbda <= 0:
        return 0.0
    sum_prob = 0.0
    for i in range(k):
        # Calculate term: (lmbda^i * e^-lmbda) / i!
        # Use log scale for safety if lambda or i is large, but for our counts standard math is fine
        try:
            term = (math.pow(lmbda, i) * math.exp(-lmbda)) / math.factorial(i)
            sum_prob += term
        except OverflowError:
            pass
    return max(0.0, 1.0 - sum_prob)

def run_siem_rules(db_path: str) -> List[int]:
    new_alerts = []
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    # Run analysis over events in the last 1 hour (or historical window)
    now_ts = datetime.utcnow()
    window_start = (now_ts - timedelta(hours=1)).isoformat() + "Z"
    
    # Get all events in the last hour
    cursor.execute(
        "SELECT * FROM security_events WHERE timestamp >= ? ORDER BY timestamp ASC",
        (window_start,)
    )
    events = [dict(r) for r in cursor.fetchall()]
    for ev in events:
        ev["details"] = json.loads(ev["details"])
        
    if not events:
        conn.close()
        return []
        
    # --- RULE 1: BRUTE FORCE DETECTION (Sliding window & Poisson) ---
    # Group failed logins (status 401 or 403) by IP in 5-minute rolling windows
    failed_logins = [e for e in events if e["event_type"] == "auth_log" and e["details"].get("status_code") in [401, 403]]
    
    # Slide a 5-minute window for each IP
    ip_failed_groups = {}
    for ev in failed_logins:
        ip = ev["source_ip"]
        if ip not in ip_failed_groups:
            ip_failed_groups[ip] = []
        ip_failed_groups[ip].append(ev)
        
    for ip, ip_evs in ip_failed_groups.items():
        # Check standard threshold: >5 failed attempts in 5 minutes
        ip_evs.sort(key=lambda x: x["timestamp"])
        for i in range(len(ip_evs)):
            t1 = datetime.fromisoformat(ip_evs[i]["timestamp"].replace("Z", ""))
            t2 = t1 + timedelta(minutes=5)
            
            window = [e for e in ip_evs if t1 <= datetime.fromisoformat(e["timestamp"].replace("Z", "")) <= t2]
            if len(window) > 5:
                # Standard threshold alert
                ev_ids = [e["id"] for e in window]
                
                # Check if this alert was already raised
                cursor.execute(
                    "SELECT id FROM alerts WHERE rule_triggered = 'BRUTE_FORCE' AND source_ip = ? AND created_at >= ?",
                    (ip, (now_ts - timedelta(minutes=10)).isoformat())
                )
                if not cursor.fetchone():
                    alert_id = add_alert(
                        rule_triggered="BRUTE_FORCE",
                        severity="HIGH",
                        source_ip=ip,
                        event_ids=ev_ids,
                        explanation=(
                            f"Brute force detected: IP {ip} triggered {len(window)} failed login attempts "
                            f"within a 5-minute rolling window."
                        ),
                        db_path=db_path
                    )
                    new_alerts.append(alert_id)
                break
                
        # Poisson-based statistical anomaly
        # Calculate historical rate of failed logins for this IP (or seed if missing)
        # For simplicity, count historical failed logins outside this 5-minute window
        cursor.execute(
            "SELECT COUNT(*) as count FROM security_events WHERE event_type = 'auth_log' AND (details LIKE '%\"status_code\": 401%' OR details LIKE '%\"status_code\": 403%') AND source_ip = ?",
            (ip,)
        )
        total_historical = cursor.fetchone()["count"]
        
        # Calculate average rate of failed logins per 5 minutes.
        # Assume server has been running for 1 day = 288 windows of 5 minutes.
        # If very few events, set baseline expected failed logins lambda to 0.05
        lmbda = max(0.05, total_historical / 288.0)
        
        # Count failures in the latest 5 minutes
        recent_cutoff = (datetime.utcnow() - timedelta(minutes=5)).isoformat() + "Z"
        recent_failures = [e for e in ip_evs if e["timestamp"] >= recent_cutoff]
        k = len(recent_failures)
        
        if k >= 3: # Only run statistical model for at least 3 attempts
            p_val = poisson_cumulative_probability(k, lmbda)
            if p_val < 0.01:
                # Statistical anomaly!
                ev_ids = [e["id"] for e in recent_failures]
                cursor.execute(
                    "SELECT id FROM alerts WHERE rule_triggered = 'BRUTE_FORCE_STAT' AND source_ip = ? AND created_at >= ?",
                    (ip, (now_ts - timedelta(minutes=10)).isoformat())
                )
                if not cursor.fetchone():
                    alert_id = add_alert(
                        rule_triggered="BRUTE_FORCE_STAT",
                        severity="MEDIUM",
                        source_ip=ip,
                        event_ids=ev_ids,
                        explanation=(
                            f"Statistical Brute Force anomaly: IP {ip} triggered {k} failed attempts. "
                            f"Expected baseline rate is {lmbda:.3f} per 5m window. "
                            f"Poisson p-value is {p_val:.4f} (anomalous if < 0.01)."
                        ),
                        db_path=db_path
                    )
                    new_alerts.append(alert_id)
                    
                    # Update/Insert baseline record
                    cursor.execute(
                        "SELECT id FROM baselines WHERE metric_name = 'failed_login_rate' AND source_ip_or_user = ?",
                        (ip,)
                    )
                    baseline_row = cursor.fetchone()
                    if baseline_row:
                        cursor.execute(
                            "UPDATE baselines SET mean_rate = ?, computed_at = ? WHERE id = ?",
                            (lmbda, datetime.utcnow().isoformat() + "Z", baseline_row["id"])
                        )
                    else:
                        cursor.execute(
                            "INSERT INTO baselines (metric_name, source_ip_or_user, mean_rate, std_dev, computed_at) VALUES (?, ?, ?, ?, ?)",
                            ("failed_login_rate", ip, lmbda, 0.0, datetime.utcnow().isoformat() + "Z")
                        )
                    conn.commit()

    # --- RULE 2: CREDENTIAL STUFFING DETECTION ---
    # Many distinct usernames from the same IP within a 5-minute rolling window
    ip_users = {}
    for ev in failed_logins:
        ip = ev["source_ip"]
        username = ev["details"].get("username")
        if ip and username:
            if ip not in ip_users:
                ip_users[ip] = []
            ip_users[ip].append((ev["timestamp"], username, ev["id"]))
            
    for ip, user_attempts in ip_users.items():
        user_attempts.sort(key=lambda x: x[0])
        for i in range(len(user_attempts)):
            t1 = datetime.fromisoformat(user_attempts[i][0].replace("Z", ""))
            t2 = t1 + timedelta(minutes=5)
            
            # Sublist in window
            window = [x for x in user_attempts if t1 <= datetime.fromisoformat(x[0].replace("Z", "")) <= t2]
            distinct_usernames = set(x[1] for x in window)
            
            if len(distinct_usernames) > 3:
                ev_ids = [x[2] for x in window]
                cursor.execute(
                    "SELECT id FROM alerts WHERE rule_triggered = 'CREDENTIAL_STUFFING' AND source_ip = ? AND created_at >= ?",
                    (ip, (now_ts - timedelta(minutes=10)).isoformat())
                )
                if not cursor.fetchone():
                    alert_id = add_alert(
                        rule_triggered="CREDENTIAL_STUFFING",
                        severity="CRITICAL",
                        source_ip=ip,
                        event_ids=ev_ids,
                        explanation=(
                            f"Credential stuffing detected: IP {ip} attempted failed logins on "
                            f"{len(distinct_usernames)} distinct user accounts ({', '.join(distinct_usernames)}) "
                            f"within a 5-minute rolling window."
                        ),
                        db_path=db_path
                    )
                    new_alerts.append(alert_id)
                break

    # --- RULE 3: JWT CORRELATION (Token Attack) ---
    # Same IP has >3 jwt_findings AND failed auth logins
    jwt_events = [e for e in events if e["event_type"] == "jwt_finding"]
    jwt_ips = set(e["source_ip"] for e in jwt_events)
    
    for ip in jwt_ips:
        ip_jwt_evs = [e for e in jwt_events if e["source_ip"] == ip]
        ip_failed_logins = [e for e in failed_logins if e["source_ip"] == ip]
        
        if len(ip_jwt_evs) >= 3 and len(ip_failed_logins) > 0:
            ev_ids = [e["id"] for e in ip_jwt_evs] + [e["id"] for e in ip_failed_logins]
            cursor.execute(
                "SELECT id FROM alerts WHERE rule_triggered = 'TOKEN_ATTACK' AND source_ip = ? AND created_at >= ?",
                (ip, (now_ts - timedelta(minutes=10)).isoformat())
            )
            if not cursor.fetchone():
                alert_id = add_alert(
                    rule_triggered="TOKEN_ATTACK",
                    severity="CRITICAL",
                    source_ip=ip,
                    event_ids=ev_ids,
                    explanation=(
                        f"Combined Token Attack Escalation: IP {ip} has triggered {len(ip_jwt_evs)} JWT "
                        f"findings (tampered/weak secrets) and has active failed login events. "
                        f"Indicates active compromise attempt."
                    ),
                    db_path=db_path
                )
                new_alerts.append(alert_id)

    # --- RULE 4: IMPOSSIBLE TRAVEL DETECTION ---
    # Find logins from the same account from distant IPs within an implausible time window
    # Track successful logins (status_code == 200 or successful requests with username)
    success_logins = [e for e in events if e["event_type"] == "auth_log" and e["details"].get("status_code") == 200]
    user_success_groups = {}
    for ev in success_logins:
        username = ev["details"].get("username")
        if username:
            if username not in user_success_groups:
                user_success_groups[username] = []
            user_success_groups[username].append(ev)
            
    for username, logins in user_success_groups.items():
        logins.sort(key=lambda x: x["timestamp"])
        for i in range(len(logins) - 1):
            l1, l2 = logins[i], logins[i+1]
            ip1, ip2 = l1["source_ip"], l2["source_ip"]
            if ip1 == ip2:
                continue
                
            t1 = datetime.fromisoformat(l1["timestamp"].replace("Z", ""))
            t2 = datetime.fromisoformat(l2["timestamp"].replace("Z", ""))
            time_diff_sec = (t2 - t1).total_seconds()
            
            if time_diff_sec > 0:
                geo1 = get_ip_geo(ip1)
                geo2 = get_ip_geo(ip2)
                
                dist = calculate_great_circle_distance(geo1["lat"], geo1["lon"], geo2["lat"], geo2["lon"])
                # Speed in km/h
                speed = (dist / time_diff_sec) * 3600.0
                
                # Flag if speed > 900 km/h and distance is meaningful (> 100km)
                if speed > 900.0 and dist > 100.0:
                    ev_ids = [l1["id"], l2["id"]]
                    # Prevent duplicate travel alerts
                    cursor.execute(
                        "SELECT id FROM alerts WHERE rule_triggered = 'IMPOSSIBLE_TRAVEL' AND source_ip = ? AND created_at >= ?",
                        (ip2, (now_ts - timedelta(minutes=10)).isoformat())
                    )
                    if not cursor.fetchone():
                        alert_id = add_alert(
                            rule_triggered="IMPOSSIBLE_TRAVEL",
                            severity="HIGH",
                            source_ip=ip2,
                            event_ids=ev_ids,
                            explanation=(
                                f"Impossible travel detected for user '{username}': "
                                f"Logged in from {geo1['city']} ({ip1}) and {geo2['city']} ({ip2}) "
                                f"within {time_diff_sec/60:.1f} minutes. "
                                f"Required travel velocity is {speed:.0f} km/h (exceeds 900 km/h threshold)."
                            ),
                            db_path=db_path
                        )
                        new_alerts.append(alert_id)

    # --- RULE 5: OFF-HOURS ACCESS DETECTION ---
    # Flag successful logins outside normal hours (9 AM - 6 PM local time, here treated as ISO hour check)
    # Weighted by the user's historical login distribution
    for ev in success_logins:
        username = ev["details"].get("username")
        ip = ev["source_ip"]
        ev_id = ev["id"]
        if username and ev_id:
            try:
                dt = datetime.fromisoformat(ev["timestamp"].replace("Z", ""))
            except Exception:
                continue
                
            hour = dt.hour
            # Off-hours defined as outside 9:00 - 18:00 (i.e. hour < 9 or hour >= 18)
            if hour < 9 or hour >= 18:
                # Check user's history of logins in the off-hours
                cursor.execute(
                    "SELECT COUNT(*) as count FROM security_events WHERE event_type = 'auth_log' AND details LIKE ? AND severity = 'INFO'",
                    (f'%"username": "{username}"%',)
                )
                total_logins = cursor.fetchone()["count"]
                
                # If they have logged in before, let's see how many were in off-hours
                # For simplicity, count how many events have hours < 9 or >= 18
                # In SQLite, we can inspect using strftime if timezone timestamp is saved
                # Or query details and parse. Let's run a query for details:
                cursor.execute(
                    "SELECT timestamp FROM security_events WHERE event_type = 'auth_log' AND details LIKE ? AND id != ?",
                    (f'%"username": "{username}"%', ev_id)
                )
                historical_timestamps = [r["timestamp"] for r in cursor.fetchall()]
                
                off_hours_historical_count = 0
                for ts in historical_timestamps:
                    try:
                        h_dt = datetime.fromisoformat(ts.replace("Z", ""))
                        if h_dt.hour < 9 or h_dt.hour >= 18:
                            off_hours_historical_count += 1
                    except Exception:
                        pass
                
                # Anomaly weighting:
                # If they have < 3 off-hours logins and total logins is significant, it's anomalous.
                # If it's a brand new user (total_logins < 3), raise as INFO/LOW.
                is_anomalous = False
                if total_logins >= 5 and off_hours_historical_count < 2:
                    is_anomalous = True
                
                if is_anomalous:
                    cursor.execute(
                        "SELECT id FROM alerts WHERE rule_triggered = 'OFF_HOURS' AND source_ip = ? AND created_at >= ?",
                        (ip, (now_ts - timedelta(minutes=10)).isoformat())
                    )
                    if not cursor.fetchone():
                        alert_id = add_alert(
                            rule_triggered="OFF_HOURS",
                            severity="LOW",
                            source_ip=ip,
                            event_ids=[ev_id],
                            explanation=(
                                f"Off-hours successful login by user '{username}' at {dt.strftime('%H:%M:%S')} UTC. "
                                f"Normal logins typically occur during work hours (9 AM - 6 PM). "
                                f"User has only {off_hours_historical_count} historical off-hours logins out of {total_logins} total."
                            ),
                            db_path=db_path
                        )
                        new_alerts.append(alert_id)
                        
    conn.close()
    return new_alerts
