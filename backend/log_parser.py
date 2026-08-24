import re
import json
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

# Nginx/Apache Combined Log format regex:
# 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /api/login HTTP/1.1" 401 2326 "http://referer.com" "Mozilla/5.0"
COMBINED_LOG_REGEX = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+([^\s"]*)\s*([^\s"]*)?"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?'
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def parse_nginx_date(date_str: str) -> str:
    """
    Parses '10/Oct/2000:13:55:36 -0700' and returns ISO8601 UTC string.
    """
    try:
        # Split into datetime and offset parts
        parts = date_str.split(" ")
        dt_part = parts[0]
        offset_part = parts[1] if len(parts) > 1 else "+0000"
        
        # Parse datetime part
        dt_subparts = dt_part.split(":")
        date_part = dt_subparts[0]  # 10/Oct/2000
        time_part = ":".join(dt_subparts[1:])  # 13:55:36
        
        day, month_str, year = date_part.split("/")
        month = MONTHS.get(month_str, 1)
        
        # Construct ISO string
        time_dt = datetime.strptime(time_part, "%H:%M:%S")
        
        # Create dt object (naive)
        dt = datetime(int(year), month, int(day), time_dt.hour, time_dt.minute, time_dt.second)
        
        # Parse offset
        sign = 1 if offset_part[0] == '+' else -1
        hrs = int(offset_part[1:3])
        mins = int(offset_part[3:5])
        
        # Adjust to UTC
        # If timezone offset is +0200, UTC time is local time - 2 hours
        # If timezone offset is -0700, UTC time is local time + 7 hours
        from datetime import timedelta
        utc_dt = dt - sign * timedelta(hours=hrs, minutes=mins)
        
        return utc_dt.isoformat() + "Z"
    except Exception:
        # Return fallback current timestamp on fail
        return datetime.utcnow().isoformat() + "Z"

def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
        
    # Try parsing as JSON line first
    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
            # Normalize fields
            timestamp = data.get("timestamp") or datetime.utcnow().isoformat() + "Z"
            # Ensure it ends with Z or matches ISO
            if not timestamp.endswith("Z") and "+" not in timestamp:
                timestamp += "Z"
                
            source_ip = data.get("source_ip") or data.get("ip") or "0.0.0.0"
            endpoint = data.get("endpoint") or data.get("url") or "/"
            status_code = int(data.get("status_code") or data.get("status") or 200)
            user_agent = data.get("user_agent") or data.get("ua") or "Unknown"
            
            # Keep additional fields in details
            details = {
                "method": data.get("method", "GET"),
                "username": data.get("username"),
                "bytes_sent": int(data.get("bytes_sent") or data.get("bytes") or 0),
                "referer": data.get("referer"),
                "raw_line": line,
                "status_code": status_code,
                "endpoint": endpoint,
                "user_agent": user_agent
            }
                
            return {
                "timestamp": timestamp,
                "event_type": "auth_log",
                "source_ip": source_ip,
                "endpoint": endpoint,
                "status_code": status_code,
                "user_agent": user_agent,
                "details": details,
                "severity": "INFO"
            }
        except Exception:
            # If JSON parsing fails, fall back to combined log regex
            pass
            
    # Try combined log format regex
    match = COMBINED_LOG_REGEX.match(line)
    if match:
        groups = match.groups()
        source_ip = groups[0]
        # groups[1] is RFC 1413 identity, groups[2] is userid
        username = groups[2] if groups[2] != "-" else None
        date_raw = groups[3]
        method = groups[4]
        endpoint = groups[5]
        protocol = groups[6]
        status_code = int(groups[7])
        bytes_sent_str = groups[8]
        bytes_sent = int(bytes_sent_str) if bytes_sent_str != "-" else 0
        referer = groups[9] if len(groups) > 9 else None
        user_agent = groups[10] if len(groups) > 10 else "Unknown"
        
        timestamp = parse_nginx_date(date_raw)
        
        details = {
            "method": method,
            "protocol": protocol,
            "bytes_sent": bytes_sent,
            "referer": referer,
            "raw_line": line,
            "status_code": status_code,
            "endpoint": endpoint,
            "user_agent": user_agent
        }
        if username:
            details["username"] = username
            
        return {
            "timestamp": timestamp,
            "event_type": "auth_log",
            "source_ip": source_ip,
            "endpoint": endpoint,
            "status_code": status_code,
            "user_agent": user_agent,
            "details": details,
            "severity": "INFO"
        }
        
    return None

def parse_log_content(content: str) -> List[Dict[str, Any]]:
    parsed_events = []
    lines = content.splitlines()
    for line in lines:
        parsed = parse_log_line(line)
        if parsed:
            parsed_events.append(parsed)
    return parsed_events
