import os
import sys
import pyshark
import json
import math
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from backend.database import add_security_event, add_alert, get_connection
from backend.jwt_analyzer import analyze_jwt

# Locating tshark.exe on Windows/Linux
COMMON_TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/usr/bin/tshark",
    "/usr/sbin/tshark",
    "/usr/local/bin/tshark"
]

def get_tshark_path() -> str:
    # 1. Check system path
    import shutil
    path = shutil.which("tshark")
    if path:
        return path
    
    # 2. Check common installation paths
    for p in COMMON_TSHARK_PATHS:
        if os.path.exists(p):
            return p
            
    # 3. Fail with a clear error message
    raise FileNotFoundError(
        "tshark was not found on your system. Please install Wireshark / tshark:\n"
        "- On Debian/Ubuntu: apt-get install tshark\n"
        "- On Windows: Install Wireshark from https://www.wireshark.org/\n"
        "And ensure C:\\Program Files\\Wireshark is added to your PATH or exists in standard directory."
    )

def check_tshark_installed() -> bool:
    try:
        get_tshark_path()
        return True
    except FileNotFoundError:
        return False

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    for x in set(text):
        p_x = text.count(x) / text_len
        entropy -= p_x * math.log2(p_x)
    return entropy

def parse_pcap_file(pcap_path: str, db_path: Optional[str] = None) -> Dict[str, Any]:
    import threading
    import asyncio
    
    result = None
    exception = None
    
    def worker():
        nonlocal result, exception
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = _parse_pcap_file_internal(pcap_path, db_path)
        except Exception as e:
            exception = e
        finally:
            try:
                loop.close()
            except Exception:
                pass
                
    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    
    if exception:
        raise exception
    return result

def _parse_pcap_file_internal(pcap_path: str, db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Parses a packet capture, saves events in the database, and returns summary stats.
    """
    tshark_exe = get_tshark_path()
    
    # Limit max packets processed to prevent memory/performance issues
    max_packets = 1000
    
    protocols_count = {}
    protocols_bytes = {}
    top_talkers_pkts = {}
    top_talkers_bytes = {}
    timeline = {} # group by seconds or minutes
    
    packet_events = []
    
    capture = pyshark.FileCapture(
        pcap_path,
        keep_packets=False,
        tshark_path=tshark_exe
    )
    
    count = 0
    total_bytes = 0
    
    try:
        for packet in capture:
            count += 1
            if count > max_packets:
                break
                
            # Extract basic packet metadata
            try:
                timestamp_float = float(packet.sniff_timestamp)
                timestamp = datetime.utcfromtimestamp(timestamp_float).isoformat() + "Z"
            except Exception:
                timestamp = datetime.utcnow().isoformat() + "Z"
                
            length = int(packet.length)
            total_bytes += length
            
            # Identify protocol layers
            proto = packet.highest_layer
            
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            src_port = 0
            dst_port = 0
            
            # Read IP layer
            if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst
            elif hasattr(packet, 'arp'):
                # ARP doesn't have IP layer in same place
                src_ip = getattr(packet.arp, 'src_proto_ipv4', '0.0.0.0')
                dst_ip = getattr(packet.arp, 'dst_proto_ipv4', '0.0.0.0')
                proto = "ARP"
                
            # Read Port Layers
            if hasattr(packet, 'tcp'):
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
                proto = "TCP"
            elif hasattr(packet, 'udp'):
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
                proto = "UDP"
                
            # Update stats
            protocols_count[proto] = protocols_count.get(proto, 0) + 1
            protocols_bytes[proto] = protocols_bytes.get(proto, 0) + length
            
            if src_ip != "0.0.0.0":
                top_talkers_pkts[src_ip] = top_talkers_pkts.get(src_ip, 0) + 1
                top_talkers_bytes[src_ip] = top_talkers_bytes.get(src_ip, 0) + length
                
            # Timeline key: YYYY-MM-DDTHH:MM:SS (bucketed by seconds)
            time_bucket = timestamp[:19]
            timeline[time_bucket] = timeline.get(time_bucket, 0) + 1
            
            # Extract TCP flags if available
            flags = {}
            if hasattr(packet, 'tcp'):
                flags = {
                    "syn": getattr(packet.tcp, 'flags_syn', '0') == '1',
                    "ack": getattr(packet.tcp, 'flags_ack', '0') == '1',
                    "fin": getattr(packet.tcp, 'flags_fin', '0') == '1',
                    "rst": getattr(packet.tcp, 'flags_rst', '0') == '1',
                    "psh": getattr(packet.tcp, 'flags_push', '0') == '1'
                }
            
            # ARP info
            arp_info = {}
            if proto == "ARP" and hasattr(packet, 'arp'):
                arp_info = {
                    "opcode": getattr(packet.arp, 'opcode', ''),
                    "src_mac": getattr(packet.arp, 'src_hw_mac', ''),
                    "dst_mac": getattr(packet.arp, 'dst_hw_mac', ''),
                    "src_ip": getattr(packet.arp, 'src_proto_ipv4', ''),
                    "dst_ip": getattr(packet.arp, 'dst_proto_ipv4', '')
                }
                
            # DNS info
            dns_info = {}
            if hasattr(packet, 'dns'):
                proto = "DNS"
                dns_info = {
                    "qry_name": getattr(packet.dns, 'qry_name', ''),
                    "qry_type": getattr(packet.dns, 'qry_type', ''),
                    "flags": getattr(packet.dns, 'flags', '')
                }
                
            # HTTP info
            http_info = {}
            if hasattr(packet, 'http'):
                proto = "HTTP"
                http_info = {
                    "request_method": getattr(packet.http, 'request_method', ''),
                    "request_uri": getattr(packet.http, 'request_uri', ''),
                    "user_agent": getattr(packet.http, 'user_agent', ''),
                    "authorization": getattr(packet.http, 'authorization', ''),
                    "content_type": getattr(packet.http, 'content_type', '')
                }

            # TTL (Time to Live) extraction
            ttl = None
            if hasattr(packet, 'ip'):
                try:
                    ttl = int(getattr(packet.ip, 'ttl', 64))
                except Exception:
                    pass
            elif hasattr(packet, 'ipv6'):
                try:
                    ttl = int(getattr(packet.ipv6, 'hlim', 64))
                except Exception:
                    pass

            # TLS Info
            tls_info = {}
            if hasattr(packet, 'tls'):
                proto = "TLS"
                tls_info = {
                    "cipher": getattr(packet.tls, 'handshake_ciphersuite', ''),
                    "sni": getattr(packet.tls, 'handshake_extensions_server_name', ''),
                    "cert_issuer": getattr(packet.tls, 'handshake_certificate_issuer', '')
                }
                
            packet_summary = getattr(packet, 'info', f"{proto} Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
            details = {
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "packet_summary": packet_summary,
                "flags": flags,
                "bytes": length,
                "raw_line": str(packet)
            }
            if ttl is not None:
                details["ttl"] = ttl
            if tls_info:
                details["tls_info"] = tls_info
            
            if arp_info:
                details["arp_info"] = arp_info
            if dns_info:
                details["dns_info"] = dns_info
            if http_info:
                details["http_info"] = http_info
                
            packet_events.append({
                "timestamp": timestamp,
                "event_type": "packet_event",
                "source_ip": src_ip,
                "details": details,
                "severity": "INFO"
            })
            
    except Exception as e:
        print(f"Error reading packets: {e}", file=sys.stderr)
    finally:
        capture.close()
        
    # Write to database if db_path is provided
    event_ids = []
    if db_path and packet_events:
        for pe in packet_events:
            ev_id = add_security_event(
                timestamp=pe["timestamp"],
                event_type=pe["event_type"],
                source_ip=pe["source_ip"],
                details=pe["details"],
                severity=pe["severity"],
                db_path=db_path
            )
            pe["id"] = ev_id
            event_ids.append(ev_id)
            
        # Run detection rules locally on this PCAP run
        run_pcap_detections(packet_events, db_path)
        
    # Format return metrics
    protocols = [
        {"protocol": k, "count": v, "bytes": protocols_bytes[k]}
        for k, v in protocols_count.items()
    ]
    top_talkers = [
        {"ip": k, "packets": v, "bytes": top_talkers_bytes[k]}
        for k, v in sorted(top_talkers_pkts.items(), key=lambda item: item[1], reverse=True)[:10]
    ]
    timeline_chart = [
        {"time": k, "packets": v}
        for k, v in sorted(timeline.items())
    ]
    
    return {
        "capture_id": os.path.basename(pcap_path),
        "total_packets": count,
        "total_bytes": total_bytes,
        "protocols": protocols,
        "top_talkers": top_talkers,
        "timeline": timeline_chart
    }

def run_pcap_detections(events: List[Dict[str, Any]], db_path: str):
    """
    Run the 5 PCAP-specific detection rules on the newly ingested list of events.
    """
    # 1. Cleartext Credentials Detection
    for ev in events:
        details = ev["details"]
        src_ip = ev["source_ip"]
        ev_id = ev.get("id")
        if not ev_id:
            continue
            
        # A. HTTP Authorization: Basic
        http_info = details.get("http_info", {})
        auth_header = http_info.get("authorization", "")
        if auth_header and auth_header.lower().startswith("basic "):
            try:
                cred_b64 = auth_header.split(" ")[1]
                decoded = base64.b64decode(cred_b64).decode("utf-8")
                user, password = decoded.split(":", 1)
                
                add_alert(
                    rule_triggered="CLEAR_CREDENTIALS",
                    severity="HIGH",
                    source_ip=src_ip,
                    event_ids=[ev_id],
                    explanation=(
                        f"Unencrypted basic credentials detected in HTTP request header: "
                        f"Username: '{user}', Password: '{password}'."
                    ),
                    db_path=db_path
                )
            except Exception:
                pass
                
        # B. HTTP Authorization: Bearer <jwt> seen in cleartext
        if auth_header and auth_header.lower().startswith("bearer "):
            try:
                jwt_token = auth_header.split(" ")[1]
                # Automatically run through the existing JWT Analyzer!
                jwt_findings = analyze_jwt(jwt_token)
                
                # Add JWT finding event
                jwt_details = {
                    "token_source": f"PCAP Cleartext HTTP packet {ev_id}",
                    "findings": jwt_findings["findings"],
                    "risk_score": jwt_findings["risk_score"],
                    "header": jwt_findings["decoded_header"],
                    "payload": jwt_findings["decoded_payload"]
                }
                
                jwt_ev_id = add_security_event(
                    timestamp=ev["timestamp"],
                    event_type="jwt_finding",
                    source_ip=src_ip,
                    details=jwt_details,
                    severity="HIGH" if jwt_findings["risk_score"] > 50 else "MEDIUM",
                    db_path=db_path
                )
                
                # Escalated alert
                add_alert(
                    rule_triggered="CLEAR_CREDENTIALS",
                    severity="CRITICAL",
                    source_ip=src_ip,
                    event_ids=[ev_id, jwt_ev_id],
                    explanation=(
                        f"Unencrypted Authorization Bearer JWT detected in transit. "
                        f"JWT Security Risk score is {jwt_findings['risk_score']}/100. "
                        f"Contains {len(jwt_findings['findings'])} findings."
                    ),
                    db_path=db_path
                )
            except Exception:
                pass
                
        # C. FTP USER/PASS commands
        packet_summary = details.get("packet_summary", "")
        if "USER " in packet_summary or "PASS " in packet_summary:
            if "USER" in packet_summary:
                username = packet_summary.split("USER ")[1].strip()
                add_alert(
                    rule_triggered="CLEAR_CREDENTIALS",
                    severity="MEDIUM",
                    source_ip=src_ip,
                    event_ids=[ev_id],
                    explanation=f"Unencrypted FTP login request detected. Username: '{username}'.",
                    db_path=db_path
                )
            elif "PASS" in packet_summary:
                password = packet_summary.split("PASS ")[1].strip()
                add_alert(
                    rule_triggered="CLEAR_CREDENTIALS",
                    severity="HIGH",
                    source_ip=src_ip,
                    event_ids=[ev_id],
                    explanation=f"Unencrypted FTP password transmission detected. Password: '{password}'.",
                    db_path=db_path
                )

    # 2. Port Scan Detection
    # Single source IP sending SYN packets to >20 distinct ports within a short window
    syn_scans = {} # src_ip -> list of (timestamp, dst_port, dst_ip, ev_id)
    for ev in events:
        details = ev["details"]
        flags = details.get("flags", {})
        if flags.get("syn") and not flags.get("ack"):
            src_ip = ev["source_ip"]
            dst_port = details.get("dst_port", 0)
            dst_ip = details.get("dst_ip", "")
            ev_id = ev.get("id")
            if src_ip and dst_port and ev_id:
                try:
                    dt = datetime.fromisoformat(ev["timestamp"].replace("Z", ""))
                except Exception:
                    dt = datetime.utcnow()
                if src_ip not in syn_scans:
                    syn_scans[src_ip] = []
                syn_scans[src_ip].append((dt, dst_port, dst_ip, ev_id))
                
    for src_ip, syns in syn_scans.items():
        # Sliding window over the packet lists
        # Find windows of 10s with > 20 distinct ports
        syns.sort(key=lambda x: x[0])
        for i in range(len(syns)):
            start_time = syns[i][0]
            end_time = start_time + float(10.0)
            
            # Gather packets in this window
            window_packets = []
            for j in range(i, len(syns)):
                # If timestamp within 10s
                diff = (syns[j][0] - start_time).total_seconds()
                if 0 <= diff <= 10.0:
                    window_packets.append(syns[j])
                else:
                    break
                    
            distinct_ports = set(wp[1] for wp in window_packets)
            if len(distinct_ports) > 20:
                # Port scan detected!
                flagged_ids = [wp[3] for wp in window_packets]
                dst_ip_scanned = window_packets[0][2]
                add_alert(
                    rule_triggered="PORT_SCAN",
                    severity="HIGH",
                    source_ip=src_ip,
                    event_ids=flagged_ids[:10], # Limit to first 10 for details reference
                    explanation=(
                        f"Port scan pattern detected: Source IP {src_ip} sent SYN packets to "
                        f"{len(distinct_ports)} distinct ports on destination {dst_ip_scanned} "
                        f"within a 10-second rolling window."
                    ),
                    db_path=db_path
                )
                break # Avoid duplicate alerts for the same source scan run

    # 3. DNS Tunneling Heuristics
    # Query length > 50, frequency high, or high entropy in subdomain labels
    for ev in events:
        details = ev["details"]
        dns_info = details.get("dns_info", {})
        qry_name = dns_info.get("qry_name", "")
        src_ip = ev["source_ip"]
        ev_id = ev.get("id")
        if qry_name and ev_id:
            entropy = calculate_shannon_entropy(qry_name)
            # Find subdomains - e.g. verylonghexsub.domain.com
            labels = qry_name.split(".")
            longest_label = max(labels, key=len) if labels else ""
            label_entropy = calculate_shannon_entropy(longest_label)
            
            if len(qry_name) > 50 or label_entropy > 4.2:
                explanation = ""
                if len(qry_name) > 50:
                    explanation = f"DNS query name too long ({len(qry_name)} chars): '{qry_name}'."
                else:
                    explanation = f"High entropy in DNS subdomain label ({label_entropy:.2f} bits/char): '{longest_label}'."
                    
                add_alert(
                    rule_triggered="DNS_TUNNEL",
                    severity="MEDIUM",
                    source_ip=src_ip,
                    event_ids=[ev_id],
                    explanation=f"DNS Tunneling indicator detected: {explanation}",
                    db_path=db_path
                )

    # 4. ARP Spoofing Indicator
    # Multiple MAC addresses claiming the same IP
    ip_to_macs = {} # IP -> set(MACs)
    mac_to_ev = {}  # MAC -> ev_id
    for ev in events:
        details = ev["details"]
        arp_info = details.get("arp_info", {})
        if arp_info:
            ip = arp_info.get("src_ip")
            mac = arp_info.get("src_mac")
            ev_id = ev.get("id")
            if ip and mac and ev_id:
                if ip not in ip_to_macs:
                    ip_to_macs[ip] = set()
                ip_to_macs[ip].add(mac)
                mac_to_ev[mac] = ev_id
                
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            # Duplicate MACs for single IP!
            affected_ids = [mac_to_ev[mac] for mac in macs if mac in mac_to_ev]
            add_alert(
                rule_triggered="ARP_SPOOFING",
                severity="HIGH",
                source_ip="0.0.0.0",
                event_ids=affected_ids,
                explanation=(
                    f"ARP Spoofing detected! The IP address {ip} was claimed by multiple "
                    f"distinct MAC addresses: {', '.join(macs)}."
                ),
                db_path=db_path
            )

    # 5. Beaconing Detection
    # Low variance in inter-arrival time (regular intervals)
    # Group packet times by (src_ip -> dst_ip)
    conn_times = {} # (src_ip, dst_ip) -> list of datetime
    conn_evs = {}   # (src_ip, dst_ip) -> list of ev_ids
    for ev in events:
        details = ev["details"]
        src_ip = ev["source_ip"]
        dst_ip = details.get("dst_ip", "")
        ev_id = ev.get("id")
        if src_ip and dst_ip and ev_id:
            try:
                dt = datetime.fromisoformat(ev["timestamp"].replace("Z", ""))
            except Exception:
                dt = datetime.utcnow()
            key = (src_ip, dst_ip)
            if key not in conn_times:
                conn_times[key] = []
                conn_evs[key] = []
            conn_times[key].append(dt)
            conn_evs[key].append(ev_id)
            
    for (src_ip, dst_ip), times in conn_times.items():
        if len(times) >= 6:
            times.sort()
            # Calculate intervals
            intervals = []
            for k in range(len(times) - 1):
                interval = (times[k+1] - times[k]).total_seconds()
                intervals.append(interval)
                
            # Compute mean and standard deviation
            mean_int = sum(intervals) / len(intervals)
            # If the mean interval is small (e.g. less than 0.5s), it could just be a fast burst stream rather than beaconing.
            # We look for regular intervals that are e.g. > 1s
            if mean_int > 1.0:
                variance = sum((x - mean_int) ** 2 for x in intervals) / len(intervals)
                std_dev = math.sqrt(variance)
                
                # Extremely regular = std_dev is low relative to the mean.
                # Coefficient of variation = std_dev / mean. If CV < 0.08, it is highly regular beaconing!
                cv = std_dev / mean_int if mean_int > 0 else 1.0
                if cv < 0.08:
                    ev_ids_flagged = conn_evs[(src_ip, dst_ip)]
                    add_alert(
                        rule_triggered="BEACONING",
                        severity="HIGH",
                        source_ip=src_ip,
                        event_ids=ev_ids_flagged[:10],
                        explanation=(
                            f"Beaconing behavior detected: Source {src_ip} is contacting destination {dst_ip} "
                            f"at suspiciously regular intervals of ~{mean_int:.2f}s "
                            f"(Standard Deviation: {std_dev:.3f}s, CV: {cv:.3f})."
                        ),
                        db_path=db_path
                    )

    # 6. TTL Drift Detection (Injected Packets Check)
    flow_ttls = {} # (src_ip, dst_ip, src_port, dst_port) -> first_seen_ttl
    for ev in events:
        details = ev["details"]
        ttl = details.get("ttl")
        if ttl is not None:
            src_ip = ev["source_ip"]
            dst_ip = details.get("dst_ip", "")
            src_port = details.get("src_port", 0)
            dst_port = details.get("dst_port", 0)
            ev_id = ev.get("id")
            if src_ip and dst_ip and ev_id:
                flow_key = (src_ip, dst_ip, src_port, dst_port)
                if flow_key not in flow_ttls:
                    flow_ttls[flow_key] = ttl
                else:
                    first_ttl = flow_ttls[flow_key]
                    if abs(ttl - first_ttl) >= 3:
                        add_alert(
                            rule_triggered="TTL_DRIFT",
                            severity="MEDIUM",
                            source_ip=src_ip,
                            event_ids=[ev_id],
                            explanation=(
                                f"Packet injection / TTL anomaly detected on connection "
                                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}. "
                                f"TTL drifted from initial value of {first_ttl} to {ttl}. "
                                f"This suggests packet modification or intermediate routing tampering."
                            ),
                            db_path=db_path
                        )
                        # Update so we don't alert constantly on the same flow
                        flow_ttls[flow_key] = ttl

    # 7. TLS Certificate Validation Check
    for ev in events:
        details = ev["details"]
        tls_info = details.get("tls_info", {})
        cert_issuer = tls_info.get("cert_issuer", "")
        if cert_issuer:
            src_ip = ev["source_ip"]
            ev_id = ev.get("id")
            # Flag self-signed, invalid, mitm, or snakeoil certs
            anomalous = False
            reason = ""
            lower_issuer = cert_issuer.lower()
            if any(k in lower_issuer for k in ["localhost", "self-signed", "snakeoil", "mitm", "dummy", "test", "proxy", "local"]):
                anomalous = True
                reason = f"Suspicious certificate issuer found in TLS Server Hello: '{cert_issuer}'"
                
            if anomalous and ev_id:
                add_alert(
                    rule_triggered="TLS_CERT_ANOMALY",
                    severity="HIGH",
                    source_ip=src_ip,
                    event_ids=[ev_id],
                    explanation=(
                        f"Potential SSL/TLS Man-in-the-Middle intercept detected! "
                        f"{reason}. This suggests traffic is being intercepted and re-signed by an proxy."
                    ),
                    db_path=db_path
                )

def get_network_interfaces() -> list:
    import subprocess
    try:
        tshark_exe = get_tshark_path()
        result = subprocess.run(
            [tshark_exe, "-D"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        interfaces = []
        for line in result.stdout.strip().splitlines():
            if ". " in line:
                idx_part, desc_part = line.split(". ", 1)
                idx = idx_part.strip()
                if " (" in desc_part:
                    name_part, friendly_part = desc_part.split(" (", 1)
                    name = name_part.strip()
                    friendly = friendly_part.replace(")", "").strip()
                else:
                    name = desc_part.strip()
                    friendly = name
                interfaces.append({
                    "index": idx,
                    "name": name,
                    "friendly_name": friendly
                })
        return interfaces
    except Exception as e:
        print(f"Error listing network interfaces: {e}")
        # Return fallback loopback adapters for convenience
        return [{"index": "1", "name": "\\Device\\NPF_Loopback", "friendly_name": "Adapter for loopback traffic capture"}]

def evaluate_filter(details: Dict[str, Any], filter_expr: str) -> bool:
    if not filter_expr:
        return True
    
    expr = filter_expr.strip().lower()
    if not expr:
        return True
        
    # Handle composite expressions (&&, ||)
    if '&&' in expr:
        parts = expr.split('&&')
        return all(evaluate_filter(details, p) for p in parts)
    if '||' in expr:
        parts = expr.split('||')
        return any(evaluate_filter(details, p) for p in parts)
    if ' and ' in expr:
        parts = expr.split(' and ')
        return all(evaluate_filter(details, p) for p in parts)
    if ' or ' in expr:
        parts = expr.split(' or ')
        return any(evaluate_filter(details, p) for p in parts)
        
    op = "=="
    if "!=" in expr: op = "!="
    elif ">" in expr: op = ">"
    elif "<" in expr: op = "<"
    
    parts = expr.split(op)
    key = parts[0].strip()
    val = parts[1].strip().replace('"', '').replace("'", "") if len(parts) > 1 else None
    
    # Check simple protocol filter
    if val is None:
        p_name = key.upper()
        if p_name in ["TCP", "UDP", "HTTP", "DNS", "ARP"]:
            return details.get("protocol") == p_name
        return False
        
    src_ip = details.get("source_ip", "")
    dst_ip = details.get("dst_ip", "")
    src_port = str(details.get("src_port", ""))
    dst_port = str(details.get("dst_port", ""))
    protocol = details.get("protocol", "").lower()
    length = details.get("bytes", 0)
    
    field_val = ""
    if key == "ip.src":
        field_val = src_ip
    elif key == "ip.dst":
        field_val = dst_ip
    elif key == "ip.addr":
        if op == "==":
            return (src_ip == val or dst_ip == val)
        elif op == "!=":
            return (src_ip != val and dst_ip != val)
        return False
    elif key in ["tcp.port", "udp.port"]:
        if op == "==":
            return (src_port == val or dst_port == val)
        elif op == "!=":
            return (src_port != val and dst_port != val)
        return False
    elif key in ["tcp.srcport", "udp.srcport"]:
        field_val = src_port
    elif key in ["tcp.dstport", "udp.dstport"]:
        field_val = dst_port
    elif key == "frame.len":
        try:
            v_int = int(val)
            if op == "==": return length == v_int
            if op == "!=": return length != v_int
            if op == ">": return length > v_int
            if op == "<": return length < v_int
        except ValueError:
            return False
        return False
    elif key == "http.request.method":
        field_val = details.get("http_info", {}).get("request_method", "")
    elif key == "dns.qry.name":
        field_val = details.get("dns_info", {}).get("qry_name", "")
    else:
        if key in ["tcp", "udp", "dns", "http", "arp"]:
            return protocol == key
        return False
        
    if op == "==":
        return field_val.lower() == val.lower()
    elif op == "!=":
        return field_val.lower() != val.lower()
        
    return False

class LiveCaptureManager:
    def __init__(self):
        import threading
        self.capture_thread = None
        self.capture_obj = None
        self.is_running = False
        self.captured_count = 0
        self.interface = None
        self.output_filepath = None
        self.lock = threading.Lock()
        
    def start_capture(self, interface_name: str, db_path: str, broadcast_callback, output_file: str = None) -> bool:
        with self.lock:
            if self.is_running:
                return False
            self.is_running = True
            self.captured_count = 0
            self.interface = interface_name
            self.output_filepath = output_file
            
        import threading
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(interface_name, db_path, broadcast_callback, output_file),
            daemon=True
        )
        self.capture_thread.start()
        return True
        
    def _capture_loop(self, interface_name: str, db_path: str, broadcast_callback, output_file: str = None):
        import asyncio
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        import pyshark
        tshark_exe = get_tshark_path()
        try:
            # Create live capture handle
            capture = pyshark.LiveCapture(
                interface=interface_name,
                tshark_path=tshark_exe,
                only_summaries=False,
                output_file=output_file
            )
            
            with self.lock:
                if not self.is_running:
                    try:
                        if hasattr(capture, '_process') and capture._process:
                            capture._process.kill()
                        capture.close()
                    except Exception:
                        pass
                    return
                self.capture_obj = capture
            
            for packet in self.capture_obj.sniff_continuously():
                with self.lock:
                    if not self.is_running:
                        break
                        
                self.captured_count += 1
                
                try:
                    timestamp_float = float(packet.sniff_timestamp)
                    timestamp = datetime.utcfromtimestamp(timestamp_float).isoformat() + "Z"
                except Exception:
                    timestamp = datetime.utcnow().isoformat() + "Z"
                    
                length = int(packet.length)
                proto = packet.highest_layer
                
                src_ip = "0.0.0.0"
                dst_ip = "0.0.0.0"
                src_port = 0
                dst_port = 0
                
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                elif hasattr(packet, 'ipv6'):
                    src_ip = packet.ipv6.src
                    dst_ip = packet.ipv6.dst
                elif hasattr(packet, 'arp'):
                    src_ip = getattr(packet.arp, 'src_proto_ipv4', '0.0.0.0')
                    dst_ip = getattr(packet.arp, 'dst_proto_ipv4', '0.0.0.0')
                    proto = "ARP"
                    
                if hasattr(packet, 'tcp'):
                    src_port = int(packet.tcp.srcport)
                    dst_port = int(packet.tcp.dstport)
                    proto = "TCP"
                elif hasattr(packet, 'udp'):
                    src_port = int(packet.udp.srcport)
                    dst_port = int(packet.udp.dstport)
                    proto = "UDP"
                    
                flags = {}
                if hasattr(packet, 'tcp'):
                    flags = {
                        "syn": getattr(packet.tcp, 'flags_syn', '0') == '1',
                        "ack": getattr(packet.tcp, 'flags_ack', '0') == '1',
                        "fin": getattr(packet.tcp, 'flags_fin', '0') == '1',
                        "rst": getattr(packet.tcp, 'flags_rst', '0') == '1',
                        "psh": getattr(packet.tcp, 'flags_push', '0') == '1'
                    }
                    
                http_info = {}
                if hasattr(packet, 'http'):
                    proto = "HTTP"
                    http_info = {
                        "request_method": getattr(packet.http, 'request_method', ''),
                        "request_uri": getattr(packet.http, 'request_uri', ''),
                        "user_agent": getattr(packet.http, 'user_agent', ''),
                        "authorization": getattr(packet.http, 'authorization', ''),
                        "content_type": getattr(packet.http, 'content_type', '')
                    }
                    
                dns_info = {}
                if hasattr(packet, 'dns'):
                    proto = "DNS"
                    dns_info = {
                        "qry_name": getattr(packet.dns, 'qry_name', ''),
                        "qry_type": getattr(packet.dns, 'qry_type', ''),
                        "flags": getattr(packet.dns, 'flags', '')
                    }
                    
                arp_info = {}
                if proto == "ARP" and hasattr(packet, 'arp'):
                    arp_info = {
                        "opcode": getattr(packet.arp, 'opcode', ''),
                        "src_mac": getattr(packet.arp, 'src_hw_mac', ''),
                        "dst_mac": getattr(packet.arp, 'dst_hw_mac', ''),
                        "src_ip": getattr(packet.arp, 'src_proto_ipv4', ''),
                        "dst_ip": getattr(packet.arp, 'dst_proto_ipv4', '')
                    }
                    
                packet_summary = getattr(packet, 'info', f"{proto} Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                
                # Dynamic extraction of layers and their fields for the collapsible accordion viewer
                layers_dict = {}
                for layer in packet.layers:
                    layer_name = layer.layer_name
                    layer_fields = {}
                    for field in layer.field_names:
                        try:
                            layer_fields[field] = str(getattr(layer, field))
                        except Exception:
                            pass
                    layers_dict[layer_name] = layer_fields
                    
                details = {
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "packet_summary": packet_summary,
                    "flags": flags,
                    "bytes": length,
                    "capture_id": "live_capture",
                    "layers": layers_dict,
                    "raw_line": str(packet)
                }
                
                if http_info: details["http_info"] = http_info
                if dns_info: details["dns_info"] = dns_info
                if arp_info: details["arp_info"] = arp_info
                
                # Write live event to SQLite
                ev_id = add_security_event(
                    timestamp=timestamp,
                    event_type="packet_event",
                    source_ip=src_ip,
                    details=details,
                    severity="INFO",
                    db_path=db_path
                )
                
                # Process security detections
                single_event = {
                    "id": ev_id,
                    "timestamp": timestamp,
                    "event_type": "packet_event",
                    "source_ip": src_ip,
                    "details": details,
                    "severity": "INFO"
                }
                run_pcap_detections([single_event], db_path)
                
                # Stream event back
                import asyncio
                broadcast_callback({
                    "type": "new_event",
                    "event": single_event
                })
                
        except Exception as e:
            print(f"Error in live capture loop: {e}")
        finally:
            with self.lock:
                self.is_running = False
                capture = self.capture_obj
                self.capture_obj = None
            if capture:
                try:
                    if hasattr(capture, '_process') and capture._process:
                        try:
                            capture._process.kill()
                        except Exception:
                            pass
                    capture.close()
                except Exception:
                    pass
                    
    def stop_capture(self) -> bool:
        with self.lock:
            if not self.is_running:
                return False
            self.is_running = False
            capture = self.capture_obj
            self.capture_obj = None
            
        if capture:
            try:
                if hasattr(capture, '_process') and capture._process:
                    try:
                        capture._process.kill()
                    except Exception:
                        pass
                capture.close()
            except Exception:
                pass
        return True

live_capture_manager = LiveCaptureManager()


def follow_tcp_stream(pcap_path: str, stream_id: int) -> List[Dict[str, Any]]:
    import subprocess
    tshark_exe = get_tshark_path()
    try:
        cmd = [
            tshark_exe,
            "-r", pcap_path,
            "-Y", f"tcp.stream == {stream_id}",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.payload"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        lines = result.stdout.strip().splitlines()
        
        dialog = []
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 5 and parts[4]:
                src_ip = parts[0]
                dst_ip = parts[1]
                src_port = parts[2]
                dst_port = parts[3]
                hex_payload = parts[4].replace(":", "")
                
                try:
                    payload_bytes = bytes.fromhex(hex_payload)
                    ascii_payload = payload_bytes.decode("utf-8", errors="replace")
                except Exception:
                    ascii_payload = f"[Hex Data: {hex_payload}]"
                
                dialog.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "payload_hex": hex_payload,
                    "payload_ascii": ascii_payload
                })
        return dialog
    except Exception as e:
        print(f"Error following stream {stream_id}: {e}", file=sys.stderr)
        return []


def compare_pcap_files(pcap_path1: str, pcap_path2: str) -> Dict[str, Any]:
    import subprocess
    import hashlib
    tshark_exe = get_tshark_path()
    
    def extract_packets_for_diff(path: str) -> List[Dict[str, Any]]:
        cmd = [
            tshark_exe,
            "-r", path,
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.seq",
            "-e", "tcp.ack",
            "-e", "tcp.payload"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        packets = []
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 5:
                packets.append({
                    "src": parts[0],
                    "dst": parts[1],
                    "seq": parts[2],
                    "ack": parts[3],
                    "payload": parts[4].replace(":", "")
                })
        return packets
        
    try:
        pkts1 = extract_packets_for_diff(pcap_path1)
        pkts2 = extract_packets_for_diff(pcap_path2)
        
        mismatches = []
        tampered_count = 0
        
        map1 = {(p["src"], p["dst"], p["seq"], p["ack"]): p for p in pkts1 if p["payload"]}
        map2 = {(p["src"], p["dst"], p["seq"], p["ack"]): p for p in pkts2 if p["payload"]}
        
        for key, p1 in map1.items():
            p2 = map2.get(key)
            if not p2:
                mismatches.append({
                    "flow": f"{key[0]} -> {key[1]}",
                    "seq": key[2],
                    "ack": key[3],
                    "type": "MISSING_PACKET",
                    "description": "Packet sent in source but missing or dropped in destination."
                })
                tampered_count += 1
            elif p1["payload"] != p2["payload"]:
                p1_bytes = bytes.fromhex(p1['payload'])
                p2_bytes = bytes.fromhex(p2['payload'])
                mismatches.append({
                    "flow": f"{key[0]} -> {key[1]}",
                    "seq": key[2],
                    "ack": key[3],
                    "type": "PAYLOAD_TAMPERED",
                    "description": f"Payload altered! Hash changed from {hashlib.sha256(p1_bytes).hexdigest()[:10]} to {hashlib.sha256(p2_bytes).hexdigest()[:10]}."
                })
                tampered_count += 1
                
        total_payload_pkts = len(map1)
        tamper_percent = (tampered_count / total_payload_pkts * 100) if total_payload_pkts > 0 else 0.0
        
        return {
            "total_monitored_packets": total_payload_pkts,
            "tampered_packets_count": tampered_count,
            "tamper_percentage": round(tamper_percent, 2),
            "mismatches": mismatches,
            "status": "TAMPERED" if tampered_count > 0 else "CLEAN"
        }
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}


def extract_pcap_artifacts(pcap_path: str) -> List[Dict[str, Any]]:
    import subprocess
    import base64
    tshark_exe = get_tshark_path()
    try:
        cmd = [
            tshark_exe,
            "-r", pcap_path,
            "-Y", "http.response or http.request",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "http.content_type",
            "-e", "http.file_data",
            "-e", "http.request.uri",
            "-e", "http.authorization"
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        lines = result.stdout.strip().splitlines()
        
        artifacts = []
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 3:
                src_ip = parts[0]
                content_type = parts[1]
                raw_data = parts[2]
                uri = parts[3] if len(parts) > 3 else ""
                auth = parts[4] if len(parts) > 4 else ""
                
                if auth:
                    artifacts.append({
                        "type": "credential",
                        "source": src_ip,
                        "details": f"Authorization header found: '{auth}'",
                        "filename": "Auth Header"
                    })
                
                if raw_data and content_type:
                    hex_clean = raw_data.replace(":", "").strip()
                    try:
                        file_bytes = bytes.fromhex(hex_clean)
                        if "image/" in content_type:
                            base64_str = base64.b64encode(file_bytes).decode("utf-8")
                            data_uri = f"data:{content_type};base64,{base64_str}"
                            artifacts.append({
                                "type": "image",
                                "source": src_ip,
                                "content_type": content_type,
                                "data_uri": data_uri,
                                "filename": f"image_{len(artifacts)+1}.{content_type.split('/')[-1]}",
                                "size": len(file_bytes)
                            })
                        else:
                            text_preview = file_bytes.decode("utf-8", errors="replace")[:200] + "..."
                            artifacts.append({
                                "type": "document",
                                "source": src_ip,
                                "content_type": content_type,
                                "preview": text_preview,
                                "filename": f"doc_{len(artifacts)+1}.txt",
                                "size": len(file_bytes)
                            })
                    except Exception:
                        pass
        return artifacts
    except Exception as e:
        print(f"Error extracting artifacts: {e}", file=sys.stderr)
        return []

