"""
Web Zenmap / Nmap Studio Engine (Module 13)
Provides asynchronous Nmap process management, streaming XML incremental parsing,
radial topology coordinate calculation, and native connect-scan fallback.
"""

import asyncio
import os
import re
import sys
import shutil
import time
import socket
import math
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Tuple, Set

# High-risk ports list (configurable)
HIGH_RISK_PORTS = {
    21: "FTP (Plaintext)",
    23: "Telnet (Insecure Plaintext)",
    69: "TFTP",
    135: "MS-RPC Endpoint",
    139: "NetBIOS Session",
    445: "SMB (EternalBlue/Ransomware Risk)",
    1433: "MS-SQL Server",
    1521: "Oracle Database",
    3306: "MySQL Database",
    3389: "RDP Remote Desktop",
    5432: "PostgreSQL Database",
    5900: "VNC Remote Access",
    6379: "Redis (Unauthenticated Risk)",
    9200: "Elasticsearch",
    27017: "MongoDB Exposed"
}

ALLOWED_NSE_SCRIPTS = {
    "vulners",
    "ssl-enum-ciphers",
    "http-headers",
    "banner",
    "default",
    "http-title",
    "ssh-auth-methods"
}

ZENMAP_PROFILES = {
    "quick_scan": {
        "id": "quick_scan",
        "name": "Quick Scan",
        "description": "Fast scan of top 100 ports using aggressive timing.",
        "flags": ["-T4", "-F"],
        "estimated_duration": "5-15s"
    },
    "ping_sweep": {
        "id": "ping_sweep",
        "name": "Ping Sweep",
        "description": "Fast ICMP & ARP host discovery sweep without port scanning.",
        "flags": ["-sn"],
        "estimated_duration": "2-8s"
    },
    "intense_scan": {
        "id": "intense_scan",
        "name": "Intense Scan (OS & Services)",
        "description": "Comprehensive scan with OS fingerprinting, version probing, scripts & traceroute.",
        "flags": ["-T4", "-A", "-v"],
        "estimated_duration": "30-90s"
    },
    "nse_vuln_audit": {
        "id": "nse_vuln_audit",
        "name": "NSE Vulnerability Audit",
        "description": "Probes services with safe NSE scripts and correlates with Vulners CVE database.",
        "flags": ["-sV", "--script=vulners,ssl-enum-ciphers,http-headers,banner"],
        "estimated_duration": "40-120s"
    }
}

# Regex for strict validation
TARGET_REGEX = re.compile(r'^[a-zA-Z0-9.\-_/:]+$')
PORT_RANGE_REGEX = re.compile(r'^(top100|top1000|[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*)$')


def find_nmap_binary() -> Optional[str]:
    """Finds nmap executable on system PATH or standard locations."""
    exe = shutil.which("nmap")
    if exe:
        return exe
    common_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/opt/homebrew/bin/nmap"
    ]
    for p in common_paths:
        if os.path.exists(p):
            return p
    return None


def validate_scan_target(target: str) -> str:
    """
    Validates and sanitizes a scan target hostname or IP address.
    Rejects shell metacharacters and suspicious injection strings.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target string cannot be empty.")
    
    clean_target = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
    
    # Check for disallowed shell characters
    for bad_char in [";", "&", "|", "$", "`", "'", '"', "<", ">", "(", ")", "!", "{", "}", "[", "]", "*", "?", "\n", "\r", " "]:
        if bad_char in target:
            raise ValueError(f"Malicious character detected in target: {repr(bad_char)}")
            
    if not TARGET_REGEX.match(clean_target):
        raise ValueError(f"Invalid target hostname or IP syntax: {target}")
        
    return clean_target


def validate_and_build_custom_flags(builder_params: Dict[str, Any]) -> List[str]:
    """
    Safely translates strongly-typed UI builder toggles into an immutable flag array.
    Guarantees no arbitrary free-text flag injection.
    """
    flags: List[str] = []
    
    # Timing template
    timing = builder_params.get("timing", "T4")
    if timing in ["T0", "T1", "T2", "T3", "T4", "T5"]:
        flags.append(f"-{timing}")
    else:
        flags.append("-T4")
        
    # Ping Mode
    if builder_params.get("no_ping", False):
        flags.append("-Pn")
        
    # Traceroute
    if builder_params.get("traceroute", False):
        flags.append("--traceroute")
        
    # Service Version Probing
    if builder_params.get("detect_version", True):
        flags.append("-sV")
        
    # OS Detection
    if builder_params.get("detect_os", False):
        flags.append("-O")
        
    # Scan Type (TCP Connect is non-root safe)
    scan_type = builder_params.get("scan_type", "tcp_connect")
    if scan_type == "tcp_connect":
        flags.append("-sT")
    elif scan_type == "udp":
        flags.append("-sU")
        
    # Port Range
    ports = builder_params.get("port_range")
    if ports:
        ports_str = str(ports).strip()
        if ports_str == "top100":
            flags.append("-F")
        elif ports_str == "top1000":
            pass # Nmap default is top 1000
        elif PORT_RANGE_REGEX.match(ports_str):
            flags.extend(["-p", ports_str])
        else:
            raise ValueError(f"Invalid port range specification: {ports_str}")
            
    # Rate Limiting
    min_rate = builder_params.get("min_rate")
    if min_rate is not None:
        try:
            rate_val = int(min_rate)
            if 1 <= rate_val <= 5000:
                flags.append(f"--min-rate={rate_val}")
            else:
                raise ValueError("min_rate must be an integer between 1 and 5000.")
        except (ValueError, TypeError):
            raise ValueError("Invalid min_rate value.")
            
    # NSE Scripts Allowlist
    requested_scripts = builder_params.get("scripts", [])
    if requested_scripts:
        if isinstance(requested_scripts, str):
            requested_scripts = [s.strip() for s in requested_scripts.split(",") if s.strip()]
        valid_scripts = [s for s in requested_scripts if s in ALLOWED_NSE_SCRIPTS]
        if valid_scripts:
            flags.append(f"--script={','.join(valid_scripts)}")
            
    return flags


class NmapScanJob:
    """Manages scan lifecycle, streaming parsing, status updates, and cancellation."""
    def __init__(self, scan_id: str, target: str, profile: str, flags: List[str]):
        self.scan_id = scan_id
        self.target = target
        self.profile = profile
        self.flags = flags
        self.status = "initializing"
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.progress: int = 0
        self.hosts: List[Dict[str, Any]] = []
        self.raw_output: str = ""
        self.engine_type: str = "nmap"
        self.error: Optional[str] = None
        self.is_cancelled: bool = False
        self._process: Optional[asyncio.subprocess.Process] = None

    def cancel(self):
        self.is_cancelled = True
        self.status = "cancelled"
        if self._process and self._process.returncode is None:
            try:
                self._process.kill()
            except Exception:
                pass


_ACTIVE_NMAP_JOBS: Dict[str, NmapScanJob] = {}


def parse_host_xml_element(host_elem: ET.Element) -> Dict[str, Any]:
    """Parses a single <host> XML element from Nmap output into a structured dict."""
    host_data: Dict[str, Any] = {
        "status": "up",
        "ip": "",
        "ipv6": "",
        "hostnames": [],
        "ports": [],
        "os_matches": [],
        "trace_hops": [],
        "vulnerabilities": [],
        "risk_level": "clean"
    }

    # Status
    status_el = host_elem.find("status")
    if status_el is not None:
        host_data["status"] = status_el.get("state", "unknown")

    # Addresses
    for addr in host_elem.findall("address"):
        addr_type = addr.get("addrtype", "ipv4")
        if addr_type == "ipv4":
            host_data["ip"] = addr.get("addr", "")
        elif addr_type == "ipv6":
            host_data["ipv6"] = addr.get("addr", "")

    # Hostnames
    hostnames_el = host_elem.find("hostnames")
    if hostnames_el is not None:
        for hn in hostnames_el.findall("hostname"):
            name = hn.get("name")
            if name:
                host_data["hostnames"].append(name)

    # Ports & Services
    ports_el = host_elem.find("ports")
    has_high_risk = False
    has_open_ports = False

    if ports_el is not None:
        for p in ports_el.findall("port"):
            p_id = int(p.get("portid", 0))
            proto = p.get("protocol", "tcp")
            
            state_el = p.find("state")
            state = state_el.get("state", "closed") if state_el is not None else "unknown"
            
            service_el = p.find("service")
            svc_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
            svc_product = service_el.get("product", "") if service_el is not None else ""
            svc_version = service_el.get("version", "") if service_el is not None else ""
            svc_extrainfo = service_el.get("extrainfo", "") if service_el is not None else ""
            
            # Check for script outputs on port
            scripts = []
            for sc in p.findall("script"):
                sc_id = sc.get("id", "")
                sc_out = sc.get("output", "")
                scripts.append({"id": sc_id, "output": sc_out})
                
                # Correlate Vulners output with findings
                if sc_id == "vulners" and sc_out:
                    for line in sc_out.splitlines():
                        if "CVE-" in line:
                            parts = [x.strip() for x in line.split("\t") if x.strip()]
                            if len(parts) >= 2:
                                host_data["vulnerabilities"].append({
                                    "cve": parts[0],
                                    "cvss_score": float(parts[1]) if parts[1].replace(".", "").isdigit() else 7.0,
                                    "port": p_id,
                                    "service": svc_name,
                                    "link": f"https://nvd.nist.gov/vuln/detail/{parts[0]}"
                                })

            if state == "open":
                has_open_ports = True
                if p_id in HIGH_RISK_PORTS:
                    has_high_risk = True

            host_data["ports"].append({
                "port": p_id,
                "protocol": proto,
                "state": state,
                "service": svc_name,
                "product": svc_product,
                "version": svc_version,
                "extra_info": svc_extrainfo,
                "is_high_risk": p_id in HIGH_RISK_PORTS,
                "high_risk_reason": HIGH_RISK_PORTS.get(p_id),
                "scripts": scripts
            })

    # OS Detection
    os_el = host_elem.find("os")
    if os_el is not None:
        for match in os_el.findall("osmatch"):
            name = match.get("name", "")
            accuracy = int(match.get("accuracy", 0))
            host_data["os_matches"].append({"name": name, "accuracy": accuracy})

    # Traceroute Hops
    trace_el = host_elem.find("trace")
    if trace_el is not None:
        for hop in trace_el.findall("hop"):
            ttl = int(hop.get("ttl", 1))
            rtt = float(hop.get("rtt", 0.0)) if hop.get("rtt") else 0.0
            hop_ip = hop.get("ipaddr", "")
            host_data["trace_hops"].append({
                "ttl": ttl,
                "rtt_ms": rtt,
                "ip": hop_ip
            })

    # Determine risk level
    if has_high_risk or len(host_data["vulnerabilities"]) > 0:
        host_data["risk_level"] = "high"
    elif has_open_ports:
        host_data["risk_level"] = "medium"
    else:
        host_data["risk_level"] = "clean"

    return host_data


def parse_nmap_xml_string(xml_str: str) -> List[Dict[str, Any]]:
    """Safely parses complete or chunked Nmap XML without external entity resolution."""
    if not xml_str.strip():
        return []
    try:
        root = ET.fromstring(xml_str)
        hosts = []
        for h in root.findall("host"):
            hosts.append(parse_host_xml_element(h))
        return hosts
    except Exception:
        # If XML is incomplete or truncated, attempt to extract complete <host> ... </host> blocks
        if "<host" in xml_str and "</host>" in xml_str:
            try:
                pattern = re.compile(r'<host.*?</host>', re.DOTALL)
                matches = pattern.findall(xml_str)
                hosts = []
                for m in matches:
                    h_elem = ET.fromstring(m)
                    hosts.append(parse_host_xml_element(h_elem))
                return hosts
            except Exception:
                pass
        return []


async def run_fallback_socket_scan(target: str, job: NmapScanJob) -> List[Dict[str, Any]]:
    """
    Native non-blocking async TCP connect-scan when Nmap binary is absent.
    Probes common ports and collects basic service banners.
    """
    job.engine_type = "basic connect-scan (nmap unavailable)"
    job.status = "running"
    
    try:
        target_ip = socket.gethostbyname(target)
    except Exception as e:
        job.error = f"DNS resolution failed: {e}"
        job.status = "failed"
        return []

    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
    open_ports = []
    
    async def probe_port(port: int):
        if job.is_cancelled:
            return
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=1.5
            )
            banner = ""
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=0.5)
                banner = data.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
                
            writer.close()
            await writer.wait_closed()
            
            svc = "http" if port in [80, 8080] else "https" if port in [443, 8443] else "ssh" if port == 22 else "unknown"
            open_ports.append({
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": svc,
                "product": banner[:50] if banner else "",
                "version": "",
                "extra_info": "",
                "is_high_risk": port in HIGH_RISK_PORTS,
                "high_risk_reason": HIGH_RISK_PORTS.get(port),
                "scripts": []
            })
        except Exception:
            pass

    tasks = [probe_port(p) for p in common_ports]
    await asyncio.gather(*tasks)

    has_high_risk = any(p["is_high_risk"] for p in open_ports)
    risk_level = "high" if has_high_risk else "medium" if len(open_ports) > 0 else "clean"

    host_data = {
        "status": "up",
        "ip": target_ip,
        "ipv6": "",
        "hostnames": [target] if target != target_ip else [],
        "ports": sorted(open_ports, key=lambda x: x["port"]),
        "os_matches": [],
        "trace_hops": [],
        "vulnerabilities": [],
        "risk_level": risk_level
    }
    
    job.hosts = [host_data]
    job.progress = 100
    job.status = "completed"
    job.end_time = time.time()
    return [host_data]


async def execute_nmap_scan_async(job: NmapScanJob, timeout_seconds: int = 180):
    """
    Launches Nmap as an asynchronous subprocess, incrementally streams stdout XML,
    and handles process timeouts and cancellations.
    """
    nmap_path = find_nmap_binary()
    if not nmap_path:
        await run_fallback_socket_scan(job.target, job)
        return

    job.status = "running"
    cmd = [nmap_path, "-oX", "-"] + job.flags + [job.target]
    
    try:
        job._process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        xml_chunks = []
        
        async def read_stream():
            while True:
                if job.is_cancelled:
                    break
                chunk = await job._process.stdout.read(4096)
                if not chunk:
                    break
                text = chunk.decode("utf-8", errors="ignore")
                xml_chunks.append(text)
                job.raw_output += text
                
                # Incremental parsing
                accumulated = "".join(xml_chunks)
                discovered = parse_nmap_xml_string(accumulated)
                if discovered:
                    job.hosts = discovered
                    job.progress = min(90, 20 + len(discovered) * 20)

        # Wait with hard wall-clock timeout
        try:
            await asyncio.wait_for(read_stream(), timeout=timeout_seconds)
            await job._process.wait()
        except asyncio.TimeoutError:
            job.cancel()
            job.error = f"Scan exceeded timeout limit of {timeout_seconds}s."
            job.status = "timeout"
            return

        if not job.is_cancelled:
            full_xml = "".join(xml_chunks)
            parsed_final = parse_nmap_xml_string(full_xml)
            if parsed_final:
                job.hosts = parsed_final
            job.progress = 100
            job.status = "completed"
            job.end_time = time.time()

    except Exception as e:
        job.status = "failed"
        job.error = str(e)
    finally:
        if job._process and job._process.returncode is None:
            try:
                job._process.kill()
            except Exception:
                pass


def compute_radial_topology_coordinates(hosts: List[Dict[str, Any]], origin_label: str = "Scanner (Localhost)") -> Dict[str, Any]:
    """
    Computes server-side radial coordinate positions (O(N)) for Zenmap topology visualization.
    Concentric rings:
    - Ring 0 (Center): Origin gateway
    - Ring 1 (Radius 140px): Intermediate router hops from traceroute
    - Ring 2 (Radius 280px): Target host endpoints
    """
    nodes = []
    links = []
    
    # 1. Center Origin Node
    origin_node = {
        "id": "node_origin",
        "label": origin_label,
        "type": "origin",
        "ring": 0,
        "x": 0.0,
        "y": 0.0,
        "risk": "clean",
        "ports_count": 0
    }
    nodes.append(origin_node)

    # Collect all unique hops
    hop_nodes_map = {}
    target_nodes = []

    for host in hosts:
        ip = host.get("ip") or (host.get("hostnames", ["Unknown"])[0] if host.get("hostnames") else "Unknown")
        risk = host.get("risk_level", "clean")
        open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
        
        # Check hops
        hops = host.get("trace_hops", [])
        last_hop_id = "node_origin"
        
        for hop in hops:
            h_ip = hop.get("ip")
            if h_ip and h_ip not in hop_nodes_map:
                h_id = f"hop_{h_ip.replace('.', '_')}"
                hop_nodes_map[h_ip] = {
                    "id": h_id,
                    "label": f"Hop {hop.get('ttl')}: {h_ip}",
                    "type": "hop",
                    "ip": h_ip,
                    "rtt_ms": hop.get("rtt_ms", 0),
                    "ring": 1,
                    "risk": "clean",
                    "parent_id": last_hop_id
                }
                last_hop_id = h_id

        target_nodes.append({
            "id": f"target_{ip.replace('.', '_').replace(':', '_')}",
            "label": host.get("hostnames", [ip])[0] if host.get("hostnames") else ip,
            "type": "target",
            "ip": ip,
            "ring": 2,
            "risk": risk,
            "open_ports_count": len(open_ports),
            "ports_preview": [p["port"] for p in open_ports[:4]],
            "os": host.get("os_matches", [{}])[0].get("name", "Unknown OS") if host.get("os_matches") else "Unknown OS",
            "parent_id": last_hop_id if hops else "node_origin"
        })

    # 2. Position Ring 1 (Traceroute Hops)
    hop_list = list(hop_nodes_map.values())
    r1 = 140.0
    for idx, h in enumerate(hop_list):
        angle = (2 * math.pi * idx) / max(1, len(hop_list))
        h["x"] = round(r1 * math.cos(angle), 2)
        h["y"] = round(r1 * math.sin(angle), 2)
        nodes.append(h)
        links.append({"source": "node_origin", "target": h["id"]})

    # 3. Position Ring 2 (Target Endpoints)
    r2 = 280.0
    for idx, t in enumerate(target_nodes):
        angle = (2 * math.pi * idx) / max(1, len(target_nodes))
        t["x"] = round(r2 * math.cos(angle), 2)
        t["y"] = round(r2 * math.sin(angle), 2)
        nodes.append(t)
        links.append({"source": t["parent_id"], "target": t["id"]})

    return {
        "nodes": nodes,
        "links": links,
        "total_hosts": len(hosts),
        "high_risk_count": sum(1 for h in hosts if h.get("risk_level") == "high"),
        "medium_risk_count": sum(1 for h in hosts if h.get("risk_level") == "medium"),
        "clean_count": sum(1 for h in hosts if h.get("risk_level") == "clean")
    }
