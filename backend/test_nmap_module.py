import sys
import os
import asyncio
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from nmap_engine import (
        validate_scan_target, validate_and_build_custom_flags,
        parse_nmap_xml_string, compute_radial_topology_coordinates,
        run_fallback_socket_scan, NmapScanJob, HIGH_RISK_PORTS
    )
except ImportError:
    from backend.nmap_engine import (
        validate_scan_target, validate_and_build_custom_flags,
        parse_nmap_xml_string, compute_radial_topology_coordinates,
        run_fallback_socket_scan, NmapScanJob, HIGH_RISK_PORTS
    )

# ── 1. INPUT VALIDATION & INJECTION PREVENTION TESTS ──────────────────────────

def test_validate_scan_target_valid():
    """Verify valid hostnames, domains, and IPs pass validation."""
    valid_targets = [
        "192.168.1.1",
        "10.0.0.5",
        "scanme.nmap.org",
        "example.internal",
        "https://api.site.com"
    ]
    for t in valid_targets:
        clean = validate_scan_target(t)
        assert clean in ["192.168.1.1", "10.0.0.5", "scanme.nmap.org", "example.internal", "api.site.com"]

def test_validate_scan_target_injection_rejection():
    """Verify malicious shell metacharacters and command injection attempts are blocked."""
    injection_attempts = [
        "127.0.0.1; cat /etc/passwd",
        "scanme.nmap.org | whoami",
        "10.0.0.1 && rm -rf /",
        "$(id)",
        "`whoami`",
        "target.com\n127.0.0.1",
        "target.com' OR '1'='1",
        "192.168.1.1 > out.txt",
        "10.0.0.1 &",
        ""
    ]
    for bad_target in injection_attempts:
        failed = False
        try:
            validate_scan_target(bad_target)
        except ValueError:
            failed = True
        assert failed, f"Expected ValueError for injection target: {bad_target}"

def test_custom_builder_flags_valid():
    """Verify custom builder produces safe, typed flag array."""
    params = {
        "timing": "T3",
        "no_ping": True,
        "detect_os": True,
        "detect_version": True,
        "traceroute": True,
        "port_range": "80,443,8000-8080",
        "min_rate": 500,
        "scripts": ["vulners", "banner", "invalid_script_name"]
    }
    flags = validate_and_build_custom_flags(params)
    assert "-T3" in flags
    assert "-Pn" in flags
    assert "-O" in flags
    assert "-sV" in flags
    assert "--traceroute" in flags
    assert "-p" in flags
    assert "80,443,8000-8080" in flags
    assert "--min-rate=500" in flags
    assert "--script=vulners,banner" in flags
    assert "invalid_script_name" not in "".join(flags)

def test_custom_builder_flags_rejection():
    """Verify out-of-range rates and malicious port syntax are rejected."""
    rate_failed = False
    try:
        validate_and_build_custom_flags({"min_rate": 99999})
    except ValueError:
        rate_failed = True
    assert rate_failed

    port_failed = False
    try:
        validate_and_build_custom_flags({"port_range": "80; rm -rf /"})
    except ValueError:
        port_failed = True
    assert port_failed

# ── 2. XML STREAMING & MALFORMED PARSER TESTS ─────────────────────────────────

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -F scanme.nmap.org" start="1700000000">
<host starttime="1700000000" endtime="1700000010">
  <status state="up" reason="echo-reply"/>
  <address addr="45.33.32.156" addrtype="ipv4"/>
  <hostnames>
    <hostname name="scanme.nmap.org" type="user"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="8.2p1"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack"/>
      <service name="http" product="Apache httpd" version="2.4.41"/>
    </port>
    <port protocol="tcp" portid="3389">
      <state state="open" reason="syn-ack"/>
      <service name="ms-wbt-server" product="Microsoft Terminal Services"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 5.4" accuracy="95"/>
  </os>
  <trace>
    <hop ttl="1" ipaddr="192.168.1.1" rtt="1.2"/>
    <hop ttl="2" ipaddr="10.0.0.1" rtt="4.5"/>
  </trace>
</host>
</nmaprun>
"""

def test_parse_nmap_xml_well_formed():
    """Verify parsing well-formed Nmap XML extract hosts, ports, OS, risk, and hops."""
    hosts = parse_nmap_xml_string(SAMPLE_NMAP_XML)
    assert len(hosts) == 1
    h = hosts[0]
    assert h["ip"] == "45.33.32.156"
    assert "scanme.nmap.org" in h["hostnames"]
    assert len(h["ports"]) == 3
    assert h["risk_level"] == "high"
    assert len(h["trace_hops"]) == 2
    assert h["os_matches"][0]["name"] == "Linux 5.4"

def test_parse_nmap_xml_truncated_streaming():
    """Verify parser recovers complete host fragments from streaming unclosed XML."""
    truncated_xml = """<nmaprun><host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host><host><status state="up"/><address addr="10.0.0.3" addrtype="ipv4"/><ports><port"""
    hosts = parse_nmap_xml_string(truncated_xml)
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "10.0.0.2"
    assert hosts[0]["ports"][0]["port"] == 80

# ── 3. RADIAL TOPOLOGY COORDINATES TESTS ──────────────────────────────────────

def test_compute_radial_topology_coordinates():
    """Verify server-side O(N) radial topology ring positioning."""
    hosts = parse_nmap_xml_string(SAMPLE_NMAP_XML)
    topo = compute_radial_topology_coordinates(hosts, origin_label="Scanner")
    
    assert "nodes" in topo
    assert "links" in topo
    nodes = topo["nodes"]
    
    # Origin node
    origin = [n for n in nodes if n["ring"] == 0]
    assert len(origin) == 1
    assert origin[0]["x"] == 0.0 and origin[0]["y"] == 0.0
    
    # Hop nodes (Ring 1)
    hops = [n for n in nodes if n["ring"] == 1]
    assert len(hops) == 2
    for hop in hops:
        radius = (hop["x"]**2 + hop["y"]**2)**0.5
        assert abs(radius - 140.0) < 1.0
        
    # Target node (Ring 2)
    targets = [n for n in nodes if n["ring"] == 2]
    assert len(targets) == 1
    radius = (targets[0]["x"]**2 + targets[0]["y"]**2)**0.5
    assert abs(radius - 280.0) < 1.0

# ── 4. FALLBACK SOCKET SCANNER TEST ───────────────────────────────────────────

async def test_run_fallback_socket_scan():
    """Verify fallback native TCP connect-scan activates when nmap is absent."""
    job = NmapScanJob("test_scan", "127.0.0.1", "fallback", [])
    hosts = await run_fallback_socket_scan("127.0.0.1", job)
    assert job.status == "completed"
    assert job.engine_type == "basic connect-scan (nmap unavailable)"
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "127.0.0.1"

if __name__ == "__main__":
    print("Running Web Zenmap / Nmap Engine test suite...")
    test_validate_scan_target_valid()
    test_validate_scan_target_injection_rejection()
    test_custom_builder_flags_valid()
    test_custom_builder_flags_rejection()
    test_parse_nmap_xml_well_formed()
    test_parse_nmap_xml_truncated_streaming()
    test_compute_radial_topology_coordinates()
    asyncio.run(test_run_fallback_socket_scan())
    print("All Nmap Engine unit tests PASSED successfully!")
