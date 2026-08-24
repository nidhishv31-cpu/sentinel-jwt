import asyncio
import uuid
import os
import sys
import tempfile
import json
from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
from datetime import datetime

from backend.database import (
    init_db, DEFAULT_DB_PATH, get_connection, add_security_event, 
    add_alert, get_alerts, update_alert_status
)
from backend.models import (
    JWTAnalysisRequest, JWTAnalysisResponse, JWTFinding,
    JWTBatchAnalysisRequest, JWTBatchAnalysisResponse,
    LogIngestResponse, AlertSchema, AlertStatusUpdate, PcapSummaryResponse
)
from backend.jwt_analyzer import analyze_jwt
from backend.log_parser import parse_log_content
from backend.pcap_analyzer import (
    parse_pcap_file, check_tshark_installed, get_tshark_path,
    get_network_interfaces, evaluate_filter, live_capture_manager,
    follow_tcp_stream, get_pcap_tcp_streams, compare_pcap_files, extract_pcap_artifacts
)
from backend.threat_intel import fetch_and_store_feeds, lookup_ip, get_threat_intel_stats
from backend.geo_lookup import geolocate_ip, get_attack_map_data
from backend.waf_middleware import WAFMiddleware, block_ip, unblock_ip, get_blocked_ips, reload_blocked_ips
from backend.key_manager import get_jwks, rotate_keys, list_keys, get_active_key
from pydantic import BaseModel

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
from backend.detection_rules import run_siem_rules

app = FastAPI(title="SentinelJWT Security Suite", version="1.0.0")

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In development, allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(WAFMiddleware, db_path=DEFAULT_DB_PATH)

# WebSocket Connections Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                # Handle disconnected or stale sockets gracefully
                pass

manager = ConnectionManager()

@app.on_event("startup")
def startup_event():
    # 1. Initialize SQLite Database
    init_db()
    print(f"[INIT] SQLite Database initialized at {DEFAULT_DB_PATH}")
    
    # Reload WAF blocked IPs now that tables exist
    reload_blocked_ips(DEFAULT_DB_PATH)
    
    # 2. Check for tshark installation
    try:
        tshark_path = get_tshark_path()
        print(f"[INIT] tshark located successfully: {tshark_path}")
    except FileNotFoundError as e:
        print("\n" + "!" * 80, file=sys.stderr)
        print(f"[CRITICAL ERROR] {str(e)}", file=sys.stderr)
        print("!" * 80 + "\n", file=sys.stderr)

@app.get("/")
@app.get("/health")
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SentinelJWT Security Suite",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

# --- 1. JWT ANALYZER ENDPOINTS ---

@app.post("/api/jwt/analyze", response_model=JWTAnalysisResponse)
def analyze_token(req: JWTAnalysisRequest):
    result = analyze_jwt(req.token, req.secret)
    # Log the analysis attempt in the database
    details = {
        "token_snippet": req.token[:15] + "..." if len(req.token) > 15 else req.token,
        "findings_count": len(result["findings"]),
        "risk_score": result["risk_score"]
    }
    
    add_security_event(
        timestamp=datetime.utcnow().isoformat() + "Z",
        event_type="jwt_finding",
        source_ip="127.0.0.1",
        details=details,
        severity="INFO" if result["risk_score"] < 30 else ("MEDIUM" if result["risk_score"] < 70 else "HIGH")
    )
    
    return result

@app.post("/api/jwt/analyze-batch", response_model=JWTBatchAnalysisResponse)
async def analyze_token_batch(req: JWTBatchAnalysisRequest):
    findings_count = 0
    
    for token in req.tokens:
        result = analyze_jwt(token)
        if result["findings"]:
            findings_count += len(result["findings"])
            
        details = {
            "token": token,
            "findings": result["findings"],
            "risk_score": result["risk_score"],
            "header": result["decoded_header"],
            "payload": result["decoded_payload"]
        }
        
        severity = "INFO"
        if result["risk_score"] >= 75:
            severity = "CRITICAL"
        elif result["risk_score"] >= 50:
            severity = "HIGH"
        elif result["risk_score"] >= 25:
            severity = "MEDIUM"
            
        # PUSH finding as SecurityEvent into SQLite
        ev_id = add_security_event(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type="jwt_finding",
            source_ip="127.0.0.1",
            details=details,
            severity=severity
        )
        
        # Broadcast to WebSocket
        await manager.broadcast({
            "type": "new_event",
            "event": {
                "id": ev_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": "jwt_finding",
                "source_ip": "127.0.0.1",
                "details": details,
                "severity": severity
            }
        })
        
    return {
        "total_analyzed": len(req.tokens),
        "findings_count": findings_count
    }

@app.get("/api/jwt/history")
def get_jwt_history(page: int = 1, limit: int = 20):
    conn = get_connection()
    cursor = conn.cursor()
    offset = (page - 1) * limit
    
    cursor.execute(
        "SELECT * FROM security_events WHERE event_type = 'jwt_finding' ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset)
    )
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for r in rows:
        item = dict(r)
        item["details"] = json.loads(item["details"])
        history.append(item)
    return history

# --- 2. SIEM LOG ANALYSIS ENDPOINTS ---

@app.post("/api/logs/ingest", response_model=LogIngestResponse)
async def ingest_logs(file: UploadFile = File(...)):
    try:
        content = (await file.read()).decode("utf-8")
        parsed_events = parse_log_content(content)
        
        if not parsed_events:
            return {
                "success": False,
                "events_parsed": 0,
                "message": "No valid log lines parsed. Check file format (Apache Combined or JSON Lines)."
            }
            
        # Write to DB & Broadcast
        for event in parsed_events:
            ev_id = add_security_event(
                timestamp=event["timestamp"],
                event_type=event.get("event_type", "auth_log"),
                source_ip=event["source_ip"],
                details=event["details"],
                severity=event["severity"]
            )
            
            # Broadcast to UI
            await manager.broadcast({
                "type": "new_event",
                "event": {
                    "id": ev_id,
                    "timestamp": event["timestamp"],
                    "event_type": event.get("event_type", "auth_log"),
                    "source_ip": event["source_ip"],
                    "details": event["details"],
                    "severity": event["severity"]
                }
            })
            
        # Run detection engine rules automatically
        new_alerts = run_siem_rules(DEFAULT_DB_PATH)
        
        # Broadcast new alerts if any
        if new_alerts:
            alerts_list = get_alerts()
            latest_alerts = [a for a in alerts_list if a["id"] in new_alerts]
            for a in latest_alerts:
                await manager.broadcast({
                    "type": "new_alert",
                    "alert": a
                })
                
        return {
            "success": True,
            "events_parsed": len(parsed_events),
            "events": parsed_events,
            "message": f"Successfully parsed and ingested {len(parsed_events)} events. Triggered {len(new_alerts)} alerts."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Log ingestion failed: {str(e)}")

@app.post("/api/analysis/run")
async def trigger_analysis():
    new_alerts = run_siem_rules(DEFAULT_DB_PATH)
    alerts_list = get_alerts()
    latest_alerts = [a for a in alerts_list if a["id"] in new_alerts]
    
    # Broadcast alerts
    for a in latest_alerts:
        await manager.broadcast({
            "type": "new_alert",
            "alert": a
        })
        
    return {
        "status": "success",
        "alerts_generated_count": len(new_alerts),
        "alerts": latest_alerts
    }

@app.get("/api/siem/diagnostics")
def fetch_siem_diagnostics():
    from backend.diagnostics import generate_diagnostics
    return generate_diagnostics(DEFAULT_DB_PATH)

@app.get("/api/alerts")
def fetch_alerts(status: Optional[str] = None):
    return get_alerts(status)

@app.put("/api/alerts/{alert_id}/status")
async def set_alert_status(alert_id: int, req: AlertStatusUpdate):
    updated = update_alert_status(alert_id, req.status)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    await manager.broadcast({
        "type": "alert_updated",
        "alert_id": alert_id,
        "status": req.status
    })
    
    return {"status": "success", "message": f"Alert status updated to {req.status}"}

# --- 3. PCAP ANALYZER ENDPOINTS ---

@app.post("/api/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)):
    # Verify tshark is installed
    if not check_tshark_installed():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "tshark engine is missing on the server. Packet Capture analysis is disabled. "
                "Please install Wireshark/tshark on the server."
            )
        )
        
    target_path = os.path.join(UPLOAD_DIR, file.filename)
    try:
        content = await file.read()
        with open(target_path, "wb") as f:
            f.write(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save upload file: {str(e)}")
        
    try:
        # Parse PCAP, save security_events, run detections
        summary = parse_pcap_file(target_path, DEFAULT_DB_PATH)
        summary["capture_id"] = file.filename
        
        # Broadcast reload trigger to UI
        await manager.broadcast({
            "type": "pcap_ingested",
            "summary": summary
        })
        
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PCAP parsing failed: {str(e)}")


@app.get("/api/pcap/captures")
def list_uploaded_captures():
    """List all available PCAP capture files in upload directory."""
    files = []
    for f in os.listdir(UPLOAD_DIR):
        if f.endswith(('.pcap', '.pcapng', '.cap')):
            full_p = os.path.join(UPLOAD_DIR, f)
            files.append({
                "filename": f,
                "size_bytes": os.path.getsize(full_p),
                "modified_at": datetime.fromtimestamp(os.path.getmtime(full_p)).isoformat()
            })
    return sorted(files, key=lambda x: x["modified_at"], reverse=True)


KEYS_DIR = os.path.join(UPLOAD_DIR, "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

@app.post("/api/pcap/upload-keylog")
async def upload_tls_keylog(file: UploadFile = File(...)):
    """Uploads a TLS keylog file (e.g. SSLKEYLOGFILE) or RSA Private Key (.pem/.key) for live packet decryption."""
    target_path = os.path.join(KEYS_DIR, file.filename)
    try:
        content = await file.read()
        with open(target_path, "wb") as f:
            f.write(content)
        return {
            "status": "success",
            "keylog_id": file.filename,
            "filename": file.filename,
            "size_bytes": len(content),
            "message": f"TLS decryption key file '{file.filename}' uploaded successfully."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload keylog: {str(e)}")

@app.get("/api/pcap/keylogs")
def list_uploaded_keylogs():
    """Lists all available TLS keylog / private key files."""
    files = []
    if os.path.exists(KEYS_DIR):
        for f in os.listdir(KEYS_DIR):
            full_p = os.path.join(KEYS_DIR, f)
            if os.path.isfile(full_p):
                files.append({
                    "keylog_id": f,
                    "filename": f,
                    "size_bytes": os.path.getsize(full_p),
                    "modified_at": datetime.fromtimestamp(os.path.getmtime(full_p)).isoformat()
                })
    return sorted(files, key=lambda x: x["modified_at"], reverse=True)

@app.get("/api/pcap/streams")
def get_pcap_streams(capture_id: str, keylog_id: Optional[str] = None):
    """Extracts all distinct TCP streams from the specified PCAP file with optional TLS keylog decryption."""
    target_path = os.path.join(UPLOAD_DIR, capture_id)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="PCAP file not found.")
    
    keylog_path = os.path.join(KEYS_DIR, keylog_id) if keylog_id else None
    if keylog_path and not os.path.exists(keylog_path):
        keylog_path = None

    streams = get_pcap_tcp_streams(target_path, keylog_path=keylog_path)
    return {"capture_id": capture_id, "streams": streams, "keylog_id": keylog_id}


@app.get("/api/pcap/follow-stream")
def get_followed_stream(capture_id: str, stream_id: int = 0, combine_all: bool = False, keylog_id: Optional[str] = None):
    target_path = os.path.join(UPLOAD_DIR, capture_id)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="PCAP file not found. Please upload it again.")
    
    keylog_path = os.path.join(KEYS_DIR, keylog_id) if keylog_id else None
    if keylog_path and not os.path.exists(keylog_path):
        keylog_path = None

    dialog = follow_tcp_stream(target_path, stream_id, combine_all=combine_all, keylog_path=keylog_path)
    return {
        "capture_id": capture_id, 
        "stream_id": -1 if combine_all else stream_id, 
        "combined": combine_all,
        "keylog_id": keylog_id,
        "dialog": dialog
    }


@app.post("/api/pcap/compare")
async def compare_captures(file1: UploadFile = File(...), file2: UploadFile = File(...)):
    path1 = os.path.join(UPLOAD_DIR, "diff_src_" + file1.filename)
    path2 = os.path.join(UPLOAD_DIR, "diff_dst_" + file2.filename)
    try:
        with open(path1, "wb") as f:
            f.write(await file1.read())
        with open(path2, "wb") as f:
            f.write(await file2.read())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write comparison files: {str(e)}")
        
    result = compare_pcap_files(path1, path2)
    
    # Cleanup comparison files to prevent storage bloat
    for p in [path1, path2]:
        if os.path.exists(p):
            os.remove(p)
            
    return result


@app.get("/api/pcap/extract-artifacts")
def get_extracted_artifacts(capture_id: str):
    target_path = os.path.join(UPLOAD_DIR, capture_id)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="PCAP file not found.")
    artifacts = extract_pcap_artifacts(target_path)
    return {"capture_id": capture_id, "artifacts": artifacts}

@app.get("/api/pcap/summary/{capture_id}")
def get_pcap_summary(capture_id: str):
    # Retrieve summary statistics on the fly based on security_events with details capture_id matching
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, timestamp, source_ip, details, severity FROM security_events WHERE event_type = 'packet_event' AND details LIKE ?",
        (f'%"{capture_id}"%',)
    )
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        raise HTTPException(status_code=404, detail="PCAP summary capture not found in database")
        
    protocols_count = {}
    protocols_bytes = {}
    top_talkers_pkts = {}
    top_talkers_bytes = {}
    timeline = {}
    
    total_packets = 0
    total_bytes = 0
    
    for r in rows:
        total_packets += 1
        src_ip = r["source_ip"]
        details = json.loads(r["details"])
        length = details.get("bytes", 0)
        total_bytes += length
        
        proto = details.get("protocol", "TCP")
        protocols_count[proto] = protocols_count.get(proto, 0) + 1
        protocols_bytes[proto] = protocols_bytes.get(proto, 0) + length
        
        if src_ip != "0.0.0.0":
            top_talkers_pkts[src_ip] = top_talkers_pkts.get(src_ip, 0) + 1
            top_talkers_bytes[src_ip] = top_talkers_bytes.get(src_ip, 0) + length
            
        time_bucket = r["timestamp"][:19]
        timeline[time_bucket] = timeline.get(time_bucket, 0) + 1
        
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
        "capture_id": capture_id,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocols": protocols,
        "top_talkers": top_talkers,
        "timeline": timeline_chart
    }

# --- 3B. PCAP LIVE CAPTURE CONTROL ENDPOINTS ---

@app.get("/api/pcap/interfaces")
def list_interfaces():
    return get_network_interfaces()

@app.post("/api/pcap/capture/start")
async def start_live_capture(interface: str):
    if not check_tshark_installed():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "tshark engine is missing on the server. Live packet capture is disabled. "
                "Please install Wireshark/tshark on the server."
            )
        )

    # Validate interface exists
    valid_interfaces = [i["name"] for i in get_network_interfaces()]
    if interface not in valid_interfaces:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Network interface '{interface}' is not valid or does not exist."
        )

    import asyncio
    loop = asyncio.get_event_loop()
    
    def broadcast_callback(msg):
        try:
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(manager.broadcast(msg), loop)
        except Exception as e:
            print(f"Error in broadcast callback: {e}")

    # Generate unique output pcap file in the uploads directory
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"live_capture_{timestamp_str}.pcap"
    filepath = os.path.join(UPLOAD_DIR, filename)

    success = live_capture_manager.start_capture(
        interface_name=interface,
        db_path=DEFAULT_DB_PATH,
        broadcast_callback=broadcast_callback,
        output_file=filepath
    )
    if not success:
        raise HTTPException(status_code=400, detail="Live capture is already running or failed to start.")
        
    return {"status": "success", "message": f"Live capture started on interface {interface}.", "filename": filename}

@app.post("/api/pcap/capture/stop")
def stop_live_capture():
    filename = None
    if live_capture_manager.output_filepath:
        filename = os.path.basename(live_capture_manager.output_filepath)
        
    stopped = live_capture_manager.stop_capture()
    if not stopped:
        return {"status": "error", "message": "Live capture was not running."}
    return {"status": "success", "message": "Live capture stopped.", "filename": filename}

@app.get("/api/pcap/download/{filename}")
def download_pcap_file(filename: str):
    filepath = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File not found.")
    return FileResponse(filepath, media_type="application/octet-stream", filename=filename)

@app.get("/api/pcap/capture/status")
def get_capture_status():
    return {
        "is_running": live_capture_manager.is_running,
        "interface": live_capture_manager.interface,
        "captured_count": live_capture_manager.captured_count
    }

# --- 4. GENERAL API ENDPOINTS ---

@app.get("/api/events")
def fetch_all_events(event_type: Optional[str] = None, page: int = 1, limit: int = 50, filter_expr: Optional[str] = None):
    conn = get_connection()
    cursor = conn.cursor()
    
    # Fetch a larger slice if Python filtering is needed
    db_limit = 500 if filter_expr else limit
    db_offset = 0 if filter_expr else (page - 1) * limit
    
    if event_type:
        cursor.execute(
            "SELECT * FROM security_events WHERE event_type = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (event_type, db_limit, db_offset)
        )
    else:
        cursor.execute(
            "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (db_limit, db_offset)
        )
    rows = cursor.fetchall()
    conn.close()
    
    events = []
    for r in rows:
        item = dict(r)
        item["details"] = json.loads(item["details"])
        
        # Apply Wireshark expression filter
        if filter_expr and item["event_type"] == "packet_event":
            if not evaluate_filter(item["details"], filter_expr):
                continue
                
        events.append(item)
        
    if filter_expr:
        start = (page - 1) * limit
        end = start + limit
        events = events[start:end]
        
from backend.diagnostics import generate_diagnostics

@app.get("/api/diagnostics")
def fetch_diagnostics():
    return generate_diagnostics(DEFAULT_DB_PATH)

@app.post("/api/demo")
async def trigger_demo_seed():
    # Import and run demo seed script
    from backend.demo import seed_demo_data
    seed_demo_data(DEFAULT_DB_PATH)
    
    # Broadcast to reload UI
    await manager.broadcast({"type": "reload_data"})
    
    return {"status": "success", "message": "Database successfully seeded with normal and malicious telemetry data."}

@app.post("/api/clear")
async def clear_database():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM security_events")
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM baselines")
    cursor.execute("DELETE FROM threat_intel_entries")
    cursor.execute("DELETE FROM geo_cache")
    cursor.execute("DELETE FROM blocked_ips")
    cursor.execute("DELETE FROM signing_keys")
    conn.commit()
    conn.close()
    
    reload_blocked_ips(DEFAULT_DB_PATH)
    
    await manager.broadcast({"type": "reload_data"})
    return {"status": "success", "message": "Database cleared."}

# --- 6. THREAT INTEL ENDPOINTS ---
@app.post("/api/threat-intel/refresh")
def refresh_threat_intel():
    count = fetch_and_store_feeds(DEFAULT_DB_PATH)
    return {"status": "success", "entries_loaded": count}

@app.get("/api/threat-intel/lookup/{ip}")
def lookup_threat_intel(ip: str):
    res = lookup_ip(ip, DEFAULT_DB_PATH)
    if not res:
        return {"is_known_threat": False}
    return res

@app.get("/api/threat-intel/stats")
def threat_intel_stats():
    return get_threat_intel_stats(DEFAULT_DB_PATH)

# --- 7. GEO LOOKUP ENDPOINTS ---
@app.get("/api/geo/lookup/{ip}")
def lookup_geo(ip: str):
    return geolocate_ip(ip)

@app.get("/api/geo/attack-map")
def get_attack_map():
    return get_attack_map_data(DEFAULT_DB_PATH)

# --- 8. WAF LITE ENDPOINTS ---
class WAFBlockRequest(BaseModel):
    ip: str
    reason: str

class WAFUnblockRequest(BaseModel):
    ip: str

@app.post("/api/waf/block")
def waf_block(req: WAFBlockRequest):
    block_ip(req.ip, req.reason, DEFAULT_DB_PATH)
    return {"status": "success", "message": f"IP {req.ip} blocked."}

@app.post("/api/waf/unblock")
def waf_unblock(req: WAFUnblockRequest):
    unblock_ip(req.ip, DEFAULT_DB_PATH)
    return {"status": "success", "message": f"IP {req.ip} unblocked."}

@app.get("/api/waf/blocked")
def waf_blocked():
    return get_blocked_ips(DEFAULT_DB_PATH)

# --- 9. KEY MANAGEMENT ENDPOINTS ---
@app.get("/api/jwks.json")
def jwks():
    return get_jwks(DEFAULT_DB_PATH)

@app.post("/api/keys/rotate")
def rotate_signing_keys():
    return rotate_keys(DEFAULT_DB_PATH)

@app.get("/api/keys/list")
def list_signing_keys():
    return list_keys(DEFAULT_DB_PATH)

@app.get("/api/keys/active")
def active_key():
    key = get_active_key(DEFAULT_DB_PATH)
    if "private_key" in key:
        del key["private_key"]
    return key

# --- 10. WEBSOCKET REAL-TIME BROADCASTS ---

@app.websocket("/ws/live-events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Maintain active connection. Read messages if user sends them, though we mostly push.
            data = await websocket.receive_text()
            # Simple ping-pong
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

# --- 11. DAST & ADVANCED SCANNER ENGINE ENDPOINTS ---
from backend.dast_scanners import (
    get_scanner_engines_status, run_nuclei_scan, run_zap_scan, run_sqli_audit
)

class NucleiScanRequest(BaseModel):
    target_url: str
    severity: Optional[str] = None
    tags: Optional[List[str]] = None

class ZapScanRequest(BaseModel):
    target_url: str
    scan_type: Optional[str] = "baseline"

class SqliAuditRequest(BaseModel):
    target_url: str
    params: Optional[Dict[str, str]] = None

@app.get("/api/scan/engines/status")
def get_engines_status():
    return get_scanner_engines_status()

@app.post("/api/scan/nuclei")
def scan_nuclei(req: NucleiScanRequest):
    return run_nuclei_scan(req.target_url, req.severity, req.tags)

@app.post("/api/scan/zap")
def scan_zap(req: ZapScanRequest):
    return run_zap_scan(req.target_url, req.scan_type)

@app.post("/api/scan/sqli")
def audit_sqli(req: SqliAuditRequest):
    return run_sqli_audit(req.target_url, req.params)



# ==============================================================================
# ADVANCED SCANNER & FORENSICS MODULE ENDPOINTS (MODULES 1 - 9)
# ==============================================================================

from backend.ssl_auditor import audit_ssl_target
from backend.scanner_orchestrator import scan_orchestrator, SCAN_PROFILES
from backend.http_repeater import replay_raw_http_request, check_ssrf_risk
from backend.file_carver import carve_files_from_bytes
from backend.geo_asn_map import batch_aggregate_pcap_geo, resolve_single_ip_geo
from backend.beacon_detector import analyze_traffic_beaconing
from backend.report_generator import generate_report_async, assemble_report_data, render_html_report, calculate_cvss31_score
from backend.baseline_diff import perform_baseline_diff

# ── MODULE 1: SSL/TLS AUDITOR ──────────────────────────────────────────────────
class SSLAuditRequest(BaseModel):
    target: str

@app.post("/api/ssl/audit")
async def run_ssl_audit(req: SSLAuditRequest):
    """Module 1: Performs deterministic SSL/TLS security & cipher suite audit."""
    try:
        result = await asyncio.to_thread(audit_ssl_target, req.target)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSL Audit failed: {str(e)}")

# ── MODULE 2: SCAN PROFILES & ORCHESTRATOR ─────────────────────────────────────
@app.get("/api/scan/profiles")
def list_scan_profiles():
    """Module 2: Lists declarative scan profiles with concurrency and rate limits."""
    return scan_orchestrator.get_profiles()

class OrchestratedScanRequest(BaseModel):
    scan_id: Optional[str] = None
    target_url: str
    profile: str = "owasp_fast"
    custom_params: Optional[Dict[str, Any]] = None

@app.post("/api/scan/orchestrated")
async def start_orchestrated_scan(req: OrchestratedScanRequest):
    """Module 2: Runs an orchestrated scan applying profile rate limits and structured logging."""
    scan_id = req.scan_id or f"scan_{uuid.uuid4().hex[:8]}"
    summary = await scan_orchestrator.run_scan(
        scan_id=scan_id,
        target_url=req.target_url,
        profile_key=req.profile,
        custom_params=req.custom_params
    )
    return summary

@app.get("/api/scan/findings")
def list_scan_findings(target: Optional[str] = None, scan_id: Optional[str] = None):
    """Retrieves normalized scan findings from database."""
    conn = get_connection(DEFAULT_DB_PATH)
    cursor = conn.cursor()
    query = "SELECT * FROM scan_findings WHERE 1=1"
    params = []
    if target:
        query += " AND target = ?"
        params.append(target)
    if scan_id:
        query += " AND scan_id = ?"
        params.append(scan_id)
    query += " ORDER BY id DESC LIMIT 500"
    
    cursor.execute(query, tuple(params))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

# ── MODULE 3: INTERACTIVE HTTP REPEATER ────────────────────────────────────────
class RepeaterRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    allow_private_network: bool = False

@app.post("/api/repeater/send")
async def repeater_send_request(req: RepeaterRequest):
    """Module 3: Replays raw HTTP request with SSRF guard and streaming cap."""
    try:
        result = await asyncio.to_thread(
            replay_raw_http_request,
            req.method,
            req.url,
            req.headers,
            req.body,
            req.allow_private_network
        )
        return result
    except Exception as e:
        return {
            "status": "network_error",
            "url": req.url,
            "error": str(e),
            "response_status": 0,
            "response_headers": {},
            "response_body": f"Backend repeater execution error: {str(e)}",
            "duration_ms": 0
        }

@app.post("/api/repeater/check-ssrf")
def repeater_check_ssrf(url: str):
    """Pre-flight SSRF check for target URL."""
    is_private, warning, resolved_ips = check_ssrf_risk(url)
    return {
        "url": url,
        "is_private_risk": is_private,
        "warning": warning,
        "resolved_ips": resolved_ips
    }

# ── MODULE 4: AUTOMATED FILE CARVER ────────────────────────────────────────────
@app.get("/api/pcap/carved/{capture_id}")
def get_pcap_carved_files(capture_id: str):
    """Module 4: Extracts images and documents from PCAP stream payloads using magic bytes."""
    target_path = os.path.join(UPLOAD_DIR, capture_id)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="PCAP file not found.")
    
    from backend.pcap_analyzer import carve_artifacts_from_pcap
    artifacts = carve_artifacts_from_pcap(target_path, capture_id=capture_id)
    return {"capture_id": capture_id, "carved_count": len(artifacts), "artifacts": artifacts}

@app.get("/api/pcap/carved/download/{filename}")
def download_carved_file(filename: str):
    """Safely serves carved file with inert octet-stream header to avoid host execution."""
    carved_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads", "carved")
    file_path = os.path.join(carved_dir, os.path.basename(filename))
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Carved file not found.")
        
    return FileResponse(
        file_path,
        media_type="application/octet-stream",
        filename=os.path.basename(filename),
        headers={"Content-Disposition": f'attachment; filename="{os.path.basename(filename)}"'}
    )

# ── MODULE 5: GEO THREAT MAP ───────────────────────────────────────────────────
@app.get("/api/pcap/geomap/{capture_id}")
def get_pcap_geo_threat_map(capture_id: str):
    """Module 5: Returns batch-aggregated and de-duplicated IP coordinates and flow arcs."""
    target_path = os.path.join(UPLOAD_DIR, capture_id)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="PCAP file not found.")
        
    streams = get_pcap_tcp_streams(target_path)
    flows = []
    for s in streams:
        src_ip = s.get("client", "").split(":")[0]
        dst_ip = s.get("server", "").split(":")[0]
        if src_ip and dst_ip:
            flows.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "packet_count": s.get("packet_count", 1)
            })
            
    geo_data = batch_aggregate_pcap_geo(flows, db_path=DEFAULT_DB_PATH)
    return {"capture_id": capture_id, **geo_data}

# ── MODULE 6: C2 BEACONING DETECTOR ────────────────────────────────────────────
@app.get("/api/pcap/beaconing/{capture_id}")
def get_pcap_beaconing_analysis(capture_id: str):
    """Module 6: Analyzes flow inter-arrival times and coefficient of variation for periodic beaconing."""
    target_path = os.path.join(UPLOAD_DIR, capture_id)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="PCAP file not found.")
        
    import subprocess
    tshark_exe = get_tshark_path()
    try:
        cmd = [
            tshark_exe,
            "-r", target_path,
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.dstport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Protocol"
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        lines = proc.stdout.strip().splitlines()
        
        timeline_pkts = []
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0]:
                try:
                    ts = float(parts[0])
                    src = parts[1]
                    dst = parts[2]
                    port = int(parts[3] or parts[4] or 0)
                    proto = parts[5] if len(parts) > 5 else "TCP"
                    timeline_pkts.append({
                        "timestamp": ts,
                        "src_ip": src,
                        "dst_ip": dst,
                        "dst_port": port,
                        "protocol": proto
                    })
                except Exception:
                    pass

        indicators = analyze_traffic_beaconing(timeline_pkts)
        return {
            "capture_id": capture_id,
            "total_packets_analyzed": len(timeline_pkts),
            "beaconing_indicators_count": len(indicators),
            "indicators": indicators
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Beaconing analysis failed: {str(e)}")

# ── MODULE 8: EXECUTIVE REPORTS & CVSS 3.1 ──────────────────────────────────────
class ReportGenRequest(BaseModel):
    target: str
    findings: Optional[List[Dict[str, Any]]] = None
    output_format: str = "html"

@app.post("/api/reports/generate")
def create_executive_report(req: ReportGenRequest):
    """Module 8: Initiates asynchronous generation of executive PDF/HTML report."""
    findings = req.findings
    if findings is None:
        # Fetch latest findings for target from DB
        conn = get_connection(DEFAULT_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_findings WHERE target = ? ORDER BY id DESC LIMIT 200", (req.target,))
        findings = [dict(r) for r in cursor.fetchall()]
        conn.close()

    report_id = generate_report_async(
        target=req.target,
        findings=findings or [],
        output_format=req.output_format,
        db_path=DEFAULT_DB_PATH
    )
    return {"report_id": report_id, "status": "generating", "target": req.target}

@app.get("/api/reports/status/{report_id}")
def check_report_status(report_id: str):
    """Polls async report generation status."""
    conn = get_connection(DEFAULT_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_reports WHERE report_id = ?", (report_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Report not found.")
    data = dict(row)
    if data.get("summary_json"):
        try:
            data["summary_data"] = json.loads(data["summary_json"])
        except Exception:
            pass
    return data

@app.get("/api/reports/download/{report_id}")
def download_executive_report(report_id: str):
    """Downloads completed executive report."""
    conn = get_connection(DEFAULT_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT file_path, format FROM scan_reports WHERE report_id = ?", (report_id,))
    row = cursor.fetchone()
    conn.close()
    if not row or not row["file_path"] or not os.path.exists(row["file_path"]):
        raise HTTPException(status_code=404, detail="Report file not ready or not found.")
        
    return FileResponse(
        row["file_path"],
        media_type="text/html" if row["format"] == "html" else "application/pdf",
        filename=f"executive_report_{report_id}.{row['format']}"
    )

@app.post("/api/cvss/calculate")
def calculate_cvss(vector: str):
    """Module 8: Computes exact FIRST.org CVSS 3.1 score from vector string."""
    try:
        return calculate_cvss31_score(vector)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid CVSS vector: {str(e)}")

# ── MODULE 9: BASELINE DIFF SCANNER ────────────────────────────────────────────
class DiffRequest(BaseModel):
    baseline_findings: List[Dict[str, Any]]
    current_findings: List[Dict[str, Any]]

@app.post("/api/scan/diff")
def compute_scan_diff(req: DiffRequest):
    """Module 9: Performs 4-way baseline comparison (New, Resolved, Still-Open, Changed-Severity)."""
    return perform_baseline_diff(req.baseline_findings, req.current_findings)


# ==============================================================================
# MODULE 13: WEB ZENMAP / NMAP STUDIO ENDPOINTS
# ==============================================================================

from backend.nmap_engine import (
    validate_scan_target, validate_and_build_custom_flags,
    NmapScanJob, _ACTIVE_NMAP_JOBS, execute_nmap_scan_async,
    compute_radial_topology_coordinates, parse_nmap_xml_string,
    ZENMAP_PROFILES
)

class NmapScanRequest(BaseModel):
    target: str
    profile: str = "quick_scan"
    custom_params: Optional[Dict[str, Any]] = None

@app.get("/api/nmap/profiles")
def get_nmap_profiles():
    """Module 13: Lists structured Zenmap scan profiles."""
    return list(ZENMAP_PROFILES.values())

@app.post("/api/nmap/scan")
async def start_nmap_scan(req: NmapScanRequest):
    """Module 13: Validates input, constructs immutable flags, and launches scan in background."""
    try:
        clean_target = validate_scan_target(req.target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    if req.profile in ZENMAP_PROFILES:
        flags = list(ZENMAP_PROFILES[req.profile]["flags"])
    elif req.profile == "custom_builder" and req.custom_params:
        try:
            flags = validate_and_build_custom_flags(req.custom_params)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    else:
        flags = list(ZENMAP_PROFILES["quick_scan"]["flags"])

    scan_id = f"nmap_{uuid.uuid4().hex[:8]}"
    job = NmapScanJob(scan_id, clean_target, req.profile, flags)
    _ACTIVE_NMAP_JOBS[scan_id] = job

    # Launch in background async task
    asyncio.create_task(execute_nmap_scan_async(job))
    
    return {
        "scan_id": scan_id,
        "target": clean_target,
        "profile": req.profile,
        "flags": flags,
        "status": "initializing"
    }

@app.get("/api/nmap/status/{scan_id}")
def get_nmap_scan_status(scan_id: str):
    """Module 13: Returns incremental scan progress, discovered hosts, and engine details."""
    job = _ACTIVE_NMAP_JOBS.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Nmap scan not found.")
        
    return {
        "scan_id": job.scan_id,
        "target": job.target,
        "profile": job.profile,
        "flags": job.flags,
        "status": job.status,
        "progress": job.progress,
        "engine_type": job.engine_type,
        "hosts_count": len(job.hosts),
        "hosts": job.hosts,
        "raw_output": job.raw_output[-5000:] if job.raw_output else "",
        "error": job.error,
        "elapsed_seconds": round((job.end_time or time.time()) - job.start_time, 1)
    }

@app.get("/api/nmap/topology/{scan_id}")
def get_nmap_topology(scan_id: str):
    """Module 13: Computes server-side radial coordinate positions for Zenmap visualization."""
    job = _ACTIVE_NMAP_JOBS.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Nmap scan not found.")
        
    return compute_radial_topology_coordinates(job.hosts, origin_label=f"Scanner ➔ {job.target}")

@app.post("/api/nmap/cancel/{scan_id}")
def cancel_nmap_scan(scan_id: str):
    """Module 13: Cleanly terminates active Nmap process and prevents zombie tasks."""
    job = _ACTIVE_NMAP_JOBS.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Nmap scan not found.")
    job.cancel()
    return {"scan_id": scan_id, "status": "cancelled"}

@app.post("/api/nmap/import-xml")
async def import_nmap_xml(file: UploadFile = File(...)):
    """Module 13: Safely imports external Nmap XML scan results with entity resolution protection."""
    content_bytes = await file.read(10 * 1024 * 1024) # Cap at 10MB
    xml_str = content_bytes.decode("utf-8", errors="ignore")
    
    hosts = parse_nmap_xml_string(xml_str)
    if not hosts:
        raise HTTPException(status_code=400, detail="Could not parse valid host records from uploaded XML.")
        
    scan_id = f"imported_{uuid.uuid4().hex[:8]}"
    job = NmapScanJob(scan_id, file.filename or "imported_scan.xml", "imported", [])
    job.hosts = hosts
    job.status = "completed"
    job.progress = 100
    job.engine_type = "imported-xml"
    _ACTIVE_NMAP_JOBS[scan_id] = job
    
    return {
        "scan_id": scan_id,
        "hosts_count": len(hosts),
        "status": "completed",
        "topology": compute_radial_topology_coordinates(hosts)
    }
