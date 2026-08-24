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
    follow_tcp_stream, compare_pcap_files, extract_pcap_artifacts
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


@app.get("/api/pcap/follow-stream")
def get_followed_stream(capture_id: str, stream_id: int):
    target_path = os.path.join(UPLOAD_DIR, capture_id)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="PCAP file not found. Please upload it again.")
    dialog = follow_tcp_stream(target_path, stream_id)
    return {"capture_id": capture_id, "stream_id": stream_id, "dialog": dialog}


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
        
    return events

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
