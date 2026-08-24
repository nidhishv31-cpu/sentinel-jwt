from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class JWTAnalysisRequest(BaseModel):
    token: str
    secret: Optional[str] = Field(None, description="Optional secret key to test brute-force and entropy strength")

class JWTFinding(BaseModel):
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # alg, expiry, claims, signature, entropy

class JWTAnalysisResponse(BaseModel):
    decoded_header: Dict[str, Any]
    decoded_payload: Dict[str, Any]
    findings: List[JWTFinding]
    risk_score: int

class JWTBatchAnalysisRequest(BaseModel):
    tokens: List[str]

class JWTBatchAnalysisResponse(BaseModel):
    total_analyzed: int
    findings_count: int

class LogIngestResponse(BaseModel):
    success: bool
    events_parsed: int
    message: str
    events: Optional[List[Dict[str, Any]]] = None

class SecurityEventSchema(BaseModel):
    id: int
    timestamp: str
    event_type: str
    source_ip: str
    details: Dict[str, Any]
    severity: str
    created_at: str

class AlertSchema(BaseModel):
    id: int
    rule_triggered: str
    severity: str
    source_ip: str
    event_ids: List[int]
    explanation: str
    status: str
    created_at: str

class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|acknowledged|resolved)$")

class TopTalkerEntry(BaseModel):
    ip: str
    packets: int
    bytes: int

class ProtocolBreakdownEntry(BaseModel):
    protocol: str
    count: int
    bytes: int

class PcapSummaryResponse(BaseModel):
    capture_id: str
    total_packets: int
    total_bytes: int
    protocols: List[ProtocolBreakdownEntry]
    top_talkers: List[TopTalkerEntry]
    timeline: List[Dict[str, Any]]
