import React, { useState, useEffect } from 'react';
import { X, CheckCircle, ShieldAlert, FileText, Globe, Key, Clock, User, AlertOctagon } from 'lucide-react';
import { API_BASE_URL } from '../config/api';

interface Alert {
  id: number;
  rule_triggered: string;
  severity: string;
  source_ip: string;
  event_ids: number[];
  explanation: string;
  status: string;
  created_at: string;
}

interface AlertDetailModalProps {
  alert: Alert;
  onClose: () => void;
  onStatusUpdated: (alertId: number, newStatus: string) => void;
}

export const AlertDetailModal: React.FC<AlertDetailModalProps> = ({ alert, onClose, onStatusUpdated }) => {
  const [evidenceEvents, setEvidenceEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [updatingStatus, setUpdatingStatus] = useState(false);

  useEffect(() => {
    const fetchEvidence = async () => {
      setLoading(true);
      try {
        // Fetch recent security events to find matching evidence IDs
        const res = await fetch(`${API_BASE_URL}/events?limit=200`);
        if (!res.ok) throw new Error('Failed to fetch events');
        const data = await res.json();
        
        // Filter events that belong to this alert
        const matched = data.filter((e: any) => alert.event_ids.includes(e.id));
        setEvidenceEvents(matched);
      } catch (err) {
        console.error('Error fetching evidence:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchEvidence();
  }, [alert]);

  const handleUpdateStatus = async (newStatus: string) => {
    setUpdatingStatus(true);
    try {
      const res = await fetch(`${API_BASE_URL}/alerts/${alert.id}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        onStatusUpdated(alert.id, newStatus);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'bg-red-500/20 text-red-400 border border-red-500/40';
      case 'HIGH': return 'bg-orange-500/20 text-orange-400 border border-orange-500/40';
      case 'MEDIUM': return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40';
      default: return 'bg-blue-500/20 text-blue-400 border border-blue-500/40';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'resolved': return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40';
      case 'acknowledged': return 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40';
      default: return 'bg-red-500/20 text-red-400 border border-red-500/40';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto glass-panel p-6 md:p-8 space-y-6">
        
        {/* Header */}
        <div className="flex justify-between items-start gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded tracking-wider ${getSeverityColor(alert.severity)}`}>
                {alert.severity} SEVERITY
              </span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded tracking-wider ${getStatusColor(alert.status)}`}>
                {alert.status.toUpperCase()}
              </span>
              <span className="text-xs text-slate-500 font-mono flex items-center gap-1">
                <Clock className="w-3.5 h-3.5" />
                {alert.created_at.substring(11, 19)} UTC
              </span>
            </div>
            <h2 className="text-xl font-bold text-slate-100 mt-1">{alert.rule_triggered.replace(/_/g, ' ')}</h2>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Description / Explanation */}
        <div className="bg-slate-950/40 border border-slate-900 rounded-xl p-5 space-y-2">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest">Incident Summary</h3>
          <p className="text-sm text-slate-300 leading-relaxed font-semibold">{alert.explanation}</p>
          <div className="pt-2 text-xs text-slate-500 font-mono">Source entity: <span className="text-cyan-400">{alert.source_ip || 'Unified Pipeline'}</span></div>
        </div>

        {/* Change Status Control */}
        <div className="flex flex-col sm:flex-row gap-4 items-center justify-between border-t border-b border-slate-900 py-4">
          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Update Incident Status</span>
          <div className="flex gap-2 w-full sm:w-auto">
            <button
              onClick={() => handleUpdateStatus('open')}
              disabled={updatingStatus || alert.status === 'open'}
              className="flex-1 sm:flex-initial text-xs font-bold px-3 py-1.5 rounded-lg border border-red-500/20 bg-red-500/5 text-red-400 hover:bg-red-500/10 disabled:opacity-30"
            >
              Open
            </button>
            <button
              onClick={() => handleUpdateStatus('acknowledged')}
              disabled={updatingStatus || alert.status === 'acknowledged'}
              className="flex-1 sm:flex-initial text-xs font-bold px-3 py-1.5 rounded-lg border border-cyan-500/20 bg-cyan-500/5 text-cyan-400 hover:bg-cyan-500/10 disabled:opacity-30"
            >
              Acknowledge
            </button>
            <button
              onClick={() => handleUpdateStatus('resolved')}
              disabled={updatingStatus || alert.status === 'resolved'}
              className="flex-1 sm:flex-initial text-xs font-bold px-3 py-1.5 rounded-lg border border-emerald-500/20 bg-emerald-500/5 text-emerald-400 hover:bg-emerald-500/10 disabled:opacity-30"
            >
              Resolve
            </button>
          </div>
        </div>

        {/* Forensic Evidence Events */}
        <div className="space-y-4">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1.5">
            <FileText className="w-4 h-4 text-cyan-400" />
            Supporting Evidence Events ({alert.event_ids.length})
          </h3>

          {loading ? (
            <div className="flex justify-center p-8">
              <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
            </div>
          ) : evidenceEvents.length === 0 ? (
            <div className="text-center p-8 border border-slate-900 rounded-xl text-xs text-slate-600">
              No evidence event descriptions found.
            </div>
          ) : (
            <div className="space-y-4 max-h-96 overflow-y-auto pr-1">
              {evidenceEvents.map((ev, idx) => (
                <div key={idx} className="border border-slate-900 bg-slate-950/20 rounded-xl p-4 space-y-3">
                  
                  {/* Event Meta */}
                  <div className="flex justify-between items-center text-[10px] text-slate-500 font-semibold border-b border-slate-900 pb-2">
                    <span className="flex items-center gap-1 uppercase tracking-wider font-bold">
                      {ev.event_type === 'jwt_finding' && <Key className="w-3 h-3 text-purple-400" />}
                      {ev.event_type === 'auth_log' && <Globe className="w-3 h-3 text-cyan-400" />}
                      {ev.event_type === 'packet_event' && <AlertOctagon className="w-3 h-3 text-pink-400" />}
                      {ev.event_type.replace(/_/g, ' ')} (ID: {ev.id})
                    </span>
                    <span className="font-mono">{ev.timestamp}</span>
                  </div>

                  {/* Evidences based on event type */}
                  {ev.event_type === 'auth_log' && (
                    <div className="space-y-2">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                        <div>
                          <span className="text-slate-500 font-bold block">IP</span>
                          <span className="font-mono text-cyan-400">{ev.source_ip}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 font-bold block">Endpoint</span>
                          <span className="font-mono">{ev.details.method} {ev.details.referer ? ev.details.raw_line.split('"')[1].split(' ')[1] : '/'}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 font-bold block">Status Code</span>
                          <span className={`font-bold ${ev.status_code >= 400 ? 'text-red-400' : 'text-emerald-400'}`}>
                            {ev.status_code}
                          </span>
                        </div>
                        {ev.details.username && (
                          <div>
                            <span className="text-slate-500 font-bold block flex items-center gap-1">
                              <User className="w-3 h-3" /> User
                            </span>
                            <span className="text-purple-400 font-semibold">{ev.details.username}</span>
                          </div>
                        )}
                      </div>
                      {ev.details.raw_line && (
                        <div className="bg-slate-950 border border-slate-900 rounded p-2.5 text-[11px] font-mono text-slate-400 overflow-auto whitespace-pre-wrap">
                          {ev.details.raw_line}
                        </div>
                      )}
                    </div>
                  )}

                  {ev.event_type === 'jwt_finding' && (
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-4 text-xs">
                        <div>
                          <span className="text-slate-500 block font-bold">Risk Score</span>
                          <span className={`text-lg font-black ${
                            ev.details.risk_score >= 75 ? 'text-red-400' :
                            ev.details.risk_score >= 50 ? 'text-orange-400' : 'text-yellow-400'
                          }`}>
                            {ev.details.risk_score}/100
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500 block font-bold">Token Origin</span>
                          <span className="text-slate-400 font-mono truncate block">{ev.details.token_source || 'Manual Analyzer'}</span>
                        </div>
                      </div>

                      {/* JWT Findings list */}
                      <div className="space-y-1.5">
                        <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Analysis Audit Findings</span>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {ev.details.findings && ev.details.findings.map((f: any, fIdx: number) => (
                            <div key={fIdx} className="bg-slate-950 border border-slate-900 rounded p-2 text-xs space-y-1">
                              <div className="flex justify-between items-center">
                                <span className="font-bold text-slate-300">{f.title}</span>
                                <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded tracking-wide ${getSeverityColor(f.severity)}`}>
                                  {f.severity}
                                </span>
                              </div>
                              <p className="text-[10px] text-slate-500 leading-normal">{f.description}</p>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Header and Payload */}
                      {ev.details.header && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[10px] font-mono">
                          <div>
                            <span className="text-slate-500 block font-bold mb-1">Decoded Header</span>
                            <pre className="bg-slate-950 border border-slate-900 rounded p-2 h-28 overflow-auto text-cyan-400">
                              {JSON.stringify(ev.details.header, null, 2)}
                            </pre>
                          </div>
                          <div>
                            <span className="text-slate-500 block font-bold mb-1">Decoded Payload</span>
                            <pre className="bg-slate-950 border border-slate-900 rounded p-2 h-28 overflow-auto text-purple-400">
                              {JSON.stringify(ev.details.payload, null, 2)}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {ev.event_type === 'packet_event' && (
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                        <div>
                          <span className="text-slate-500 font-bold block">Protocol</span>
                          <span className="text-pink-400 font-bold font-mono">{ev.details.protocol}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 font-bold block">Source Socket</span>
                          <span className="font-mono">{ev.source_ip}:{ev.details.src_port}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 font-bold block">Destination Socket</span>
                          <span className="font-mono">{ev.details.dst_ip}:{ev.details.dst_port}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 font-bold block">Size</span>
                          <span className="font-mono">{ev.details.bytes} Bytes</span>
                        </div>
                      </div>
                      
                      <div className="bg-slate-950 border border-slate-900 rounded p-2 text-xs space-y-1">
                        <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Packet Summary Info</span>
                        <p className="font-mono text-cyan-400 font-semibold">{ev.details.packet_summary}</p>
                      </div>

                      {/* Protocol specific highlights */}
                      {ev.details.dns_info && (
                        <div className="bg-slate-950 border border-slate-900 rounded p-2.5 text-xs font-mono space-y-1">
                          <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">DNS Query Metadata</span>
                          <div className="text-slate-300">Name: <span className="text-purple-400">{ev.details.dns_info.qry_name}</span></div>
                          <div className="text-slate-400 text-[10px]">Type: {ev.details.dns_info.qry_type} | Flags: {ev.details.dns_info.flags}</div>
                        </div>
                      )}

                      {ev.details.arp_info && (
                        <div className="bg-slate-950 border border-slate-900 rounded p-2.5 text-xs font-mono space-y-1">
                          <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">ARP Header Fields</span>
                          <div className="text-slate-300">Sender MAC: <span className="text-pink-400">{ev.details.arp_info.src_mac}</span> claims IP: <span className="text-cyan-400">{ev.details.arp_info.src_ip}</span></div>
                          <div className="text-slate-400 text-[10px]">Opcode: {ev.details.arp_info.opcode} | Target IP: {ev.details.arp_info.dst_ip}</div>
                        </div>
                      )}

                      {ev.details.http_info && (
                        <div className="bg-slate-950 border border-slate-900 rounded p-2.5 text-xs font-mono space-y-2">
                          <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">HTTP Session Fields</span>
                          <div className="text-slate-300 font-bold">{ev.details.http_info.request_method} {ev.details.http_info.request_uri}</div>
                          {ev.details.http_info.authorization && (
                            <div className="text-red-400 border border-red-950/20 bg-red-950/10 p-1.5 rounded text-[10px]">
                              Auth Header: <span className="font-bold">{ev.details.http_info.authorization}</span>
                            </div>
                          )}
                          <div className="text-[10px] text-slate-500">UA: {ev.details.http_info.user_agent}</div>
                        </div>
                      )}
                    </div>
                  )}

                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
