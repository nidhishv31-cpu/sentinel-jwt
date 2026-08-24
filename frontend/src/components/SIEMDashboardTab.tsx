import React, { useState, useEffect, useRef } from 'react';
import { Shield, Play, Trash2, Database, AlertTriangle, CheckCircle, Clock, Filter, Eye } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, PieChart, Pie, Cell } from 'recharts';
import { API_BASE_URL, WS_BASE_URL } from '../config/api';
import { AlertDetailModal } from './AlertDetailModal';

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

interface SecurityEvent {
  id: number;
  timestamp: string;
  event_type: string;
  source_ip: string;
  details: any;
  severity: string;
  created_at: string;
}

const SEV_COLORS = {
  CRITICAL: '#f43f5e',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFO: '#64748b'
};

export const SIEMDashboardTab: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [diagnostics, setDiagnostics] = useState<any[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  
  // Filtering states
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [websocketStatus, setWebsocketStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected');

  const wsRef = useRef<WebSocket | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [alertsRes, eventsRes, diagRes] = await Promise.all([
        fetch(`${API_BASE_URL}/alerts`),
        fetch(`${API_BASE_URL}/events?limit=200`),
        fetch(`${API_BASE_URL}/siem/diagnostics`)
      ]);
      
      if (alertsRes.ok && eventsRes.ok && diagRes.ok) {
        const alertsData = await alertsRes.json();
        const eventsData = await eventsRes.json();
        const diagData = await diagRes.json();
        setAlerts(alertsData);
        setEvents(eventsData);
        setDiagnostics(diagData);
      }
    } catch (err) {
      console.error("Error loading SIEM data:", err);
    } finally {
      setLoading(false);
    }
  };

  // Connect WebSockets for real-time streaming
  useEffect(() => {
    fetchData();

    const connectWebSocket = () => {
      setWebsocketStatus('connecting');
      const ws = new WebSocket(WS_BASE_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        setWebsocketStatus('connected');
        console.log("WebSocket connected.");
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          if (data.type === 'new_event') {
            setEvents(prev => [data.event, ...prev.slice(0, 199)]);
          } else if (data.type === 'new_alert') {
            setAlerts(prev => [data.alert, ...prev]);
          } else if (data.type === 'alert_updated') {
            setAlerts(prev => prev.map(a => a.id === data.alert_id ? { ...a, status: data.status } : a));
          } else if (data.type === 'reload_data' || data.type === 'pcap_ingested') {
            fetchData();
          }
        } catch (err) {
          console.error("WebSocket message parsing error:", err);
        }
      };

      ws.onclose = () => {
        setWebsocketStatus('disconnected');
        console.log("WebSocket disconnected. Reconnecting in 5 seconds...");
        setTimeout(connectWebSocket, 5000);
      };

      ws.onerror = (err) => {
        console.error("WebSocket error:", err);
        ws.close();
      };
    };

    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const handleTriggerAnalysis = async () => {
    setScanning(true);
    try {
      const res = await fetch(`${API_BASE_URL}/analysis/run`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        console.log("Detections completed. Alerts generated:", data.alerts_generated_count);
        fetchData();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setScanning(false);
    }
  };

  const handleSeedDemo = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/demo`, { method: 'POST' });
      if (res.ok) {
        fetchData();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleClearDb = async () => {
    if (!window.confirm("Are you sure you want to clear all telemetry database tables?")) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/clear`, { method: 'POST' });
      if (res.ok) {
        setAlerts([]);
        setEvents([]);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleStatusUpdated = (alertId: number, newStatus: string) => {
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: newStatus } : a));
    if (selectedAlert && selectedAlert.id === alertId) {
      setSelectedAlert({ ...selectedAlert, status: newStatus });
    }
  };

  // Filtering Logic
  const filteredAlerts = alerts.filter(a => {
    const matchesSearch = 
      a.explanation.toLowerCase().includes(search.toLowerCase()) || 
      a.rule_triggered.toLowerCase().includes(search.toLowerCase()) ||
      a.source_ip.toLowerCase().includes(search.toLowerCase());
      
    const matchesSev = sevFilter === 'ALL' || a.severity === sevFilter;
    const matchesStatus = statusFilter === 'ALL' || a.status === statusFilter;
    
    return matchesSearch && matchesSev && matchesStatus;
  });

  // 1. Chart: Severity distribution data
  const severityDistribution = React.useMemo(() => {
    const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    alerts.forEach(a => {
      if (a.severity in counts) counts[a.severity]++;
    });
    return Object.keys(counts).map(key => ({
      name: key,
      value: counts[key]
    })).filter(item => item.value > 0);
  }, [alerts]);

  // 2. Chart: Timeline of events bucketed by minutes/hours
  const timelineData = React.useMemo(() => {
    const buckets: Record<string, number> = {};
    events.forEach(e => {
      // Group by hours or minutes - e.g. "15:30"
      if (e.timestamp) {
        const timeStr = e.timestamp.substring(11, 16); // Extract "HH:MM"
        buckets[timeStr] = (buckets[timeStr] || 0) + 1;
      }
    });
    return Object.keys(buckets).map(key => ({
      time: key,
      events: buckets[key]
    })).sort((a, b) => a.time.localeCompare(b.time)).slice(-10); // Show last 10 minutes bucket
  }, [events]);

  // 3. Top offending IPs data
  const topOffendingIps = React.useMemo(() => {
    const ipCounts: Record<string, { alerts: number; events: number }> = {};
    alerts.forEach(a => {
      if (a.source_ip && a.source_ip !== '0.0.0.0' && a.source_ip !== 'Unified Pipeline') {
        if (!ipCounts[a.source_ip]) ipCounts[a.source_ip] = { alerts: 0, events: 0 };
        ipCounts[a.source_ip].alerts++;
      }
    });
    events.forEach(e => {
      if (e.source_ip && e.source_ip !== '0.0.0.0') {
        if (!ipCounts[e.source_ip]) ipCounts[e.source_ip] = { alerts: 0, events: 0 };
        ipCounts[e.source_ip].events++;
      }
    });
    return Object.keys(ipCounts).map(ip => ({
      ip,
      alerts: ipCounts[ip].alerts,
      events: ipCounts[ip].events
    })).sort((a, b) => b.alerts - a.alerts || b.events - a.events).slice(0, 5);
  }, [alerts, events]);

  const getAlertSeverityStyle = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'HIGH': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      default: return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
    }
  };

  return (
    <div className="space-y-6 p-4">
      {/* Action Bar / Quick Stats */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-950/40 border border-slate-900 rounded-xl p-4">
        
        {/* Connection status */}
        <div className="flex items-center gap-2">
          <div className={`w-2.5 h-2.5 rounded-full ${
            websocketStatus === 'connected' ? 'bg-emerald-500 animate-pulse' :
            websocketStatus === 'connecting' ? 'bg-yellow-500 animate-pulse' : 'bg-red-500'
          }`} />
          <span className="text-xs font-semibold text-slate-400">
            {websocketStatus === 'connected' ? 'SIEM Pipeline Active (WebSocket Streaming)' :
             websocketStatus === 'connecting' ? 'Pipeline connecting...' : 'Pipeline offline'}
          </span>
        </div>

        {/* Dashboard Actions */}
        <div className="flex gap-2 w-full md:w-auto">
          <button
            onClick={handleTriggerAnalysis}
            disabled={scanning || loading}
            className="flex-1 md:flex-initial flex items-center justify-center gap-1.5 bg-cyan-900/25 border border-cyan-800 hover:bg-cyan-900/50 text-cyan-400 text-xs font-bold py-2 px-3.5 rounded-lg transition"
          >
            <Play className="w-3.5 h-3.5" />
            {scanning ? 'Analyzing...' : 'Scan Threats'}
          </button>
          
          <button
            onClick={handleSeedDemo}
            disabled={loading}
            className="flex-1 md:flex-initial flex items-center justify-center gap-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 text-xs font-bold py-2 px-3.5 rounded-lg transition"
          >
            <Database className="w-3.5 h-3.5" />
            Seed Demo Data
          </button>

          <button
            onClick={handleClearDb}
            disabled={loading}
            className="p-2 bg-slate-900 border border-slate-850 hover:border-red-950/50 hover:text-red-400 rounded-lg transition text-slate-500"
            title="Clear Database"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Visualizations Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Timeline Area Chart */}
        <div className="lg:col-span-2 glass-panel p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Ingested Events Timeline</h3>
          <div className="h-56">
            {timelineData.length === 0 ? (
              <div className="w-full h-full flex items-center justify-center text-xs text-slate-600">No events timeline data available. Seed demo to view.</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <defs>
                    <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00d2ff" stopOpacity={0.2}/>
                      <stop offset="95%" stopColor="#00d2ff" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#475569" fontSize={9} />
                  <YAxis stroke="#475569" fontSize={9} />
                  <Tooltip contentStyle={{ backgroundColor: '#090a0f', borderColor: '#1e293b', color: '#fff', fontSize: 11 }} />
                  <Area type="monotone" dataKey="events" stroke="#00d2ff" strokeWidth={2} fillOpacity={1} fill="url(#colorEvents)" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Severity Distribution Pie Chart */}
        <div className="glass-panel p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Alerts Severity Breakdown</h3>
          <div className="h-44 flex items-center justify-center">
            {severityDistribution.length === 0 ? (
              <div className="text-xs text-slate-600">No alerts triggered yet</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityDistribution}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={55}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    labelLine={false}
                    fontSize={8}
                  >
                    {severityDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={SEV_COLORS[entry.name as keyof typeof SEV_COLORS] || '#64748b'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#090a0f', borderColor: '#1e293b', color: '#fff', fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
          
          <div className="flex justify-center gap-4 text-[10px] text-slate-400 font-bold">
            <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-red-500"></span> CRITICAL</span>
            <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-orange-500"></span> HIGH</span>
            <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-yellow-500"></span> MEDIUM</span>
            <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-blue-500"></span> LOW</span>
          </div>
        </div>
      </div>

      {/* Security Diagnostics & Root Cause Analysis (RCA) Advisor */}
      {diagnostics.length > 0 && (
        <div className="glass-panel p-6 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-md font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-5 h-5 text-purple-400" />
              Security Diagnostics & Root Cause Analysis (RCA)
            </h3>
            <span className="text-[10px] text-slate-500 font-bold uppercase">
              Correlated {diagnostics.length} Active Threat Patterns
            </span>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {diagnostics.map((diag, index) => (
              <div key={index} className="border border-slate-900 bg-slate-950/40 rounded-xl p-5 flex flex-col justify-between space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <span className={`text-[9px] font-black px-2 py-0.5 border rounded tracking-wider uppercase ${
                      diag.severity === 'CRITICAL' ? 'border-red-500/20 bg-red-500/5 text-red-400' :
                      diag.severity === 'HIGH' ? 'border-orange-500/20 bg-orange-500/5 text-orange-400' :
                      diag.severity === 'MEDIUM' ? 'border-yellow-500/20 bg-yellow-500/5 text-yellow-400' :
                      'border-blue-500/20 bg-blue-500/5 text-blue-400'
                    }`}>
                      {diag.severity}
                    </span>
                    <span className="text-[10px] font-bold text-slate-600 font-mono">
                      {diag.alerts_count} alert(s)
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-slate-200">{diag.issue_name}</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">{diag.description}</p>
                </div>
                
                <div className="space-y-2 border-t border-slate-900/60 pt-3">
                  <div>
                    <span className="text-[9px] uppercase font-bold text-red-500/80">Why is it caused?</span>
                    <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">{diag.why_caused}</p>
                  </div>
                  <div>
                    <span className="text-[9px] uppercase font-bold text-emerald-500/80">Remediation Plan</span>
                    <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">{diag.remediation}</p>
                  </div>
                  {diag.affected_ips.length > 0 && (
                    <div className="text-[9px] font-mono text-slate-500 mt-2">
                      Affected Host(s): <span className="text-cyan-400">{diag.affected_ips.join(', ')}</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Grid: Alert Feed & Top Offending IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Alerts Feed */}
        <div className="lg:col-span-2 glass-panel p-6 space-y-4">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
            <h3 className="text-md font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              SIEM Incidents & Alerts Feed ({filteredAlerts.length})
            </h3>
            
            {/* Filter controls */}
            <div className="flex gap-2 flex-wrap w-full sm:w-auto">
              <div className="relative flex-1 sm:flex-initial">
                <input
                  type="text"
                  placeholder="Filter alerts..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-900 rounded-lg py-1 px-3 pl-8 text-xs font-semibold focus:outline-none focus:ring-1 focus:ring-cyan-500 text-slate-300 placeholder-slate-700"
                />
                <Filter className="absolute left-2.5 top-2 w-3.5 h-3.5 text-slate-700" />
              </div>
              <select
                value={sevFilter}
                onChange={(e) => setSevFilter(e.target.value)}
                className="bg-slate-950 border border-slate-900 rounded-lg py-1 px-2 text-xs font-semibold text-slate-400 focus:outline-none"
              >
                <option value="ALL">All Severity</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-slate-950 border border-slate-900 rounded-lg py-1 px-2 text-xs font-semibold text-slate-400 focus:outline-none"
              >
                <option value="ALL">All Status</option>
                <option value="open">Open</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>
          </div>

          {/* Alerts List */}
          <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
            {filteredAlerts.length === 0 ? (
              <div className="text-center py-16 border border-slate-950 rounded-xl text-xs text-slate-600">
                No incidents triggered matching the current filters.
              </div>
            ) : (
              filteredAlerts.map((alert) => (
                <div
                  key={alert.id}
                  className="border border-slate-900/60 bg-slate-950/20 hover:border-slate-800 rounded-xl p-4 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 transition"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[9px] font-black px-2 py-0.5 border rounded tracking-wider uppercase ${getAlertSeverityStyle(alert.severity)}`}>
                        {alert.severity}
                      </span>
                      <span className={`text-[9px] font-semibold px-2 py-0.5 border rounded uppercase ${
                        alert.status === 'resolved' ? 'border-emerald-500/20 bg-emerald-500/5 text-emerald-400' :
                        alert.status === 'acknowledged' ? 'border-cyan-500/20 bg-cyan-500/5 text-cyan-400' :
                        'border-red-500/20 bg-red-500/5 text-red-400'
                      }`}>
                        {alert.status}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {alert.created_at.substring(11, 16)} UTC
                      </span>
                    </div>
                    <p className="text-sm font-bold text-slate-200">{alert.rule_triggered.replace(/_/g, ' ')}</p>
                    <p className="text-xs text-slate-400 leading-normal max-w-xl">{alert.explanation}</p>
                    <div className="text-[10px] text-slate-500 font-semibold font-mono">Source Entity: <span className="text-cyan-400">{alert.source_ip}</span></div>
                  </div>
                  
                  <button
                    onClick={() => setSelectedAlert(alert)}
                    className="w-full md:w-auto flex items-center justify-center gap-1 border border-slate-800 hover:border-slate-700 bg-slate-900 text-slate-300 font-bold py-1.5 px-3 rounded-lg text-xs transition"
                  >
                    <Eye className="w-3.5 h-3.5" />
                    Inspect Details
                  </button>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Top Offending IPs Sidebar */}
        <div className="space-y-6">
          <div className="glass-panel p-5 space-y-4">
            <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Top Offending Entities</h3>
            <p className="text-xs text-slate-500 leading-normal">
              List of source IP addresses sorted by incident frequencies and total raw logging telemetry signatures.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-900 text-[10px] uppercase text-slate-500 font-bold">
                    <th className="pb-2">IP Address</th>
                    <th className="pb-2 text-right">Alerts</th>
                    <th className="pb-2 text-right">Events</th>
                  </tr>
                </thead>
                <tbody>
                  {topOffendingIps.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="text-center py-8 text-xs text-slate-700">No telemetry recorded yet.</td>
                    </tr>
                  ) : (
                    topOffendingIps.map((entity, idx) => (
                      <tr key={idx} className="border-b border-slate-950 text-xs text-slate-300">
                        <td className="py-2.5 font-mono text-cyan-400">{entity.ip}</td>
                        <td className="py-2.5 text-right font-bold text-red-500">{entity.alerts}</td>
                        <td className="py-2.5 text-right font-semibold text-slate-500">{entity.events}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Evidence Viewer Detail Modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onStatusUpdated={handleStatusUpdated}
        />
      )}
    </div>
  );
};
