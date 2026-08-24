import React, { useState } from 'react';
import { Upload, FileText, CheckCircle2, AlertTriangle, RefreshCw, BarChart2, ShieldAlert } from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';
import { API_BASE_URL } from '../config/api';

const SAMPLE_LOGS = `192.168.1.50 - - [17/Aug/2026:10:15:30 +0000] "POST /api/auth/login HTTP/1.1" 200 450 "https://sentineljwt.io/" "Mozilla/5.0"
198.51.100.1 - - [17/Aug/2026:10:20:01 +0000] "POST /api/auth/login HTTP/1.1" 401 120 "https://sentineljwt.io/" "Mozilla/5.0"
198.51.100.1 - - [17/Aug/2026:10:20:10 +0000] "POST /api/auth/login HTTP/1.1" 401 120 "https://sentineljwt.io/" "Mozilla/5.0"
198.51.100.1 - - [17/Aug/2026:10:20:15 +0000] "POST /api/auth/login HTTP/1.1" 401 120 "https://sentineljwt.io/" "Mozilla/5.0"
198.51.100.1 - - [17/Aug/2026:10:20:20 +0000] "POST /api/auth/login HTTP/1.1" 401 120 "https://sentineljwt.io/" "Mozilla/5.0"
198.51.100.1 - - [17/Aug/2026:10:20:25 +0000] "POST /api/auth/login HTTP/1.1" 401 120 "https://sentineljwt.io/" "Mozilla/5.0"
198.51.100.1 - - [17/Aug/2026:10:20:30 +0000] "POST /api/auth/login HTTP/1.1" 401 120 "https://sentineljwt.io/" "Mozilla/5.0"
203.0.113.2 - - [17/Aug/2026:10:25:00 +0000] "POST /api/auth/login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
203.0.113.2 - - [17/Aug/2026:10:25:05 +0000] "POST /api/auth/login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
203.0.113.2 - - [17/Aug/2026:10:25:10 +0000] "POST /api/auth/login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
203.0.113.2 - - [17/Aug/2026:10:25:15 +0000] "POST /api/auth/login HTTP/1.1" 401 120 "-" "Mozilla/5.0"
{"timestamp": "2026-08-17T10:30:00Z", "source_ip": "192.168.1.100", "endpoint": "/api/dashboard", "status_code": 200, "user_agent": "Mozilla/5.0", "username": "admin"}`;

const COLORS = ['#10b981', '#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6'];

export const LogIngestTab: React.FC = () => {
  const [dragActive, setDragActive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<{ success: boolean; count: number; msg: string } | null>(null);
  const [manualText, setManualText] = useState('');
  const [error, setError] = useState('');
  
  // Parsed logs dashboard state
  const [ingestedEvents, setIngestedEvents] = useState<any[]>([]);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const uploadLogFile = async (file: File) => {
    setLoading(true);
    setError('');
    setStatus(null);
    setIngestedEvents([]);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`${API_BASE_URL}/logs/ingest`, {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) throw new Error('File upload failed.');
      const data = await res.json();
      
      setStatus({
        success: data.success,
        count: data.events_parsed,
        msg: data.message
      });

      if (data.success && data.events) {
        setIngestedEvents(data.events);
      }
    } catch (err: any) {
      setError(err.message || 'An error occurred during ingestion.');
    } finally {
      setLoading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      uploadLogFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      uploadLogFile(e.target.files[0]);
    }
  };

  const handleManualSubmit = async () => {
    if (!manualText.trim()) return;
    setLoading(true);
    setError('');
    setStatus(null);
    setIngestedEvents([]);

    // Create file blob from text
    const blob = new Blob([manualText], { type: 'text/plain' });
    const file = new File([blob], 'manual_input.log');
    await uploadLogFile(file);
  };

  const loadSample = () => {
    setManualText(SAMPLE_LOGS);
  };

  // Compile metrics for analytics dashboard
  const getStatusCodeDistribution = () => {
    const counts: Record<string, number> = {};
    ingestedEvents.forEach(ev => {
      const details = ev.details || {};
      const code = String(details.status_code || 200);
      counts[code] = (counts[code] || 0) + 1;
    });
    return Object.keys(counts).map(code => ({
      name: `HTTP ${code}`,
      value: counts[code]
    }));
  };

  const getTopEndpoints = () => {
    const counts: Record<string, number> = {};
    ingestedEvents.forEach(ev => {
      const details = ev.details || {};
      const ep = details.endpoint || "/";
      counts[ep] = (counts[ep] || 0) + 1;
    });
    return Object.keys(counts)
      .map(ep => ({ endpoint: ep, count: counts[ep] }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  };

  const getTopSourceIps = () => {
    const counts: Record<string, number> = {};
    ingestedEvents.forEach(ev => {
      counts[ev.source_ip] = (counts[ev.source_ip] || 0) + 1;
    });
    return Object.keys(counts)
      .map(ip => ({ ip, count: counts[ip] }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  };

  const statusCodesData = getStatusCodeDistribution();
  const topEndpoints = getTopEndpoints();
  const topSourceIps = getTopSourceIps();

  return (
    <div className="space-y-6 p-4">
      {/* Upper row: Upload & Manual workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* File Ingest Panel */}
        <div className="glass-panel p-6 space-y-6">
          <h2 className="text-xl font-bold flex items-center gap-2 text-cyan-400">
            <Upload className="w-5 h-5" />
            Log File Ingest (SIEM-lite)
          </h2>
          <p className="text-sm text-slate-400">
            Upload server access logs in standard Apache/Nginx Combined format or JSON Lines formats. The SIEM engine will automatically index events and evaluate brute-force, stuffing, or correlation rules.
          </p>

          {/* Drag and Drop Zone */}
          <div
            onDragEnter={handleDrag}
            onDragOver={handleDrag}
            onDragLeave={handleDrag}
            onDrop={handleDrop}
            className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition relative h-60 flex flex-col justify-center items-center ${
              dragActive ? 'border-cyan-500 bg-cyan-950/20' : 'border-slate-800 hover:border-slate-700 bg-slate-950/20'
            }`}
          >
            <input
              type="file"
              onChange={handleFileChange}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              accept=".log,.txt,.json"
            />
            {loading ? (
              <div className="space-y-3">
                <RefreshCw className="w-10 h-10 animate-spin text-cyan-400 mx-auto" />
                <span className="text-xs font-semibold text-slate-300">Parsing and running SIEM detections...</span>
              </div>
            ) : (
              <div className="space-y-4">
                <FileText className="w-12 h-12 text-slate-600 mx-auto" />
                <div>
                  <p className="text-sm font-semibold text-slate-200">Drag and drop your server log file here</p>
                  <p className="text-xs text-slate-500 mt-1">Supports Nginx Combined or JSON lines format (.log, .txt, .json)</p>
                </div>
                <button className="bg-slate-900 border border-slate-850 text-slate-300 px-4 py-2 rounded-lg text-xs font-bold hover:bg-slate-850">
                  Browse Files
                </button>
              </div>
            )}
          </div>

          {/* Status outputs */}
          {status && (
            <div className={`border rounded-lg p-4 flex gap-3 ${
              status.success ? 'border-emerald-950 bg-emerald-950/15 text-emerald-400' : 'border-amber-950 bg-amber-950/15 text-amber-400'
            }`}>
              {status.success ? (
                <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-500" />
              ) : (
                <AlertTriangle className="w-5 h-5 shrink-0 text-amber-500" />
              )}
              <div className="text-xs">
                <p className="font-bold">{status.success ? 'Log Ingestion Successful' : 'Ingestion Partial/Failed'}</p>
                <p className="text-slate-400 mt-1">{status.msg}</p>
              </div>
            </div>
          )}

          {error && (
            <div className="border border-red-950 bg-red-950/20 text-red-400 rounded-lg p-4 text-xs">
              <p className="font-bold">Error Ingesting Log</p>
              <p className="text-slate-500 mt-1">{error}</p>
            </div>
          )}
        </div>

        {/* Manual Input Workspace */}
        <div className="glass-panel p-6 space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-md font-bold text-slate-300">Raw Logs Workspace</h3>
            <button
              onClick={loadSample}
              className="text-xs font-semibold text-cyan-400 hover:text-cyan-300"
            >
              Load Sample Telemetry
            </button>
          </div>
          <p className="text-xs text-slate-400">
            Paste log entries below to test raw string parsing or simulate specific security incidents.
          </p>

          <textarea
            className="w-full h-64 bg-slate-950 border border-slate-900 rounded-lg p-3 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 text-slate-300 placeholder-slate-800"
            placeholder="Paste log lines here..."
            value={manualText}
            onChange={(e) => setManualText(e.target.value)}
          />

          <button
            onClick={handleManualSubmit}
            disabled={loading || !manualText.trim()}
            className="w-full bg-slate-900 border border-slate-800 hover:border-slate-700 text-cyan-400 font-bold py-2.5 px-4 rounded-lg text-sm transition disabled:opacity-50"
          >
            Submit Workspace Logs
          </button>
        </div>
      </div>

      {/* LOWER ROW: Detailed Log Analysis Dashboard (Appears after successful ingestion) */}
      {ingestedEvents.length > 0 && (
        <div className="glass-panel p-6 space-y-6 animate-fade-in">
          <div className="flex justify-between items-center border-b border-slate-900 pb-4">
            <div>
              <h2 className="text-lg font-bold text-slate-300 flex items-center gap-2">
                <BarChart2 className="w-5 h-5 text-cyan-400" />
                Log Telemetry Analysis & Insights
              </h2>
              <p className="text-xs text-slate-500 mt-1">Processed {ingestedEvents.length} log rows from your payload.</p>
            </div>
            <span className="text-[10px] bg-cyan-950/40 text-cyan-400 font-mono font-bold px-3 py-1 rounded-full border border-cyan-900/30">
              LOGS STREAM ACTIVE
            </span>
          </div>

          {/* Grid charts and top lists */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* Chart: Status Codes */}
            <div className="border border-slate-900 bg-slate-950/20 rounded-xl p-5 space-y-3 flex flex-col justify-between">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Response Codes Share</h4>
              <div className="h-40 flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={statusCodesData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      outerRadius={45}
                      label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                      fontSize={8}
                    >
                      {statusCodesData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#090a0f', borderColor: '#334155', color: '#fff', fontSize: 10 }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* List: Top Requested Endpoints */}
            <div className="border border-slate-900 bg-slate-950/20 rounded-xl p-5 space-y-3">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Top Requested URIs</h4>
              <div className="space-y-2 mt-2">
                {topEndpoints.map((ep, idx) => (
                  <div key={idx} className="flex justify-between items-center text-xs font-mono py-1 border-b border-slate-950/30">
                    <span className="text-cyan-400 truncate max-w-[170px]" title={ep.endpoint}>{ep.endpoint}</span>
                    <span className="text-slate-500 font-bold">{ep.count} hits</span>
                  </div>
                ))}
              </div>
            </div>

            {/* List: Top Requester IPs */}
            <div className="border border-slate-900 bg-slate-950/20 rounded-xl p-5 space-y-3">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Top Client IPs</h4>
              <div className="space-y-2 mt-2">
                {topSourceIps.map((ip, idx) => (
                  <div key={idx} className="flex justify-between items-center text-xs font-mono py-1 border-b border-slate-950/30">
                    <span className="text-purple-400">{ip.ip}</span>
                    <span className="text-slate-500 font-bold">{ip.count} events</span>
                  </div>
                ))}
              </div>
            </div>

          </div>

          {/* Grid: Parsed Lines Data Table */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Parsed Access Events List</h4>
            <div className="overflow-x-auto border border-slate-900 rounded-xl">
              <table className="w-full text-left border-collapse min-w-[700px] bg-slate-950/20">
                <thead>
                  <tr className="border-b border-slate-900 text-[10px] uppercase text-slate-500 font-bold font-mono">
                    <th className="p-3">Time</th>
                    <th className="p-3">Source IP</th>
                    <th className="p-3">Method</th>
                    <th className="p-3">Endpoint</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">User Agent</th>
                  </tr>
                </thead>
                <tbody>
                  {ingestedEvents.map((ev, idx) => {
                    const details = ev.details || {};
                    const isFailed = details.status_code >= 400;
                    return (
                      <tr key={idx} className="border-b border-slate-950 text-xs font-mono hover:bg-slate-950/40 text-slate-300">
                        <td className="p-3 text-slate-500 truncate max-w-[130px]">{ev.timestamp}</td>
                        <td className="p-3 text-purple-400">{ev.source_ip}</td>
                        <td className="p-3 font-semibold text-slate-400">{details.method || "GET"}</td>
                        <td className="p-3 text-cyan-400 truncate max-w-[150px]" title={details.endpoint}>{details.endpoint}</td>
                        <td className={`p-3 font-bold ${isFailed ? 'text-red-500' : 'text-emerald-500'}`}>
                          {details.status_code}
                        </td>
                        <td className="p-3 text-slate-500 truncate max-w-[180px]" title={details.user_agent}>{details.user_agent}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default LogIngestTab;
