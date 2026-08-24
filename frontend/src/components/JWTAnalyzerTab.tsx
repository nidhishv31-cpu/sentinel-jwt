import React, { useState, useEffect } from 'react';
import { ShieldAlert, ShieldCheck, Key, RefreshCw, Upload, AlertCircle } from 'lucide-react';
import { API_BASE_URL } from '../config/api';

interface Finding {
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
}

interface AnalysisResult {
  decoded_header: any;
  decoded_payload: any;
  findings: Finding[];
  risk_score: number;
}

export const JWTAnalyzerTab: React.FC = () => {
  const [token, setToken] = useState('');
  const [secret, setSecret] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');
  
  // Batch processing states
  const [batchTokensText, setBatchTokensText] = useState('');
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchResult, setBatchResult] = useState<{ total: number; findings: number } | null>(null);

  // Live decoding logic
  const [liveHeader, setLiveHeader] = useState<any>(null);
  const [livePayload, setLivePayload] = useState<any>(null);

  useEffect(() => {
    if (!token) {
      setLiveHeader(null);
      setLivePayload(null);
      return;
    }

    const parts = token.trim().split('.');
    if (parts.length >= 2) {
      try {
        const base64UrlDecode = (str: string) => {
          let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
          while (base64.length % 4) {
            base64 += '=';
          }
          return decodeURIComponent(
            atob(base64)
              .split('')
              .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
              .join('')
          );
        };

        const decodedH = JSON.parse(base64UrlDecode(parts[0]));
        const decodedP = JSON.parse(base64UrlDecode(parts[1]));
        setLiveHeader(decodedH);
        setLivePayload(decodedP);
      } catch (err) {
        setLiveHeader({ error: "Malformed Base64 / JSON Header" });
        setLivePayload({ error: "Malformed Base64 / JSON Payload" });
      }
    } else {
      setLiveHeader(null);
      setLivePayload(null);
    }
  }, [token]);

  const handleAnalyze = async () => {
    if (!token) return;
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const res = await fetch(`${API_BASE_URL}/jwt/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, secret: secret || undefined }),
      });

      if (!res.ok) throw new Error('Failed to analyze token');
      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'An error occurred during analysis');
    } finally {
      setLoading(false);
    }
  };

  const handleBatchAnalyze = async () => {
    // Regex to scan text and extract JWT tokens
    const jwtRegex = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/g;
    const matches = batchTokensText.match(jwtRegex) || [];
    
    if (matches.length === 0) {
      setError('No valid JWT tokens found in the batch input.');
      return;
    }

    setBatchLoading(true);
    setError('');
    setBatchResult(null);

    try {
      const res = await fetch(`${API_BASE_URL}/jwt/analyze-batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tokens: matches }),
      });

      if (!res.ok) throw new Error('Batch analysis failed');
      const data = await res.json();
      setBatchResult({
        total: data.total_analyzed,
        findings: data.findings_count
      });
      setBatchTokensText('');
    } catch (err: any) {
      setError(err.message || 'An error occurred during batch analysis');
    } finally {
      setBatchLoading(false);
    }
  };

  const handleBatchUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setBatchTokensText(text);
    };
    reader.readAsText(file);
  };

  // Color selection based on risk score
  const getRiskColor = (score: number) => {
    if (score >= 75) return 'text-red-500 border-red-500/30 bg-red-500/10';
    if (score >= 50) return 'text-orange-500 border-orange-500/30 bg-orange-500/10';
    if (score >= 25) return 'text-yellow-500 border-yellow-500/30 bg-yellow-500/10';
    return 'text-emerald-500 border-emerald-500/30 bg-emerald-500/10';
  };

  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border border-orange-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40';
      case 'LOW':
        return 'bg-blue-500/20 text-blue-400 border border-blue-500/40';
      default:
        return 'bg-slate-500/20 text-slate-400 border border-slate-500/40';
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 p-4">
      {/* Input Form and Live Decode */}
      <div className="lg:col-span-2 space-y-6">
        {/* Token Input Box */}
        <div className="glass-panel p-6 space-y-4">
          <h2 className="text-xl font-bold flex items-center gap-2 text-cyan-400">
            <Key className="w-5 h-5 text-cyan-400" />
            JWT Security Analyzer
          </h2>
          <p className="text-sm text-slate-400">
            Analyze JSON Web Tokens safely. Paste a token to inspect its claims, structure, signature strength, and verify weaknesses like algorithm confusion or brute-forceable secrets.
          </p>

          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">JWT Token String</label>
            <textarea
              className="w-full h-32 bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 text-slate-300 placeholder-slate-700"
              placeholder="eyJhbGciOi..."
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Signature Verification Secret (Optional)
              </label>
              <input
                type="text"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 text-slate-300 placeholder-slate-800"
                placeholder="e.g. secret, 123456"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
              />
            </div>
            
            <div className="flex items-end">
              <button
                onClick={handleAnalyze}
                disabled={loading || !token}
                className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold py-2.5 px-4 rounded-lg transition disabled:opacity-50"
              >
                {loading ? <RefreshCw className="w-4 h-5 animate-spin" /> : 'Analyze Token'}
              </button>
            </div>
          </div>
          
          {error && (
            <div className="flex items-center gap-2 border border-red-950/40 bg-red-950/20 text-red-400 rounded-lg p-3 text-sm">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Live Decoded Viewer */}
        <div className="glass-panel p-6">
          <h3 className="text-md font-bold text-slate-300 mb-4 uppercase tracking-wider text-xs">Live Decode Preview (Safe Parse)</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Header Box */}
            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-500 uppercase">Header</span>
              <pre className="bg-slate-950 border border-slate-900 rounded-lg p-4 h-64 text-xs font-mono overflow-auto text-cyan-400">
                {liveHeader ? JSON.stringify(liveHeader, null, 2) : '// Paste token to view header'}
              </pre>
            </div>
            {/* Payload Box */}
            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-500 uppercase">Payload</span>
              <pre className="bg-slate-950 border border-slate-900 rounded-lg p-4 h-64 text-xs font-mono overflow-auto text-purple-400">
                {livePayload ? JSON.stringify(livePayload, null, 2) : '// Paste token to view payload'}
              </pre>
            </div>
          </div>
        </div>
      </div>

      {/* Results and Batch Upload Sidebar */}
      <div className="space-y-6">
        {/* Risk Gauge and Findings */}
        {result && (
          <div className="glass-panel p-6 space-y-6">
            <h3 className="text-lg font-bold text-slate-300">Analysis Results</h3>
            
            {/* Risk Score gauge */}
            <div className="flex flex-col items-center justify-center p-4 rounded-xl border border-slate-900 bg-slate-950/40">
              <div className="relative w-36 h-36 flex items-center justify-center">
                {/* SVG Progress Circle */}
                <svg className="w-full h-full transform -rotate-90">
                  <circle
                    cx="72"
                    cy="72"
                    r="60"
                    className="stroke-slate-900 fill-none"
                    strokeWidth="10"
                  />
                  <circle
                    cx="72"
                    cy="72"
                    r="60"
                    className={`fill-none transition-all duration-1000 ${
                      result.risk_score >= 75 ? 'stroke-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]' :
                      result.risk_score >= 50 ? 'stroke-orange-500' :
                      result.risk_score >= 25 ? 'stroke-yellow-500' : 'stroke-emerald-500'
                    }`}
                    strokeWidth="10"
                    strokeDasharray={2 * Math.PI * 60}
                    strokeDashoffset={2 * Math.PI * 60 * (1 - result.risk_score / 100)}
                    strokeLinecap="round"
                  />
                </svg>
                <div className="absolute flex flex-col items-center justify-center">
                  <span className="text-3xl font-black text-slate-100">{result.risk_score}</span>
                  <span className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Risk Score</span>
                </div>
              </div>
              
              <div className={`mt-4 px-4 py-1 border rounded-full text-xs font-bold ${getRiskColor(result.risk_score)}`}>
                {result.risk_score >= 75 ? 'CRITICAL RISK' :
                 result.risk_score >= 50 ? 'HIGH RISK' :
                 result.risk_score >= 25 ? 'MEDIUM RISK' : 'LOW RISK'}
              </div>
            </div>

            {/* Findings list */}
            <div className="space-y-3">
              <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest">Findings ({result.findings.length})</h4>
              
              {result.findings.length === 0 ? (
                <div className="flex items-center gap-3 border border-emerald-950/20 bg-emerald-950/10 text-emerald-400 rounded-lg p-4">
                  <ShieldCheck className="w-5 h-5 shrink-0" />
                  <div className="text-xs">
                    <p className="font-bold">No findings detected</p>
                    <p className="text-slate-400">Token conforms to basic security standard requirements.</p>
                  </div>
                </div>
              ) : (
                <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
                  {result.findings.map((f, i) => (
                    <div key={i} className="border border-slate-900 bg-slate-950/20 rounded-lg p-3 space-y-1.5">
                      <div className="flex justify-between items-start gap-2">
                        <span className="text-xs font-bold text-slate-200">{f.title}</span>
                        <span className={`text-[9px] px-2 py-0.5 rounded font-black tracking-wider uppercase ${getSeverityStyle(f.severity)}`}>
                          {f.severity}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 leading-relaxed">{f.description}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Batch Upload Section */}
        <div className="glass-panel p-6 space-y-4">
          <h3 className="text-lg font-bold text-slate-300 flex items-center gap-2">
            <Upload className="w-4 h-4 text-cyan-400" />
            Batch Log Extraction
          </h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Upload logs/files to automatically identify, parse, and scan any JWT tokens. They will be submitted to the event pipeline as <code className="text-purple-400">jwt_finding</code>.
          </p>
          
          <div className="border border-dashed border-slate-800 hover:border-slate-700 bg-slate-950/30 rounded-lg p-4 text-center cursor-pointer transition relative">
            <input
              type="file"
              onChange={handleBatchUpload}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
              accept=".txt,.log,.json"
            />
            <Upload className="w-6 h-6 mx-auto text-slate-600 mb-2" />
            <span className="text-xs font-semibold text-slate-400">Click or Drag Log File here</span>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-500 uppercase">Or Paste Text / Log Lines containing JWTs</label>
            <textarea
              className="w-full h-24 bg-slate-950 border border-slate-900 rounded-lg p-2 text-[10px] font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 text-slate-300 placeholder-slate-800"
              placeholder="Paste raw text here..."
              value={batchTokensText}
              onChange={(e) => setBatchTokensText(e.target.value)}
            />
          </div>

          <button
            onClick={handleBatchAnalyze}
            disabled={batchLoading || !batchTokensText}
            className="w-full flex items-center justify-center gap-2 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 font-semibold py-2 px-3 rounded-lg text-sm transition disabled:opacity-50"
          >
            {batchLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : 'Run Batch Analysis'}
          </button>

          {batchResult && (
            <div className="border border-cyan-950/30 bg-cyan-950/10 text-cyan-400 rounded-lg p-3 text-xs space-y-1">
              <p className="font-bold">Batch Processing Completed</p>
              <p className="text-slate-400">Analyzed {batchResult.total} tokens. Created {batchResult.findings} finding events.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
