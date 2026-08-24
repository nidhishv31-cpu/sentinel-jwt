import React, { useEffect, useState } from 'react';
import { API_BASE_URL } from '../config/api';
import { KeyRound, RefreshCw, Copy, Shield, ShieldCheck, Clock, Trash2, AlertTriangle } from 'lucide-react';

interface KeyInfo {
  kid: string;
  alg: string;
  status: 'active' | 'retired' | 'expired';
  created_at: string;
}

interface BlockedIp {
  ip: string;
  reason: string;
  blocked_at: string;
}

export const KeyManagementTab: React.FC = () => {
  const [activeKey, setActiveKey] = useState<KeyInfo | null>(null);
  const [keyHistory, setKeyHistory] = useState<KeyInfo[]>([]);
  const [blockedIps, setBlockedIps] = useState<BlockedIp[]>([]);
  
  const [rotating, setRotating] = useState(false);
  const [loading, setLoading] = useState(true);
  const [newBlockIp, setNewBlockIp] = useState('');
  const [newBlockReason, setNewBlockReason] = useState('');

  useEffect(() => {
    fetchKeyData();
    fetchBlockedIps();
  }, []);

  const fetchKeyData = async () => {
    setLoading(true);
    try {
      const [activeRes, listRes] = await Promise.all([
        fetch(`${API_BASE_URL}/keys/active`),
        fetch(`${API_BASE_URL}/keys/list`)
      ]);
      
      if (activeRes.ok) setActiveKey(await activeRes.json());
      if (listRes.ok) setKeyHistory(await listRes.json());
    } catch (err) {
      console.error('Error fetching keys:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchBlockedIps = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/waf/blocked`);
      if (res.ok) setBlockedIps(await res.json());
    } catch (err) {
      console.error('Error fetching blocked IPs:', err);
    }
  };

  const handleRotateKey = async () => {
    if (!window.confirm('Are you sure you want to rotate the active JWT key? This will issue a new key for future tokens.')) {
      return;
    }
    setRotating(true);
    try {
      const res = await fetch(`${API_BASE_URL}/keys/rotate`, { method: 'POST' });
      if (res.ok) {
        await fetchKeyData();
      }
    } catch (err) {
      console.error('Error rotating key:', err);
    } finally {
      setRotating(false);
    }
  };

  const handleCopyJwks = () => {
    const jwksUrl = `${API_BASE_URL.replace('/api', '')}/api/jwks.json`;
    navigator.clipboard.writeText(jwksUrl);
    alert('JWKS URL copied to clipboard');
  };

  const handleUnblock = async (ip: string) => {
    try {
      const res = await fetch(`${API_BASE_URL}/waf/unblock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      if (res.ok) fetchBlockedIps();
    } catch (err) {
      console.error('Error unblocking IP:', err);
    }
  };

  const handleBlockNew = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newBlockIp) return;
    try {
      const res = await fetch(`${API_BASE_URL}/waf/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: newBlockIp, reason: newBlockReason || 'Manual block' })
      });
      if (res.ok) {
        setNewBlockIp('');
        setNewBlockReason('');
        fetchBlockedIps();
      }
    } catch (err) {
      console.error('Error blocking IP:', err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Active Key Display */}
        <div className="lg:col-span-2 glass-panel p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-black text-cyan-400 flex items-center gap-2">
                <KeyRound className="w-6 h-6" /> Active Cryptographic Key
              </h2>
              {activeKey && (
                <span className="px-3 py-1 bg-emerald-500/20 text-emerald-400 border border-emerald-500/50 rounded-full text-xs font-black uppercase tracking-widest flex items-center gap-1">
                  <ShieldCheck className="w-3 h-3" /> Active
                </span>
              )}
            </div>
            
            {loading ? (
              <div className="flex items-center gap-2 text-slate-400">
                <RefreshCw className="w-5 h-5 animate-spin" /> Loading key data...
              </div>
            ) : activeKey ? (
              <div className="space-y-4 bg-slate-900/50 p-4 rounded-xl border border-slate-800">
                <div>
                  <p className="text-xs text-slate-500 uppercase font-bold tracking-wider mb-1">Key ID (KID)</p>
                  <p className="font-mono text-lg text-slate-200">{activeKey.kid}</p>
                </div>
                <div className="flex gap-8">
                  <div>
                    <p className="text-xs text-slate-500 uppercase font-bold tracking-wider mb-1">Algorithm</p>
                    <p className="font-bold text-cyan-400">{activeKey.alg}</p>
                  </div>
                  <div>
                    <p className="text-xs text-slate-500 uppercase font-bold tracking-wider mb-1">Created At</p>
                    <p className="text-slate-300">{new Date(activeKey.created_at).toLocaleString()}</p>
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-slate-500">No active key found.</p>
            )}
          </div>
          
          <div className="mt-6 flex flex-col sm:flex-row gap-4">
            <button
              onClick={handleRotateKey}
              disabled={rotating}
              className="flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white px-6 py-3 rounded-lg font-black tracking-wide transition shadow-[0_0_15px_rgba(0,210,255,0.3)]"
            >
              <RefreshCw className={`w-5 h-5 ${rotating ? 'animate-spin' : ''}`} />
              {rotating ? 'ROTATING...' : 'ROTATE KEY NOW'}
            </button>
          </div>
        </div>

        {/* JWKS Endpoint Info */}
        <div className="glass-panel p-6">
          <h2 className="text-lg font-black text-purple-400 mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5" /> JWKS Discovery
          </h2>
          <p className="text-sm text-slate-400 mb-4">
            Public keys for verifying JWT signatures are published via the JWKS endpoint. Services should cache this response.
          </p>
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 relative group">
            <p className="text-xs font-mono text-cyan-400 break-all pr-8">
              {API_BASE_URL.replace('/api', '')}/api/jwks.json
            </p>
            <button
              onClick={handleCopyJwks}
              className="absolute right-2 top-2 p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition"
              title="Copy URL"
            >
              <Copy className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Key History Table */}
        <div className="glass-panel p-6 overflow-hidden flex flex-col">
          <h2 className="text-lg font-black text-cyan-400 mb-4 flex items-center gap-2">
            <Clock className="w-5 h-5" /> Key Rotation History
          </h2>
          <div className="flex-grow overflow-auto border border-slate-800 rounded-lg">
            <table className="w-full text-left border-collapse">
              <thead className="bg-slate-900/80 text-xs uppercase tracking-wider text-slate-400 font-black sticky top-0">
                <tr>
                  <th className="p-3 border-b border-slate-800">KID</th>
                  <th className="p-3 border-b border-slate-800">Alg</th>
                  <th className="p-3 border-b border-slate-800">Status</th>
                  <th className="p-3 border-b border-slate-800">Created</th>
                </tr>
              </thead>
              <tbody className="text-sm divide-y divide-slate-800/50">
                {keyHistory.map((key) => (
                  <tr key={key.kid} className="hover:bg-slate-800/20 transition">
                    <td className="p-3 font-mono text-slate-300 text-xs">{key.kid.substring(0, 16)}...</td>
                    <td className="p-3 font-bold text-slate-400">{key.alg}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                        key.status === 'active' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                        key.status === 'retired' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                        'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                      }`}>
                        {key.status}
                      </span>
                    </td>
                    <td className="p-3 text-slate-400 text-xs whitespace-nowrap">
                      {new Date(key.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
                {keyHistory.length === 0 && !loading && (
                  <tr>
                    <td colSpan={4} className="p-4 text-center text-slate-500">No key history found.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* WAF Blocked IPs Panel */}
        <div className="glass-panel p-6 flex flex-col">
          <h2 className="text-lg font-black text-rose-400 mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" /> WAF Blocklist
          </h2>
          
          <form onSubmit={handleBlockNew} className="flex gap-2 mb-4">
            <input
              type="text"
              placeholder="IP Address"
              value={newBlockIp}
              onChange={(e) => setNewBlockIp(e.target.value)}
              className="w-1/3 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-rose-500/50 transition"
              required
            />
            <input
              type="text"
              placeholder="Reason (optional)"
              value={newBlockReason}
              onChange={(e) => setNewBlockReason(e.target.value)}
              className="flex-grow bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-rose-500/50 transition"
            />
            <button
              type="submit"
              className="bg-rose-600/20 hover:bg-rose-600/40 text-rose-400 border border-rose-500/50 px-4 py-2 rounded-lg text-sm font-bold transition whitespace-nowrap"
            >
              Block IP
            </button>
          </form>

          <div className="flex-grow overflow-auto border border-slate-800 rounded-lg">
            <table className="w-full text-left border-collapse">
              <thead className="bg-slate-900/80 text-xs uppercase tracking-wider text-slate-400 font-black sticky top-0">
                <tr>
                  <th className="p-3 border-b border-slate-800">IP Address</th>
                  <th className="p-3 border-b border-slate-800">Reason</th>
                  <th className="p-3 border-b border-slate-800">Date</th>
                  <th className="p-3 border-b border-slate-800 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="text-sm divide-y divide-slate-800/50">
                {blockedIps.map((b) => (
                  <tr key={b.ip} className="hover:bg-slate-800/20 transition">
                    <td className="p-3 font-mono text-rose-400 font-bold">{b.ip}</td>
                    <td className="p-3 text-slate-300 text-xs">{b.reason}</td>
                    <td className="p-3 text-slate-400 text-xs whitespace-nowrap">
                      {new Date(b.blocked_at).toLocaleDateString()}
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => handleUnblock(b.ip)}
                        className="p-1.5 bg-slate-800 hover:bg-emerald-500/20 text-slate-400 hover:text-emerald-400 rounded transition"
                        title="Unblock IP"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
                {blockedIps.length === 0 && (
                  <tr>
                    <td colSpan={4} className="p-4 text-center text-slate-500">No IPs currently blocked.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
