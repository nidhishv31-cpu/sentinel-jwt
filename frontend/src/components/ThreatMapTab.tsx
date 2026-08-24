import React, { useEffect, useState } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, Tooltip } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import { API_BASE_URL } from '../config/api';
import { Shield, RefreshCw, Search, ShieldAlert, Activity, Globe } from 'lucide-react';

interface GeoEvent {
  ip: string;
  country: string;
  city: string;
  lat: number;
  lon: number;
  event_count: number;
  isp?: string;
}

interface ThreatStats {
  total_known_threats: number;
  feeds_loaded: number;
  last_updated: string;
}

export const ThreatMapTab: React.FC = () => {
  const [geoEvents, setGeoEvents] = useState<GeoEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [threatStats, setThreatStats] = useState<ThreatStats | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [ipLookup, setIpLookup] = useState('');
  const [lookupResult, setLookupResult] = useState<any>(null);
  const [blockingIp, setBlockingIp] = useState<string | null>(null);

  useEffect(() => {
    fetchMapData();
    fetchThreatStats();
  }, []);

  const fetchMapData = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE_URL}/geo/attack-map`);
      if (res.ok) {
        const data = await res.json();
        setGeoEvents(data);
      }
    } catch (err) {
      console.error('Error fetching map data:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchThreatStats = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/threat-intel/stats`);
      if (res.ok) {
        const data = await res.json();
        setThreatStats(data);
      }
    } catch (err) {
      console.error('Error fetching threat stats:', err);
    }
  };

  const handleRefreshFeeds = async () => {
    setRefreshing(true);
    try {
      const res = await fetch(`${API_BASE_URL}/threat-intel/refresh`, { method: 'POST' });
      if (res.ok) {
        await fetchThreatStats();
      }
    } catch (err) {
      console.error('Error refreshing feeds:', err);
    } finally {
      setRefreshing(false);
    }
  };

  const handleBlockIp = async (ip: string) => {
    setBlockingIp(ip);
    try {
      const res = await fetch(`${API_BASE_URL}/waf/block`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason: 'Blocked from threat map' })
      });
      if (res.ok) {
        alert(`Successfully blocked IP: ${ip}`);
      }
    } catch (err) {
      console.error('Error blocking IP:', err);
    } finally {
      setBlockingIp(null);
    }
  };

  const handleIpLookup = async () => {
    if (!ipLookup) return;
    try {
      const res = await fetch(`${API_BASE_URL}/threat-intel/lookup/${ipLookup}`);
      if (res.ok) {
        const data = await res.json();
        setLookupResult(data);
      } else {
        setLookupResult({ error: 'Lookup failed' });
      }
    } catch (err) {
      console.error('Error looking up IP:', err);
      setLookupResult({ error: 'Network error' });
    }
  };

  const getMarkerColor = (count: number) => {
    if (count > 10) return '#ef4444'; // red
    if (count >= 5) return '#f97316'; // orange
    return '#06b6d4'; // cyan
  };

  const getMarkerRadius = (count: number) => {
    const radius = 5 + Math.log10(count) * 10;
    return Math.min(Math.max(radius, 5), 25);
  };

  const totalEvents = geoEvents.reduce((acc, curr) => acc + curr.event_count, 0);
  const totalIps = geoEvents.length;
  const countryCounts = geoEvents.reduce((acc, curr) => {
    acc[curr.country] = (acc[curr.country] || 0) + curr.event_count;
    return acc;
  }, {} as Record<string, number>);
  const topCountry = Object.keys(countryCounts).sort((a, b) => countryCounts[b] - countryCounts[a])[0] || 'N/A';

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-panel p-4 flex items-center gap-4">
          <div className="p-3 bg-cyan-500/10 rounded-lg text-cyan-400">
            <Globe className="w-6 h-6" />
          </div>
          <div>
            <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Unique Attack IPs</p>
            <p className="text-2xl font-black text-slate-100">{totalIps}</p>
          </div>
        </div>
        <div className="glass-panel p-4 flex items-center gap-4">
          <div className="p-3 bg-purple-500/10 rounded-lg text-purple-400">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Total Geo Events</p>
            <p className="text-2xl font-black text-slate-100">{totalEvents}</p>
          </div>
        </div>
        <div className="glass-panel p-4 flex items-center gap-4">
          <div className="p-3 bg-rose-500/10 rounded-lg text-rose-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Top Origin Country</p>
            <p className="text-2xl font-black text-slate-100">{topCountry}</p>
          </div>
        </div>
      </div>

      <div className="glass-panel p-1 rounded-xl overflow-hidden relative" style={{ height: '500px' }}>
        {loading ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center bg-[#05060b]/80 z-[1000]">
            <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mb-4" />
            <p className="text-cyan-400 font-bold">Loading Geo Data...</p>
          </div>
        ) : geoEvents.length === 0 ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center bg-[#05060b]/80 z-[1000]">
            <Globe className="w-12 h-12 text-slate-600 mb-4" />
            <p className="text-slate-400 font-bold text-lg">No attack origin data available.</p>
          </div>
        ) : null}
        <MapContainer center={[20, 0]} zoom={2} style={{ height: '100%', width: '100%', borderRadius: '0.75rem' }}>
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            attribution="&copy; OpenStreetMap contributors &copy; CARTO"
          />
          {geoEvents.map((evt, idx) => (
            <CircleMarker
              key={`${evt.ip}-${idx}`}
              center={[evt.lat, evt.lon]}
              radius={getMarkerRadius(evt.event_count)}
              pathOptions={{
                color: getMarkerColor(evt.event_count),
                fillColor: getMarkerColor(evt.event_count),
                fillOpacity: 0.6,
                weight: 1
              }}
            >
              <Tooltip>
                <div className="text-xs font-bold bg-slate-900 text-slate-100 p-1 border border-slate-700 rounded">
                  {evt.ip} <br />
                  {evt.city}, {evt.country}
                </div>
              </Tooltip>
              <Popup className="bg-slate-900 border-slate-700">
                <div className="p-2 space-y-2">
                  <p className="font-black text-cyan-400 text-base">{evt.ip}</p>
                  <div className="text-xs text-slate-300">
                    <p><strong>Location:</strong> {evt.city}, {evt.country}</p>
                    {evt.isp && <p><strong>ISP:</strong> {evt.isp}</p>}
                    <p><strong>Events:</strong> {evt.event_count}</p>
                  </div>
                  <button
                    onClick={() => handleBlockIp(evt.ip)}
                    disabled={blockingIp === evt.ip}
                    className="w-full mt-2 bg-rose-500/20 hover:bg-rose-500/40 text-rose-400 border border-rose-500/50 py-1 px-2 rounded text-xs font-bold transition flex items-center justify-center gap-2"
                  >
                    <Shield className="w-3 h-3" />
                    {blockingIp === evt.ip ? 'Blocking...' : 'Block IP'}
                  </button>
                </div>
              </Popup>
            </CircleMarker>
          ))}
        </MapContainer>
      </div>

      <div className="glass-panel p-6">
        <h2 className="text-lg font-black text-cyan-400 mb-4 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5" /> Threat Intelligence
        </h2>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <div className="space-y-4">
            <div className="bg-slate-900/50 border border-slate-800 p-4 rounded-lg flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400 font-bold mb-1">Total Known Threats</p>
                <p className="text-2xl font-black text-rose-400">{threatStats?.total_known_threats || 0}</p>
              </div>
              <div className="text-right">
                <p className="text-sm text-slate-400 font-bold mb-1">Feeds Loaded</p>
                <p className="text-xl font-black text-cyan-400">{threatStats?.feeds_loaded || 0}</p>
              </div>
            </div>
            
            <div className="flex items-center justify-between">
              <p className="text-xs text-slate-500">
                Last updated: {threatStats?.last_updated ? new Date(threatStats.last_updated).toLocaleString() : 'N/A'}
              </p>
              <button
                onClick={handleRefreshFeeds}
                disabled={refreshing}
                className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 px-4 py-2 rounded-lg text-sm font-bold transition border border-slate-700"
              >
                <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
                {refreshing ? 'Refreshing...' : 'Refresh Feeds'}
              </button>
            </div>
          </div>

          <div className="space-y-4 border-t lg:border-t-0 lg:border-l border-slate-800 pt-4 lg:pt-0 lg:pl-8">
            <p className="text-sm text-slate-400 font-bold">Threat IP Lookup</p>
            <div className="flex gap-2">
              <div className="relative flex-grow">
                <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-500" />
                <input
                  type="text"
                  placeholder="Enter IP address (e.g. 1.1.1.1)"
                  value={ipLookup}
                  onChange={(e) => setIpLookup(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500/50 transition"
                />
              </div>
              <button
                onClick={handleIpLookup}
                className="bg-cyan-600/20 hover:bg-cyan-600/40 text-cyan-400 border border-cyan-500/50 px-4 py-2 rounded-lg text-sm font-bold transition"
              >
                Check IP
              </button>
            </div>
            
            {lookupResult && (
              <div className={`p-4 rounded-lg text-sm font-bold border ${lookupResult.error ? 'bg-slate-800/50 text-slate-300 border-slate-700' : lookupResult.known_threat || lookupResult.status === 'malicious' ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'}`}>
                <pre className="whitespace-pre-wrap font-sans">
                  {JSON.stringify(lookupResult, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
