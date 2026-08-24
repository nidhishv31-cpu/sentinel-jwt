import React, { useState, useEffect, useRef } from 'react';
import { Upload, FileCode, CheckCircle2, AlertOctagon, RefreshCw, BarChart2, Play, Square, Filter, ChevronRight, ChevronDown } from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, Tooltip } from 'recharts';
import { API_BASE_URL, WS_BASE_URL } from '../config/api';

interface ProtocolEntry {
  protocol: string;
  count: number;
  bytes: number;
}

interface TalkerEntry {
  ip: string;
  packets: number;
  bytes: number;
}

interface TimelineEntry {
  time: string;
  packets: number;
}

interface PcapSummary {
  capture_id: string;
  total_packets: number;
  total_bytes: number;
  protocols: ProtocolEntry[];
  top_talkers: TalkerEntry[];
  timeline: TimelineEntry[];
}

interface NetworkInterface {
  index: string;
  name: string;
  friendly_name: string;
}

interface PacketEvent {
  id: number;
  timestamp: string;
  source_ip: string;
  details: {
    dst_ip: string;
    src_port: number;
    dst_port: number;
    protocol: string;
    packet_summary: string;
    bytes: number;
    layers: Record<string, Record<string, string>>;
    raw_line: string;
    flags?: Record<string, boolean>;
    dns_info?: any;
    arp_info?: any;
    http_info?: any;
  };
}

const COLORS = ['#00d2ff', '#9d00ff', '#f43f5e', '#10b981', '#f59e0b', '#3b82f6', '#ec4899'];

export const PcapIngestTab: React.FC = () => {
  // Mode toggle: 'upload' or 'live'
  const [mode, setMode] = useState<'upload' | 'live'>('upload');

  // Trace Upload States
  const [dragActive, setDragActive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState<PcapSummary | null>(null);
  const [error, setError] = useState('');

  // Live Capture States
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);
  const [livePacketCount, setLivePacketCount] = useState(0);
  const [livePackets, setLivePackets] = useState<PacketEvent[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<PacketEvent | null>(null);
  const [filterExpr, setFilterExpr] = useState('');
  const [activeFilter, setActiveFilter] = useState('');
  
  // Collapsible layers state for tree view
  const [expandedLayers, setExpandedLayers] = useState<Record<string, boolean>>({});

  const wsRef = useRef<WebSocket | null>(null);

  // Fetch interfaces and capture status on mount
  useEffect(() => {
    const fetchInterfaces = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/pcap/interfaces`);
        if (res.ok) {
          const data = await res.json();
          setInterfaces(data);
          if (data.length > 0) {
            setSelectedInterface(data[0].name);
          }
        }
      } catch (err) {
        console.error("Error loading network interfaces:", err);
      }
    };

    const fetchCaptureStatus = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/pcap/capture/status`);
        if (res.ok) {
          const data = await res.json();
          setIsCapturing(data.is_running);
          setLivePacketCount(data.captured_count);
          if (data.interface) {
            setSelectedInterface(data.interface);
          }
        }
      } catch (err) {
        console.error("Error fetching capture status:", err);
      }
    };

    fetchInterfaces();
    fetchCaptureStatus();
    loadLivePackets();
  }, []);

  // Set up WebSockets to receive live packets when capturing
  useEffect(() => {
    const ws = new WebSocket(WS_BASE_URL);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'new_event' && data.event.event_type === 'packet_event') {
          // If a display filter is active, check if it matches before adding,
          // or just load all packets and filter client-side for simplicity,
          // but reloading packets is also fine. Let's append to list
          const newPkt = data.event as PacketEvent;
          setLivePackets(prev => [newPkt, ...prev].slice(0, 500)); // limit UI list to 500
          setLivePacketCount(c => c + 1);
        }
      } catch (err) {
        console.error(err);
      }
    };

    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const loadLivePackets = async (expr: string = '') => {
    try {
      const url = expr 
        ? `${API_BASE_URL}/events?event_type=packet_event&limit=100&filter_expr=${encodeURIComponent(expr)}`
        : `${API_BASE_URL}/events?event_type=packet_event&limit=100`;
        
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setLivePackets(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleStartCapture = async () => {
    if (!selectedInterface) return;
    try {
      setError('');
      const res = await fetch(`${API_BASE_URL}/pcap/capture/start?interface=${encodeURIComponent(selectedInterface)}`, {
        method: 'POST'
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || 'Failed to start live capture.');
      }
      setIsCapturing(true);
      setLivePackets([]);
      setLivePacketCount(0);
      setSelectedPacket(null);
    } catch (err: any) {
      setError(err.message || 'Ensure backend has administrative / capture capabilities.');
    }
  };

  const handleStopCapture = async () => {
    try {
      await fetch(`${API_BASE_URL}/pcap/capture/stop`, { method: 'POST' });
      setIsCapturing(false);
      loadLivePackets(activeFilter);
    } catch (err) {
      console.error(err);
    }
  };

  const handleApplyFilter = () => {
    setActiveFilter(filterExpr);
    loadLivePackets(filterExpr);
    setSelectedPacket(null);
  };

  const handleClearFilter = () => {
    setFilterExpr('');
    setActiveFilter('');
    loadLivePackets('');
    setSelectedPacket(null);
  };

  const uploadPcapFile = async (file: File) => {
    setLoading(true);
    setError('');
    setSummary(null);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`${API_BASE_URL}/pcap/upload`, {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.detail || 'PCAP processing failed.');
      }
      const data = await res.json();
      setSummary(data);
    } catch (err: any) {
      setError(err.message || 'An error occurred. Ensure tshark is installed on the backend.');
    } finally {
      setLoading(false);
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      uploadPcapFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      uploadPcapFile(e.target.files[0]);
    }
  };

  const toggleLayer = (layerName: string) => {
    setExpandedLayers(prev => ({
      ...prev,
      [layerName]: !prev[layerName]
    }));
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-6">
      
      {/* Workspace toggle navigation bar */}
      <div className="flex bg-slate-950 border border-slate-900 rounded-xl p-1 max-w-sm mx-auto">
        <button
          onClick={() => setMode('upload')}
          className={`flex-1 text-center py-2.5 rounded-lg text-xs font-bold transition ${
            mode === 'upload' ? 'bg-slate-900 text-cyan-400 border border-slate-800' : 'text-slate-500 hover:text-slate-300'
          }`}
        >
          Trace File Ingest
        </button>
        <button
          onClick={() => setMode('live')}
          className={`flex-1 text-center py-2.5 rounded-lg text-xs font-bold transition ${
            mode === 'live' ? 'bg-slate-900 text-cyan-400 border border-slate-800' : 'text-slate-500 hover:text-slate-300'
          }`}
        >
          Live Interface Capture
        </button>
      </div>

      {mode === 'upload' ? (
        // TRACE FILE INGEST VIEW (Original charts)
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 glass-panel p-6 space-y-4">
              <h2 className="text-xl font-bold flex items-center gap-2 text-cyan-400">
                <FileCode className="w-5 h-5" />
                Upload Captured Trace (PCAP)
              </h2>
              <p className="text-sm text-slate-400">
                Upload Wireshark captures to parse protocol timelines, talkers, and check rules logic.
              </p>
              
              <div
                onDragEnter={handleDrag}
                onDragOver={handleDrag}
                onDragLeave={handleDrag}
                onDrop={handleDrop}
                className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition relative h-52 flex flex-col justify-center items-center ${
                  dragActive ? 'border-cyan-500 bg-cyan-950/20' : 'border-slate-800 hover:border-slate-700 bg-slate-950/20'
                }`}
              >
                <input
                  type="file"
                  onChange={handleFileChange}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  accept=".pcap,.pcapng"
                />
                {loading ? (
                  <div className="space-y-3">
                    <RefreshCw className="w-10 h-10 animate-spin text-cyan-400 mx-auto" />
                    <span className="text-xs font-semibold text-slate-300">Extracting trace headers... (1000 packets cap)</span>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <FileCode className="w-12 h-12 text-slate-600 mx-auto" />
                    <div>
                      <p className="text-sm font-semibold text-slate-200">Drag and drop PCAP/PCAPNG trace file here</p>
                    </div>
                    <button className="bg-slate-900 border border-slate-850 text-slate-300 px-4 py-2 rounded-lg text-xs font-bold hover:bg-slate-850">
                      Select Trace File
                    </button>
                  </div>
                )}
              </div>
            </div>

            <div className="glass-panel p-6 flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider mb-2">Capture Requirements</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  FastAPI backend routes parsing via local `tshark` instance. Ensure Wireshark engine package is installed on the hosting server.
                </p>
              </div>

              <div className="mt-4">
                {error && (
                  <div className="border border-red-950 bg-red-950/25 text-red-400 rounded-lg p-4 flex gap-3 text-xs leading-relaxed">
                    <AlertOctagon className="w-5 h-5 shrink-0 text-red-500" />
                    <div>
                      <p className="font-bold">Parsing Engine Error</p>
                      <p className="text-slate-400 mt-1">{error}</p>
                    </div>
                  </div>
                )}
                {summary && (
                  <div className="border border-emerald-950/40 bg-emerald-950/15 text-emerald-400 rounded-lg p-4 flex gap-3 text-xs">
                    <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-500" />
                    <div>
                      <p className="font-bold">Trace Loaded</p>
                      <p className="text-slate-400 mt-1">Processed {summary.total_packets} packets from capture trace.</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {summary && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-fade-in">
              <div className="lg:col-span-2 space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="border border-slate-900 bg-slate-950/40 rounded-xl p-5 space-y-1">
                    <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Trace File Identifier</span>
                    <p className="text-sm font-semibold truncate text-purple-400 font-mono">{summary.capture_id}</p>
                  </div>
                  <div className="border border-slate-900 bg-slate-950/40 rounded-xl p-5 space-y-1">
                    <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Total Packets</span>
                    <p className="text-2xl font-black text-cyan-400">{summary.total_packets}</p>
                  </div>
                  <div className="border border-slate-900 bg-slate-950/40 rounded-xl p-5 space-y-1">
                    <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Captured Size</span>
                    <p className="text-2xl font-black text-cyan-400">{formatBytes(summary.total_bytes)}</p>
                  </div>
                </div>

                <div className="glass-panel p-6 space-y-4">
                  <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                    <BarChart2 className="w-4 h-4 text-cyan-400" />
                    Traffic Timeline (Packets count per seconds)
                  </h3>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={summary.timeline}>
                        <XAxis dataKey="time" stroke="#475569" fontSize={9} />
                        <YAxis stroke="#475569" fontSize={9} />
                        <Tooltip contentStyle={{ backgroundColor: '#090a0f', borderColor: '#334155', color: '#fff', fontSize: 11 }} />
                        <Line type="monotone" dataKey="packets" stroke="#00d2ff" strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>

              <div className="space-y-6">
                <div className="glass-panel p-6 space-y-4">
                  <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Protocol Statistics</h3>
                  <div className="h-44 flex items-center justify-center">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={summary.protocols}
                          dataKey="count"
                          nameKey="protocol"
                          cx="50%"
                          cy="50%"
                          outerRadius={55}
                          label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                          labelLine={false}
                          fontSize={8}
                        >
                          {summary.protocols.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#090a0f', borderColor: '#334155', color: '#fff', fontSize: 11 }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="glass-panel p-6 space-y-4">
                  <h3 className="text-sm font-bold text-slate-400 uppercase tracking-wider">Top Talkers</h3>
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-slate-900 text-[10px] uppercase text-slate-500 font-bold">
                        <th className="pb-2">IP Address</th>
                        <th className="pb-2 text-right">Packets</th>
                        <th className="pb-2 text-right">Volume</th>
                      </tr>
                    </thead>
                    <tbody>
                      {summary.top_talkers.map((t, idx) => (
                        <tr key={idx} className="border-b border-slate-950 text-[11px] text-slate-300">
                          <td className="py-2 font-mono truncate max-w-[120px]">{t.ip}</td>
                          <td className="py-2 text-right">{t.packets}</td>
                          <td className="py-2 text-right font-semibold text-cyan-500">{formatBytes(t.bytes)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      ) : (
        // WIRESHARK LIVE CAPTURE WORKSPACE VIEW (3-pane layout)
        <div className="space-y-6">
          
          {/* Live capture toolbar and interface select */}
          <div className="glass-panel p-6 flex flex-col md:flex-row gap-4 justify-between items-center">
            <div className="flex items-center gap-3 w-full md:w-auto">
              <label className="text-xs font-bold text-slate-400 uppercase tracking-wider whitespace-nowrap">Interface</label>
              <select
                value={selectedInterface}
                onChange={(e) => setSelectedInterface(e.target.value)}
                disabled={isCapturing}
                className="w-full md:w-96 bg-slate-950 border border-slate-900 rounded-lg py-2 px-3 text-xs font-semibold text-slate-300 focus:outline-none focus:ring-1 focus:ring-cyan-500 disabled:opacity-50"
              >
                {interfaces.map((i) => (
                  <option key={i.name} value={i.name}>
                    {i.friendly_name} [{i.index}]
                  </option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-4 w-full md:w-auto">
              {/* Start / Stop Capture */}
              <div className="flex gap-2 w-full md:w-auto">
                <button
                  onClick={handleStartCapture}
                  disabled={isCapturing || !selectedInterface}
                  className="flex-1 md:flex-initial flex items-center justify-center gap-1.5 bg-emerald-950/40 border border-emerald-900 text-emerald-400 text-xs font-bold py-2 px-4 rounded-lg hover:bg-emerald-950/60 disabled:opacity-30 transition"
                >
                  <Play className="w-3.5 h-3.5" />
                  Start Sniffing
                </button>
                <button
                  onClick={handleStopCapture}
                  disabled={!isCapturing}
                  className="flex-1 md:flex-initial flex items-center justify-center gap-1.5 bg-red-950/40 border border-red-900 text-red-400 text-xs font-bold py-2 px-4 rounded-lg hover:bg-red-950/60 disabled:opacity-30 transition"
                >
                  <Square className="w-3.5 h-3.5 fill-red-400" />
                  Stop Capture
                </button>
              </div>

              {/* Status banner */}
              <div className="flex items-center gap-2 shrink-0 border-l border-slate-900 pl-4">
                <div className={`w-2.5 h-2.5 rounded-full ${isCapturing ? 'bg-emerald-500 animate-pulse' : 'bg-slate-700'}`} />
                <span className="text-xs text-slate-400">
                  {isCapturing ? `Captured: ${livePacketCount}` : 'Capture Idle'}
                </span>
              </div>
            </div>
          </div>

          {/* Wireshark Style Display Filter Bar */}
          <div className="glass-panel px-6 py-3 flex items-center gap-3">
            <Filter className="w-4 h-4 text-slate-500" />
            <input
              type="text"
              value={filterExpr}
              onChange={(e) => setFilterExpr(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleApplyFilter()}
              placeholder='Filter packets, e.g. ip.src == 192.168.1.100 && tcp.port == 80'
              className="flex-grow bg-slate-950 border border-slate-900 rounded-lg py-1.5 px-3 text-xs font-mono text-cyan-400 placeholder-slate-800 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
            <button
              onClick={handleApplyFilter}
              className="text-xs bg-slate-900 border border-slate-850 hover:border-slate-700 text-cyan-400 font-bold px-3 py-1.5 rounded-lg"
            >
              Apply Filter
            </button>
            {activeFilter && (
              <button
                onClick={handleClearFilter}
                className="text-xs text-slate-500 hover:text-slate-300 font-bold"
              >
                Clear
              </button>
            )}
          </div>

          {/* Wireshark 3-pane Layout */}
          <div className="grid grid-cols-1 lg:grid-cols-1 gap-6">
            
            {/* PANE 1: Packet List Grid */}
            <div className="glass-panel p-4 flex flex-col h-80">
              <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2">1. Ingested Packet List</h3>
              <div className="flex-grow overflow-auto">
                <table className="w-full text-left border-collapse min-w-[700px]">
                  <thead>
                    <tr className="border-b border-slate-900 text-[10px] uppercase text-slate-500 font-bold font-mono">
                      <th className="pb-2 w-12">No.</th>
                      <th className="pb-2 w-28">Time</th>
                      <th className="pb-2 w-36">Source IP</th>
                      <th className="pb-2 w-36">Destination IP</th>
                      <th className="pb-2 w-20">Protocol</th>
                      <th className="pb-2 w-20 text-right">Length</th>
                      <th className="pb-2 pl-4">Info</th>
                    </tr>
                  </thead>
                  <tbody>
                    {livePackets.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="text-center py-16 text-xs text-slate-700">
                          {isCapturing ? 'Listening on interfaces... Run local client requests to capture traffic.' : 'Capture is idle. Start capture to stream traffic.'}
                        </td>
                      </tr>
                    ) : (
                      livePackets.map((pkt, idx) => {
                        const date = pkt.timestamp ? pkt.timestamp.substring(11, 19) : '00:00:00';
                        const isSelected = selectedPacket?.id === pkt.id;
                        return (
                          <tr
                            key={pkt.id || idx}
                            onClick={() => setSelectedPacket(pkt)}
                            className={`border-b border-slate-950 text-xs font-mono cursor-pointer transition ${
                              isSelected ? 'bg-cyan-950/20 border-cyan-800/40 text-cyan-400' : 'hover:bg-slate-950/50 text-slate-300'
                            }`}
                          >
                            <td className="py-1.5">{pkt.id}</td>
                            <td className="py-1.5">{date}</td>
                            <td className="py-1.5 truncate max-w-[140px] text-purple-400">{pkt.source_ip}</td>
                            <td className="py-1.5 truncate max-w-[140px] text-pink-400">{pkt.details.dst_ip}</td>
                            <td className="py-1.5 font-bold">{pkt.details.protocol}</td>
                            <td className="py-1.5 text-right font-semibold">{pkt.details.bytes}</td>
                            <td className="py-1.5 pl-4 truncate max-w-[320px] text-slate-400">{pkt.details.packet_summary}</td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Split row for Detail Tree (Pane 2) and Hex Dump (Pane 3) */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              {/* PANE 2: Collapsible Protocol Details Accordion */}
              <div className="glass-panel p-4 h-96 flex flex-col">
                <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3">2. Collapsible Protocol Tree</h3>
                <div className="flex-grow overflow-y-auto space-y-2 pr-1">
                  {!selectedPacket ? (
                    <div className="w-full h-full flex items-center justify-center text-xs text-slate-700">
                      Select a packet in Pane 1 to expand layers tree.
                    </div>
                  ) : !selectedPacket.details.layers ? (
                    <div className="w-full h-full flex items-center justify-center text-xs text-slate-500">
                      No layer trees parsed for this packet. Only trace metadata available.
                    </div>
                  ) : (
                    Object.keys(selectedPacket.details.layers).map((layerName) => {
                      const fields = selectedPacket.details.layers[layerName];
                      const isExpanded = expandedLayers[layerName] ?? false;
                      return (
                        <div key={layerName} className="border border-slate-900/60 rounded-lg overflow-hidden bg-slate-950/20">
                          <button
                            onClick={() => toggleLayer(layerName)}
                            className="w-full flex items-center justify-between px-3 py-2 text-xs font-bold font-mono text-cyan-400 hover:bg-slate-900 bg-slate-950/50"
                          >
                            <span className="uppercase">{layerName} Layer</span>
                            {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                          </button>
                          
                          {isExpanded && (
                            <div className="p-3 border-t border-slate-950 space-y-1 max-h-48 overflow-y-auto bg-black/10">
                              {Object.keys(fields).map((fieldName) => (
                                <div key={fieldName} className="flex justify-between items-start text-[10px] font-mono text-slate-400 py-0.5 border-b border-slate-950/30">
                                  <span className="text-slate-500 font-semibold">{fieldName}</span>
                                  <span className="text-slate-300 select-text max-w-[200px] text-right truncate" title={fields[fieldName]}>
                                    {fields[fieldName]}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

              {/* PANE 3: Hex Dump / Raw Packet Details View */}
              <div className="glass-panel p-4 h-96 flex flex-col">
                <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3">3. Raw Packet String / Hex Inspector</h3>
                <div className="flex-grow overflow-auto bg-slate-950 border border-slate-900/50 rounded-lg p-3">
                  {!selectedPacket ? (
                    <div className="w-full h-full flex items-center justify-center text-xs text-slate-700 font-mono">
                      No frame selected.
                    </div>
                  ) : (
                    <pre className="text-[10px] font-mono text-slate-400 select-text leading-relaxed whitespace-pre overflow-auto h-full">
                      {selectedPacket.details.raw_line}
                    </pre>
                  )}
                </div>
              </div>

            </div>

          </div>

        </div>
      )}

    </div>
  );
};
export default PcapIngestTab;
