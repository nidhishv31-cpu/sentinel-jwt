import React, { useState } from 'react';
import { Shield, Key, FileText, Activity, Layers, Globe, KeyRound } from 'lucide-react';
import { SIEMDashboardTab } from './components/SIEMDashboardTab';
import { JWTAnalyzerTab } from './components/JWTAnalyzerTab';
import { LogIngestTab } from './components/LogIngestTab';
import { PcapIngestTab } from './components/PcapIngestTab';
import { ThreatMapTab } from './components/ThreatMapTab';
import { KeyManagementTab } from './components/KeyManagementTab';
import './styles/glass.css';

type Tab = 'siem' | 'jwt' | 'logs' | 'pcap' | 'threatmap' | 'keys';

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<Tab>('siem');

  return (
    <div className="relative min-h-screen bg-[#05060b] text-slate-100 flex flex-col font-sans select-none overflow-x-hidden">
      
      {/* Background Ambient Glow Orbs */}
      <div className="bg-glow-orb top-10 left-10 bg-cyan-500/20" />
      <div className="bg-glow-orb bottom-10 right-10 bg-purple-500/20" />

      {/* Main Header / Navbar */}
      <header className="relative z-10 glass-panel mx-4 mt-4 px-6 py-4 flex flex-col sm:flex-row justify-between items-center gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-tr from-cyan-500 to-purple-600 shadow-[0_0_15px_rgba(0,210,255,0.3)]">
            <Shield className="w-6 h-6 text-white animate-pulse" />
          </div>
          <div>
            <h1 className="text-xl font-black tracking-tight bg-gradient-to-r from-cyan-400 via-blue-400 to-purple-500 bg-clip-text text-transparent">
              SENTINEL<span className="font-extralight text-slate-100">JWT</span>
            </h1>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-black">Security Suite & SIEM Engine</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex bg-slate-950 border border-slate-900 rounded-xl p-1 w-full sm:w-auto overflow-x-auto">
          <button
            onClick={() => setActiveTab('siem')}
            className={`flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition whitespace-nowrap ${
              activeTab === 'siem'
                ? 'bg-gradient-to-r from-cyan-600/30 to-blue-600/30 text-cyan-400 border border-cyan-500/20 shadow-[0_0_10px_rgba(0,210,255,0.05)]'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            SIEM Dashboard
          </button>
          
          <button
            onClick={() => setActiveTab('jwt')}
            className={`flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition whitespace-nowrap ${
              activeTab === 'jwt'
                ? 'bg-gradient-to-r from-cyan-600/30 to-blue-600/30 text-cyan-400 border border-cyan-500/20 shadow-[0_0_10px_rgba(0,210,255,0.05)]'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            JWT Analyzer
          </button>

          <button
            onClick={() => setActiveTab('logs')}
            className={`flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition whitespace-nowrap ${
              activeTab === 'logs'
                ? 'bg-gradient-to-r from-cyan-600/30 to-blue-600/30 text-cyan-400 border border-cyan-500/20 shadow-[0_0_10px_rgba(0,210,255,0.05)]'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            Log Ingest
          </button>

          <button
            onClick={() => setActiveTab('pcap')}
            className={`flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition whitespace-nowrap ${
              activeTab === 'pcap'
                ? 'bg-gradient-to-r from-cyan-600/30 to-blue-600/30 text-cyan-400 border border-cyan-500/20 shadow-[0_0_10px_rgba(0,210,255,0.05)]'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            PCAP Ingest
          </button>

          <button
            onClick={() => setActiveTab('threatmap')}
            className={`flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition whitespace-nowrap ${
              activeTab === 'threatmap'
                ? 'bg-gradient-to-r from-cyan-600/30 to-blue-600/30 text-cyan-400 border border-cyan-500/20 shadow-[0_0_10px_rgba(0,210,255,0.05)]'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            Threat Map
          </button>
          
          <button
            onClick={() => setActiveTab('keys')}
            className={`flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold transition whitespace-nowrap ${
              activeTab === 'keys'
                ? 'bg-gradient-to-r from-cyan-600/30 to-blue-600/30 text-cyan-400 border border-cyan-500/20 shadow-[0_0_10px_rgba(0,210,255,0.05)]'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            Key Mgmt
          </button>
        </nav>
      </header>

      {/* Main Workspace Frame */}
      <main className="relative z-10 flex-grow max-w-7xl mx-auto w-full my-6 px-4">
        {activeTab === 'siem' && <SIEMDashboardTab />}
        {activeTab === 'jwt' && <JWTAnalyzerTab />}
        {activeTab === 'logs' && <LogIngestTab />}
        {activeTab === 'pcap' && <PcapIngestTab />}
        {activeTab === 'threatmap' && <ThreatMapTab />}
        {activeTab === 'keys' && <KeyManagementTab />}
      </main>

      {/* Footer */}
      <footer className="relative z-10 text-center py-6 text-[10px] text-slate-600 uppercase tracking-widest font-black border-t border-slate-950 mt-auto">
        SentinelJWT &copy; {new Date().getFullYear()} &bull; Unified Telemetry SIEM Engine
      </footer>
    </div>
  );
};

export default App;
