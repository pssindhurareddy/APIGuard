import React from 'react';
import { SystemHealth, Scan } from '../types';
import { Server, Activity, ShieldAlert, CheckCircle } from 'lucide-react';

interface TopBarProps {
  health: SystemHealth | null;
  activeScan: Scan | null;
}

export const TopBar: React.FC<TopBarProps> = ({ health, activeScan }) => {
  const vulnOnline = health?.demo_apis?.vulnerable_demo?.status === 'online';
  const secOnline = health?.demo_apis?.secure_demo?.status === 'online';
  const vampiVuln = health?.demo_apis?.vampi_vulnerable?.status === 'online';
  const vampiSec = health?.demo_apis?.vampi_secure?.status === 'online';
  const vampiCount = Number(vampiVuln) + Number(vampiSec);

  return (
    <header className="h-16 bg-[#111827] border-b border-[#1f2937] px-6 flex items-center justify-between shrink-0">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-sm text-gray-300">
          <Server size={16} className="text-cyan-400" />
          <span className="font-medium">Environment:</span>
          <span className="px-2 py-0.5 rounded bg-gray-800 text-xs font-mono text-cyan-300 border border-gray-700">
            LOCAL-DEMO-LAB
          </span>
        </div>

        {/* Demo Targets Status */}
        <div className="hidden md:flex items-center gap-3 text-xs pl-4 border-l border-gray-800">
          <div className="flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${vulnOnline ? 'bg-amber-400' : 'bg-gray-600'}`}></span>
            <span className="text-gray-400">Vuln API (8001):</span>
            <span className={vulnOnline ? 'text-amber-300 font-mono' : 'text-gray-500 font-mono'}>
              {vulnOnline ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${secOnline ? 'bg-emerald-400' : 'bg-gray-600'}`}></span>
            <span className="text-gray-400">Secure API (8002):</span>
            <span className={secOnline ? 'text-emerald-300 font-mono' : 'text-gray-500 font-mono'}>
              {secOnline ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>

          <div className="hidden lg:flex items-center gap-1.5" title="Third-party VAmPI benchmark (vulnerable 8003, secure 8004)">
            <span className={`w-2 h-2 rounded-full ${vampiCount === 2 ? 'bg-violet-400' : vampiCount === 1 ? 'bg-amber-400' : 'bg-gray-600'}`}></span>
            <span className="text-gray-400">VAmPI (8003/8004):</span>
            <span className={vampiCount === 2 ? 'text-violet-300 font-mono' : 'text-gray-500 font-mono'}>
              {vampiCount === 2 ? 'ONLINE' : vampiCount === 1 ? 'PARTIAL' : 'OFFLINE'}
            </span>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Active scan indicator */}
        {activeScan && activeScan.status === 'RUNNING' && (
          <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs">
            <Activity size={14} className="animate-spin text-cyan-400" />
            <span>Scanning: {activeScan.target_name}</span>
          </div>
        )}

        {/* Backend health pill */}
        <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-[#182438] border border-gray-800 text-xs">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span className="text-gray-300 font-medium">Scanner Backend:</span>
          <span className="text-emerald-400 font-mono">{health?.status ? 'HEALTHY' : 'CONNECTING...'}</span>
        </div>
      </div>
    </header>
  );
};

