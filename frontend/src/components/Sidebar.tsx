import React from 'react';
import {
  LayoutDashboard,
  PlayCircle,
  Crosshair,
  AlertTriangle,
  History,
  FileText,
  BookOpen,
  Settings,
  ShieldCheck,
} from 'lucide-react';

interface SidebarProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onTabChange }) => {
  const menuItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'new-scan', label: 'New Scan', icon: PlayCircle },
    { id: 'targets', label: 'Targets', icon: Crosshair },
    { id: 'findings', label: 'Findings', icon: AlertTriangle },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'test-library', label: 'Test Library', icon: BookOpen },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#111827] border-r border-[#1f2937] flex flex-col shrink-0">
      {/* Brand header */}
      <div className="h-16 px-6 border-b border-[#1f2937] flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
          <ShieldCheck size={20} />
        </div>
        <div>
          <span className="font-bold text-white text-base tracking-tight">APIGuard</span>
          <span className="block text-[10px] text-cyan-400 font-mono tracking-wider uppercase">Sec Scanner</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-[#1a2333]'
              }`}
            >
              <Icon size={18} className={isActive ? 'text-cyan-400' : 'text-gray-400'} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Footer status notice */}
      <div className="p-4 border-t border-[#1f2937] text-xs text-gray-400 space-y-1">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span className="font-mono text-gray-300">Local Lab Scope</span>
        </div>
        <p className="text-[11px] text-gray-400">Authorized loopback targets only</p>
      </div>
    </aside>
  );
};

