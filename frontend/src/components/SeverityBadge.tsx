import React from 'react';
import { SeverityLevel } from '../types';
import { ShieldAlert, AlertTriangle, AlertCircle, Info } from 'lucide-react';

interface Props {
  severity: SeverityLevel | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<Props> = ({ severity, size = 'md' }) => {
  const getStyles = () => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/15 text-red-400 border-red-500/30';
      case 'HIGH':
        return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
      case 'MEDIUM':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      case 'LOW':
        return 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30';
      default:
        return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
    }
  };

  const getIcon = () => {
    const s = size === 'sm' ? 12 : 14;
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return <ShieldAlert size={s} className="mr-1" />;
      case 'HIGH':
        return <AlertTriangle size={s} className="mr-1" />;
      case 'MEDIUM':
        return <AlertCircle size={s} className="mr-1" />;
      default:
        return <Info size={s} className="mr-1" />;
    }
  };

  const pad = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center font-semibold rounded border ${getStyles()} ${pad}`}>
      {getIcon()}
      {severity}
    </span>
  );
};

