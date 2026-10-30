import React from 'react';
import { TestResultStatus, ScanStatus } from '../types';
import { CheckCircle2, XCircle, AlertCircle, Clock, Loader2 } from 'lucide-react';

interface Props {
  status: TestResultStatus | ScanStatus | string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<Props> = ({ status, size = 'md' }) => {
  const getStyles = () => {
    switch (status?.toUpperCase()) {
      case 'PASS':
      case 'COMPLETED':
        return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
      case 'CONFIRMED':
      case 'FAILED':
        return 'bg-red-500/15 text-red-400 border-red-500/30';
      case 'SUSPECTED':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      case 'RUNNING':
        return 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30 animate-pulse';
      case 'QUEUED':
        return 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30';
      case 'ERROR':
        return 'bg-purple-500/15 text-purple-400 border-purple-500/30';
      default:
        return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
    }
  };

  const getIcon = () => {
    const s = size === 'sm' ? 12 : 14;
    switch (status?.toUpperCase()) {
      case 'PASS':
      case 'COMPLETED':
        return <CheckCircle2 size={s} className="mr-1" />;
      case 'CONFIRMED':
      case 'FAILED':
        return <XCircle size={s} className="mr-1" />;
      case 'SUSPECTED':
        return <AlertCircle size={s} className="mr-1" />;
      case 'RUNNING':
        return <Loader2 size={s} className="mr-1 animate-spin" />;
      default:
        return <Clock size={s} className="mr-1" />;
    }
  };

  const pad = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center font-medium rounded border ${getStyles()} ${pad}`}>
      {getIcon()}
      {status}
    </span>
  );
};

