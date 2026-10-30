import React, { useState, useEffect } from 'react';
import { Scan, ScanComparison } from '../types';
import { api } from '../services/api';
import { X, CheckCircle, AlertTriangle, ArrowRight, ShieldCheck, RefreshCw } from 'lucide-react';
import { SeverityBadge } from './SeverityBadge';

interface Props {
  scans: Scan[];
  initialBaselineId?: string;
  initialComparisonId?: string;
  onClose: () => void;
}

export const ScanComparisonModal: React.FC<Props> = ({
  scans,
  initialBaselineId,
  initialComparisonId,
  onClose,
}) => {
  const [baselineId, setBaselineId] = useState(initialBaselineId || (scans[1]?.id || scans[0]?.id || ''));
  const [comparisonId, setComparisonId] = useState(initialComparisonId || (scans[0]?.id || ''));
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runComparison = async () => {
    if (!baselineId || !comparisonId || baselineId === comparisonId) {
      setError('Please select two distinct scans to compare.');
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const data = await api.compareScans(baselineId, comparisonId);
      setComparison(data);
    } catch (err: any) {
      setError(err.message || 'Comparison failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (baselineId && comparisonId && baselineId !== comparisonId) {
      runComparison();
    }
  }, []);

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-[#111827] border border-[#23324d] rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="p-5 border-b border-[#1f2937] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="text-cyan-400" size={22} />
            <h2 className="text-lg font-bold text-white tracking-tight">
              Before & After Remediation Validation
            </h2>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-gray-400 hover:text-white">
            <X size={20} />
          </button>
        </div>

        {/* Scan selector bar */}
        <div className="p-5 border-b border-[#1f2937] bg-[#0b0f19] flex flex-wrap items-center gap-4 text-xs">
          <div className="flex-1 min-w-[220px]">
            <label className="block text-gray-400 font-mono uppercase mb-1">Baseline Scan (e.g. Vulnerable)</label>
            <select
              value={baselineId}
              onChange={(e) => setBaselineId(e.target.value)}
              className="w-full bg-[#182438] border border-[#23324d] rounded-lg px-3 py-2 text-white"
            >
              <option value="">Select Baseline Scan</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.target_name} ({s.id.slice(0, 8)}) — {s.confirmed} weaknesses
                </option>
              ))}
            </select>
          </div>

          <div className="pt-5 text-gray-500">
            <ArrowRight size={18} />
          </div>

          <div className="flex-1 min-w-[220px]">
            <label className="block text-gray-400 font-mono uppercase mb-1">Remediation Scan (e.g. Secured)</label>
            <select
              value={comparisonId}
              onChange={(e) => setComparisonId(e.target.value)}
              className="w-full bg-[#182438] border border-[#23324d] rounded-lg px-3 py-2 text-white"
            >
              <option value="">Select Comparison Scan</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.target_name} ({s.id.slice(0, 8)}) — {s.confirmed} weaknesses
                </option>
              ))}
            </select>
          </div>

          <div className="pt-4">
            <button
              onClick={runComparison}
              disabled={loading}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium rounded-lg flex items-center gap-1.5"
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
              <span>Compare</span>
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-sm">
          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 text-red-300 rounded-lg text-xs">
              {error}
            </div>
          )}

          {comparison && (
            <>
              {/* Summary Metrics */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="p-4 rounded-lg bg-[#182438] border border-[#23324d] text-center">
                  <div className="text-xs uppercase text-gray-400 font-mono mb-1">Remediation Rate</div>
                  <div className="text-2xl font-bold text-emerald-400 font-mono">
                    {comparison.remediation_success_rate}
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-[#182438] border border-[#23324d] text-center">
                  <div className="text-xs uppercase text-gray-400 font-mono mb-1">Remediated Weaknesses</div>
                  <div className="text-2xl font-bold text-emerald-400 font-mono">
                    {comparison.remediated_findings.length}
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-[#182438] border border-[#23324d] text-center">
                  <div className="text-xs uppercase text-gray-400 font-mono mb-1">Persistent Weaknesses</div>
                  <div className="text-2xl font-bold text-amber-400 font-mono">
                    {comparison.persistent_findings.length}
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-[#182438] border border-[#23324d] text-center">
                  <div className="text-xs uppercase text-gray-400 font-mono mb-1">New Weaknesses</div>
                  <div className="text-2xl font-bold text-red-400 font-mono">
                    {comparison.new_findings.length}
                  </div>
                </div>
              </div>

              {/* Remediated Findings List */}
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-3 flex items-center gap-2">
                  <CheckCircle size={16} className="text-emerald-400" />
                  <span>Successfully Remediated Weaknesses ({comparison.remediated_findings.length})</span>
                </h3>
                {comparison.remediated_findings.length === 0 ? (
                  <p className="text-gray-400 text-xs italic">No weaknesses resolved between these scans.</p>
                ) : (
                  <div className="space-y-2">
                    {comparison.remediated_findings.map((item, idx) => (
                      <div
                        key={idx}
                        className="p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg flex items-center justify-between"
                      >
                        <div>
                          <div className="font-semibold text-white flex items-center gap-2">
                            <span>{item.test_name}</span>
                            <code className="text-xs text-gray-400">({item.test_id})</code>
                          </div>
                          <div className="text-xs text-gray-400 mt-0.5">
                            Endpoint: <code className="text-gray-300">{item.endpoint}</code>
                          </div>
                        </div>

                        <div className="text-right">
                          <span className="inline-block px-2.5 py-1 bg-emerald-500/20 text-emerald-400 rounded text-xs font-bold">
                            RETEST: PASS
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Persistent Findings */}
              {comparison.persistent_findings.length > 0 && (
                <div>
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-3 flex items-center gap-2">
                    <AlertTriangle size={16} className="text-amber-400" />
                    <span>Unresolved / Persistent Weaknesses ({comparison.persistent_findings.length})</span>
                  </h3>
                  <div className="space-y-2">
                    {comparison.persistent_findings.map((item, idx) => (
                      <div
                        key={idx}
                        className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg flex items-center justify-between"
                      >
                        <div>
                          <div className="font-semibold text-white">
                            {item.test_name} <span className="text-xs text-gray-400">({item.test_id})</span>
                          </div>
                          <div className="text-xs text-gray-400">
                            Endpoint: <code className="text-gray-300">{item.http_method} {item.endpoint}</code>
                          </div>
                        </div>
                        <SeverityBadge severity={item.severity} size="sm" />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

