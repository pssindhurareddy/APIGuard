import React, { useState } from 'react';
import { Finding, FindingWorkflowStatus } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { StatusBadge } from './StatusBadge';
import { X, ShieldAlert, CheckCircle2, AlertTriangle, FileCode, Check } from 'lucide-react';
import { api } from '../services/api';

interface ModalProps {
  finding: Finding | null;
  onClose: () => void;
  onStatusUpdated?: () => void;
}

export const FindingDetailModal: React.FC<ModalProps> = ({ finding, onClose, onStatusUpdated }) => {
  if (!finding) return null;

  const [currentStatus, setCurrentStatus] = useState<FindingWorkflowStatus>(finding.finding_status);
  const [updating, setUpdating] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const handleStatusChange = async (newStatus: FindingWorkflowStatus) => {
    try {
      setUpdating(true);
      await api.updateFindingStatus(finding.id, newStatus);
      setCurrentStatus(newStatus);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 2000);
      onStatusUpdated?.();
    } catch (err) {
      alert(`Failed to update status: ${err}`);
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-[#111827] border border-[#23324d] rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="p-5 border-b border-[#1f2937] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.status} />
            <h2 className="text-lg font-bold text-white tracking-tight">{finding.test_name}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
          >
            <X size={20} />
          </button>
        </div>

        {/* Content body */}
        <div className="p-6 space-y-6 overflow-y-auto text-sm text-gray-300">
          {/* Metadata bar */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-3.5 rounded-lg bg-[#0b0f19] border border-[#1f2937]">
            <div>
              <span className="block text-[11px] font-mono text-gray-400 uppercase">Test Identifier</span>
              <span className="font-mono text-white text-xs font-semibold">{finding.test_id}</span>
            </div>
            <div>
              <span className="block text-[11px] font-mono text-gray-400 uppercase">Category</span>
              <span className="text-cyan-400 font-medium text-xs capitalize">{finding.category.replace('_', ' ')}</span>
            </div>
            <div>
              <span className="block text-[11px] font-mono text-gray-400 uppercase">Confidence</span>
              <span className="text-white text-xs font-medium">{finding.confidence}</span>
            </div>
            <div>
              <span className="block text-[11px] font-mono text-gray-400 uppercase">Endpoint</span>
              <span className="font-mono text-white text-xs truncate block">{finding.http_method} {finding.endpoint}</span>
            </div>
          </div>

          {/* Standards mapping */}
          {finding.standards?.owasp && (
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="font-mono text-[11px] text-gray-400 uppercase mr-1">Standards</span>
              <a
                href={finding.standards.owasp.url}
                target="_blank"
                rel="noreferrer"
                className="px-2 py-0.5 rounded border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20"
              >
                OWASP {finding.standards.owasp.id} · {finding.standards.owasp.name}
              </a>
              {finding.standards.cwe.map((c) => (
                <a
                  key={c.id}
                  href={c.url}
                  target="_blank"
                  rel="noreferrer"
                  title={c.name}
                  className="px-2 py-0.5 rounded border border-gray-700 bg-gray-800 text-gray-300 font-mono hover:bg-gray-700"
                >
                  {c.id}
                </a>
              ))}
            </div>
          )}

          {/* Explanation */}
          <div>
            <h4 className="text-xs font-bold font-mono text-gray-400 uppercase tracking-wider mb-1.5">
              1. Vulnerability Explanation
            </h4>
            <p className="bg-[#182438] p-3.5 rounded-lg border border-[#23324d] text-gray-200 leading-relaxed">
              {finding.explanation || 'Detailed explanation not provided.'}
            </p>
          </div>

          {/* Security Impact */}
          {finding.impact && (
            <div>
              <h4 className="text-xs font-bold font-mono text-gray-400 uppercase tracking-wider mb-1.5">
                2. Security Impact
              </h4>
              <p className="bg-red-500/10 p-3.5 rounded-lg border border-red-500/20 text-red-200">
                {finding.impact}
              </p>
            </div>
          )}

          {/* Expected vs Actual */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="text-xs font-bold font-mono text-emerald-400 uppercase tracking-wider mb-1.5">
                Expected Behavior (Secure API)
              </h4>
              <div className="bg-[#0b0f19] p-3 rounded-lg border border-emerald-500/20 text-xs font-mono text-emerald-300">
                {finding.expected_result || 'Expected behavior not recorded.'}
              </div>
            </div>

            <div>
              <h4 className="text-xs font-bold font-mono text-amber-400 uppercase tracking-wider mb-1.5">
                Actual Behavior (Observed)
              </h4>
              <div className="bg-[#0b0f19] p-3 rounded-lg border border-amber-500/20 text-xs font-mono text-amber-300">
                {finding.actual_result || 'Actual response not recorded.'}
              </div>
            </div>
          </div>

          {/* Evidence */}
          {finding.evidence && Object.keys(finding.evidence).length > 0 && (
            <div>
              <h4 className="text-xs font-bold font-mono text-gray-400 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                <FileCode size={14} className="text-cyan-400" />
                <span>Collected Test Evidence (Sensitive Data Redacted)</span>
              </h4>
              <pre className="bg-[#0b0f19] p-3.5 rounded-lg border border-[#23324d] font-mono text-xs text-cyan-300 overflow-x-auto max-h-48">
                {JSON.stringify(finding.evidence, null, 2)}
              </pre>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div>
              <h4 className="text-xs font-bold font-mono text-emerald-400 uppercase tracking-wider mb-1.5">
                Validated Remediation Recommendation
              </h4>
              <div className="bg-emerald-500/10 p-3.5 rounded-lg border border-emerald-500/30 text-emerald-200 text-sm">
                {finding.remediation}
              </div>
            </div>
          )}

          {/* Status workflow updater */}
          <div className="pt-4 border-t border-[#1f2937] flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-xs font-medium text-gray-400">Finding Workflow Status:</span>
              <div className="flex gap-1.5">
                {(['OPEN', 'ACKNOWLEDGED', 'FIXED', 'ACCEPTED_RISK'] as FindingWorkflowStatus[]).map((st) => (
                  <button
                    key={st}
                    disabled={updating}
                    onClick={() => handleStatusChange(st)}
                    className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
                      currentStatus === st
                        ? 'bg-cyan-500 text-black font-semibold'
                        : 'bg-[#182438] text-gray-300 hover:bg-[#23324d]'
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>
              {saveSuccess && (
                <span className="text-xs text-emerald-400 flex items-center gap-1">
                  <Check size={14} /> Saved
                </span>
              )}
            </div>

            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-gray-800 text-gray-200 hover:bg-gray-700 text-xs font-medium"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

