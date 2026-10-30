import React, { useState } from 'react';
import { Scan } from '../types';
import { api } from '../services/api';
import { FileText, Download, ExternalLink, ShieldCheck, FileJson } from 'lucide-react';

interface Props {
  scans: Scan[];
}

export const ReportsPage: React.FC<Props> = ({ scans }) => {
  const [selectedScanId, setSelectedScanId] = useState<string>(scans[0]?.id || '');
  const activeScan = scans.find((s) => s.id === selectedScanId);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Security Assessment Reports</h1>
        <p className="text-sm text-gray-400 mt-1">
          Export structured JSON and styled HTML reports with redacted evidence and ethical testing disclaimers.
        </p>
      </div>

      {scans.length === 0 ? (
        <div className="bg-[#111827] border border-[#1f2937] p-12 rounded-xl text-center text-gray-400 text-sm">
          No reports available. Run a security scan to generate reports.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Scan Selector Column */}
          <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl space-y-3">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">
              Select Assessment Run
            </h3>
            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {scans.map((s) => (
                <div
                  key={s.id}
                  onClick={() => setSelectedScanId(s.id)}
                  className={`p-3 rounded-lg border cursor-pointer transition-colors text-xs ${
                    selectedScanId === s.id
                      ? 'bg-cyan-500/10 border-cyan-500/40 text-white'
                      : 'bg-[#182438] border-[#23324d] text-gray-400 hover:border-gray-700'
                  }`}
                >
                  <div className="font-semibold text-white">{s.target_name}</div>
                  <div className="font-mono text-[11px] text-gray-400 mt-0.5">{s.id.slice(0, 8)}...</div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-gray-800 text-[11px]">
                    <span className="text-emerald-400">{s.passed} passed</span>
                    <span className="text-red-400 font-bold">{s.confirmed} weaknesses</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Report Preview & Export Column */}
          {activeScan && (
            <div className="md:col-span-2 bg-[#111827] border border-[#1f2937] p-6 rounded-xl space-y-6">
              <div className="flex items-start justify-between border-b border-[#1f2937] pb-4">
                <div>
                  <h2 className="text-lg font-bold text-white tracking-tight">{activeScan.target_name}</h2>
                  <code className="text-xs text-gray-400 font-mono mt-0.5 block">{activeScan.target_url}</code>
                </div>
                <div className="flex gap-2">
                  <a
                    href={api.getHtmlReportUrl(activeScan.id)}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow"
                  >
                    <FileText size={14} />
                    <span>Open HTML Report</span>
                  </a>
                  <a
                    href={api.getJsonReportUrl(activeScan.id)}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3.5 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 rounded-lg text-xs font-semibold flex items-center gap-1.5"
                  >
                    <FileJson size={14} />
                    <span>Download JSON</span>
                  </a>
                </div>
              </div>

              {/* Summary Stats */}
              <div className="grid grid-cols-4 gap-3 text-center text-xs">
                <div className="p-3 rounded bg-[#0b0f19] border border-[#1f2937]">
                  <span className="text-gray-400 block font-mono">Total Tests</span>
                  <span className="text-lg font-bold text-white">{activeScan.total_tests}</span>
                </div>
                <div className="p-3 rounded bg-[#0b0f19] border border-[#1f2937]">
                  <span className="text-gray-400 block font-mono">Passed</span>
                  <span className="text-lg font-bold text-emerald-400">{activeScan.passed}</span>
                </div>
                <div className="p-3 rounded bg-[#0b0f19] border border-[#1f2937]">
                  <span className="text-gray-400 block font-mono">Confirmed</span>
                  <span className="text-lg font-bold text-red-400">{activeScan.confirmed}</span>
                </div>
                <div className="p-3 rounded bg-[#0b0f19] border border-[#1f2937]">
                  <span className="text-gray-400 block font-mono">Duration</span>
                  <span className="text-lg font-bold text-gray-300">{activeScan.duration_ms || 0}ms</span>
                </div>
              </div>

              {/* Executive Summary */}
              <div className="space-y-2 text-sm">
                <h4 className="text-xs font-bold text-gray-400 uppercase font-mono tracking-wider">
                  Executive Summary
                </h4>
                <p className="bg-[#182438] p-4 rounded-lg border border-[#23324d] text-gray-300 text-xs leading-relaxed">
                  {activeScan.summary || 'Summary not recorded.'}
                </p>
              </div>

              {/* Scope & Redaction notice */}
              <div className="p-3.5 bg-cyan-950/20 border border-cyan-800/30 rounded-lg text-xs text-cyan-300 flex items-center gap-2">
                <ShieldCheck size={16} className="text-cyan-400 shrink-0" />
                <span>
                  All exported evidence has been cleansed by EvidenceRedactor: Bearer tokens, cookies, and password hashes are obscured.
                </span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

