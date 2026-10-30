import React from 'react';
import { Scan } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { History, FileText, ExternalLink, TrendingUp } from 'lucide-react';
import { api } from '../services/api';

interface Props {
  scans: Scan[];
  onOpenScanDetails: (scanId: string) => void;
  onOpenComparison: () => void;
}

export const HistoryPage: React.FC<Props> = ({ scans, onOpenScanDetails, onOpenComparison }) => {
  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Scan Execution History</h1>
          <p className="text-sm text-gray-400 mt-1">
            Persisted SQLite scan runs, execution timelines, and exportable reports.
          </p>
        </div>
        {scans.length >= 2 && (
          <button
            onClick={onOpenComparison}
            className="px-4 py-2 bg-[#1f293d] hover:bg-[#283852] text-gray-200 border border-[#334666] font-medium rounded-lg text-sm flex items-center gap-2"
          >
            <TrendingUp size={16} className="text-emerald-400" />
            <span>Compare Two Scans</span>
          </button>
        )}
      </div>

      <div className="bg-[#111827] border border-[#1f2937] rounded-xl overflow-hidden shadow">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-[#182438] border-b border-[#1f2937] text-gray-400 font-mono uppercase">
                <th className="py-3 px-4">Scan Identifier</th>
                <th className="py-3 px-4">Target API</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Tests</th>
                <th className="py-3 px-4">Passed</th>
                <th className="py-3 px-4">Weaknesses</th>
                <th className="py-3 px-4">Duration</th>
                <th className="py-3 px-4">Executed At</th>
                <th className="py-3 px-4 text-right">Reports</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1f2937]">
              {scans.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-gray-400 italic">
                    No scan runs recorded in database. Launch your first security scan.
                  </td>
                </tr>
              ) : (
                scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-[#182438] transition-colors">
                    <td className="py-3 px-4 font-mono font-semibold text-cyan-400">
                      {scan.id.slice(0, 8)}...
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-semibold text-white">{scan.target_name}</div>
                      <code className="text-gray-400 text-[11px]">{scan.target_url}</code>
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={scan.status} size="sm" />
                    </td>
                    <td className="py-3 px-4 font-mono font-bold text-gray-200">
                      {scan.total_tests}
                    </td>
                    <td className="py-3 px-4 font-mono text-emerald-400 font-bold">
                      {scan.passed}
                    </td>
                    <td className="py-3 px-4 font-mono text-red-400 font-bold">
                      {scan.confirmed}
                    </td>
                    <td className="py-3 px-4 font-mono text-gray-400">
                      {scan.duration_ms || 0} ms
                    </td>
                    <td className="py-3 px-4 text-gray-400 font-mono">
                      {scan.created_at?.slice(0, 19).replace('T', ' ')}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      <a
                        href={api.getHtmlReportUrl(scan.id)}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 px-2.5 py-1 bg-cyan-600/20 text-cyan-300 hover:bg-cyan-600/30 rounded border border-cyan-500/30 font-medium"
                      >
                        <FileText size={12} />
                        <span>HTML</span>
                      </a>
                      <a
                        href={api.getJsonReportUrl(scan.id)}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 px-2.5 py-1 bg-gray-800 text-gray-300 hover:bg-gray-700 rounded border border-gray-700 font-medium"
                      >
                        <ExternalLink size={12} />
                        <span>JSON</span>
                      </a>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

