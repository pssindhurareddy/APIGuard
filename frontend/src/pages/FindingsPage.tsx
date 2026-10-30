import React, { useState } from 'react';
import { Finding } from '../types';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { Search, Filter, ShieldAlert, CheckCircle } from 'lucide-react';

interface Props {
  findings: Finding[];
  onOpenFinding: (finding: Finding) => void;
}

export const FindingsPage: React.FC<Props> = ({ findings, onOpenFinding }) => {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  const filtered = findings.filter((f) => {
    if (search) {
      const q = search.toLowerCase();
      const match =
        f.test_name.toLowerCase().includes(q) ||
        f.test_id.toLowerCase().includes(q) ||
        f.endpoint.toLowerCase().includes(q) ||
        f.explanation?.toLowerCase().includes(q);
      if (!match) return false;
    }
    if (severityFilter && f.severity !== severityFilter) return false;
    if (categoryFilter && f.category !== categoryFilter) return false;
    if (statusFilter && f.status !== statusFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Findings Catalog</h1>
          <p className="text-sm text-gray-400 mt-1">
            Granular evaluation outcomes with reproducible evidence and remediation guidance.
          </p>
        </div>
        <div className="text-xs text-gray-400 font-mono">
          Showing {filtered.length} of {findings.length} findings
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-[#111827] border border-[#1f2937] p-4 rounded-xl flex flex-wrap items-center gap-3 text-xs">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <Search size={14} className="absolute left-3 top-2.5 text-gray-400" />
          <input
            type="text"
            placeholder="Search by test ID, name, or endpoint..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#182438] border border-[#23324d] rounded-lg pl-9 pr-3 py-2 text-white placeholder-gray-500"
          />
        </div>

        {/* Severity filter */}
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-[#182438] border border-[#23324d] rounded-lg px-3 py-2 text-gray-200"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        {/* Category filter */}
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="bg-[#182438] border border-[#23324d] rounded-lg px-3 py-2 text-gray-200"
        >
          <option value="">All Categories</option>
          <option value="authentication">Authentication</option>
          <option value="authorization">Authorization (BOLA)</option>
          <option value="input_validation">Input Validation</option>
          <option value="data_exposure">Data Exposure</option>
        </select>

        {/* Status filter */}
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-[#182438] border border-[#23324d] rounded-lg px-3 py-2 text-gray-200"
        >
          <option value="">All Result Statuses</option>
          <option value="CONFIRMED">CONFIRMED (Vulnerability)</option>
          <option value="PASS">PASS (Secure)</option>
          <option value="SUSPECTED">SUSPECTED</option>
          <option value="ERROR">ERROR</option>
          <option value="SKIPPED">SKIPPED</option>
        </select>
      </div>

      {/* Findings Table */}
      <div className="bg-[#111827] border border-[#1f2937] rounded-xl overflow-hidden shadow">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-[#182438] border-b border-[#1f2937] text-gray-400 font-mono uppercase">
                <th className="py-3 px-4">Test ID</th>
                <th className="py-3 px-4">Finding Name</th>
                <th className="py-3 px-4">Endpoint</th>
                <th className="py-3 px-4">Category</th>
                <th className="py-3 px-4">Result</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Workflow Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1f2937]">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-gray-400 italic">
                    No findings match the current filter criteria.
                  </td>
                </tr>
              ) : (
                filtered.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => onOpenFinding(f)}
                    className="hover:bg-[#182438] cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 font-mono font-semibold text-cyan-400">
                      {f.test_id}
                      {f.standards?.owasp && (
                        <span className="block text-[10px] font-normal text-gray-500" title={f.standards.owasp.name}>
                          {f.standards.owasp.id}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-medium text-white max-w-[220px] truncate">
                      {f.test_name}
                    </td>
                    <td className="py-3 px-4 font-mono text-gray-300">
                      <span className="text-gray-400 mr-1.5">{f.http_method}</span>
                      {f.endpoint}
                    </td>
                    <td className="py-3 px-4 text-gray-400 capitalize">
                      {f.category.replace('_', ' ')}
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={f.status} size="sm" />
                    </td>
                    <td className="py-3 px-4">
                      <SeverityBadge severity={f.severity} size="sm" />
                    </td>
                    <td className="py-3 px-4 text-gray-300 font-medium">
                      {f.confidence}
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-gray-400">
                      {f.finding_status}
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

