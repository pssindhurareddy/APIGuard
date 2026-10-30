import React from 'react';
import { Scan, Finding, Target } from '../types';
import {
  Shield,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  PlayCircle,
  Clock,
  ArrowRight,
  TrendingUp,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { StatusBadge } from '../components/StatusBadge';
import { SeverityBadge } from '../components/SeverityBadge';

interface Props {
  scans: Scan[];
  findings: Finding[];
  targets: Target[];
  onNavigate: (tab: string) => void;
  onOpenFinding: (finding: Finding) => void;
  onOpenComparison: () => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#06b6d4',
  INFO: '#64748b',
};

export const OverviewPage: React.FC<Props> = ({
  scans,
  findings,
  targets,
  onNavigate,
  onOpenFinding,
  onOpenComparison,
}) => {
  const confirmedFindings = findings.filter((f) => f.status === 'CONFIRMED');
  const suspectedFindings = findings.filter((f) => f.status === 'SUSPECTED');
  const latestScan = scans[0];

  // Severity data for chart
  const severityCounts = {
    CRITICAL: findings.filter((f) => f.severity === 'CRITICAL' && f.status === 'CONFIRMED').length,
    HIGH: findings.filter((f) => f.severity === 'HIGH' && f.status === 'CONFIRMED').length,
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM' && f.status === 'CONFIRMED').length,
    LOW: findings.filter((f) => f.severity === 'LOW' && f.status === 'CONFIRMED').length,
  };

  const severityChartData = [
    { name: 'Critical', count: severityCounts.CRITICAL, fill: SEVERITY_COLORS.CRITICAL },
    { name: 'High', count: severityCounts.HIGH, fill: SEVERITY_COLORS.HIGH },
    { name: 'Medium', count: severityCounts.MEDIUM, fill: SEVERITY_COLORS.MEDIUM },
    { name: 'Low', count: severityCounts.LOW, fill: SEVERITY_COLORS.LOW },
  ];

  // Category coverage data
  const categoryData = [
    {
      name: 'Authentication',
      count: findings.filter((f) => f.category === 'authentication').length,
      color: '#06b6d4',
    },
    {
      name: 'Authorization (BOLA)',
      count: findings.filter((f) => f.category === 'authorization').length,
      color: '#8b5cf6',
    },
    {
      name: 'Input Validation',
      count: findings.filter((f) => f.category === 'input_validation').length,
      color: '#3b82f6',
    },
    {
      name: 'Data Exposure',
      count: findings.filter((f) => f.category === 'data_exposure').length,
      color: '#ec4899',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner & Quick Actions */}
      <div className="bg-gradient-to-r from-[#111827] via-[#162032] to-[#111827] border border-[#23324d] rounded-xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Posture Overview</h1>
          <p className="text-sm text-gray-400 mt-1">
            Automated evaluation of REST API authentication, BOLA authorization, schema validation, and excessive data exposure.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => onNavigate('new-scan')}
            className="px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-medium rounded-lg text-sm flex items-center gap-2 shadow-lg shadow-cyan-900/20"
          >
            <PlayCircle size={16} />
            <span>Launch Security Scan</span>
          </button>
          {scans.length >= 2 && (
            <button
              onClick={onOpenComparison}
              className="px-4 py-2.5 bg-[#1f293d] hover:bg-[#283852] text-gray-200 border border-[#334666] font-medium rounded-lg text-sm flex items-center gap-2"
            >
              <TrendingUp size={16} className="text-emerald-400" />
              <span>Compare Scans</span>
            </button>
          )}
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <div className="flex items-center justify-between text-gray-400 text-xs font-mono uppercase">
            <span>Total Scans</span>
            <Clock size={16} className="text-cyan-400" />
          </div>
          <div className="text-3xl font-bold text-white mt-2 font-mono">{scans.length}</div>
          <div className="text-xs text-gray-400 mt-1">Stored test executions</div>
        </div>

        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <div className="flex items-center justify-between text-gray-400 text-xs font-mono uppercase">
            <span>Confirmed Weaknesses</span>
            <ShieldAlert size={16} className="text-red-400" />
          </div>
          <div className="text-3xl font-bold text-red-400 mt-2 font-mono">
            {confirmedFindings.length}
          </div>
          <div className="text-xs text-gray-400 mt-1">Verified with reproducible evidence</div>
        </div>

        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <div className="flex items-center justify-between text-gray-400 text-xs font-mono uppercase">
            <span>Suspected Issues</span>
            <AlertTriangle size={16} className="text-amber-400" />
          </div>
          <div className="text-3xl font-bold text-amber-400 mt-2 font-mono">
            {suspectedFindings.length}
          </div>
          <div className="text-xs text-gray-400 mt-1">Requires manual verification</div>
        </div>

        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <div className="flex items-center justify-between text-gray-400 text-xs font-mono uppercase">
            <span>Active Targets</span>
            <Shield size={16} className="text-emerald-400" />
          </div>
          <div className="text-3xl font-bold text-emerald-400 mt-2 font-mono">
            {targets.length}
          </div>
          <div className="text-xs text-gray-400 mt-1">Scoped test environments</div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Confirmed Weaknesses by Severity */}
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4 flex items-center justify-between">
            <span>Confirmed Findings by Severity</span>
            <span className="text-xs text-gray-400 font-normal">Real scan evidence</span>
          </h3>
          <div className="h-60">
            {findings.length === 0 ? (
              <div className="h-full flex items-center justify-center text-gray-400 text-xs italic">
                No scan data recorded yet. Run a scan to view metrics.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={12} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#182438', borderColor: '#23324d', borderRadius: '8px' }}
                    itemStyle={{ color: '#fff' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Category Coverage Breakdown */}
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-4 flex items-center justify-between">
            <span>Evaluated Test Suites</span>
            <span className="text-xs text-gray-400 font-normal">Four core modules</span>
          </h3>
          <div className="h-60 flex items-center justify-center">
            {findings.length === 0 ? (
              <div className="text-gray-400 text-xs italic">No tests executed yet.</div>
            ) : (
              <div className="w-full flex items-center justify-between px-4">
                <div className="w-1/2 h-full">
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie
                        data={categoryData}
                        dataKey="count"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={4}
                      >
                        {categoryData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ backgroundColor: '#182438', borderColor: '#23324d', borderRadius: '8px' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="w-1/2 space-y-2 text-xs">
                  {categoryData.map((cat) => (
                    <div key={cat.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: cat.color }}></span>
                        <span className="text-gray-300">{cat.name}</span>
                      </div>
                      <span className="font-mono text-white font-semibold">{cat.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Latest Scan & Recent Activity */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Most Recent Scan */}
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl md:col-span-1">
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider mb-3">
            Latest Assessment
          </h3>
          {latestScan ? (
            <div className="space-y-3 text-sm">
              <div className="p-3.5 rounded-lg bg-[#0b0f19] border border-[#1f2937]">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white">{latestScan.target_name}</span>
                  <StatusBadge status={latestScan.status} size="sm" />
                </div>
                <div className="text-xs text-gray-400 font-mono mt-1">{latestScan.target_url}</div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="p-2.5 rounded bg-[#182438]">
                  <span className="text-gray-400 block font-mono">Passed Checks</span>
                  <span className="text-emerald-400 font-bold text-base">{latestScan.passed}</span>
                </div>
                <div className="p-2.5 rounded bg-[#182438]">
                  <span className="text-gray-400 block font-mono">Weaknesses</span>
                  <span className="text-red-400 font-bold text-base">{latestScan.confirmed}</span>
                </div>
              </div>

              <div className="text-xs text-gray-400 flex items-center justify-between pt-1">
                <span>Duration: {latestScan.duration_ms || 0}ms</span>
                <span>{latestScan.created_at?.slice(0, 16)}</span>
              </div>

              <button
                onClick={() => onNavigate('history')}
                className="w-full mt-2 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium rounded-lg flex items-center justify-center gap-1.5"
              >
                <span>View Full Scan Details</span>
                <ArrowRight size={14} />
              </button>
            </div>
          ) : (
            <div className="py-8 text-center text-gray-400 text-xs italic">
              No scans performed yet.
            </div>
          )}
        </div>

        {/* Confirmed Weakness Highlights */}
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl md:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider">
              Confirmed Security Findings
            </h3>
            <button
              onClick={() => onNavigate('findings')}
              className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
            >
              <span>View All</span>
              <ArrowRight size={12} />
            </button>
          </div>

          {confirmedFindings.length === 0 ? (
            <div className="py-12 text-center text-gray-400 text-xs italic">
              No confirmed vulnerabilities detected.
            </div>
          ) : (
            <div className="space-y-2">
              {confirmedFindings.slice(0, 4).map((f) => (
                <div
                  key={f.id}
                  onClick={() => onOpenFinding(f)}
                  className="p-3 bg-[#182438] hover:bg-[#1f2f4a] border border-[#23324d] rounded-lg cursor-pointer transition-colors flex items-center justify-between"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-white text-sm">{f.test_name}</span>
                      <code className="text-xs text-gray-400">({f.test_id})</code>
                    </div>
                    <div className="text-xs text-gray-400">
                      Endpoint: <code className="text-gray-300">{f.http_method} {f.endpoint}</code>
                    </div>
                  </div>
                  <SeverityBadge severity={f.severity} size="sm" />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

