import React, { useState } from 'react';
import { Target } from '../types';
import { api } from '../services/api';
import { Crosshair, Plus, Shield, Check, X, AlertCircle } from 'lucide-react';

interface Props {
  targets: Target[];
  onRefresh: () => void;
}

export const TargetsPage: React.FC<Props> = ({ targets, onRefresh }) => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [newTargetName, setNewTargetName] = useState('');
  const [newTargetUrl, setNewTargetUrl] = useState('');
  const [newAllowedPaths, setNewAllowedPaths] = useState('/api/');
  const [isAuthorized, setIsAuthorized] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.createTarget({
        name: newTargetName,
        base_url: newTargetUrl,
        allowed_paths: newAllowedPaths.split(',').map((p) => p.trim()),
        is_authorized: isAuthorized,
        environment: 'custom',
      });
      setShowAddModal(false);
      setNewTargetName('');
      setNewTargetUrl('');
      onRefresh();
    } catch (err: any) {
      setError(err.message || 'Failed to register target.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">API Targets & Scope</h1>
          <p className="text-sm text-gray-400 mt-1">
            Authorized target configurations and safety boundaries enforced by ScopeGuard.
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium rounded-lg text-sm flex items-center gap-1.5"
        >
          <Plus size={16} />
          <span>Add Custom Target</span>
        </button>
      </div>

      {/* Target Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {targets.map((target) => (
          <div key={target.id} className="bg-[#111827] border border-[#1f2937] rounded-xl p-5 space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="font-bold text-white text-base">{target.name}</h3>
                <code className="text-xs text-cyan-400 font-mono mt-0.5 block">{target.base_url}</code>
              </div>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-gray-800 text-gray-300 border border-gray-700 uppercase">
                {target.environment}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs bg-[#0b0f19] p-3 rounded-lg border border-[#1f2937]">
              <div>
                <span className="text-gray-400 block font-mono uppercase text-[10px]">Permitted Hosts</span>
                <span className="text-gray-200 font-mono">{target.allowed_hosts?.join(', ')}</span>
              </div>
              <div>
                <span className="text-gray-400 block font-mono uppercase text-[10px]">Permitted Ports</span>
                <span className="text-gray-200 font-mono">{target.allowed_ports?.join(', ')}</span>
              </div>
              <div className="col-span-2 pt-1 border-t border-gray-800">
                <span className="text-gray-400 block font-mono uppercase text-[10px]">Allowed Path Prefixes</span>
                <span className="text-gray-200 font-mono">{target.allowed_paths?.join(', ')}</span>
              </div>
            </div>

            {/* Public profiles */}
            <div>
              <span className="text-xs text-gray-400 font-mono uppercase block mb-1">
                Configured Auth Profiles (Tokens Redacted)
              </span>
              <div className="flex flex-wrap gap-1.5">
                {target.auth_profiles_public?.map((p) => (
                  <span
                    key={p.name}
                    className="px-2 py-0.5 rounded bg-[#182438] text-[11px] text-gray-300 border border-[#23324d]"
                  >
                    {p.name} ({p.role})
                  </span>
                ))}
              </div>
            </div>

            <div className="pt-2 border-t border-[#1f2937] flex items-center justify-between text-xs text-gray-400">
              <span>Status: <strong className="text-emerald-400">Authorized</strong></span>
              <span>Last Scan: {target.last_scan_status || 'Never scanned'}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Add Custom Target Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-[#23324d] rounded-xl w-full max-w-md p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[#1f2937]">
              <h3 className="font-bold text-white text-base">Register Custom Target</h3>
              <button onClick={() => setShowAddModal(false)} className="text-gray-400 hover:text-white">
                <X size={18} />
              </button>
            </div>

            {error && (
              <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-300 text-xs flex items-center gap-2">
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleCreateTarget} className="mt-4 space-y-4 text-xs">
              <div>
                <label className="block text-gray-400 font-mono uppercase mb-1">Target Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Local Staging Service"
                  value={newTargetName}
                  onChange={(e) => setNewTargetName(e.target.value)}
                  className="w-full bg-[#182438] border border-[#23324d] rounded-lg px-3 py-2 text-white"
                />
              </div>

              <div>
                <label className="block text-gray-400 font-mono uppercase mb-1">Base URL</label>
                <input
                  type="url"
                  required
                  placeholder="http://127.0.0.1:8003"
                  value={newTargetUrl}
                  onChange={(e) => setNewTargetUrl(e.target.value)}
                  className="w-full bg-[#182438] border border-[#23324d] rounded-lg px-3 py-2 text-white"
                />
                <span className="text-[10px] text-gray-400 mt-0.5 block">
                  Only loopback URLs (127.0.0.1, localhost) allowed by default for ethical containment.
                </span>
              </div>

              <div>
                <label className="block text-gray-400 font-mono uppercase mb-1">Allowed Paths (Comma-separated)</label>
                <input
                  type="text"
                  required
                  placeholder="/api/, /v1/"
                  value={newAllowedPaths}
                  onChange={(e) => setNewAllowedPaths(e.target.value)}
                  className="w-full bg-[#182438] border border-[#23324d] rounded-lg px-3 py-2 text-white"
                />
              </div>

              <label className="flex items-center gap-2 cursor-pointer select-none text-gray-300">
                <input
                  type="checkbox"
                  checked={isAuthorized}
                  onChange={(e) => setIsAuthorized(e.target.checked)}
                  className="w-4 h-4 rounded text-cyan-600 bg-gray-800 border-gray-700"
                />
                <span>Target is formally authorized for ethical security testing.</span>
              </label>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 bg-gray-800 text-gray-300 rounded-lg font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg font-medium"
                >
                  {submitting ? 'Registering...' : 'Save Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

