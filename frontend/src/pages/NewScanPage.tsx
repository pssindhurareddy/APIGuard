import React, { useState } from 'react';
import { Target, Scan, Finding } from '../types';
import { api } from '../services/api';
import {
  Play,
  Shield,
  CheckSquare,
  Square,
  Key,
  AlertCircle,
  CheckCircle2,
  Loader2,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';
import { StatusBadge } from '../components/StatusBadge';
import { SeverityBadge } from '../components/SeverityBadge';

interface Props {
  targets: Target[];
  onScanCompleted: (scanId: string) => void;
  onOpenFinding: (finding: Finding) => void;
}

const CATEGORIES = [
  {
    id: 'authentication',
    name: 'Authentication Testing',
    desc: 'AUTH-001 to 004: Missing tokens, forged tokens, and identity validation.',
  },
  {
    id: 'authorization',
    name: 'Authorization & BOLA Testing',
    desc: 'AUTHZ-001 to 004: Broken object level authorization and privilege escalation.',
  },
  {
    id: 'input_validation',
    name: 'Input Validation Testing',
    desc: 'INPUT-001 to 005: Missing fields, wrong types, boundary limits, and malformed JSON.',
  },
  {
    id: 'data_exposure',
    name: 'Excessive Data Exposure',
    desc: 'DATA-001 to 004: Sensitive field leakages (hashes, keys) and response allowlists.',
  },
];

export const NewScanPage: React.FC<Props> = ({ targets, onScanCompleted, onOpenFinding }) => {
  const [selectedTargetId, setSelectedTargetId] = useState<string>(targets[0]?.id || '');
  const [selectedAuthProfile, setSelectedAuthProfile] = useState<string>('alice');
  const [selectedCategories, setSelectedCategories] = useState<string[]>([
    'authentication',
    'authorization',
    'input_validation',
    'data_exposure',
  ]);
  const [authorizedConfirmation, setAuthorizedConfirmation] = useState<boolean>(true);

  // Scan execution state
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [currentScan, setCurrentScan] = useState<Scan | null>(null);
  const [scanFindings, setScanFindings] = useState<Finding[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const activeTarget = targets.find((t) => t.id === selectedTargetId);

  const toggleCategory = (catId: string) => {
    if (selectedCategories.includes(catId)) {
      if (selectedCategories.length === 1) return; // Keep at least one
      setSelectedCategories(selectedCategories.filter((c) => c !== catId));
    } else {
      setSelectedCategories([...selectedCategories, catId]);
    }
  };

  const handleStartScan = async () => {
    if (!selectedTargetId) {
      setErrorMessage('Please select a target.');
      return;
    }
    if (!authorizedConfirmation) {
      setErrorMessage('You must confirm authorization before scanning.');
      return;
    }
    if (selectedCategories.length === 0) {
      setErrorMessage('Please select at least one test category.');
      return;
    }

    setErrorMessage(null);
    setIsScanning(true);
    setCurrentScan(null);
    setScanFindings([]);

    try {
      // 1. Trigger backend scan endpoint
      const scan = await api.createScan(selectedTargetId, selectedCategories, selectedAuthProfile);
      setCurrentScan(scan);

      // 2. Poll until real scan completes
      const pollInterval = setInterval(async () => {
        try {
          const updated = await api.getScan(scan.id);
          setCurrentScan(updated);

          if (updated.status === 'COMPLETED' || updated.status === 'FAILED') {
            clearInterval(pollInterval);
            setIsScanning(false);

            // Fetch final findings
            const findings = await api.getScanFindings(scan.id);
            setScanFindings(findings);
            onScanCompleted(scan.id);
          }
        } catch (err) {
          clearInterval(pollInterval);
          setIsScanning(false);
          setErrorMessage('Error checking scan status.');
        }
      }, 1000);
    } catch (err: any) {
      setIsScanning(false);
      setErrorMessage(err.message || 'Failed to initiate scan.');
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Configure New Security Scan</h1>
        <p className="text-sm text-gray-400 mt-1">
          Perform a deterministic, evidence-backed security assessment against an authorized target.
        </p>
      </div>

      {errorMessage && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-red-300 text-sm flex items-center gap-2">
          <AlertCircle size={18} />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Step 1: Target Selection */}
      <div className="bg-[#111827] border border-[#1f2937] p-6 rounded-xl space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-xs">
            1
          </span>
          <span>Target Selection</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {targets.map((t) => (
            <div
              key={t.id}
              onClick={() => setSelectedTargetId(t.id)}
              className={`p-4 rounded-lg border cursor-pointer transition-all ${
                selectedTargetId === t.id
                  ? 'bg-cyan-500/10 border-cyan-500/40 shadow-sm'
                  : 'bg-[#182438] border-[#23324d] hover:border-gray-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-white text-sm">{t.name}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-400 uppercase">
                  {t.environment}
                </span>
              </div>
              <div className="text-xs text-gray-400 font-mono mt-1">{t.base_url}</div>
              <div className="text-[11px] text-gray-400 mt-2">
                Allowed paths: {t.allowed_paths?.join(', ')}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Step 2: Authentication Profile */}
      <div className="bg-[#111827] border border-[#1f2937] p-6 rounded-xl space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-xs">
            2
          </span>
          <span>Authentication Test Profiles</span>
        </h2>

        <div className="grid grid-cols-3 gap-3">
          {[
            { id: 'alice', label: 'Alice (User)', desc: 'Standard tenant owner' },
            { id: 'bob', label: 'Bob (User)', desc: 'Second tenant for BOLA checks' },
            { id: 'admin', label: 'Admin (Privileged)', desc: 'Administrative role' },
          ].map((profile) => (
            <div
              key={profile.id}
              onClick={() => setSelectedAuthProfile(profile.id)}
              className={`p-3 rounded-lg border cursor-pointer transition-all ${
                selectedAuthProfile === profile.id
                  ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-300'
                  : 'bg-[#182438] border-[#23324d] text-gray-300 hover:border-gray-700'
              }`}
            >
              <div className="flex items-center gap-1.5 font-medium text-xs">
                <Key size={13} className="text-cyan-400" />
                <span>{profile.label}</span>
              </div>
              <div className="text-[11px] text-gray-400 mt-0.5">{profile.desc}</div>
            </div>
          ))}
        </div>
        <p className="text-[11px] text-gray-400 italic">
          Zero credential persistence: Bearer tokens are stored in memory only during active execution.
        </p>
      </div>

      {/* Step 3: Test Categories */}
      <div className="bg-[#111827] border border-[#1f2937] p-6 rounded-xl space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-xs">
            3
          </span>
          <span>Security Test Modules</span>
        </h2>

        <div className="space-y-2">
          {CATEGORIES.map((cat) => {
            const isChecked = selectedCategories.includes(cat.id);
            return (
              <div
                key={cat.id}
                onClick={() => toggleCategory(cat.id)}
                className={`p-3.5 rounded-lg border cursor-pointer flex items-center justify-between transition-colors ${
                  isChecked
                    ? 'bg-[#162238] border-cyan-500/30 text-white'
                    : 'bg-[#182438] border-[#23324d] text-gray-400 hover:border-gray-700'
                }`}
              >
                <div>
                  <div className="font-semibold text-sm">{cat.name}</div>
                  <div className="text-xs text-gray-400 mt-0.5">{cat.desc}</div>
                </div>
                {isChecked ? (
                  <CheckSquare size={18} className="text-cyan-400" />
                ) : (
                  <Square size={18} className="text-gray-500" />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Step 4: Safety Scope Review */}
      <div className="bg-[#111827] border border-[#1f2937] p-6 rounded-xl space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 flex items-center justify-center text-xs">
            4
          </span>
          <span>Scope Review & Ethical Safeguards</span>
        </h2>

        {activeTarget && (
          <div className="p-3.5 bg-[#0b0f19] border border-[#1f2937] rounded-lg text-xs space-y-1.5 font-mono text-gray-300">
            <div>
              <strong className="text-gray-400">Target Base URL:</strong> {activeTarget.base_url}
            </div>
            <div>
              <strong className="text-gray-400">Permitted Hosts:</strong> {activeTarget.allowed_hosts?.join(', ')}
            </div>
            <div>
              <strong className="text-gray-400">Permitted Ports:</strong> {activeTarget.allowed_ports?.join(', ')}
            </div>
            <div>
              <strong className="text-gray-400">Loopback Boundary:</strong> Strictly enforced (127.0.0.1)
            </div>
          </div>
        )}

        <label className="flex items-center gap-3 cursor-pointer select-none text-xs text-gray-300">
          <input
            type="checkbox"
            checked={authorizedConfirmation}
            onChange={(e) => setAuthorizedConfirmation(e.target.checked)}
            className="w-4 h-4 rounded text-cyan-600 focus:ring-0 bg-gray-800 border-gray-700"
          />
          <span>I confirm explicit authorization to perform API penetration and security testing on this target.</span>
        </label>
      </div>

      {/* Step 5: Launch Scan Action */}
      <div className="flex items-center justify-between pt-2">
        <button
          disabled={isScanning || !authorizedConfirmation}
          onClick={handleStartScan}
          className={`px-6 py-3 rounded-xl font-bold text-sm flex items-center gap-2.5 shadow-xl transition-all ${
            isScanning || !authorizedConfirmation
              ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
              : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-cyan-900/30'
          }`}
        >
          {isScanning ? (
            <>
              <Loader2 size={18} className="animate-spin" />
              <span>Scanning API Target...</span>
            </>
          ) : (
            <>
              <Play size={18} />
              <span>Start Security Scan</span>
            </>
          )}
        </button>

        {isScanning && (
          <div className="text-xs text-cyan-400 font-mono animate-pulse flex items-center gap-2">
            <span>Executing test requests through ScopeGuard...</span>
          </div>
        )}
      </div>

      {/* Step 6: Live Results View */}
      {currentScan && (
        <div className="bg-[#111827] border border-[#1f2937] p-6 rounded-xl space-y-4 mt-8">
          <div className="flex items-center justify-between border-b border-[#1f2937] pb-4">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <span>Scan Execution: {currentScan.target_name}</span>
                <StatusBadge status={currentScan.status} size="sm" />
              </h3>
              <p className="text-xs text-gray-400 mt-1">{currentScan.summary || 'Executing checks...'}</p>
            </div>
            <div className="text-right text-xs text-gray-400 font-mono">
              Duration: {currentScan.duration_ms || 0} ms
            </div>
          </div>

          {/* Counters */}
          <div className="grid grid-cols-5 gap-2 text-center text-xs">
            <div className="p-2.5 rounded bg-[#182438]">
              <span className="text-gray-400 block font-mono">Total</span>
              <span className="text-white font-bold text-base">{currentScan.total_tests}</span>
            </div>
            <div className="p-2.5 rounded bg-emerald-500/10 border border-emerald-500/20">
              <span className="text-emerald-400 block font-mono">Passed</span>
              <span className="text-emerald-300 font-bold text-base">{currentScan.passed}</span>
            </div>
            <div className="p-2.5 rounded bg-red-500/10 border border-red-500/20">
              <span className="text-red-400 block font-mono">Confirmed</span>
              <span className="text-red-300 font-bold text-base">{currentScan.confirmed}</span>
            </div>
            <div className="p-2.5 rounded bg-amber-500/10 border border-amber-500/20">
              <span className="text-amber-400 block font-mono">Suspected</span>
              <span className="text-amber-300 font-bold text-base">{currentScan.suspected}</span>
            </div>
            <div className="p-2.5 rounded bg-purple-500/10 border border-purple-500/20">
              <span className="text-purple-400 block font-mono">Errors</span>
              <span className="text-purple-300 font-bold text-base">{currentScan.errors}</span>
            </div>
          </div>

          {/* Findings List */}
          {scanFindings.length > 0 && (
            <div className="pt-3 space-y-2">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">
                Detected Results & Evidence
              </h4>
              {scanFindings.map((f) => (
                <div
                  key={f.id}
                  onClick={() => onOpenFinding(f)}
                  className="p-3 bg-[#182438] hover:bg-[#1f2f4a] border border-[#23324d] rounded-lg cursor-pointer flex items-center justify-between text-xs"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-white">{f.test_name}</span>
                      <code className="text-gray-400">({f.test_id})</code>
                    </div>
                    <div className="text-gray-400">
                      {f.http_method} {f.endpoint} &bull; <span className="capitalize">{f.category}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <StatusBadge status={f.status} size="sm" />
                    <SeverityBadge severity={f.severity} size="sm" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

