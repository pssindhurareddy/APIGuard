import React, { useState } from 'react';
import { SystemHealth } from '../types';
import { api } from '../services/api';
import { Settings, Shield, AlertTriangle, FileCode, CheckCircle2, Server } from 'lucide-react';

interface Props {
  health: SystemHealth | null;
}

export const SettingsPage: React.FC<Props> = ({ health }) => {
  const [openApiSpec, setOpenApiSpec] = useState('');
  const [parseResult, setParseResult] = useState<any>(null);
  const [parsing, setParsing] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);

  const handleParseSpec = async () => {
    if (!openApiSpec.trim()) return;
    setParsing(true);
    setParseError(null);
    setParseResult(null);
    try {
      const data = await api.parseOpenApi(openApiSpec);
      setParseResult(data);
    } catch (err: any) {
      setParseError(err.message || 'Failed to parse specification.');
    } finally {
      setParsing(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Scanner Settings & Safety Limits</h1>
        <p className="text-sm text-gray-400 mt-1">
          Review execution constraints, application health, and import OpenAPI specifications.
        </p>
      </div>

      {/* Safety Warning */}
      <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl text-amber-200 text-xs flex items-start gap-3">
        <AlertTriangle size={20} className="text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <strong className="text-amber-300 block text-sm font-semibold">
            Ethical Boundaries & Authorized Testing Warning
          </strong>
          <p>
            APIGuard is built strictly for academic security research and authorized ethical hacking demonstrations.
            Default execution permits loopback targets only (127.0.0.1, localhost). Testing third-party systems without prior explicit written permission is strictly prohibited and illegal.
          </p>
        </div>
      </div>

      {/* Health & Engine Info */}
      <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Server size={16} className="text-cyan-400" />
          <span>Scanner Backend Diagnostics</span>
        </h2>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div className="p-3 bg-[#0b0f19] border border-[#1f2937] rounded-lg">
            <span className="text-gray-400 block font-mono">Backend Status</span>
            <span className="text-emerald-400 font-bold font-mono">
              {health?.status?.toUpperCase() || 'ONLINE'}
            </span>
          </div>

          <div className="p-3 bg-[#0b0f19] border border-[#1f2937] rounded-lg">
            <span className="text-gray-400 block font-mono">Framework Version</span>
            <span className="text-white font-mono">1.0.0</span>
          </div>

          <div className="p-3 bg-[#0b0f19] border border-[#1f2937] rounded-lg">
            <span className="text-gray-400 block font-mono">Vulnerable Demo API</span>
            <span className="text-amber-300 font-mono">
              Port 8001 ({health?.demo_apis?.vulnerable_demo?.status || 'Active'})
            </span>
          </div>

          <div className="p-3 bg-[#0b0f19] border border-[#1f2937] rounded-lg">
            <span className="text-gray-400 block font-mono">Secured Demo API</span>
            <span className="text-emerald-300 font-mono">
              Port 8002 ({health?.demo_apis?.secure_demo?.status || 'Active'})
            </span>
          </div>
        </div>
      </div>

      {/* Default Safety Constraints */}
      <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl space-y-4 text-xs">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Shield size={16} className="text-cyan-400" />
          <span>Active ScopeGuard Safety Controls</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="p-3.5 bg-[#0b0f19] border border-[#1f2937] rounded-lg space-y-1">
            <span className="font-semibold text-white block">Request Budget Limit</span>
            <p className="text-gray-400">
              Maximum 200 requests per scan run to prevent unintended load on tested endpoints.
            </p>
          </div>

          <div className="p-3.5 bg-[#0b0f19] border border-[#1f2937] rounded-lg space-y-1">
            <span className="font-semibold text-white block">Response Size Ceiling</span>
            <p className="text-gray-400">
              Payloads capped at 1 MB. Large responses are safely truncated to prevent memory exhaustion.
            </p>
          </div>

          <div className="p-3.5 bg-[#0b0f19] border border-[#1f2937] rounded-lg space-y-1">
            <span className="font-semibold text-white block">Redirect Escape Interception</span>
            <p className="text-gray-400">
              HTTP 301/302 redirects are validated before navigation. Redirects to non-approved hosts are blocked.
            </p>
          </div>

          <div className="p-3.5 bg-[#0b0f19] border border-[#1f2937] rounded-lg space-y-1">
            <span className="font-semibold text-white block">Evidence Redaction Pipeline</span>
            <p className="text-gray-400">
              Bearer tokens, authorization headers, and password hashes are automatically sanitized prior to DB storage.
            </p>
          </div>
        </div>
      </div>

      {/* OpenAPI Spec Import Inspector */}
      <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl space-y-4 text-xs">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <FileCode size={16} className="text-cyan-400" />
          <span>OpenAPI Specification Import</span>
        </h2>

        <p className="text-gray-400">
          Paste OpenAPI 3.0 / Swagger JSON or YAML to extract routes and schemas. All imported endpoints are validated against ScopeGuard before execution.
        </p>

        <textarea
          rows={6}
          placeholder='{"openapi": "3.0.0", "info": {"title": "Test API"}, "paths": {...}}'
          value={openApiSpec}
          onChange={(e) => setOpenApiSpec(e.target.value)}
          className="w-full bg-[#0b0f19] border border-[#23324d] rounded-lg p-3 font-mono text-xs text-cyan-300 placeholder-gray-600"
        ></textarea>

        {parseError && (
          <div className="p-2.5 bg-red-500/10 border border-red-500/30 text-red-300 rounded text-xs">
            {parseError}
          </div>
        )}

        {parseResult && (
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded text-emerald-300 space-y-1">
            <strong className="block text-white">Parsed: {parseResult.title} (v{parseResult.version})</strong>
            <p>Extracted {parseResult.endpoint_count} endpoints safely into memory.</p>
          </div>
        )}

        <button
          onClick={handleParseSpec}
          disabled={parsing || !openApiSpec.trim()}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg font-medium"
        >
          {parsing ? 'Parsing Spec...' : 'Parse Specification'}
        </button>
      </div>
    </div>
  );
};

