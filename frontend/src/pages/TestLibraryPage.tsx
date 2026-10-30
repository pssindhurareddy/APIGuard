import React, { useEffect, useState } from 'react';
import { TestCase } from '../types';
import { api } from '../services/api';
import { BookOpen, Shield, AlertCircle, CheckCircle, Info } from 'lucide-react';

export const TestLibraryPage: React.FC = () => {
  const [testCases, setTestCases] = useState<TestCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  useEffect(() => {
    api
      .getTestCases()
      .then((data) => setTestCases(data))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  const filtered = selectedCategory === 'all'
    ? testCases
    : testCases.filter((tc) => tc.category === selectedCategory);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Security Test Library</h1>
        <p className="text-sm text-gray-400 mt-1">
          Catalog of deterministic, non-destructive test rules, evidence criteria, and boundary preconditions.
        </p>
      </div>

      {/* Category selector */}
      <div className="flex flex-wrap gap-2 text-xs">
        {['all', 'authentication', 'authorization', 'input_validation', 'data_exposure'].map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              selectedCategory === cat
                ? 'bg-cyan-600 text-white'
                : 'bg-[#182438] text-gray-300 hover:bg-[#23324d]'
            }`}
          >
            {cat === 'all' ? 'All Test Modules' : cat.replace('_', ' ').toUpperCase()}
          </button>
        ))}
      </div>

      {/* Test Rule Cards */}
      {loading ? (
        <div className="text-gray-400 text-xs py-10 text-center">Loading test library...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filtered.map((tc) => (
            <div
              key={tc.id}
              className="bg-[#111827] border border-[#1f2937] rounded-xl p-5 space-y-3 text-xs"
            >
              <div className="flex items-center justify-between border-b border-[#1f2937] pb-3">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2 py-0.5 rounded">
                    {tc.id}
                  </span>
                  <h3 className="font-bold text-white text-sm">{tc.name}</h3>
                </div>
                <span className="text-[10px] text-gray-400 uppercase font-mono">
                  {tc.category.replace('_', ' ')}
                </span>
              </div>

              {tc.standards?.owasp && (
                <div className="flex flex-wrap gap-1.5 text-[10px]">
                  <a href={tc.standards.owasp.url} target="_blank" rel="noreferrer"
                     className="px-1.5 py-0.5 rounded border border-cyan-500/30 bg-cyan-500/10 text-cyan-300">
                    OWASP {tc.standards.owasp.id} · {tc.standards.owasp.name}
                  </a>
                  {tc.standards.cwe.map((c) => (
                    <a key={c.id} href={c.url} target="_blank" rel="noreferrer" title={c.name}
                       className="px-1.5 py-0.5 rounded border border-gray-700 bg-gray-800 text-gray-300 font-mono">
                      {c.id}
                    </a>
                  ))}
                </div>
              )}

              <div>
                <span className="text-gray-400 font-mono uppercase text-[10px] block">1. Description</span>
                <p className="text-gray-300 mt-0.5">{tc.description}</p>
              </div>

              <div>
                <span className="text-red-400 font-mono uppercase text-[10px] block">2. Why It Matters</span>
                <p className="text-gray-300 mt-0.5">{tc.why_it_matters}</p>
              </div>

              <div>
                <span className="text-emerald-400 font-mono uppercase text-[10px] block">3. Success Criteria (PASS)</span>
                <p className="text-emerald-300 mt-0.5 font-mono">{tc.success_criteria}</p>
              </div>

              <div className="p-2.5 rounded bg-[#0b0f19] border border-[#1f2937] text-[11px] space-y-1">
                <div>
                  <strong className="text-gray-400">Preconditions:</strong>{' '}
                  <span className="text-gray-300">{tc.preconditions}</span>
                </div>
                <div>
                  <strong className="text-gray-400">Evidence Collected:</strong>{' '}
                  <span className="text-gray-300">{tc.evidence_collected}</span>
                </div>
                <div>
                  <strong className="text-amber-400">Known Limitations:</strong>{' '}
                  <span className="text-gray-400">{tc.limitations}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

