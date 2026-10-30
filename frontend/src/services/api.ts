import { Target, Scan, Finding, TestCase, SystemHealth, ScanComparison } from '../types';

const API_BASE = '/api';

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorDetail = `HTTP Error ${res.status}`;
    try {
      const data = await res.json();
      errorDetail = data.detail || data.message || errorDetail;
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }
  return res.json();
}

export const api = {
  // Health
  getHealth: async (): Promise<SystemHealth> => {
    const res = await fetch(`${API_BASE}/health`);
    return handleResponse<SystemHealth>(res);
  },

  // Targets
  getTargets: async (): Promise<Target[]> => {
    const res = await fetch(`${API_BASE}/targets`);
    return handleResponse<Target[]>(res);
  },

  getTarget: async (id: string): Promise<Target> => {
    const res = await fetch(`${API_BASE}/targets/${id}`);
    return handleResponse<Target>(res);
  },

  createTarget: async (data: Partial<Target>): Promise<Target> => {
    const res = await fetch(`${API_BASE}/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse<Target>(res);
  },

  updateTarget: async (id: string, data: Partial<Target>): Promise<Target> => {
    const res = await fetch(`${API_BASE}/targets/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse<Target>(res);
  },

  // Scans
  getScans: async (): Promise<Scan[]> => {
    const res = await fetch(`${API_BASE}/scans`);
    return handleResponse<Scan[]>(res);
  },

  getScan: async (id: string): Promise<Scan> => {
    const res = await fetch(`${API_BASE}/scans/${id}`);
    return handleResponse<Scan>(res);
  },

  createScan: async (targetId: string, categories: string[], authProfile?: string): Promise<Scan> => {
    const res = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_id: targetId,
        categories,
        auth_profile: authProfile || null,
      }),
    });
    return handleResponse<Scan>(res);
  },

  getScanFindings: async (scanId: string): Promise<Finding[]> => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/findings`);
    return handleResponse<Finding[]>(res);
  },

  // Findings
  getFindings: async (params?: { scan_id?: string; category?: string; severity?: string; status?: string }): Promise<Finding[]> => {
    const query = new URLSearchParams();
    if (params?.scan_id) query.append('scan_id', params.scan_id);
    if (params?.category) query.append('category', params.category);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.status) query.append('status', params.status);

    const res = await fetch(`${API_BASE}/findings?${query.toString()}`);
    return handleResponse<Finding[]>(res);
  },

  getFinding: async (id: string): Promise<Finding> => {
    const res = await fetch(`${API_BASE}/findings/${id}`);
    return handleResponse<Finding>(res);
  },

  updateFindingStatus: async (id: string, status: string): Promise<Finding> => {
    const res = await fetch(`${API_BASE}/findings/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_status: status }),
    });
    return handleResponse<Finding>(res);
  },

  // Reports
  getJsonReportUrl: (scanId: string): string => `${API_BASE}/scans/${scanId}/report.json`,
  getHtmlReportUrl: (scanId: string): string => `${API_BASE}/scans/${scanId}/report.html`,

  compareScans: async (baselineId: string, comparisonId: string): Promise<ScanComparison> => {
    const res = await fetch(`${API_BASE}/scans/${baselineId}/compare/${comparisonId}`);
    return handleResponse<ScanComparison>(res);
  },

  // Test library
  getTestCases: async (): Promise<TestCase[]> => {
    const res = await fetch(`${API_BASE}/test-cases`);
    return handleResponse<TestCase[]>(res);
  },

  // OpenAPI parser
  parseOpenApi: async (content: string): Promise<any> => {
    const res = await fetch(`${API_BASE}/openapi/parse`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });
    return handleResponse<any>(res);
  },
};

