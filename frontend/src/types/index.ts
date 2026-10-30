export type ScanStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
export type TestResultStatus = 'PASS' | 'CONFIRMED' | 'SUSPECTED' | 'ERROR' | 'SKIPPED';
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingWorkflowStatus = 'OPEN' | 'ACKNOWLEDGED' | 'FIXED' | 'ACCEPTED_RISK';

export interface Target {
  id: string;
  name: string;
  base_url: string;
  environment: string;
  allowed_hosts: string[];
  allowed_ports: number[];
  allowed_paths: string[];
  allowed_methods: string[];
  is_authorized: boolean;
  auth_profiles_public: {
    name: string;
    username: string;
    role: string;
  }[];
  created_at: string;
  updated_at: string;
  last_scan_id?: string;
  last_scan_status?: string;
}

export interface Scan {
  id: string;
  target_id: string;
  target_name: string;
  target_url: string;
  status: ScanStatus;
  categories: string[];
  auth_profile?: string;
  started_at?: string;
  completed_at?: string;
  total_tests: number;
  passed: number;
  confirmed: number;
  suspected: number;
  errors: number;
  skipped: number;
  duration_ms?: number;
  summary?: string;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  test_id: string;
  test_name: string;
  category: string;
  endpoint: string;
  http_method: string;
  status: TestResultStatus;
  severity: SeverityLevel;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  expected_result?: string;
  actual_result?: string;
  evidence?: any;
  explanation?: string;
  remediation?: string;
  impact?: string;
  preconditions?: string;
  limitations?: string;
  fingerprint?: string;
  finding_status: FindingWorkflowStatus;
  created_at: string;
  standards?: FindingStandards;
}

export interface FindingStandards {
  owasp: { id: string; name: string; url: string } | null;
  cwe: { id: string; name: string; url: string }[];
}

export interface TestCase {
  id: string;
  name: string;
  category: string;
  description: string;
  why_it_matters: string;
  preconditions: string;
  success_criteria: string;
  evidence_collected: string;
  limitations: string;
  standards?: FindingStandards;
}

export interface SystemHealth {
  status: string;
  service: string;
  version: string;
  demo_apis: {
    vulnerable_demo?: { status: string; port: number; details?: any };
    secure_demo?: { status: string; port: number; details?: any };
    vampi_vulnerable?: { status: string; port: number; details?: any };
    vampi_secure?: { status: string; port: number; details?: any };
  };
}

export interface ScanComparison {
  baseline_scan: {
    id: string;
    target_name: string;
    target_url: string;
    total_tests: number;
    confirmed_findings: number;
    completed_at: string;
  };
  remediation_scan: {
    id: string;
    target_name: string;
    target_url: string;
    total_tests: number;
    confirmed_findings: number;
    completed_at: string;
  };
  remediated_findings: {
    test_id: string;
    test_name: string;
    endpoint: string;
    original_severity: string;
    retest_status: string;
    evidence_resolved: string;
    verified_remediation: boolean;
  }[];
  persistent_findings: Finding[];
  new_findings: Finding[];
  remediation_success_rate: string;
}

