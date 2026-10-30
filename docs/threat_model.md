# APIGuard — Threat Model & Ethical Boundaries

## 1. Assets, Boundaries, and Trust Assumptions

### Primary Assets
1. **Target Systems & Infrastructure**: Target APIs being tested must be protected against denial-of-service, data destruction, and unauthorized scanning.
2. **Scanner Persistence & History**: Scan results, findings, and reports stored in the local SQLite database.
3. **Synthetic User Credentials & Identities**: Static demo tokens (`demo-token-alice-12345`, etc.) used during scanning.

### Trust Boundaries
- **Untrusted Input**: User-provided target URLs, imported OpenAPI/Swagger specifications, and target API HTTP response payloads are strictly treated as **untrusted**.
- **Internal Scanner Engine**: Operates within a controlled Python execution environment on localhost.
- **Network Egress Boundary**: Governed exclusively by `ScopeGuard`. Outbound connections are blocked unless matching authorized target hosts and ports.

---

## 2. Threat Analysis & Mitigations

| Threat | Risk | Mitigation Strategy |
| :--- | :--- | :--- |
| **Out-of-Scope Network Scanning** | Critical | `ScopeGuard` enforces scheme (http/https), hostname allowlists, port allowlists, and loopback DNS resolution check before each request. |
| **SSRF via OpenAPI Specification Import** | High | Imported OpenAPI files are parsed in memory without initiating external network fetches. Every target URL must match pre-approved scope. |
| **OpenAPI / Report HTML Injection (XSS)** | Medium | HTML report generator applies Jinja2 auto-escaping (`select_autoescape`) and HTML entity escaping on all user-supplied and target-returned strings. |
| **Denial of Service (DoS) of Target API** | Medium | Request volume strictly capped at 200 requests/scan. Default pacing delay (50ms) applied between test suites. Bounded concurrency. |
| **Credential & Secret Leakage in Reports** | High | `EvidenceRedactor` intercepts headers and bodies, stripping Bearer tokens, cookies, and sensitive field values recursively before DB write. |
| **Server-Side Request Redirection Escape** | High | HTTP 301/302 redirects are not followed automatically (`follow_redirects=False`). If location header points outside scope, redirect is dropped. |
| **Path Traversal during Report Export** | Medium | Report file paths are validated against `reports/` directory with path traversal checks (`..` prevention). |
| **Database Corruption from Concurrent Scans** | Low | SQLite WAL (Write-Ahead Logging) enabled. Foreign keys enforced. Scan IDs use UUIDv4. |

---

## 3. Ethical Use & Academic Code of Conduct

1. **Authorization Mandatory**: Scanning any third-party API or network without documented authorization is illegal.
2. **Destructive Testing Prohibited**: APIGuard excludes SQL injection destruction, OS command execution, denial-of-service fuzzing, and credential brute-forcing.
3. **Synthetic Data Only**: All fixtures, user IDs, and tokens in APIGuard are fake synthetic test values.

