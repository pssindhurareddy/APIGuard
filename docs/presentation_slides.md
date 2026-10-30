# APIGuard — Presentation Slides Content (Deliverable F)

---

## Slide 1: Problem Definition & Motivation

### The Challenge of REST API Security
- **API Sprawl & Hidden Flaws**: Modern microservices expose hundreds of REST endpoints. Traditional web scanners focus on HTML/XSS, failing to understand structured JSON contracts, stateful authentication, and object tenancy.
- **OWASP API Top 10 Dominance**: Broken Object Level Authorization (BOLA/IDOR) and Excessive Data Exposure represent the most critical vulnerabilities causing massive cloud data breaches.
- **Project Objective**:
  > “Assess REST APIs for authentication, authorization, input validation, and excessive data exposure weaknesses through reproducible automated tests, evidence-backed findings, and validated remediation recommendations.”
- **Ethical Foundation**: Software-only framework utilizing strictly controlled loopback environments, synthetic identities, and non-destructive test execution.

---

## Slide 2: Architecture & Implementation

### Layered Defense & Local-First Engine
- **React 18 + TypeScript Frontend**: Dark-themed security engineer interface featuring live backend diagnostics, scan history, real Recharts visualization, and before-and-after remediation comparison.
- **FastAPI Scanning Core**: Async execution engine using HTTPX, SQLite persistence, and declarative YAML/OpenAPI policy resolution.
- **Zero-Trust ScopeGuard**:
  - Pre-flight validation on every request (scheme, host, port, path prefix, method).
  - DNS loopback verification preventing DNS rebinding attacks.
  - Interception of out-of-scope 301/302 redirects.
  - Bounded request volume (200 requests/scan).
- **EvidenceRedactor**: Real-time recursive scrubbing of Bearer tokens, cookies, and secret values before database storage or export.

---

## Slide 3: Demonstration Results & Evidence

### Seeded Vulnerability Detection (Port 8001)
1. **AUTH-001 (High)**: `GET /api/profile` returns HTTP 200 with sensitive data when called without an Authorization token.
2. **AUTHZ-001 (Critical - BOLA)**: Alice's bearer token requested Bob's private order (`order-1002`) and received HTTP 200 with complete order details.
3. **AUTHZ-002 (High - Privilege Escalation)**: Ordinary user accessed `GET /api/admin/stats` with HTTP 200.
4. **INPUT-001 & 003 (Medium)**: `POST /api/orders` accepted negative quantities (`-5`) and omitted mandatory product attributes.
5. **DATA-001 (High)**: `GET /api/profile` leaked raw `password_hash` and `api_key` attributes in the JSON response payload.

All findings accompanied by reproducible HTTP evidence, status codes, and confidence ratings.

---

## Slide 4: Remediation, Limitations & Future Work

### Verified Remediation & Responsible Disclosure
- **Side-by-Side Remediation Validation (Port 8002)**:
  - Scanning the secured API confirms 100% of previous weaknesses transitioned from `CONFIRMED` to `PASS`.
  - Alice blocked from Bob's order with HTTP 403 Forbidden.
  - Unauthenticated calls rejected with HTTP 401 Unauthorized.
  - Strict Pydantic DTOs exclude `password_hash` from serialization.
- **Evaluator Limitations**: Non-destructive by design; policy-dependent BOLA checks; loopback containment.
- **Future Improvements**: Dynamic GraphQL introspection, CI/CD GitHub Actions scanner action, and automated OpenAPI fuzz generation.

