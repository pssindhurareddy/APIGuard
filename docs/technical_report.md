# APIGuard: Automated REST API Security Testing Framework
**Technical Report & Evaluation Brief**

## Abstract
Modern cloud architectures rely heavily on REST APIs for microservice communication and client interfaces. However, traditional vulnerability scanners fail to capture complex API vulnerabilities such as Broken Object Level Authorization (BOLA), business schema violations, and excessive data exposure. This paper presents **APIGuard**, an automated, evidence-driven REST API security testing framework. APIGuard provides deterministic evaluation across four key domains: Authentication, Authorization (BOLA), Input Validation, and Excessive Data Exposure. Integrated with a zero-trust Scope Guard and automated evidence redactor, the framework evaluates both deliberately vulnerable and secured targets, demonstrating verifiable before-and-after remediation validation.

---

## 1. Problem Definition
Application programming interfaces (APIs) represent the primary attack surface for modern enterprise breaches. According to the OWASP API Security Top 10, authorization flaws (notably BOLA and Broken Function Level Authorization) and sensitive data exposure account for the vast majority of severe cloud compromises. Conventional Dynamic Application Security Testing (DAST) tools built for server-rendered HTML applications struggle to parse JSON schemas, manage stateless bearer tokens, or recognize multi-tenant object access boundaries. 

APIGuard addresses this gap by combining declarative policy specification with automated, non-destructive test execution.

---

## 2. Scope & Threat Model
The operational boundary of APIGuard is strictly controlled by an application-level `ScopeGuard`:
- **Allowed Targets**: Restricted by default to local loopback addresses (`127.0.0.1`, `localhost`) on designated demonstration ports (`8001`, `8002`).
- **SSRF Prevention**: Loopback DNS resolution checks prevent DNS rebinding attacks. Outbound requests verifying external destinations are dropped immediately.
- **Data Protection**: `EvidenceRedactor` scrubs all incoming Authorization headers, cookies, and sensitive JSON keys (e.g. `password_hash`, `api_key`) before storing findings in SQLite or rendering reports.
- **Safe Request Ceiling**: Total requests are capped at 200 per scan to avoid unintentional service degradation.

---

## 3. System Architecture & Implementation
The application is structured into four decoupled layers:
1. **Frontend Presentation**: Built with React 18, TypeScript, Vite, Tailwind CSS, and Recharts. Features dark-themed cybersecurity aesthetics, live health monitoring, and scan comparison.
2. **Scanner Backend**: Built on FastAPI, HTTPX, and Pydantic. Implements async scan orchestration, bounded request execution, and SQLite persistence.
3. **Check Engine**: Four modular suites (`AuthenticationCheck`, `AuthorizationCheck`, `InputValidationCheck`, `DataExposureCheck`) returning standardized `CheckResult` taxonomies (`PASS`, `CONFIRMED`, `SUSPECTED`, `ERROR`, `SKIPPED`).
4. **Controlled Demonstration Targets**: Dual FastAPI applications running in Vulnerable mode (port 8001) and Secure mode (port 8002) using identical synthetic fixtures.

---

## 4. Test Methodology & Empirical Results
A controlled testing experiment was conducted by scanning the Vulnerable API followed by the Secured API.

### Vulnerable Mode Evaluation (Port 8001)
- **AUTH-001**: Confirmed unauthenticated access to `GET /api/profile` (HTTP 200 returned).
- **AUTHZ-001 (BOLA)**: Confirmed Alice accessing Bob's order `order-1002` (HTTP 200 returned).
- **AUTHZ-002**: Confirmed regular user executing `GET /api/admin/stats` (HTTP 200 returned).
- **INPUT-001 & 003**: Confirmed acceptance of missing required fields and negative quantities (`quantity: -5`).
- **DATA-001**: Confirmed leakage of `password_hash` and `api_key` in profile responses.

### Secured Mode Evaluation (Port 8002)
- Re-executing the identical test suite against the secured API resulted in **100% of previous weaknesses transitioning to PASS**.
- Alice's cross-tenant access to Bob's order was denied with HTTP 403 Forbidden.
- Unauthenticated requests were denied with HTTP 401 Unauthorized.
- Strict Pydantic serialization models excluded sensitive attributes from response bodies.

---

## 5. Limitations & Future Research
- **Policy Dependency**: The framework requires schema hints or OpenAPI definitions to infer intended business rules.
- **Non-Destructive Scope**: Excludes destructive SQL injection or volumetric DoS attacks by design.
- **Future Directions**: Implementing dynamic OpenAPI fuzzing, GraphQL AST query introspection, and automated CI/CD pipeline integration.

---

## 6. References & Standards
1. OWASP API Security Top 10 (2023). Open Worldwide Application Security Project.
2. NIST Special Publication 800-95: Guide to Secure Web Services.
3. RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage.
4. FastAPI Documentation & OpenAPI Specification 3.0.3.

