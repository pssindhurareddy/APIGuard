# APIGuard — Master Test Plan & Verification Matrix

## 1. Test Methodology

APIGuard combines automated unit tests, integration tests via in-memory ASGI transports, and live end-to-end HTTP scans against dual demonstration APIs (vulnerable mode on port 8001, secure mode on port 8002).

```
Test Classification Taxonomy:
- PASS: Security property confirmed intact and properly enforced.
- CONFIRMED: Reproducible evidence demonstrates security requirement violated.
- SUSPECTED: Anomalous status or unexpected response requiring manual verification.
- ERROR: Connection, network, or execution exception occurred.
- SKIPPED: Preconditions or required credentials missing.
```

---

## 2. Test Cases Specification & Verification Matrix

| Test ID | Test Category | Target Endpoint | Vulnerable API Result | Secure API Result | Verified Outcome |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AUTH-001** | Authentication | `GET /api/profile` | **CONFIRMED (High)**<br>HTTP 200 returned without credentials | **PASS**<br>HTTP 401 Unauthorized returned | Remediation verified |
| **AUTH-002** | Authentication | `GET /api/profile` | **CONFIRMED (High)**<br>HTTP 200 accepting forged token | **PASS**<br>HTTP 401 rejecting invalid token | Remediation verified |
| **AUTH-003** | Authentication | `GET /api/profile` | **CONFIRMED (Medium)**<br>Token identity mismatch | **PASS**<br>Identity bound to token claims | Remediation verified |
| **AUTH-004** | Authentication | All endpoints | **CONFIRMED (Medium)**<br>Observed policy drift | **PASS**<br>Enforcement matches policy | Remediation verified |
| **AUTHZ-001** | Authorization | `GET /api/orders/{order_id}` | **CONFIRMED (Critical)**<br>Alice accesses Bob's order (BOLA) | **PASS**<br>HTTP 403 Forbidden | Tenant isolation verified |
| **AUTHZ-002** | Authorization | `GET /api/admin/stats` | **CONFIRMED (High)**<br>Regular user gets admin stats | **PASS**<br>HTTP 403 Forbidden | RBAC verified |
| **AUTHZ-003** | Authorization | `GET /api/orders/{order_id}` | **CONFIRMED (Critical)**<br>Bob accesses Alice's order | **PASS**<br>HTTP 403 Forbidden | Bidirectional BOLA fixed |
| **AUTHZ-004** | Authorization | `GET /api/admin/stats` | **PASS**<br>Admin gets access | **PASS**<br>Admin gets access | Legitimate access preserved |
| **INPUT-001** | Input Validation | `POST /api/orders` | **CONFIRMED (Medium)**<br>Missing required field accepted | **PASS**<br>HTTP 422 Validation Error | Schema validation verified |
| **INPUT-002** | Input Validation | `POST /api/orders` | **CONFIRMED (Medium)**<br>String accepted for integer | **PASS**<br>HTTP 422 Validation Error | Type checking verified |
| **INPUT-003** | Input Validation | `POST /api/orders` | **CONFIRMED (Medium)**<br>Negative quantity accepted | **PASS**<br>HTTP 422 Boundary Error | Range constraints verified |
| **INPUT-004** | Input Validation | `POST /api/orders` | **PASS**<br>Handled gracefully | **PASS**<br>HTTP 422 on broken JSON | Exception handling verified |
| **INPUT-005** | Input Validation | `POST /api/orders` | **CONFIRMED (Low)**<br>Extraneous parameters accepted | **PASS**<br>Strict schema filtering | Mass assignment protected |
| **DATA-001** | Data Exposure | `GET /api/profile` | **CONFIRMED (High)**<br>Leaks `password_hash`, `api_key` | **PASS**<br>Safe user DTO returned | Credential leakage prevented |
| **DATA-002** | Data Exposure | `GET /api/orders/{id}` | **CONFIRMED (Medium)**<br>Exceeds declared allowlist | **PASS**<br>Conforms to allowlist | Minimal exposure verified |
| **DATA-003** | Data Exposure | `GET /api/admin/stats` | **CONFIRMED (High)**<br>Leaks `internal_config` nested | **PASS**<br>Nested config removed | Deep exposure verified |
| **DATA-004** | Data Exposure | `GET /api/profile` | **CONFIRMED (Medium)**<br>Excessive attributes exposed | **PASS**<br>Minimal attributes exposed | Least privilege serialization |

---

## 3. Automated Test Suite Execution

The automated pytest suite (`backend/tests/` and `demo_api/tests/`) contains 54 tests covering:
1. Detection engine assertions for each seeded weakness.
2. Verified remediation passes on secure counterparts.
3. ScopeGuard out-of-scope host, port, scheme, redirect, and budget rejections.
4. Evidence redactor recursive masking.
5. OpenAPI 3.0 JSON and YAML specification parsing.
6. SQLite scan history persistence and foreign key enforcement.
7. HTML and JSON report export schema validations.

