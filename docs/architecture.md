# APIGuard — System Architecture Specification

## 1. Executive Architectural Overview

**APIGuard** is a modular, local-first API security testing framework designed to assess REST endpoints for authentication gaps, Broken Object Level Authorization (BOLA), schema input validation weaknesses, and excessive data exposure.

The architecture strictly separates the **Scanner Core**, the **Scope Guard**, the **Target APIs**, and the **Management Frontend**.

```
+-------------------------------------------------------------------------+
|                              APIGuard Web UI                            |
|             (React 18 + TypeScript + Vite + Tailwind CSS)               |
+------------------------------------+------------------------------------+
                                     | (REST HTTP /api)
                                     v
+-------------------------------------------------------------------------+
|                         APIGuard Backend Server                         |
|                         (FastAPI + Uvicorn + SQLite)                    |
|                                                                         |
|  +--------------------+   +-------------------+   +------------------+  |
|  | Targets Management |   | Scan Orchestrator |   | Report Generator |  |
|  +--------------------+   +---------+---------+   +------------------+  |
|                                     |                                   |
|                                     v                                   |
|  +-------------------------------------------------------------------+  |
|  |                          Scope Guard                              |  |
|  |  * Host allowlisting          * Loopback DNS resolution check     |  |
|  |  * Port restrictions          * Max request budget enforcement    |  |
|  |  * Path prefix filtering      * Out-of-scope redirect blocking    |  |
|  +----------------------------------+--------------------------------+  |
|                                     |                                   |
|                                     v                                   |
|  +-------------------------------------------------------------------+  |
|  |                         Request Engine                            |  |
|  |  * HTTPX Async Client         * Response size ceiling (1 MB)      |  |
|  |  * Pre-flight validation      * Timeout bounds                    |  |
|  +----------------------------------+--------------------------------+  |
|                                     |                                   |
|           +-------------------------+-------------------------+         |
|           |                         |                         |         |
|           v                         v                         v         |
|     +-----------+             +-----------+             +-----------+   |
|     | Auth      |             | AuthZ     |             | Input &   |   |
|     | Checks    |             | (BOLA)    |             | Data Exp  |   |
|     | AUTH-001  |             | AUTHZ-001 |             | INPUT-001 |   |
|     | AUTH-002  |             | AUTHZ-002 |             | DATA-001  |   |
|     +-----------+             +-----------+             +-----------+   |
+-------------------------------------+-----------------------------------+
                                      |
              +-----------------------+-----------------------+
              | (Loopback HTTP: 8001)                         | (Loopback HTTP: 8002)
              v                                               v
+-----------------------------+                 +-----------------------------+
|    Vulnerable Demo API      |                 |       Secured Demo API      |
|    (Deliberate Weaknesses)  |                 |     (Remediated Controls)   |
|    Port 8001 (FastAPI)      |                 |     Port 8002 (FastAPI)     |
+-----------------------------+                 +-----------------------------+
```

---

## 2. Core Architectural Components

### A. Scope Guard (`backend/app/services/scope_guard.py`)
- Acts as the primary security firewall protecting against unauthorized network probes.
- Re-evaluates target scheme, resolved IP address, port, and path before **every single outbound request**.
- Forces loopback resolution (`127.0.0.1`, `::1`) by default, intercepting DNS rebinding or hostname spoofing.
- Intercepts HTTP 301/302 redirects: if a target attempts to redirect the scanner to an external IP, the redirect is dropped with a `ScopeViolation`.
- Caps request budget (max 200 requests/scan) to prevent unintentional denial-of-service.

### B. Request Engine (`backend/app/services/request_engine.py`)
- Wraps `httpx.AsyncClient` with bounded concurrency and explicit connection timeouts (default: 10s).
- Enforces payload size ceiling (default: 1 MB) to prevent buffer overflows or memory exhaustion.
- Returns standardized `RequestResult` objects capturing HTTP status, duration, headers, text, and parsed JSON.

### C. Check Modules (`backend/app/checks/`)
Modular implementations subclassing `BaseCheck`:
1. **AuthenticationCheck**: Missing Bearer token probes, forged token validation, identity binding verification.
2. **AuthorizationCheck**: Cross-user resource access (BOLA/IDOR), vertical privilege escalation (user -> admin).
3. **InputValidationCheck**: Missing required parameters, primitive type mismatches, boundary & numeric constraints, malformed JSON syntax.
4. **DataExposureCheck**: Sensitive keyword heuristics (`password_hash`, `api_key`), strict response field allowlists, nested object graph traversal.

### D. Evidence Redactor (`backend/app/services/evidence_redactor.py`)
- Sanitizes HTTP headers, JSON bodies, and query strings.
- Strips Bearer tokens (`Bearer [REDACTED]`), session cookies, and secret values before findings are written to SQLite or rendered into reports.

### E. Persistence Layer (`backend/app/models/database.py`)
- Powered by `aiosqlite` with SQLite WAL mode.
- Separates target configurations from scan results.
- Maintains relational foreign keys linking scans to targets and findings to scans.

### F. Dual-Mode Demonstration API (`demo_api/`)
- A separate standalone service running on ports `8001` (Vulnerable mode) and `8002` (Secure mode).
- Both modes share identical synthetic data fixtures and logical route paths, enabling fair before-and-after remediation validation.

