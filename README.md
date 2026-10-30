# APIGuard — Automated REST API Security Testing Framework

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688.svg)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18-61dafb.svg)](https://react.dev/)
[![Tests](https://img.shields.io/badge/tests-54%20passing-brightgreen.svg)](#7-running-the-automated-tests)
[![Precision](https://img.shields.io/badge/precision-100%25-brightgreen.svg)](#8-detection-accuracy-evaluation)
[![OWASP API Top 10](https://img.shields.io/badge/OWASP-API%20Top%2010%202023-blue.svg)](#2-what-it-tests-17-checks-4-categories)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

APIGuard is a local-first security testing framework that checks REST APIs for **broken authentication, broken object-level authorization (BOLA/IDOR), weak input validation, and excessive data exposure** (OWASP API Security Top 10, 2023). Every finding comes with redacted HTTP evidence, a severity rating, an **OWASP API Top 10 / CWE mapping** and a remediation, and the tool proves a fix works by re-scanning a hardened version of the same API and comparing the results.

It is evaluated on its own demo API **and on [VAmPI](https://github.com/erev0s/VAmPI), an independent third-party vulnerable API**, with source-code-labelled ground truth: **100% precision and recall over 125 check/endpoint verdicts**, and 3 of VAmPI's 4 in-scope published vulnerabilities detected.

> **Ethical use:** APIGuard is for authorized testing and academic work only. Its `ScopeGuard` module blocks every non-loopback target by default. Do not point it at any system you do not own or have written permission to test.

---

## 1. Problem

REST APIs now carry most application traffic, but classic web scanners (DAST) were built for HTML pages and look for patterns like XSS. They cannot tell that *Alice should not be able to read Bob's order*, which is the most common real API flaw (OWASP API1:2023, BOLA). APIGuard closes that gap: you declare each endpoint's security policy (who may call it, who owns which object, which fields may be returned), and APIGuard sends safe, non-destructive probes to check the running API against that policy.

---

## 2. What It Tests (17 checks, 4 categories)

Every check is mapped to the **OWASP API Security Top 10 (2023)** (or OWASP ASVS where the Top 10 has no category) and to **CWE**. The mapping is shown in the dashboard, the Test Library and both report formats (`backend/app/services/standards.py`).

| Checks | OWASP | CWE |
| :--- | :--- | :--- |
| AUTH-001, AUTH-004 | API2:2023 Broken Authentication | CWE-306 |
| AUTH-002, AUTH-003 | API2:2023 Broken Authentication | CWE-287 |
| AUTHZ-001, AUTHZ-003 | API1:2023 Broken Object Level Authorization | CWE-639, CWE-862 |
| AUTHZ-002, AUTHZ-004 | API5:2023 Broken Function Level Authorization | CWE-285 |
| INPUT-001 / 002 / 003 | OWASP ASVS V5 Validation | CWE-20 / CWE-1287 / CWE-1284 |
| INPUT-004 | API8:2023 Security Misconfiguration | CWE-755 |
| INPUT-005 | API3:2023 Broken Object Property Level Authorization | CWE-915 |
| DATA-001 … DATA-004 | API3:2023 Broken Object Property Level Authorization | CWE-200, CWE-213 |

The framework assesses four foundational security categories:

1. **Authentication Security Testing**
   - `AUTH-001`: Unauthenticated request verification on declared protected routes.
   - `AUTH-002`: Forged and invalid Bearer token rejection.
   - `AUTH-003`: Token claim identity binding and profile verification.
   - `AUTH-004`: Specification-versus-runtime policy consistency.

2. **Authorization & BOLA Testing (OWASP API #1)**
   - `AUTHZ-001`: Cross-user object access: User A (Alice) attempts to retrieve User B's (Bob) order.
   - `AUTHZ-002`: Vertical privilege escalation: Ordinary test user calls admin-only endpoints (`/api/admin/stats`).
   - `AUTHZ-003`: Bidirectional BOLA verification: User B (Bob) attempts to retrieve User A's (Alice) order.
   - `AUTHZ-004`: Legitimate role access preservation.

3. **Input Validation Testing**
   - `INPUT-001`: Rejection of payloads missing declared mandatory attributes.
   - `INPUT-002`: Rejection of incompatible primitive types (e.g., string supplied where integer required).
   - `INPUT-003`: Rejection of out-of-range numeric boundaries (e.g., negative quantity `-5`).
   - `INPUT-004`: Graceful handling of truncated or syntactically malformed JSON.
   - `INPUT-005`: Mass assignment. When the policy says how, the check **verifies** binding: it registers an account with `admin: true`, logs in as it and reads the attribute back, so silently-ignored fields are not reported as false positives.

4. **Excessive Data Exposure Testing (OWASP API #3)**
   - `DATA-001`: Detection of sensitive credential fields (`password_hash`, `api_key`, `secret`, `internal_notes`).
   - `DATA-002`: Contract validation against strict endpoint response allowlists.
   - `DATA-003`: Deep recursive inspection of nested object hierarchies.
   - `DATA-004`: Principle of least privilege minimal response validation.

---

## 3. Architecture & Tech Stack

```
+-------------------------------------------------------------+
|                     APIGuard React UI                       |
|               (Dashboard : served on Port 8000)             |
+------------------------------+------------------------------+
                               | REST API (http://127.0.0.1:8000)
                               v
+-------------------------------------------------------------+
|                 APIGuard Scanner Backend                    |
|                (FastAPI Engine : Port 8000)                 |
|                                                             |
|   +-------------------+    +----------------------------+   |
|   | Scan Orchestrator |    | ScopeGuard Safety Boundary |   |
|   +---------+---------+    +-------------+--------------+   |
|             |                            |                  |
|             v                            v                  |
|   +-------------------+    +----------------------------+   |
|   | 4 Check Modules   |--->| HTTPX Client (Timeout/Cap) |   |
|   +-------------------+    +-------------+--------------+   |
+------------------------------------------|------------------+
                                           |
          +------------------+-------------+-------------+------------------+
          | :8001            | :8002                     | :8003            | :8004
          v                  v                           v                  v
+------------------+ +------------------+      +------------------+ +------------------+
| Demo API         | | Demo API         |      | VAmPI            | | VAmPI            |
| vulnerable       | | secure           |      | vulnerable       | | "secure" mode    |
| (own, FastAPI)   | | (own, FastAPI)   |      | (3rd-party,Flask)| | (3rd-party,Flask)|
+------------------+ +------------------+      +------------------+ +------------------+
```


**Data flow:** UI → `POST /api/scans` → Scan Orchestrator loads target + YAML policies → **runtime context**: logs in auth profiles that use real credentials (e.g. VAmPI JWTs) and discovers each user's object IDs → every request is checked by **ScopeGuard** (host/port/path/method allowlists, loopback-only, 200-request budget, no redirects) → HTTPX request engine → 4 check modules evaluate responses → **Evidence Redactor** strips tokens/secrets → findings stored in SQLite → dashboard + HTML/JSON reports.

| Layer | Technology |
| :--- | :--- |
| Frontend | React 18.3, TypeScript 5, Vite 6, Tailwind CSS 3.4, Recharts 2.15, Lucide |
| Scanner backend | Python 3.12+, FastAPI 0.115, Uvicorn 0.34, HTTPX 0.28 (async), Pydantic 2.11, PyYAML, Jinja2, aiosqlite |
| Storage | SQLite 3 (WAL mode, foreign keys) — `backend/apiguard.db`, created on first run |
| Demo targets | Own FastAPI app in two modes: **vulnerable** (8001) and **secure** (8002) |
| Third-party benchmark | [VAmPI](https://github.com/erev0s/VAmPI) (MIT, Flask/Connexion), bundled in `third_party/`: **vulnerable** (8003) and **secure mode** (8004) |
| CI | GitHub Actions: tests on Windows + Linux × Python 3.12/3.13, dashboard build, end-to-end accuracy evaluation |
| Tests | Pytest 8.3 + pytest-asyncio (in-memory ASGI transport, no network needed) |

---

## 4. Repository Structure

```
APIgaurd/
├── backend/                     # Scanner engine (FastAPI, port 8000)
│   ├── app/
│   │   ├── api/                 # REST routes: health, targets, scans, findings, reports, test-cases, openapi
│   │   ├── checks/              # authentication.py, authorization.py, input_validation.py, data_exposure.py
│   │   ├── services/            # scan_orchestrator, request_engine, scope_guard, evidence_redactor,
│   │   │                        # report_generator, openapi_parser, risk_classifier, standards (OWASP/CWE)
│   │   ├── models/database.py   # Async SQLite layer (targets, scans, findings)
│   │   ├── schemas/             # Pydantic request/response models
│   │   ├── templates/report.html# Jinja2 HTML report
│   │   ├── config.py            # Timeouts, request budget, pacing, size limits
│   │   └── main.py              # App entrypoint, CORS, demo target seeding
│   ├── tests/                   # 48 backend tests (see §7)
│   └── requirements.txt
├── demo_api/                    # Deliberately vulnerable + hardened target API
│   ├── app/routes/              # profile, orders, admin, health, fixtures-reset
│   ├── app/security.py          # Token lookup, ownership + role checks
│   ├── app/fixtures.py          # Synthetic users/orders/tokens (all fake)
│   ├── tests/test_demo_api.py   # 6 tests
│   └── requirements.txt
├── frontend/                    # React dashboard source; dist/ = pre-built copy served on port 8000
│   └── src/{pages,components,services,types}
├── third_party/
│   ├── VAmPI/                   # Bundled third-party vulnerable API (MIT licence, see its LICENSE)
│   ├── run_vampi.py             # Loopback launcher: --mode vulnerable|secure --port 8003|8004
│   └── requirements-vampi.txt   # VAmPI dependencies (pins updated for Python 3.12/3.13)
├── evaluation/
│   ├── ground_truth.yaml        # Source-code-derived labels for all 4 targets
│   ├── run_evaluation.py        # Scans all targets, computes TP/FP/TN/FN, precision, recall, F1
│   └── results/                 # evaluation_report.md + evaluation_results.json
├── test_evidence/               # Raw evidence for test cases TC-01…TC-08 (HTTP captures, screenshots)
├── .github/workflows/ci.yml     # Continuous integration
├── config/
│   ├── demo_targets.yaml        # Endpoint policies, auth profiles (static or login), resource discovery
│   ├── demo_test_cases.yaml     # Test case catalogue
│   └── response_policies.yaml   # Sensitive-field patterns & allowlists
├── docs/                        # architecture, threat model, test plan, limitations, report, slides
├── scripts/                     # run_all / run_tests / per-service launchers (.ps1 Windows, .sh macOS/Linux)
├── reports/                     # Generated report output (git-ignored)
├── requirements.txt             # One-line install of everything
├── pytest.ini, conftest.py
├── LICENSE                      # MIT
└── README.md
```

---

## 5. Setup

### Prerequisites
| Requirement | Version |
| :--- | :--- |
| Python | 3.12 or 3.13 (both verified) |
| Node.js + npm | **Optional** — only needed to modify the dashboard (Node 20+, verified on 22) |
| OS | Windows 10/11, macOS, or Linux |
| Network | None at runtime — everything runs on `127.0.0.1` |

No GPU, database server, API keys or environment variables are needed. **The project uses no secrets**; all configuration is in `config/*.yaml` and `backend/app/config.py`.

### Install

From the project root (the folder containing this README):

```bash
# (optional) create a virtual environment
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate

# Everything (scanner, demo API, VAmPI benchmark) in one command
python -m pip install -r requirements.txt
```

The dashboard ships pre-built in `frontend/dist/` and is served by the backend, so **no Node.js or `npm install` is required to run it.**

---

## 6. Running

### One command

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1
```

**macOS / Linux:**
```bash
./scripts/run_all.sh
```

This starts 5 windows (demo API ×2, VAmPI ×2, backend) and opens the dashboard at **http://127.0.0.1:8000**. The top bar shows all targets as ONLINE. Stop with `scripts\stop_all.ps1` (Windows) or Ctrl+C (macOS/Linux).

### Manually (5 terminals, run from the project root)

| # | Service | Command |
| :-- | :--- | :--- |
| 1 | Vulnerable demo API (8001) | `python -m demo_api.app.main --mode vulnerable --port 8001` |
| 2 | Secure demo API (8002) | `python -m demo_api.app.main --mode secure --port 8002` |
| 3 | VAmPI vulnerable (8003) | `python third_party/run_vampi.py --mode vulnerable --port 8003` |
| 4 | VAmPI secure mode (8004) | `python third_party/run_vampi.py --mode secure --port 8004` |
| 5 | Scanner backend + dashboard (8000) | `python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000` |

Open **http://127.0.0.1:8000** for the dashboard. `http://127.0.0.1:8000/api/health` should report all four targets as `"online"`, and `http://127.0.0.1:8000/docs` shows the interactive API documentation.

### Modifying the dashboard (optional, developers only)
```bash
cd frontend
npm ci
npm run dev      # live-reload dev server at http://127.0.0.1:5173 (proxies /api to port 8000)
npm run build    # rebuild frontend/dist, which the backend then serves on port 8000
```

### Expected scan results

Scanning with all four categories and the **Alice** profile gives these results (verified on the current code):

| Target | Checks run | PASS | CONFIRMED | SUSPECTED | Errors |
| :--- | :--: | :--: | :--: | :--: | :--: |
| Local Vulnerable Demo API (8001) | 45 | 9 | **36** | 0 | 0 |
| Local Secured Demo API (8002) | 44 | **44** | 0 | 0 | 0 |
| VAmPI (third-party) - Vulnerable (8003) | 34 | 28 | **5** | 0 | 0 |
| VAmPI (third-party) - Secure mode (8004) | 34 | 31 | **2** | 0 | 0 |

(Each VAmPI scan also reports 1 SKIPPED check: AUTHZ-002/004 need an admin-only *read* endpoint, which VAmPI does not have.)

**Compare Two Scans:**
- Demo vulnerable → secure: **100.0% remediation**. All 27 distinct confirmed findings are fixed, with none persisting.
- VAmPI vulnerable → secure mode: **60.0% remediation**. BOLA and mass assignment are fixed, but the **`/users/v1/_debug` password leak persists**. VAmPI's "secure" mode really does still leak every user's plaintext password, and APIGuard catches it.

A full scan takes about 1.2 seconds per target.

Sample confirmed findings on the vulnerable API:

| Check | Severity | What was observed |
| :--- | :--- | :--- |
| AUTHZ-001 BOLA | CRITICAL | Alice's token reads Bob's `order-1002` → HTTP 200 with Bob's data |
| AUTHZ-002 Privilege escalation | HIGH | Ordinary user reads `/api/admin/stats` → HTTP 200 |
| AUTH-001 Missing auth | HIGH | `/api/profile` returns data with no `Authorization` header |
| DATA-001 Sensitive fields | HIGH | Profile response contains `password_hash`, `api_key`, `internal_notes` |
| INPUT-003 Boundary | MEDIUM | `quantity: -5` accepted on `POST /api/orders` |
| INPUT-005 Mass assignment | LOW | Unknown field `is_admin: true` accepted |

Confirmed on **VAmPI** (third-party code):

| Check | Severity | What was observed |
| :--- | :--- | :--- |
| AUTHZ-001 / 003 BOLA | CRITICAL | `name1` reads `name2`'s secret book via `/books/v1/{book_title}` (and vice versa) |
| INPUT-005 Mass assignment (verified) | HIGH | Registering with `admin: true` creates an admin; confirmed by logging in and reading `/me` → `data.admin = true` |
| DATA-001 / 003 Data exposure | HIGH | `/users/v1/_debug` returns every user's plaintext `password` (in **both** modes) |

### Reports
On the **Reports** page, open the HTML report or download JSON. You can also call the API directly: `GET /api/scans/{scan_id}/report.html`, `/report.json`, and `GET /api/scans/{baseline_id}/compare/{remediated_id}`. Bearer tokens, cookies and sensitive field values show as `[REDACTED]`.

### Demo walkthrough (about 7 minutes)
1. **Overview**: the top bar shows the demo APIs (8001/8002) and VAmPI (8003/8004) as ONLINE.
2. **New Scan** → *Local Vulnerable Demo API* → profile *Alice* → all 4 categories → **Start Security Scan**. 36 confirmed findings appear.
3. **Findings** → open **AUTHZ-001** → evidence shows Bob's order returned to Alice, with the token redacted → set status to *ACKNOWLEDGED*.
4. **New Scan** → *Local Secured Demo API* → **44/44 PASS**.
5. **Overview / History** → **Compare Two Scans** (vulnerable as baseline, secure as comparison) → **100% remediation**.
6. **Reports** → open the HTML report and download the JSON. Each finding lists its OWASP category and CWE.
7. **Third-party proof:** scan *VAmPI (third-party) - Vulnerable* and then *Secure mode* → compare → 60%. Open the persisting `DATA-001` finding to show the leaked passwords.

---

## 7. Running the Automated Tests

```bash
python -m pytest backend/tests demo_api/tests -v
# or: scripts\run_tests.ps1  (Windows)   ./scripts/run_tests.sh  (macOS/Linux)
```
Expected: `54 passed` in about 1 second. The tests run in memory against the demo API through an ASGI transport, so you do not need to start any services first.

| File | Tests | What it verifies |
| :--- | :--: | :--- |
| `backend/tests/test_detection_engine.py` | 10 | Each category is CONFIRMED on the vulnerable API and PASSES on the secure API |
| `backend/tests/test_scope_guard.py` | 9 | Rejects other hosts/ports/paths/methods, public internet, URL credentials, out-of-scope redirects, and enforces the request budget |
| `backend/tests/test_remediation_regression.py` | 6 | No false "suspected" results; mass assignment blocked; auth before object lookup; full secure scan has zero open findings; dashboard served on port 8000 |
| `backend/tests/test_dynamic_targets.py` | 7 | Login-based auth profiles, resource discovery, generic path templating, BOLA on discovered IDs, verified mass assignment (no false positive when the field is ignored) |
| `backend/tests/test_standards.py` | 3 | Every check maps to OWASP + CWE; mappings appear in JSON/HTML reports |
| `backend/tests/test_evaluation_metrics.py` | 3 | Accuracy scoring logic (TP/FP/TN/FN, precision, recall, F1) and ground-truth file format |
| `backend/tests/test_evidence_redactor.py` | 5 | Tokens, cookies, nested sensitive fields, and sensitive key/value pairs inside text previews are redacted |
| `backend/tests/test_openapi_parser.py` | 3 | JSON/YAML spec import and malformed-spec handling |
| `backend/tests/test_reports_and_comparison.py` | 2 | SQLite persistence; JSON/HTML report generation without leaking secrets |
| `demo_api/tests/test_demo_api.py` | 6 | Demo API behaves vulnerably/securely as intended |

### Continuous integration
`.github/workflows/ci.yml` runs on every push to GitHub:
1. **Unit tests** on Windows and Ubuntu with Python 3.12 and 3.13 (4 combinations).
2. **Dashboard build** (`npm ci && npm run build`, including the TypeScript type-check).
3. **End-to-end**: starts all 5 services, checks the dashboard is served, runs `evaluation/run_evaluation.py --strict` (fails on any false positive or false negative) and uploads the evaluation report as a build artifact.

---

## 8. Detection Accuracy Evaluation

```bash
# with all services running (scripts/run_all)
python evaluation/run_evaluation.py
```

The script scans all four targets and compares every verdict with `evaluation/ground_truth.yaml`. Its labels were written **from the targets' source code** (each positive cites the responsible code), not from scanner output. The full report is written to `evaluation/results/evaluation_report.md`.

| Benchmark | (check, endpoint) pairs | TP | FP | TN | FN | Precision | Recall | Accuracy |
| :--- | --: | --: | --: | --: | --: | --: | --: | --: |
| Own demo API (vulnerable + secure) | 71 | 27 | 0 | 44 | 0 | 100% | 100% | 100% |
| VAmPI, third-party (vulnerable + secure) | 54 | 7 | 0 | 47 | 0 | 100% | 100% | 100% |
| **All** | **125** | **34** | **0** | **91** | **0** | **100%** | **100%** | **100%** |

**Coverage of VAmPI's 9 published vulnerabilities:** **3 of the 4** that fall inside APIGuard's scope are detected (BOLA, mass assignment, excessive data exposure). The fourth, *unauthorized password change*, is a write-based BOLA; APIGuard deliberately probes only reads to stay non-destructive. The other 5 (SQL injection, user enumeration, ReDoS, rate limiting, weak JWT key) are outside the declared scope. So it is **3/9 overall**.

These numbers show the checks behave correctly on the benchmarks. They are not a claim about detection rates on arbitrary real-world APIs; see *Threats to validity* in the report.

---

## 9. Synthetic Test Data

| Identity | Role | Demo bearer token | Owns |
| :--- | :--- | :--- | :--- |
| Alice | user | `demo-token-alice-12345` | `user-alice-001`, `order-1001`, `order-1003` |
| Bob | user | `demo-token-bob-67890` | `user-bob-002`, `order-1002` |
| Admin | admin | `demo-token-admin-99999` | access to `/api/admin/stats` |

All tokens, hashes (`FAKE_HASH_NOT_REAL_…`), API keys (`FAKE_API_KEY_…`) and records are fake and exist only in `demo_api/app/fixtures.py`. No real or personal data is used.

VAmPI ships its own dummy users (`name1`/`pass1`, `name2`/`pass2`, `admin`/`pass1`). APIGuard logs in as them at scan time to obtain real, short-lived JWTs. These credentials are public, fake, and only valid against the local VAmPI instance.

---

## 10. Security Controls in APIGuard Itself

| Risk | Control |
| :--- | :--- |
| Scanning systems you don't own | ScopeGuard: host/port/path/method allowlists, DNS must resolve to loopback, URLs with embedded credentials rejected |
| SSRF via redirects | `follow_redirects=False`; out-of-scope `Location` headers dropped |
| Accidental DoS of the target | Max 200 requests per scan, 50 ms pacing, 4 concurrent requests, 10 s timeout, 1 MB response cap |
| Credentials leaking into reports | Evidence Redactor scrubs `Authorization`, cookies and sensitive fields recursively before anything is saved |
| XSS in HTML reports | Jinja2 auto-escaping |

---

## 11. Limitations

- **Policy-driven, not autonomous.** BOLA, role and response-field checks need declared endpoint policies (`config/demo_targets.yaml` or an imported OpenAPI spec). APIGuard does not infer business rules on its own.
- **Four REST categories only.** It does not test SQL/command injection, XSS, rate limiting, SSRF, business-logic workflows, GraphQL, gRPC, WebSockets or SOAP.
- **Non-destructive by design.** It does not brute-force credentials, enumerate IDs exhaustively, or run destructive payloads.
- **No token cryptanalysis.** Auth profiles can log in for real JWTs, but APIGuard does not attack JWT signing keys, expiry or refresh logic.
- **Read-only object probes.** Write-based BOLA (e.g. changing another user's password via `PUT`) is not tested, to stay non-destructive. This is why VAmPI's "Unauthorized Password Change" is not detected.
- **Loopback only by default.** Testing a remote host requires deliberately editing the allowlist (and having authorization).
- **OpenAPI support** covers 3.0 and Swagger 2.0 with JSON bodies. Multipart/XML bodies and discriminators are not supported.
- **Single user, local tool.** SQLite with a single writer and no login on the dashboard. CI runs the project's own tests; APIGuard is not yet packaged as a CI step for scanning other projects.
- **Small benchmark.** Evaluated on 4 targets (own demo API + third-party VAmPI, each in two modes). The ground truth was labelled by the authors from source code, so it is auditable but not independently produced.

Details: [`docs/limitations.md`](docs/limitations.md) · threat model: [`docs/threat_model.md`](docs/threat_model.md)

---

## 12. Troubleshooting

| Symptom | Fix |
| :--- | :--- |
| `ModuleNotFoundError: demo_api` / `app` | Run commands from the project root, not from inside `backend/` or `demo_api/` |
| Dashboard shows a target as OFFLINE | Start that service (8001/8002 demo, 8003/8004 VAmPI); check that the ports are free (`netstat -ano \| findstr 800` on Windows, `lsof -i :8003` on macOS/Linux) |
| VAmPI scan FAILED: "Login for auth profile … failed" | VAmPI is not running on 8003/8004. Start it (see §6) and re-run the scan |
| `ModuleNotFoundError: connexion` / `flask` | Install everything with `python -m pip install -r requirements.txt` (root file) |
| PowerShell: "running scripts is disabled" | Use `powershell -ExecutionPolicy Bypass -File …` as shown above |
| Old scans clutter the dashboard | Stop the backend and delete `backend/apiguard.db*`; it is recreated (with demo targets) on the next start |
| Browser shows **404** on `localhost:5173` | The dashboard is now on **http://127.0.0.1:8000**; port 5173 is only used by the optional developer server |
| Page says "dashboard build was not found" | `frontend/dist` is missing. Re-extract the zip, or run `cd frontend && npm ci && npm run build` |
| `npm run dev` fails (developers) | Use Node 20 or newer; delete `frontend/node_modules` and run `npm ci` again |

---

## 13. Changelog (submission build)

- **Fixed false "suspected" results:** AUTH-001/002 now substitute real synthetic IDs into templated paths (`/api/orders/{order_id}` → `order-1001`) and send a schema-valid body to write endpoints. Before, they probed the literal template and got 404/422 noise.
- **Hardened the secure demo API:** authentication now runs before object lookup (removing a 404-vs-401 existence oracle), and the order schema uses `extra="forbid"` to block mass assignment (INPUT-005).
- **Added 6 regression tests** (34 → 40). The secure scan went from 37/44 PASS (73.1% remediation) to **44/44 PASS (100%)**.
- Added `frontend/src/vite-env.d.ts` so `npm run build` type-checks, plus macOS/Linux scripts and cross-platform setup docs.
- **The backend now serves the pre-built dashboard on port 8000.** Running the tool needs only Python, with no Node.js or separate dev server. This removes the Windows `localhost:5173` 404 issue.
- **Third-party benchmark:** bundled VAmPI with a loopback launcher, plus new generic scanner features: login-based auth profiles (real JWTs), resource-ID discovery, generic `{placeholder}` path templating, `{unique}` probe values and **verified** mass-assignment detection.
- **Fixed AUTH-004 false negatives:** the same template-path bug hid 3 real policy-drift findings on the vulnerable demo (33 → 36 confirmed). Also fixed AUTH-003 (it assumed the user is literally named "alice") and isolated the tests from the app database.
- **OWASP API Top 10 (2023) + CWE mapping** for all 17 checks, in the API, dashboard, Test Library and reports.
- **Detection accuracy evaluation** with source-code ground truth: 100% precision/recall over 125 verdicts; 3/4 in-scope VAmPI vulnerabilities.
- **GitHub Actions CI** (Windows + Linux, Python 3.12/3.13, dashboard build, end-to-end evaluation).
- **Fixed a redaction leak** found while collecting test evidence: password hashes and API keys survived inside the stored `response_preview` text. Now 0 secrets across 157 stored findings. Tests: 34 → 54.

---

## 14. Team & Contributions

| Name | Role | Contributions |
| :--- | :--- | :--- |
| _[Name]_ | Application Security | Check module design (Auth, BOLA, Input, Data Exposure), ScopeGuard, evidence redactor |
| _[Name]_ | Backend | FastAPI engine, request engine, SQLite persistence, OpenAPI parser, report generator |
| _[Name]_ | Frontend | React/TypeScript dashboard, charts, scan comparison |
| _[Name]_ | QA & Testing | Pytest suite, synthetic fixtures, automation scripts |

---

## 15. References

- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- MITRE CWE: https://cwe.mitre.org/ (CWE-20, 200, 213, 285, 287, 306, 639, 755, 862, 915, 1284, 1287)
- OWASP Application Security Verification Standard 4.0.3: https://owasp.org/www-project-application-security-verification-standard/
- VAmPI, the Vulnerable API (erev0s, MIT licence): https://github.com/erev0s/VAmPI
- RFC 6750: OAuth 2.0 Bearer Token Usage
- OpenAPI Specification 3.0.3: https://spec.openapis.org/oas/v3.0.3

## License
MIT, see [LICENSE](LICENSE). The bundled `third_party/VAmPI` is © erev0s under its own MIT licence (`third_party/VAmPI/LICENSE`). APIGuard's only change to it is a documented, opt-in database-path setting in `config.py`.
