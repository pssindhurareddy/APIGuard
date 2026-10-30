# APIGuard — Limitations & Disclosure for Evaluators

## 1. Prototype Scope and Boundaries

APIGuard is an academic cybersecurity and ethical hacking prototype created for university demonstration. To ensure responsible evaluation, the following operational limitations must be disclosed:

1. **Not a Full Web Application Scanner (DAST)**
   - APIGuard assesses specific REST API vulnerabilities: authentication gaps, BOLA authorization, schema input validation, and excessive data exposure.
   - It does not test for binary exploitation, memory corruption, blind SSRF, asynchronous webhook race conditions, or complex multi-step workflow business logic.

2. **Policy-Dependent Detection**
   - Certain checks (such as BOLA and response field allowlists) require declared endpoint policies or schema definitions (`config/demo_targets.yaml` or imported OpenAPI files).
   - The scanner does not autonomously infer business access rules without policy context.

3. **Non-Destructive by Design**
   - Destructive SQL injection (`DROP TABLE`), operating system command execution, and volumetric Denial of Service (DoS) attacks are deliberately excluded to prevent collateral damage.

4. **Synthetic Credentials & Identifiers**
   - The framework operates on configured synthetic user identities (Alice, Bob, Admin) and known test object IDs (`order-1001`, `order-1002`). It does not perform brute-force credential stuffing or unconstrained object ID enumeration.

5. **Loopback Containment by Default**
   - To safeguard local development environments, `ScopeGuard` strictly blocks public internet IP addresses by default, requiring explicit manual allowlist confirmation for any remote hosts.

6. **OpenAPI Compatibility**
   - OpenAPI parser supports standard OpenAPI 3.0 and Swagger 2.0 schemas. Advanced features such as XML payloads, file uploads (`multipart/form-data`), and dynamic discriminators are outside current prototype scope.


## Benchmark and evaluation scope (submission build)

- APIGuard is evaluated on 4 targets: its own demo API and the independent third-party
  VAmPI, each in a vulnerable and a hardened mode (`evaluation/`).
- Ground truth was labelled by the authors from the targets' source code; every positive
  cites the responsible code so it can be audited.
- Of VAmPI's 9 published vulnerabilities, 4 fall in APIGuard's scope and 3 are detected.
  The missed one (unauthorized password change) is a write-based BOLA; APIGuard only
  probes object reads to stay non-destructive. Injection, enumeration, ReDoS, rate
  limiting and JWT key attacks are out of scope by design.
