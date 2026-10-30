"""Mapping of every APIGuard check to OWASP API Security Top 10 (2023) and CWE.

Used to enrich findings in the API, the dashboard and the HTML/JSON reports so
each result is traceable to a recognised industry taxonomy.
"""
from typing import Any

_OWASP = {
    "API1": ("API1:2023", "Broken Object Level Authorization",
             "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"),
    "API2": ("API2:2023", "Broken Authentication",
             "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"),
    "API3": ("API3:2023", "Broken Object Property Level Authorization",
             "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"),
    "API5": ("API5:2023", "Broken Function Level Authorization",
             "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"),
    "API8": ("API8:2023", "Security Misconfiguration",
             "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"),
    # Input validation is not a stand-alone API Top 10 (2023) category; it is
    # covered by the OWASP Application Security Verification Standard instead.
    "ASVS5": ("ASVS V5", "Validation, Sanitization and Encoding (OWASP ASVS 4.0.3)",
              "https://owasp.org/www-project-application-security-verification-standard/"),
}

_CWE = {
    20: "Improper Input Validation",
    200: "Exposure of Sensitive Information to an Unauthorized Actor",
    213: "Exposure of Sensitive Information Due to Incompatible Policies",
    285: "Improper Authorization",
    287: "Improper Authentication",
    306: "Missing Authentication for Critical Function",
    639: "Authorization Bypass Through User-Controlled Key",
    755: "Improper Handling of Exceptional Conditions",
    862: "Missing Authorization",
    915: "Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)",
    1284: "Improper Validation of Specified Quantity in Input",
    1287: "Improper Validation of Specified Type of Input",
}

CHECK_STANDARDS: dict[str, tuple[str, list[int]]] = {
    "AUTH-001": ("API2", [306]),
    "AUTH-002": ("API2", [287]),
    "AUTH-003": ("API2", [287]),
    "AUTH-004": ("API2", [306]),
    "AUTHZ-001": ("API1", [639, 862]),
    "AUTHZ-002": ("API5", [285]),
    "AUTHZ-003": ("API1", [639, 862]),
    "AUTHZ-004": ("API5", [285]),
    "INPUT-001": ("ASVS5", [20]),
    "INPUT-002": ("ASVS5", [1287]),
    "INPUT-003": ("ASVS5", [1284]),
    "INPUT-004": ("API8", [755]),
    "INPUT-005": ("API3", [915]),
    "DATA-001": ("API3", [200]),
    "DATA-002": ("API3", [213]),
    "DATA-003": ("API3", [200]),
    "DATA-004": ("API3", [213]),
}


def standards_for(test_id: str) -> dict[str, Any]:
    """Return {"owasp": {...}, "cwe": [...]} for a test ID (empty if unknown)."""
    entry = CHECK_STANDARDS.get(test_id)
    if not entry:
        return {"owasp": None, "cwe": []}
    key, cwes = entry
    owasp_id, owasp_name, url = _OWASP[key]
    return {
        "owasp": {"id": owasp_id, "name": owasp_name, "url": url},
        "cwe": [
            {"id": f"CWE-{n}", "name": _CWE[n], "url": f"https://cwe.mitre.org/data/definitions/{n}.html"}
            for n in cwes
        ],
    }


def enrich(finding: dict[str, Any]) -> dict[str, Any]:
    """Add the standards mapping to a finding dict in place and return it."""
    finding["standards"] = standards_for(finding.get("test_id", ""))
    return finding
