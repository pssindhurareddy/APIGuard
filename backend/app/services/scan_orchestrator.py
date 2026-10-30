"""Scan Orchestrator - coordinates test suites, safety scope, and persistence."""
import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from pathlib import Path

from .scope_guard import ScopeGuard, ScopeViolation
from .request_engine import RequestEngine
from .evidence_redactor import redact_evidence
from ..checks.registry import create_check, get_all_categories
from ..checks.base import CheckResult
from ..models.database import insert_row, update_row, fetch_one
from ..config import ScanConfig, CONFIG_DIR


class ScanOrchestrator:
    """Orchestrates security scans against targets with full scope compliance."""

    def __init__(self, scan_config: Optional[ScanConfig] = None):
        self.config = scan_config or ScanConfig()
        self._active_scans: dict[str, bool] = {}

    async def execute_scan(
        self,
        scan_id: str,
        target_dict: dict[str, Any],
        categories: list[str],
    ) -> dict[str, Any]:
        """Execute all configured checks for a scan run."""
        self._active_scans[scan_id] = True
        start_time = time.monotonic()
        started_at = datetime.now(timezone.utc).isoformat()

        # Transition status to RUNNING
        await update_row("scans", scan_id, {
            "status": "RUNNING",
            "started_at": started_at,
        })

        try:
            # 1. Resolve target configuration & endpoint policies
            target_config = self._build_target_config(target_dict)

            # 2. Instantiate ScopeGuard
            scope_guard = self._create_scope_guard(target_config)

            # 3. Instantiate RequestEngine
            engine = RequestEngine(
                scope_guard=scope_guard,
                timeout=self.config.timeout,
                max_response_size=self.config.max_response_size,
            )

            # 3b. Runtime context: log in auth profiles that use real credentials
            #     and discover per-user resource IDs (e.g. VAmPI book titles).
            await self._prepare_runtime_context(target_config, engine)

            # 4. Sequentially execute each selected security check category
            all_results: list[CheckResult] = []
            for category in categories:
                if not self._active_scans.get(scan_id, False):
                    # Scan was cancelled
                    break

                check = create_check(category, engine, target_config)
                if check is None:
                    continue

                try:
                    results = await check.run()
                    all_results.extend(results)
                except Exception as ex:
                    all_results.append(CheckResult(
                        test_id=f"{category.upper()}-ERR",
                        test_name=f"{category} check failure",
                        category=category,
                        endpoint="N/A",
                        http_method="N/A",
                        status="ERROR",
                        severity="INFO",
                        confidence="LOW",
                        actual_result=f"Execution error: {type(ex).__name__}: {str(ex)}",
                    ))

                # Paced delay between suites
                await asyncio.sleep(self.config.request_delay)

            # 5. Persist granular findings with evidence redaction
            counters = {"PASS": 0, "CONFIRMED": 0, "SUSPECTED": 0, "ERROR": 0, "SKIPPED": 0}
            now_iso = datetime.now(timezone.utc).isoformat()

            for result in all_results:
                counters[result.status] = counters.get(result.status, 0) + 1
                sanitized_evidence = redact_evidence(result.evidence) if result.evidence else {}

                finding_id = str(uuid.uuid4())
                await insert_row("findings", {
                    "id": finding_id,
                    "scan_id": scan_id,
                    "test_id": result.test_id,
                    "test_name": result.test_name,
                    "category": result.category,
                    "endpoint": result.endpoint,
                    "http_method": result.http_method,
                    "status": result.status,
                    "severity": result.severity,
                    "confidence": result.confidence,
                    "expected_result": result.expected_result,
                    "actual_result": result.actual_result,
                    "evidence": json.dumps(sanitized_evidence),
                    "explanation": result.explanation,
                    "remediation": result.remediation,
                    "impact": result.impact,
                    "preconditions": result.preconditions,
                    "limitations": result.limitations,
                    "fingerprint": result.fingerprint,
                    "finding_status": "OPEN" if result.status in ("CONFIRMED", "SUSPECTED") else "PASS",
                    "created_at": now_iso,
                })

            # 6. Finalize scan status and summary statistics
            duration_ms = int((time.monotonic() - start_time) * 1000)
            completed_at = datetime.now(timezone.utc).isoformat()

            summary = (
                f"Scan completed: {len(all_results)} tests executed. "
                f"{counters['PASS']} passed, {counters['CONFIRMED']} confirmed, "
                f"{counters['SUSPECTED']} suspected, {counters['ERROR']} errors, "
                f"{counters['SKIPPED']} skipped."
            )

            await update_row("scans", scan_id, {
                "status": "COMPLETED",
                "completed_at": completed_at,
                "total_tests": len(all_results),
                "passed": counters["PASS"],
                "confirmed": counters["CONFIRMED"],
                "suspected": counters["SUSPECTED"],
                "errors": counters["ERROR"],
                "skipped": counters["SKIPPED"],
                "duration_ms": duration_ms,
                "summary": summary,
            })

            # Update target record
            await update_row("targets", target_dict["id"], {
                "last_scan_id": scan_id,
                "last_scan_status": "COMPLETED",
                "updated_at": completed_at,
            })

            return {
                "scan_id": scan_id,
                "status": "COMPLETED",
                "total_tests": len(all_results),
                "counters": counters,
                "duration_ms": duration_ms,
                "summary": summary,
            }

        except Exception as e:
            err_msg = f"Scan aborted with error: {type(e).__name__}: {str(e)}"
            await update_row("scans", scan_id, {
                "status": "FAILED",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "summary": err_msg,
            })
            return {"scan_id": scan_id, "status": "FAILED", "error": err_msg}
        finally:
            self._active_scans.pop(scan_id, None)

    def _build_target_config(self, target: dict[str, Any]) -> dict[str, Any]:
        """Construct full target policy incorporating YAML definitions."""
        config = dict(target)

        # Deserialize JSON strings if needed
        for f in ("allowed_hosts", "allowed_ports", "allowed_paths", "allowed_methods", "auth_profiles"):
            if isinstance(config.get(f), str):
                try:
                    config[f] = json.loads(config[f])
                except Exception:
                    config[f] = [] if f != "auth_profiles" else {}

        # Merge with file-based policy specifications
        config["endpoint_policies"] = self._resolve_endpoint_policies(config)
        config["test_resources"] = self._resolve_test_resources(config)

        yaml_target = self._yaml_target(config)
        config["resource_discovery"] = yaml_target.get("resource_discovery", [])
        # Login settings live only in YAML (never in the DB); merge them in.
        yaml_profiles = yaml_target.get("auth_profiles", {}) or {}
        profiles = dict(config.get("auth_profiles") or {})
        for name, yprof in yaml_profiles.items():
            merged = dict(profiles.get(name, {}))
            for key, value in yprof.items():
                merged.setdefault(key, value)
            profiles[name] = merged
        config["auth_profiles"] = profiles
        return config

    def _yaml_target(self, target_config: dict[str, Any]) -> dict[str, Any]:
        """Return the config/demo_targets.yaml entry matching this target's base_url."""
        import yaml
        yaml_path = CONFIG_DIR / "demo_targets.yaml"
        if not yaml_path.exists():
            return {}
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            return {}
        for t in data.get("targets", []):
            if t.get("base_url", "").rstrip("/") == target_config.get("base_url", "").rstrip("/"):
                return t
        return {}

    async def _prepare_runtime_context(self, target_config: dict[str, Any], engine: RequestEngine) -> None:
        """Obtain real bearer tokens and discover resource IDs before checks run.

        * auth_profiles.<name>.login: {path, method, body, token_field}
          -> POSTs the credentials and stores the returned token on the profile.
        * resource_discovery: [{path, list_field, owner_field, value_field, resource_key}]
          -> lists objects and records, for each profile, the ID of an object it owns.
        All requests still pass through ScopeGuard via the request engine.
        """
        base = target_config.get("base_url", "").rstrip("/")
        profiles = target_config.get("auth_profiles") or {}

        for name, profile in profiles.items():
            login = profile.get("login")
            if not login:
                continue
            result = await engine.request(
                login.get("method", "POST"), base + login["path"], json_body=login.get("body", {})
            )
            token = None
            if result.success and isinstance(result.body, dict):
                token = _get_nested(result.body, login.get("token_field", "token"))
            if not token:
                status = result.status_code if result.success else result.error
                raise RuntimeError(
                    f"Login for auth profile '{name}' failed at {login['path']} ({status}). "
                    "Is the target running and are the credentials in config/demo_targets.yaml correct?"
                )
            profile["token"] = token

        resources = target_config.setdefault("test_resources", {})
        for rule in target_config.get("resource_discovery", []) or []:
            headers = {}
            token = (profiles.get(rule.get("auth_profile", "alice")) or {}).get("token")
            if token:
                headers["Authorization"] = f"Bearer {token}"
            result = await engine.request("GET", base + rule["path"], headers=headers)
            items = _get_nested(result.body, rule.get("list_field", "")) if result.success else None
            if not isinstance(items, list):
                raise RuntimeError(f"Resource discovery failed at {rule['path']}: unexpected response")
            for name, profile in profiles.items():
                owner = profile.get("username", name)
                for item in items:
                    if isinstance(item, dict) and item.get(rule["owner_field"]) == owner:
                        resources.setdefault(name, {})[rule["resource_key"]] = item.get(rule["value_field"])
                        break

    def _resolve_endpoint_policies(self, target_config: dict[str, Any]) -> list[dict[str, Any]]:
        """Load endpoint policies from config/demo_targets.yaml matching base_url."""
        import yaml
        yaml_path = CONFIG_DIR / "demo_targets.yaml"
        if yaml_path.exists():
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                targets = data.get("targets", [])
                for t in targets:
                    if t.get("base_url", "").rstrip("/") == target_config.get("base_url", "").rstrip("/"):
                        return t.get("endpoint_policies", [])
            except Exception:
                pass
        return []

    def _resolve_test_resources(self, target_config: dict[str, Any]) -> dict[str, Any]:
        """Load synthetic test resource IDs matching target."""
        import yaml
        yaml_path = CONFIG_DIR / "demo_targets.yaml"
        if yaml_path.exists():
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                targets = data.get("targets", [])
                for t in targets:
                    if t.get("base_url", "").rstrip("/") == target_config.get("base_url", "").rstrip("/"):
                        return t.get("test_resources", {})
            except Exception:
                pass
        return {}

    def _create_scope_guard(self, target_config: dict[str, Any]) -> ScopeGuard:
        """Instantiate ScopeGuard initialized with target parameters."""
        guard = ScopeGuard(
            allowed_hosts=target_config.get("allowed_hosts", ["127.0.0.1", "localhost"]),
            allowed_ports=[int(p) for p in target_config.get("allowed_ports", [8001, 8002])],
            allowed_paths=target_config.get("allowed_paths", ["/api/"]),
            allowed_methods=target_config.get("allowed_methods", ["GET", "POST", "PUT", "PATCH", "DELETE"]),
            require_loopback=True,
            is_authorized=bool(target_config.get("is_authorized", True)),
        )
        guard.set_max_requests(self.config.max_requests)
        return guard


def _get_nested(body: Any, dotted: str) -> Any:
    """Read a possibly nested field such as "data.token"; empty path returns body."""
    if not dotted:
        return body
    cur = body
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur
