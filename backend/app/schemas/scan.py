"""Schemas for scan lifecycle, finding classifications, and test suites."""
from pydantic import BaseModel, Field
from typing import Optional, Any
from enum import Enum


class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class TestResult(str, Enum):
    PASS = "PASS"
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FIXED = "FIXED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class TestCategory(str, Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    DATA_EXPOSURE = "data_exposure"


class CreateScanRequest(BaseModel):
    target_id: str
    categories: list[str] = Field(
        default_factory=lambda: [
            "authentication",
            "authorization",
            "input_validation",
            "data_exposure",
        ]
    )
    auth_profile: Optional[str] = None


class ScanResponse(BaseModel):
    id: str
    target_id: str
    target_name: str
    target_url: str
    status: str
    categories: list[str]
    auth_profile: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    total_tests: int = 0
    passed: int = 0
    confirmed: int = 0
    suspected: int = 0
    errors: int = 0
    skipped: int = 0
    duration_ms: Optional[int] = None
    summary: Optional[str] = None
    created_at: str


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    test_id: str
    test_name: str
    category: str
    endpoint: str
    http_method: str
    status: str
    severity: str
    confidence: str
    expected_result: Optional[str] = None
    actual_result: Optional[str] = None
    evidence: Optional[Any] = None
    explanation: Optional[str] = None
    remediation: Optional[str] = None
    impact: Optional[str] = None
    preconditions: Optional[str] = None
    limitations: Optional[str] = None
    fingerprint: Optional[str] = None
    finding_status: str = "OPEN"
    created_at: str


class UpdateFindingRequest(BaseModel):
    finding_status: FindingStatus


class TestCaseInfo(BaseModel):
    id: str
    name: str
    category: str
    description: str
    why_it_matters: str
    preconditions: str
    success_criteria: str
    evidence_collected: str
    limitations: str

