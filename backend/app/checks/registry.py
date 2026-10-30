"""Security Check Registry and Factory."""
from typing import Any, Optional
from .base import BaseCheck
from .authentication import AuthenticationCheck
from .authorization import AuthorizationCheck
from .input_validation import InputValidationCheck
from .data_exposure import DataExposureCheck

CHECK_REGISTRY: dict[str, type[BaseCheck]] = {
    "authentication": AuthenticationCheck,
    "authorization": AuthorizationCheck,
    "input_validation": InputValidationCheck,
    "data_exposure": DataExposureCheck,
}


def get_check_class(category: str) -> Optional[type[BaseCheck]]:
    """Retrieve check class for given category."""
    return CHECK_REGISTRY.get(category)


def get_all_categories() -> list[str]:
    """Retrieve list of all active check categories."""
    return list(CHECK_REGISTRY.keys())


def create_check(category: str, request_engine: Any, target_config: dict[str, Any]) -> Optional[BaseCheck]:
    """Instantiate a security check module for a specific target."""
    cls = get_check_class(category)
    if cls is None:
        return None
    return cls(request_engine, target_config)

