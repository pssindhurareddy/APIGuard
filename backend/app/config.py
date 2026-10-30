"""Application configuration for APIGuard scanner backend."""
from pathlib import Path
from pydantic import BaseModel

# Base paths
APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent
DB_PATH = BACKEND_DIR / "apiguard.db"
REPORTS_DIR = PROJECT_ROOT / "reports"
TEMPLATES_DIR = APP_DIR / "templates"
CONFIG_DIR = PROJECT_ROOT / "config"

# Safe scanning constraints
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_REQUESTS_PER_SCAN = 200
DEFAULT_MAX_RESPONSE_SIZE = 1_048_576  # 1 MB
DEFAULT_CONCURRENT_REQUESTS = 4
DEFAULT_REQUEST_DELAY = 0.05

# Target Scope constraints
ALLOWED_SCHEMES = {"http", "https"}
LOOPBACK_ADDRESSES = {"127.0.0.1", "::1"}
LOOPBACK_HOSTNAMES = {"localhost"}


class ScanConfig(BaseModel):
    """Scan execution configuration parameters."""
    timeout: float = DEFAULT_TIMEOUT
    max_requests: int = DEFAULT_MAX_REQUESTS_PER_SCAN
    max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE
    concurrent_requests: int = DEFAULT_CONCURRENT_REQUESTS
    request_delay: float = DEFAULT_REQUEST_DELAY

