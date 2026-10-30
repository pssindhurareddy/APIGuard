"""Pytest conftest to ensure backend is in sys.path."""
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
demo_dir = backend_dir.parent / "demo_api"
root_dir = backend_dir.parent

for p in (str(backend_dir), str(demo_dir), str(root_dir)):
    if p not in sys.path:
        sys.path.insert(0, p)



# Isolate tests from the real application database: every test run writes to a
# throwaway SQLite file, so the dashboard's backend/apiguard.db never fills up
# with "Test Target" rows or test scans.
import tempfile

from app.models import database as _database

_database.DB_FILE = str(Path(tempfile.mkdtemp(prefix="apiguard-test-")) / "apiguard_test.db")
