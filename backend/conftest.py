"""Pytest conftest for backend."""
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
demo_dir = backend_dir.parent / "demo_api"
root_dir = backend_dir.parent

for p in (str(backend_dir), str(demo_dir), str(root_dir)):
    if p not in sys.path:
        sys.path.insert(0, p)

