"""Global pytest configuration adding backend and demo_api to sys.path."""
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
backend_dir = root / "backend"
demo_dir = root / "demo_api"

for p in (str(backend_dir), str(demo_dir), str(root)):
    if p not in sys.path:
        sys.path.insert(0, p)

