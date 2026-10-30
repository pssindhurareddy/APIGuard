"""Launch the bundled VAmPI third-party target on the loopback interface.

Usage (from the project root):
    python third_party/run_vampi.py --mode vulnerable --port 8003
    python third_party/run_vampi.py --mode secure     --port 8004

VAmPI (https://github.com/erev0s/VAmPI, MIT licence) is an independent,
deliberately vulnerable REST API. APIGuard uses it as an external benchmark that
was not written by the APIGuard authors. Each mode gets its own SQLite file.
"""
import argparse
import os
import sys
from pathlib import Path

VAMPI_DIR = Path(__file__).resolve().parent / "VAmPI"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run VAmPI for APIGuard")
    parser.add_argument("--mode", choices=["vulnerable", "secure"], default="vulnerable")
    parser.add_argument("--port", type=int, default=8003)
    args = parser.parse_args()

    # VAmPI reads these at import time.
    os.environ["vulnerable"] = "1" if args.mode == "vulnerable" else "0"
    os.environ.setdefault("tokentimetolive", "600")  # 10-minute JWTs (VAmPI default: 60 s)
    db_dir = VAMPI_DIR / "database"
    db_dir.mkdir(exist_ok=True)
    os.environ["VAMPI_DB_PATH"] = str(db_dir / f"vampi_{args.mode}.db")

    os.chdir(VAMPI_DIR)
    sys.path.insert(0, str(VAMPI_DIR))

    from config import vuln_app  # noqa: E402  (VAmPI's own Connexion app)
    import app as _vampi_app  # noqa: F401,E402  (registers vuln/alive globals)

    # Populate the database on start-up so the target is immediately scannable.
    # VAmPI assigns random book titles (bookTitle0-99) that must be unique, so the
    # seed step can occasionally collide; retry until it succeeds.
    with vuln_app.app.app_context():
        from api_views.main import populate_db  # noqa: E402
        from config import db  # noqa: E402
        for attempt in range(20):
            try:
                populate_db()
                break
            except Exception:
                db.session.rollback()
        else:
            raise SystemExit("Could not initialise the VAmPI database")

    print(f"VAmPI ({args.mode}) listening on http://127.0.0.1:{args.port}")
    vuln_app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
