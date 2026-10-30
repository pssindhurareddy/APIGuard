# Changes made by APIGuard to the bundled VAmPI

Source: https://github.com/erev0s/VAmPI (commit f16052d, MIT licence, see LICENSE).

1. `config.py`: the SQLite path can be overridden with the `VAMPI_DB_PATH`
   environment variable, so the vulnerable and secure instances run side by side
   with separate databases. Without the variable, behaviour is unchanged.
2. Removed Docker/GitHub CI files that are not needed here.
3. Dependencies are installed from `../requirements-vampi.txt`. Upstream pins
   SQLAlchemy 2.0.2, which does not run on Python 3.13.

No vulnerability logic was changed. Launch via `third_party/run_vampi.py`.
