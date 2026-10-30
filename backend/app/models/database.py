"""SQLite database storage layer for APIGuard scanner.

Persists targets, scan runs, and granular findings.
Ensures zero secret leakage: auth tokens and raw sensitive credentials
are NEVER stored in findings or persistent scan records.
"""
import aiosqlite
import json
from pathlib import Path
from typing import Any, Optional
from ..config import DB_PATH

DB_FILE = str(DB_PATH)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    base_url TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'demo',
    allowed_hosts TEXT NOT NULL DEFAULT '[]',
    allowed_ports TEXT NOT NULL DEFAULT '[]',
    allowed_paths TEXT NOT NULL DEFAULT '[]',
    allowed_methods TEXT NOT NULL DEFAULT '[]',
    is_authorized INTEGER NOT NULL DEFAULT 0,
    auth_profiles TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_scan_id TEXT,
    last_scan_status TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    target_name TEXT NOT NULL,
    target_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'QUEUED',
    categories TEXT NOT NULL DEFAULT '[]',
    auth_profile TEXT,
    started_at TEXT,
    completed_at TEXT,
    total_tests INTEGER NOT NULL DEFAULT 0,
    passed INTEGER NOT NULL DEFAULT 0,
    confirmed INTEGER NOT NULL DEFAULT 0,
    suspected INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    skipped INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER,
    summary TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    test_id TEXT NOT NULL,
    test_name TEXT NOT NULL,
    category TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    http_method TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    expected_result TEXT,
    actual_result TEXT,
    evidence TEXT,
    explanation TEXT,
    remediation TEXT,
    impact TEXT,
    preconditions TEXT,
    limitations TEXT,
    fingerprint TEXT,
    finding_status TEXT NOT NULL DEFAULT 'OPEN',
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id);
"""


async def get_db() -> aiosqlite.Connection:
    """Acquire database connection with WAL mode and foreign keys enabled."""
    db = await aiosqlite.connect(DB_FILE)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


async def init_db() -> None:
    """Initialize database tables and indexes."""
    Path(DB_FILE).parent.mkdir(parents=True, exist_ok=True)
    db = await get_db()
    try:
        await db.executescript(SCHEMA_SQL)
        await db.commit()
    finally:
        await db.close()


async def insert_row(table: str, data: dict[str, Any]) -> None:
    """Insert a dictionary into the specified table."""
    cols = ", ".join(data.keys())
    placeholders = ", ".join(["?"] * len(data))
    values = []
    for v in data.values():
        if isinstance(v, (dict, list)):
            values.append(json.dumps(v))
        elif isinstance(v, bool):
            values.append(int(v))
        else:
            values.append(v)
    db = await get_db()
    try:
        await db.execute(f"INSERT INTO {table} ({cols}) VALUES ({placeholders})", values)
        await db.commit()
    finally:
        await db.close()


async def update_row(table: str, row_id: str, data: dict[str, Any]) -> None:
    """Update a row matching primary key id."""
    sets = ", ".join([f"{k} = ?" for k in data.keys()])
    values = []
    for v in data.values():
        if isinstance(v, (dict, list)):
            values.append(json.dumps(v))
        elif isinstance(v, bool):
            values.append(int(v))
        else:
            values.append(v)
    values.append(row_id)
    db = await get_db()
    try:
        await db.execute(f"UPDATE {table} SET {sets} WHERE id = ?", values)
        await db.commit()
    finally:
        await db.close()


async def fetch_one(table: str, row_id: str) -> Optional[dict[str, Any]]:
    """Retrieve a single row by id."""
    db = await get_db()
    try:
        cursor = await db.execute(f"SELECT * FROM {table} WHERE id = ?", [row_id])
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)
    finally:
        await db.close()


async def fetch_all(
    table: str,
    where: str = "",
    params: Optional[list[Any]] = None,
    order_by: str = "created_at DESC"
) -> list[dict[str, Any]]:
    """Retrieve multiple rows with optional query clause."""
    query = f"SELECT * FROM {table}"
    if where:
        query += f" WHERE {where}"
    query += f" ORDER BY {order_by}"
    db = await get_db()
    try:
        cursor = await db.execute(query, params or [])
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()

