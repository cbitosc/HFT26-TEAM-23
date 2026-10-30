"""Persist masked analysis results in a local SQLite audit database."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "audit.db"

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS audit_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT,
    app TEXT,
    host TEXT,
    port TEXT,
    path TEXT,
    is_ai INTEGER,
    provider TEXT,
    score INTEGER NOT NULL,
    risk_label TEXT NOT NULL,
    findings TEXT NOT NULL
)
"""

INSERT_SQL = """
INSERT INTO audit_requests (
    time, app, host, port, path, is_ai, provider, score, risk_label, findings
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

SELECT_SQL = """
SELECT id, time, app, host, port, path, is_ai, provider, score, risk_label, findings
FROM audit_requests
ORDER BY id ASC
"""


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return "[]"


def _masked_findings(findings: Any) -> list[dict[str, str]]:
    if not isinstance(findings, list):
        return []
    cleaned = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        cleaned.append(
            {
                "type": str(item.get("type") or "unknown"),
                "severity": str(item.get("severity") or "medium"),
                "preview": str(item.get("preview") or "***"),
            }
        )
    return cleaned


def init_db(db_path: str | Path | None = None) -> Path:
    path = Path(db_path) if db_path else DEFAULT_DB
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(CREATE_SQL)
        conn.commit()
    return path


def save_analysis(result: Any, db_path: str | Path | None = None) -> int | None:
    """Insert one analyzed request. Stores masked finding previews only."""
    if not isinstance(result, dict):
        return None
    path = init_db(db_path)
    findings_json = _safe_json(_masked_findings(result.get("findings")))
    values = (
        str(result.get("time") or ""),
        str(result.get("app") or ""),
        str(result.get("host") or ""),
        "" if result.get("port") is None else str(result.get("port")),
        str(result.get("path") or ""),
        1 if result.get("is_ai") else 0,
        None if result.get("provider") in (None, "") else str(result.get("provider")),
        int(result.get("score") or 0),
        str(result.get("risk_label") or "Low"),
        findings_json,
    )
    with sqlite3.connect(path) as conn:
        cursor = conn.execute(INSERT_SQL, values)
        conn.commit()
        return int(cursor.lastrowid)


def fetch_analyses(db_path: str | Path | None = None) -> list[dict[str, Any]]:
    path = init_db(db_path)
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(SELECT_SQL).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        try:
            item["findings"] = json.loads(item.get("findings") or "[]")
        except json.JSONDecodeError:
            item["findings"] = []
        item["is_ai"] = bool(item.get("is_ai"))
        results.append(item)
    return results
