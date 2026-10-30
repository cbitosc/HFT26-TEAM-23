"""Run the full Shadow IT analysis pipeline and persist masked results."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from agent_checker import check_record
from ai_detector import detect_ai
from database import DEFAULT_DB, fetch_analyses, save_analysis
from parser import SAMPLE_PATH, normalize_record, parse_file
from risk_scorer import score_findings
from secret_scanner import scan_record

STANDARD_KEYS = {"time", "app", "host", "port", "path", "payload"}


def _empty_result() -> dict[str, Any]:
    scored = score_findings([])
    return {
        "time": "",
        "app": "unknown",
        "host": "",
        "port": None,
        "path": "/",
        "payload": {},
        "is_ai": False,
        "provider": None,
        "findings": [],
        "score": scored["score"],
        "risk_label": scored["risk_label"],
        "categories": scored["categories"],
    }


def _copy_request_extras(raw: dict[str, Any]) -> dict[str, Any]:
    extras: dict[str, Any] = {}
    user_agent = raw.get("user_agent") or raw.get("user-agent")
    if user_agent:
        extras["user_agent"] = user_agent
    if raw.get("headers") is not None:
        extras["headers"] = raw["headers"]
    return extras


def _ensure_record(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    extras = _copy_request_extras(raw)
    if STANDARD_KEYS.issubset(raw) and "url" not in raw:
        return {**raw, **extras}
    record = normalize_record(raw)
    if record is None:
        return None
    return {**record, **extras}


def analyze_request(
    raw: Any,
    db_path: str | Path | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Analyze one request, score it, and optionally save masked results."""
    record = _ensure_record(raw)
    if record is None:
        result = _empty_result()
        if persist:
            save_analysis(result, db_path or DEFAULT_DB)
        return result

    detection = detect_ai(record)
    findings = scan_record(record) + check_record(record)
    scored = score_findings(findings)
    result = {
        "time": record.get("time") or "",
        "app": record.get("app") or "unknown",
        "host": record.get("host") or "",
        "port": record.get("port"),
        "path": record.get("path") or "/",
        "payload": record.get("payload") if isinstance(record.get("payload"), (dict, list, str)) else {},
        "is_ai": bool(detection.get("is_ai")),
        "provider": detection.get("provider"),
        "findings": findings,
        "score": scored["score"],
        "risk_label": scored["risk_label"],
        "categories": scored["categories"],
    }
    if persist:
        save_analysis(result, db_path or DEFAULT_DB)
    return result


def analyze_records(
    records: Any,
    db_path: str | Path | None = None,
    persist: bool = True,
) -> list[dict[str, Any]]:
    if not isinstance(records, list):
        return []
    return [analyze_request(item, db_path=db_path, persist=persist) for item in records]


def analyze_file(
    path: str | Path,
    db_path: str | Path | None = None,
    persist: bool = True,
) -> list[dict[str, Any]]:
    return analyze_records(parse_file(path), db_path=db_path, persist=persist)


def main() -> None:
    results = analyze_file(SAMPLE_PATH, persist=True)
    labels: dict[str, int] = {}
    for row in results:
        name = row.get("risk_label") or "Low"
        labels[name] = labels.get(name, 0) + 1
    print(f"records={len(results)}")
    print("labels=" + json.dumps(labels, sort_keys=True))
    stored = fetch_analyses()
    print(f"audit_rows={len(stored)}")
    sample = [
        {
            "host": row.get("host"),
            "score": row.get("score"),
            "risk_label": row.get("risk_label"),
            "findings": row.get("findings"),
        }
        for row in results
        if row.get("findings")
    ][:5]
    print(json.dumps(sample, indent=2))


if __name__ == "__main__":
    main()
