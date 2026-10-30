"""Normalize JSON, HAR, and CSV traffic logs into a standard record format."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_PATH = ROOT / "data" / "sample_traffic.json"

STANDARD_FIELDS = ("time", "app", "host", "port", "path", "payload")


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _default_port(scheme: str, port: Any) -> int | None:
    if port in (None, ""):
        if scheme == "https":
            return 443
        if scheme == "http":
            return 80
        return None
    try:
        return int(port)
    except (TypeError, ValueError):
        return None


def _infer_app(host: str, extra: dict[str, Any] | None = None) -> str:
    extra = extra or {}
    explicit = _as_text(extra.get("app"))
    if explicit:
        return explicit

    host_l = host.lower()
    category = _as_text(extra.get("category")).lower()
    if "openai" in host_l:
        return "openai"
    if "anthropic" in host_l:
        return "anthropic"
    if "generativelanguage" in host_l or "gemini" in host_l:
        return "gemini"
    if "agent" in host_l or "copilot" in host_l or category == "risky_agent":
        return "agent"
    if category in {"clean_ai", "sensitive_ai"}:
        return "ai"
    if category == "normal_web":
        return "browser"
    if host:
        return host.split(".")[0]
    return "unknown"


def _parse_payload(value: Any) -> Any:
    if value is None:
        return {}
    if isinstance(value, (dict, list)):
        return value
    text = _as_text(value)
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}
    return parsed


def normalize_record(raw: Any) -> dict[str, Any] | None:
    """Convert one log object into the standard scanner record."""
    if not isinstance(raw, dict):
        return None

    url = _as_text(raw.get("url") or raw.get("request_url"))
    host = _as_text(raw.get("host") or raw.get("hostname"))
    path = _as_text(raw.get("path"))
    port = raw.get("port")
    scheme = ""
    time_value = raw.get("time") or raw.get("timestamp") or raw.get("startedDateTime") or ""

    if url:
        try:
            parsed_url = urlparse(url)
        except ValueError:
            parsed_url = urlparse("")
        scheme = parsed_url.scheme
        host = host or (parsed_url.hostname or "")
        if not path and (parsed_url.scheme or parsed_url.netloc):
            path = parsed_url.path or "/"
            if parsed_url.query:
                path = f"{path}?{parsed_url.query}"
        if port in (None, ""):
            port = parsed_url.port

    payload = raw.get("payload")
    if payload is None:
        payload = raw.get("postData") or raw.get("body") or raw.get("content") or {}

    return {
        "time": _as_text(time_value),
        "app": _infer_app(host, raw),
        "host": host,
        "port": _default_port(scheme, port),
        "path": path or "/",
        "payload": _parse_payload(payload),
    }


def _from_har_entry(entry: Any) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        return None
    request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
    post_data = request.get("postData") if isinstance(request.get("postData"), dict) else {}
    return normalize_record(
        {
            "timestamp": entry.get("startedDateTime"),
            "url": request.get("url"),
            "payload": post_data.get("text") or post_data.get("params") or {},
            "app": "browser",
        }
    )


def parse_json_logs(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict) and isinstance(data.get("log"), dict):
        entries = data["log"].get("entries") or []
        return [row for row in (_from_har_entry(item) for item in entries) if row]

    if isinstance(data, dict) and "entries" in data:
        return [row for row in (_from_har_entry(item) for item in data.get("entries") or []) if row]

    rows: Any
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("logs") or data.get("records") or [data]
    else:
        return []

    parsed = []
    for item in rows:
        record = normalize_record(item)
        if record:
            parsed.append(record)
    return parsed


def parse_csv_text(text: str) -> list[dict[str, Any]]:
    try:
        reader = csv.DictReader(io.StringIO(text))
    except csv.Error:
        return []
    parsed = []
    for row in reader:
        if not isinstance(row, dict):
            continue
        cleaned = {(_as_text(k).lower() if k else ""): v for k, v in row.items()}
        record = normalize_record(cleaned)
        if record:
            parsed.append(record)
    return parsed


def parse_file(path: str | Path) -> list[dict[str, Any]]:
    file_path = Path(path)
    try:
        raw_text = file_path.read_text(encoding="utf-8")
    except OSError:
        return []

    suffix = file_path.suffix.lower()
    if suffix == ".csv":
        return parse_csv_text(raw_text)
    if suffix in {".har", ".json"}:
        try:
            data = json.loads(raw_text) if raw_text.strip() else []
        except json.JSONDecodeError:
            return parse_csv_text(raw_text) if suffix == ".json" else []
        if suffix == ".har":
            if isinstance(data, dict):
                return parse_json_logs(data)
            return []
        return parse_json_logs(data)

    try:
        return parse_json_logs(json.loads(raw_text))
    except json.JSONDecodeError:
        return parse_csv_text(raw_text)


def main() -> None:
    records = parse_file(SAMPLE_PATH)
    print(len(records))
    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
