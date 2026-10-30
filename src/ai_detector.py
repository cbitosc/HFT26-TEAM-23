"""Detect AI provider calls in normalized traffic records."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from parser import SAMPLE_PATH, parse_file

IGNORED_HOSTS = ("google.com", "www.google.com")

HOST_PROVIDERS = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "huggingface.co": "huggingface",
    "api.featherless.ai": "featherless",
}

PATH_PROVIDERS = {
    "/v1/chat/completions": "openai",
    "/v1/messages": "anthropic",
    "/api/generate": "ollama",
}

OLLAMA_PORT = 11434


def _host(record: dict[str, Any]) -> str:
    return str(record.get("host") or "").strip().lower().rstrip(".")


def _path(record: dict[str, Any]) -> str:
    raw = str(record.get("path") or "").strip()
    path = raw.split("?", 1)[0]
    if len(path) > 1:
        path = path.rstrip("/")
    return path or "/"


def _is_ignored_host(host: str) -> bool:
    return any(host == name or host.endswith("." + name) for name in IGNORED_HOSTS)


def _provider_from_host(host: str) -> str | None:
    for name, provider in HOST_PROVIDERS.items():
        if host == name or host.endswith("." + name):
            return provider
    return None


def _provider_from_path(path: str) -> str | None:
    for known, provider in PATH_PROVIDERS.items():
        if path == known or path.startswith(known + "/"):
            return provider
    return None


def detect_ai(record: dict[str, Any]) -> dict[str, Any]:
    """Return whether a normalized record is an AI call and which provider."""
    host = _host(record)
    if _is_ignored_host(host):
        return {"is_ai": False, "provider": None}

    port = record.get("port")
    try:
        port_num = int(port) if port is not None and port != "" else None
    except (TypeError, ValueError):
        port_num = None

    provider = None
    if port_num == OLLAMA_PORT:
        provider = "ollama"
    if provider is None:
        provider = _provider_from_host(host)
    if provider is None:
        provider = _provider_from_path(_path(record))

    return {"is_ai": provider is not None, "provider": provider}


def detect_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []
    for record in records:
        detection = detect_ai(record)
        results.append({**record, **detection})
    return results


def main() -> None:
    records = detect_records(parse_file(SAMPLE_PATH))
    ai_calls = [row for row in records if row.get("is_ai")]
    print(f"records={len(records)}")
    print(f"ai_calls={len(ai_calls)}")
    providers = {}
    for row in ai_calls:
        name = row.get("provider") or "unknown"
        providers[name] = providers.get(name, 0) + 1
    print("providers=" + json.dumps(providers, sort_keys=True))
    print(json.dumps(ai_calls, indent=2))


if __name__ == "__main__":
    main()
