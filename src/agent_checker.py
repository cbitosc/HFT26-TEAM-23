"""Detect risky agent behavior in normalized traffic records."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from secret_scanner import mask_secret, payload_to_text

SEVERITY = {
    "shell_command": "high",
    "sensitive_file": "high",
    "risky_agent": "medium",
}

_SHELL_RE = re.compile(
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\b[^\n;|&]*"
    r"|\brm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\b[^\n;|&]*"
    r"|\bcat\s+[^\n;|&]+"
    r"|\bchmod\s+[^\n;|&]+"
    r"|\bchown\s+[^\n;|&]+"
    r"|\bsudo\s+[^\n;|&]+"
    r"|\b(?:curl|wget)\b[^\n]*\|\s*(?:sh|bash|zsh)\b"
    r"|\bpowershell\b[^\n;|&]*"
    r"|\binvoke-webrequest\b[^\n;|&]*"
    r"|\bcmd\.exe\b[^\n;|&]*"
    r"|/bin/(?:ba)?sh\b[^\n;|&]*"
    r"|\bnc\s+-[a-zA-Z]*e[a-zA-Z]*\b[^\n;|&]*"
    r"|:\(\)\s*\{\s*:\|:&\s*\};:",
    re.IGNORECASE,
)

_SENSITIVE_FILE_RE = re.compile(
    r"(?:^|[\s'\"=:`])((?:[\w./\\-]*?)(?:\.env(?:\.\w+)?|id_rsa|id_ed25519|"
    r"id_dsa|credentials(?:\.json)?|secrets?\.(?:json|ya?ml|env)|"
    r"\.netrc|kubeconfig|[\w./\\-]*\.pem)(?:\b|$))",
    re.IGNORECASE,
)

_RISKY_AGENT_RE = re.compile(
    r"\b(?:cursor|autogpt|auto-gpt|langchain|langgraph|crewai)\b",
    re.IGNORECASE,
)

_PATTERN_RULES = (
    ("shell_command", _SHELL_RE),
    ("sensitive_file", _SENSITIVE_FILE_RE),
    ("risky_agent", _RISKY_AGENT_RE),
)


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _headers_text(headers: Any) -> str:
    if isinstance(headers, dict):
        parts = []
        for key, value in headers.items():
            parts.append(f"{key}: {value}")
        return "\n".join(parts)
    if isinstance(headers, list):
        parts = []
        for item in headers:
            if isinstance(item, dict):
                parts.append(_as_text(item.get("name") or item.get("key")) + ": " + _as_text(item.get("value")))
            else:
                parts.append(_as_text(item))
        return "\n".join(parts)
    return _as_text(headers)


def record_to_text(record: Any) -> str:
    if not isinstance(record, dict):
        return payload_to_text(record)
    chunks = [
        payload_to_text(record.get("payload")),
        _as_text(record.get("user_agent") or record.get("user-agent")),
        _headers_text(record.get("headers")),
        _as_text(record.get("host")),
        _as_text(record.get("path")),
        _as_text(record.get("app")),
    ]
    return "\n".join(chunk for chunk in chunks if chunk)


def _finding(finding_type: str, value: str) -> dict[str, str]:
    preview_type = "private_key" if finding_type == "sensitive_file" and "PRIVATE KEY" in value.upper() else ""
    return {
        "type": finding_type,
        "severity": SEVERITY.get(finding_type, "medium"),
        "preview": mask_secret(value, preview_type),
    }


def check_text(text: Any) -> list[dict[str, str]]:
    """Return agent-risk findings for a string. Invalid input yields no findings."""
    if text is None:
        return []
    if not isinstance(text, str):
        try:
            text = payload_to_text(text)
        except Exception:
            return []
    if not text.strip():
        return []

    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for finding_type, pattern in _PATTERN_RULES:
        for match in pattern.finditer(text):
            value = (match.group(1) if match.lastindex else match.group(0)).strip()
            if not value:
                continue
            key = (finding_type, value.lower())
            if key in seen:
                continue
            seen.add(key)
            findings.append(_finding(finding_type, value))
    return findings


def check_payload(payload: Any) -> list[dict[str, str]]:
    if payload in ("", None, {}, []):
        return []
    try:
        return check_text(payload_to_text(payload))
    except Exception:
        return []


def check_record(record: Any) -> list[dict[str, str]]:
    """Scan a normalized record for shell, file, and risky-agent signals."""
    if not isinstance(record, dict):
        return []
    try:
        return check_text(record_to_text(record))
    except Exception:
        return []


def check_records(records: Any) -> list[dict[str, Any]]:
    if not isinstance(records, list):
        return []
    results = []
    for record in records:
        if not isinstance(record, dict):
            continue
        results.append({**record, "agent_findings": check_record(record)})
    return results
