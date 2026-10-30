"""Combine scanner findings into a 0-100 risk score and label."""

from __future__ import annotations

from typing import Any

from secret_scanner import SEVERITY as SECRET_SEVERITY

SECRET_TYPES = set(SECRET_SEVERITY)
SHELL_TYPES = {"shell_command"}
FILE_TYPES = {"sensitive_file"}
AGENT_TYPES = {"risky_agent"}

WEIGHTS = {
    "secret_leak": 40,
    "shell_command": 30,
    "sensitive_file": 30,
    "risky_agent": 10,
}


def risk_label(score: int) -> str:
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def _as_findings(findings: Any) -> list[dict[str, Any]]:
    if not findings:
        return []
    if isinstance(findings, dict):
        return [findings]
    if not isinstance(findings, list):
        return []
    return [item for item in findings if isinstance(item, dict)]


def score_findings(findings: Any) -> dict[str, Any]:
    """Score masked findings. Missing or empty input is Low / 0."""
    items = _as_findings(findings)
    categories: set[str] = set()
    for item in items:
        finding_type = str(item.get("type") or "")
        if finding_type in SECRET_TYPES:
            categories.add("secret_leak")
        elif finding_type in SHELL_TYPES:
            categories.add("shell_command")
        elif finding_type in FILE_TYPES:
            categories.add("sensitive_file")
        elif finding_type in AGENT_TYPES:
            categories.add("risky_agent")

    score = min(100, sum(WEIGHTS[name] for name in categories))
    return {
        "score": score,
        "risk_label": risk_label(score),
        "categories": sorted(categories),
    }
