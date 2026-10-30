"""Pipeline tests for agent checks, scoring, analysis, and SQLite storage."""

from __future__ import annotations

import json
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from analyzer import analyze_request  # noqa: E402
from database import fetch_analyses  # noqa: E402
from risk_scorer import score_findings  # noqa: E402

FAKE_API_KEY = "sk-test_FAKEKEY_9f3a21c8d4e5b607"
FAKE_EMAIL = "qa.bot@example.net"


def _types(findings: list[dict]) -> set[str]:
    return {item["type"] for item in findings}


def test_normal_request_is_low_risk(tmp_path: Path) -> None:
    result = analyze_request(
        {
            "url": "https://www.example.com/home",
            "payload": {"path": "/home", "user_agent": "Mozilla/5.0"},
        },
        db_path=tmp_path / "audit.db",
    )
    assert result["findings"] == []
    assert result["score"] == 0
    assert result["risk_label"] == "Low"


def test_secret_leaking_request_scores_medium(tmp_path: Path) -> None:
    result = analyze_request(
        {
            "url": "https://api.openai.example.com/v1/chat/completions",
            "payload": {
                "model": "gpt-test",
                "messages": [
                    {
                        "role": "user",
                        "content": f"Store fictional email={FAKE_EMAIL} api_key={FAKE_API_KEY}",
                    }
                ],
            },
        },
        db_path=tmp_path / "audit.db",
    )
    assert "api_key" in _types(result["findings"])
    assert "secret_leak" in result["categories"]
    assert result["score"] == 40
    assert result["risk_label"] == "Medium"
    assert FAKE_API_KEY not in json.dumps(result["findings"])


def test_shell_command_request_scores_medium(tmp_path: Path) -> None:
    result = analyze_request(
        {
            "url": "https://agent.shadow-it.example.com/v1/run",
            "payload": {
                "tool": "shell",
                "command": "rm -rf /tmp/demo-workspace",
            },
        },
        db_path=tmp_path / "audit.db",
    )
    assert "shell_command" in _types(result["findings"])
    assert result["score"] == 30
    assert result["risk_label"] == "Medium"
    assert "rm -rf /tmp/demo-workspace" not in json.dumps(result["findings"])


def test_sensitive_file_request_scores_medium(tmp_path: Path) -> None:
    result = analyze_request(
        {
            "url": "https://agent.shadow-it.example.com/v1/files",
            "payload": {"action": "read", "path": "/app/.env"},
        },
        db_path=tmp_path / "audit.db",
    )
    assert "sensitive_file" in _types(result["findings"])
    assert result["score"] == 30
    assert result["risk_label"] == "Medium"


def test_risky_agent_user_agent_scores_low(tmp_path: Path) -> None:
    result = analyze_request(
        {
            "url": "https://tools.example.com/v1/run",
            "user_agent": "LangChain/0.2 AutoGPT-test",
            "payload": {"prompt": "Summarize this public README."},
        },
        db_path=tmp_path / "audit.db",
    )
    assert "risky_agent" in _types(result["findings"])
    assert result["score"] == 10
    assert result["risk_label"] == "Low"


def test_combined_score_caps_at_100_and_persists_masked_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    result = analyze_request(
        {
            "url": "https://agent.shadow-it.example.com/v1/run",
            "user_agent": "Cursor/1.0",
            "payload": {
                "command": "cat .env && rm -rf ./backup",
                "note": f"api_key={FAKE_API_KEY}",
            },
        },
        db_path=db_path,
    )
    assert result["score"] == 100
    assert result["risk_label"] == "High"
    assert FAKE_API_KEY not in json.dumps(result["findings"])

    rows = fetch_analyses(db_path)
    assert len(rows) == 1
    stored = rows[0]
    assert stored["score"] == 100
    assert stored["risk_label"] == "High"
    assert stored["findings"]
    blob = json.dumps(stored)
    assert FAKE_API_KEY not in blob
    assert "cat .env && rm -rf ./backup" not in blob
    assert "payload" not in stored


def test_empty_and_invalid_input_is_safe(tmp_path: Path) -> None:
    db_path = tmp_path / "audit.db"
    empty = analyze_request(None, db_path=db_path)
    assert empty["score"] == 0
    assert empty["risk_label"] == "Low"
    assert empty["findings"] == []

    missing = analyze_request({"payload": None}, db_path=db_path, persist=False)
    assert missing["score"] == 0
    assert score_findings(None)["score"] == 0
    assert score_findings([])["risk_label"] == "Low"
