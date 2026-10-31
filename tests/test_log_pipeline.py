"""Tests for parsing and analyzing uploaded traffic log formats."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from analyzer import analyze_records  # noqa: E402
from parser import parse_csv_text, parse_json_logs  # noqa: E402

FAKE_API_KEY = "sk-test_FAKEKEY_9f3a21c8d4e5b607"
FAKE_EMAIL = "qa.bot@example.net"


def _analyze_json(text: str) -> list[dict[str, Any]]:
    return analyze_records(parse_json_logs(json.loads(text)), persist=False)


def test_events_envelope_runs_through_provider_scanner_and_risk_pipeline() -> None:
    upload = json.dumps(
        {
            "events": [
                {
                    "timestamp": "2026-10-31T00:00:00Z",
                    "provider": "OpenAI",
                    "application": "ChatGPT",
                    "request": {
                        "url": "https://api.openai.com/v1/chat/completions",
                        "body": {"prompt": f"email={FAKE_EMAIL} api_key={FAKE_API_KEY}"},
                    },
                },
                {
                    "timestamp": "2026-10-31T00:01:00Z",
                    "url": "https://api.anthropic.com/v1/messages",
                    "content": f"email={FAKE_EMAIL}; command=rm -rf /tmp/demo-workspace",
                },
                {
                    "timestamp": "2026-10-31T00:02:00Z",
                    "provider": "Google Gemini",
                    "host": "generativelanguage.googleapis.com",
                    "path": "/v1beta/models/gemini:generateContent",
                    "prompt": "Contact ABCDE1234F",
                },
            ]
        }
    )

    results = _analyze_json(upload)

    assert len(results) == 3
    assert sum(row["is_ai"] for row in results) == 3
    assert [row["provider"] for row in results] == ["openai", "anthropic", "gemini"]
    finding_types = [{finding["type"] for finding in row["findings"]} for row in results]
    assert {"email", "api_key"} <= finding_types[0]
    assert {"email", "shell_command"} <= finding_types[1]
    assert "pan" in finding_types[2]
    assert results[1]["score"] >= 60
    assert results[1]["risk_label"] == "High"
    assert FAKE_API_KEY not in json.dumps(results[0]["findings"])


def test_csv_upload_records_still_analyze() -> None:
    records = parse_csv_text(
        "timestamp,url,payload\n"
        f"2026-10-31T00:00:00Z,https://api.openai.com/v1/chat/completions,email={FAKE_EMAIL}\n"
    )

    results = analyze_records(records, persist=False)

    assert len(results) == 1
    assert results[0]["provider"] == "openai"
    assert "email" in {finding["type"] for finding in results[0]["findings"]}


def test_har_upload_records_still_analyze() -> None:
    upload = json.dumps(
        {
            "log": {
                "entries": [
                    {
                        "startedDateTime": "2026-10-31T00:00:00Z",
                        "request": {
                            "url": "https://api.anthropic.com/v1/messages",
                            "postData": {"text": json.dumps({"prompt": FAKE_EMAIL})},
                        },
                    }
                ]
            }
        }
    )

    results = _analyze_json(upload)

    assert len(results) == 1
    assert results[0]["provider"] == "anthropic"
    assert "email" in {finding["type"] for finding in results[0]["findings"]}
