"""Generate fictional mock HTTP traffic logs for the scanner project."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = ROOT / "data" / "sample_traffic.json"

CATEGORIES = (
    "normal_web",
    "clean_ai",
    "sensitive_ai",
    "risky_agent",
)

# Weighted mix so most traffic looks ordinary.
CATEGORY_WEIGHTS = (40, 25, 20, 15)

FAKE_EMAILS = (
    "alex.demo@example.com",
    "priya.test@example.org",
    "qa.bot@example.net",
)
FAKE_API_KEYS = (
    "sk-test_FAKEKEY_9f3a21c8d4e5b607",
    "ak_test_NOTREAL_88bbccdd1122eeff",
    "gsk_test_dummy_44aa55bb66cc77dd",
)
FAKE_AADHAAR = (
    "9999-1111-2222",
    "8888-0000-3333",
    "7777-2222-1111",
)


def _timestamp(index: int) -> str:
    start = datetime(2026, 10, 31, 0, 0, tzinfo=timezone.utc)
    return (start + timedelta(seconds=index * 37)).isoformat()


def _normal_web() -> tuple[str, str, dict]:
    samples = (
        ("GET", "https://www.example.com/home", {"path": "/home", "user_agent": "Mozilla/5.0"}),
        ("GET", "https://cdn.example.com/static/app.js", {"asset": "app.js"}),
        ("POST", "https://shop.example.com/api/cart", {"item_id": "SKU-1001", "qty": 1}),
        ("GET", "https://news.example.org/tech", {"section": "tech"}),
        ("POST", "https://weather.example.com/v1/forecast", {"city": "Hyderabad"}),
        ("PUT", "https://profile.example.com/settings", {"theme": "dark"}),
    )
    method, url, payload = random.choice(samples)
    return method, url, payload


def _clean_ai() -> tuple[str, str, dict]:
    samples = (
        (
            "POST",
            "https://api.openai.example.com/v1/chat/completions",
            {
                "model": "gpt-test",
                "messages": [{"role": "user", "content": "Summarize this public README."}],
            },
        ),
        (
            "POST",
            "https://api.anthropic.example.com/v1/messages",
            {
                "model": "claude-test",
                "messages": [{"role": "user", "content": "Explain HTTP status codes."}],
            },
        ),
        (
            "POST",
            "https://generativelanguage.example.com/v1/generate",
            {"prompt": "Write a polite meeting agenda for a student project."},
        ),
    )
    method, url, payload = random.choice(samples)
    return method, url, payload


def _sensitive_ai() -> tuple[str, str, dict]:
    email = random.choice(FAKE_EMAILS)
    api_key = random.choice(FAKE_API_KEYS)
    aadhaar = random.choice(FAKE_AADHAAR)
    prompt = (
        f"Store this fictional test record: email={email}, "
        f"api_key={api_key}, aadhaar={aadhaar}"
    )
    return (
        "POST",
        "https://api.openai.example.com/v1/chat/completions",
        {
            "model": "gpt-test",
            "messages": [{"role": "user", "content": prompt}],
        },
    )


def _risky_agent() -> tuple[str, str, dict]:
    samples = (
        (
            "POST",
            "https://agent.shadow-it.example.com/v1/run",
            {
                "tool": "shell",
                "command": "rm -rf /tmp/demo-workspace",
                "reason": "cleanup after fictional agent task",
            },
        ),
        (
            "POST",
            "https://agent.shadow-it.example.com/v1/files",
            {
                "action": "read",
                "path": "/app/.env",
                "note": "attempt to load local secrets file",
            },
        ),
        (
            "POST",
            "https://copilot.internal.example.com/tools/exec",
            {
                "command": "cat .env && rm -rf ./backup",
                "cwd": "/srv/demo-app",
            },
        ),
    )
    method, url, payload = random.choice(samples)
    return method, url, payload


BUILDERS = {
    "normal_web": _normal_web,
    "clean_ai": _clean_ai,
    "sensitive_ai": _sensitive_ai,
    "risky_agent": _risky_agent,
}


def generate_logs(count: int = 100) -> list[dict]:
    logs = []
    for i in range(count):
        category = random.choices(CATEGORIES, weights=CATEGORY_WEIGHTS, k=1)[0]
        method, url, payload = BUILDERS[category]()
        logs.append(
            {
                "timestamp": _timestamp(i),
                "url": url,
                "method": method,
                "category": category,
                "payload": payload,
            }
        )
    return logs


def main() -> None:
    random.seed(23)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    logs = generate_logs(100)
    OUTPUT_PATH.write_text(json.dumps(logs, indent=2), encoding="utf-8")
    print(f"Wrote {len(logs)} logs to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
