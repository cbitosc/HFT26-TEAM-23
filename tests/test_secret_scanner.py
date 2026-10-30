"""Tests for secret scanning using only fictional identifiers."""

from __future__ import annotations

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from secret_scanner import (  # noqa: E402
    mask_secret,
    scan_payload,
    scan_record,
    scan_records,
    scan_text,
    shannon_entropy,
)

FAKE_EMAIL = "qa.bot@example.net"
FAKE_API_KEY = "sk-test_FAKEKEY_9f3a21c8d4e5b607"
FAKE_AWS_KEY = "AKIATEST0FAKE0KEY000"
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJmaWN0aW9uYWwtdXNlciIsImlhdCI6MX0."
    "testsignaturevalue00000000"
)
FAKE_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBFAKESECRETBLOCKFORTESTSNOTAREALKEY0001\n"
    "-----END RSA PRIVATE KEY-----"
)
FAKE_PHONE = "9876543210"
FAKE_CARD = "4111111111111111"
FAKE_AADHAAR = "9999-1111-2222"
FAKE_PAN = "ABCDE1234F"
FAKE_ENTROPY = "Xk9mP2qR7vN4wL8jT5yH3bC6dF1aZ0uS"


def _types(findings: list[dict]) -> set[str]:
    return {item["type"] for item in findings}


def test_empty_and_invalid_input_returns_no_findings() -> None:
    assert scan_text("") == []
    assert scan_text("   ") == []
    assert scan_text(None) == []
    assert scan_payload(None) == []
    assert scan_payload({}) == []
    assert scan_payload([]) == []
    assert scan_record(None) == []
    assert scan_record("not-a-record") == []
    assert scan_records(None) == []
    assert scan_records("bad") == []


def test_detects_api_key_aws_jwt_and_private_key() -> None:
    text = "\n".join([FAKE_API_KEY, FAKE_AWS_KEY, FAKE_JWT, FAKE_PRIVATE_KEY])
    found = _types(scan_text(text))
    assert {"api_key", "aws_access_key", "jwt", "private_key"} <= found


def test_detects_pii_patterns() -> None:
    text = f"email={FAKE_EMAIL} phone={FAKE_PHONE} aadhaar={FAKE_AADHAAR} pan={FAKE_PAN}"
    found = _types(scan_text(text))
    assert {"email", "phone", "aadhaar", "pan"} <= found


def test_detects_luhn_credit_card_and_rejects_invalid() -> None:
    valid = scan_text(f"card={FAKE_CARD}")
    assert "credit_card" in _types(valid)
    invalid = scan_text("card=4111111111111112")
    assert "credit_card" not in _types(invalid)


def test_entropy_flags_random_secret_but_not_plain_language() -> None:
    random_hits = scan_text(f"token={FAKE_ENTROPY}")
    assert "high_entropy" in _types(random_hits)
    assert shannon_entropy(FAKE_ENTROPY) >= 3.5
    ordinary = scan_text("Please summarize this public README for the student project.")
    assert ordinary == []


def test_nested_payload_and_normalized_record_are_scanned() -> None:
    payload = {
        "model": "gpt-test",
        "messages": [{"role": "user", "content": f"email={FAKE_EMAIL} api_key={FAKE_API_KEY}"}],
    }
    payload_hits = scan_payload(payload)
    assert {"email", "api_key"} <= _types(payload_hits)

    record_hits = scan_record({"payload": payload})
    assert {"email", "api_key"} <= _types(record_hits)

    scanned = scan_records([{"host": "api.openai.example.com", "payload": payload}])
    assert len(scanned) == 1
    assert "secrets" in scanned[0]
    assert {"email", "api_key"} <= _types(scanned[0]["secrets"])


def test_preview_is_masked_and_never_exposes_full_secret() -> None:
    secrets = {
        "api_key": FAKE_API_KEY,
        "email": FAKE_EMAIL,
        "credit_card": FAKE_CARD,
        "aws_access_key": FAKE_AWS_KEY,
        "jwt": FAKE_JWT,
        "private_key": FAKE_PRIVATE_KEY,
    }
    text = " ".join(secrets.values())
    findings = scan_text(text)
    assert findings
    for finding in findings:
        assert "preview" in finding
        assert "severity" in finding
        assert finding["preview"] != secrets.get(finding["type"], "")
        for raw in secrets.values():
            assert raw not in finding["preview"]
        assert "***" in finding["preview"]

    assert FAKE_EMAIL not in mask_secret(FAKE_EMAIL, "email")
    assert FAKE_API_KEY not in mask_secret(FAKE_API_KEY, "api_key")


def test_clean_sample_payload_has_no_secrets() -> None:
    findings = scan_payload(
        {
            "model": "gpt-test",
            "messages": [{"role": "user", "content": "Summarize this public README."}],
        }
    )
    assert findings == []
