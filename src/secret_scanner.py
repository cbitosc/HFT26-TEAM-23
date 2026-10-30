"""Detect sensitive values in HTTP request payloads without exposing them."""

from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from parser import SAMPLE_PATH, parse_file

SEVERITY = {
    "private_key": "critical",
    "aws_access_key": "critical",
    "credit_card": "critical",
    "api_key": "high",
    "jwt": "high",
    "aadhaar": "high",
    "pan": "high",
    "email": "medium",
    "phone": "medium",
    "high_entropy": "medium",
}

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----",
    re.DOTALL,
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_API_KEY_RE = re.compile(
    r"\b(?:sk|ak|gsk|pk|rk|xox[baprs])[-_][A-Za-z0-9_-]{12,}\b"
    r"|\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}\b"
    r"|\bAIza[0-9A-Za-z_-]{20,}\b",
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b|\+\d{1,3}[\s-][6-9]\d{9}\b")
_AADHAAR_RE = re.compile(r"\b\d{4}[\s-]\d{4}[\s-]\d{4}\b|\b\d{12}\b")
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-.]{20,}")

_COMMON_TOKEN_MARKERS = (
    "http://",
    "https://",
    "mozilla",
    "example.com",
    "example.org",
    "example.net",
    "text/html",
    "application/json",
)

_PATTERN_RULES = (
    ("private_key", _PRIVATE_KEY_RE),
    ("jwt", _JWT_RE),
    ("aws_access_key", _AWS_KEY_RE),
    ("api_key", _API_KEY_RE),
    ("email", _EMAIL_RE),
    ("phone", _PHONE_RE),
    ("pan", _PAN_RE),
    ("aadhaar", _AADHAAR_RE),
    ("credit_card", _CARD_RE),
)


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _collect_strings(value: Any, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
        return
    if isinstance(value, dict):
        for item in value.values():
            _collect_strings(item, out)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _collect_strings(item, out)
        return
    if isinstance(value, (bool, type(None))):
        return
    out.append(str(value))


def payload_to_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    strings: list[str] = []
    _collect_strings(payload, strings)
    if strings:
        return "\n".join(strings)
    try:
        return json.dumps(payload)
    except (TypeError, ValueError):
        return _as_text(payload)


def _luhn_ok(digits: str) -> bool:
    if not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        number = ord(char) - 48
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def _is_valid_match(secret_type: str, value: str) -> bool:
    if secret_type == "credit_card":
        digits = re.sub(r"\D", "", value)
        if len(digits) < 13 or len(digits) > 19:
            return False
        if len(set(digits)) == 1:
            return False
        return _luhn_ok(digits)
    if secret_type == "aadhaar":
        digits = re.sub(r"\D", "", value)
        return len(digits) == 12 and not digits.startswith("0000")
    if secret_type == "phone":
        digits = re.sub(r"\D", "", value)
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        return len(digits) == 10 and digits[0] in "6789"
    return True


def mask_secret(value: str, secret_type: str = "") -> str:
    text = " ".join(_as_text(value).split())
    if not text:
        return "***"
    if secret_type == "email" and "@" in text:
        local, _, domain = text.partition("@")
        prefix = local[:1] if local else "*"
        return f"{prefix}***@{domain}"
    if secret_type == "private_key":
        return "-----BEGIN *** PRIVATE KEY-----"
    length = len(text)
    if length <= 4:
        return text[:1] + "***"
    if length <= 10:
        return text[:2] + "***" + text[-1:]
    return text[:4] + "***" + text[-2:]


def _finding(secret_type: str, value: str) -> dict[str, str]:
    preview = mask_secret(value, secret_type)
    return {
        "type": secret_type,
        "severity": SEVERITY.get(secret_type, "medium"),
        "preview": preview,
    }


def _overlaps(start: int, end: int, used: list[tuple[int, int]]) -> bool:
    for used_start, used_end in used:
        if start < used_end and end > used_start:
            return True
    return False


def shannon_entropy(value: str) -> float:
    text = _as_text(value)
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_common_token(token: str) -> bool:
    lower = token.lower()
    if any(marker in lower for marker in _COMMON_TOKEN_MARKERS):
        return True
    if token.replace(".", "").replace("-", "").isalpha():
        return True
    letters = sum(char.isalpha() for char in token)
    digits = sum(char.isdigit() for char in token)
    if letters == 0 or digits == 0:
        return True
    return False


def _high_entropy_findings(text: str, used: list[tuple[int, int]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for match in _ENTROPY_TOKEN_RE.finditer(text):
        if _overlaps(match.start(), match.end(), used):
            continue
        token = match.group(0).strip(".-_")
        if len(token) < 20:
            continue
        if _looks_common_token(token):
            continue
        if shannon_entropy(token) < 3.5:
            continue
        findings.append(_finding("high_entropy", token))
        used.append((match.start(), match.end()))
    return findings


def scan_text(text: Any) -> list[dict[str, str]]:
    """Scan a string for secrets and PII. Invalid input yields no findings."""
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
    used: list[tuple[int, int]] = []
    seen: set[tuple[str, str]] = set()

    for secret_type, pattern in _PATTERN_RULES:
        for match in pattern.finditer(text):
            value = match.group(0)
            if not _is_valid_match(secret_type, value):
                continue
            if _overlaps(match.start(), match.end(), used):
                continue
            key = (secret_type, value)
            if key in seen:
                used.append((match.start(), match.end()))
                continue
            seen.add(key)
            used.append((match.start(), match.end()))
            findings.append(_finding(secret_type, value))

    findings.extend(_high_entropy_findings(text, used))
    return findings


def scan_payload(payload: Any) -> list[dict[str, str]]:
    """Scan a request payload (string, dict, list, or other JSON-like value)."""
    if payload in ("", None, {}, []):
        return []
    try:
        return scan_text(payload_to_text(payload))
    except Exception:
        return []


def scan_record(record: Any) -> list[dict[str, str]]:
    """Scan the payload field of a normalized parser record."""
    if not isinstance(record, dict):
        return []
    return scan_payload(record.get("payload"))


def scan_records(records: Any) -> list[dict[str, Any]]:
    if not isinstance(records, list):
        return []
    results = []
    for record in records:
        if not isinstance(record, dict):
            continue
        results.append({**record, "secrets": scan_record(record)})
    return results


def main() -> None:
    records = scan_records(parse_file(SAMPLE_PATH))
    hits = [row for row in records if row.get("secrets")]
    print(f"records={len(records)}")
    print(f"secret_hits={len(hits)}")
    print(json.dumps(hits[:5], indent=2))


if __name__ == "__main__":
    main()
