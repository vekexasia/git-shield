from __future__ import annotations

import re
from dataclasses import dataclass

from .allowlist import allowed
from .opf import PrivacyDetector, PrivacyFinding


@dataclass(frozen=True)
class ScanFinding:
    label: str
    redacted: str
    line: int | None = None


EMAIL_LABELS = {"private_email"}
PHONE_LABELS = {"private_phone"}
PERSON_LABELS = {"private_person"}
SECRET_LABELS = {"secret", "account_number", "private_address", "private_url", "private_date"}
DEFAULT_LABELS = EMAIL_LABELS | PHONE_LABELS | PERSON_LABELS | SECRET_LABELS


def redact_email(value: str) -> str:
    local, _, domain = value.partition("@")
    if len(local) <= 2:
        local = local[0] + "*" if local else "*"
    else:
        local = f"{local[0]}***{local[-1]}"
    return f"{local}@{domain}"


def redact_generic(value: str, label: str) -> str:
    clean = re.sub(r"\s+", " ", value).strip()
    if label in EMAIL_LABELS:
        return redact_email(clean)
    if label in PHONE_LABELS:
        digits = re.sub(r"\D", "", clean)
        return f"[phone:***{digits[-4:]}]" if len(digits) >= 4 else "[phone:redacted]"
    if label in PERSON_LABELS:
        return "[person:redacted]"
    return f"[{label}:redacted]"


def _line_number(text: str, finding: PrivacyFinding) -> int | None:
    start = finding.start
    if start is None:
        start = text.find(finding.text)
    if start < 0:
        return None
    return text.count("\n", 0, start) + 1


def filter_findings(
    findings: list[PrivacyFinding],
    allow_patterns: list[re.Pattern[str]],
    labels_to_block: set[str] | frozenset[str] | None = None,
    source_text: str | None = None,
) -> list[ScanFinding]:
    labels = labels_to_block if labels_to_block is not None else DEFAULT_LABELS
    results: list[ScanFinding] = []
    seen_text: set[tuple[str, str]] = set()

    for finding in findings:
        if finding.label not in labels:
            continue
        if allowed(finding.text, allow_patterns):
            continue
        # Dedupe by raw text (not redacted) so two distinct values that share a
        # redaction don't collapse into one. The user still only sees redacted.
        key = (finding.label, finding.text)
        if key in seen_text:
            continue
        seen_text.add(key)
        line = _line_number(source_text, finding) if source_text is not None else None
        results.append(ScanFinding(label=finding.label, redacted=redact_generic(finding.text, finding.label), line=line))

    return results


def scan_text(
    detector: PrivacyDetector,
    text: str,
    allow_patterns: list[re.Pattern[str]],
    labels_to_block: set[str] | frozenset[str] | None = None,
) -> list[ScanFinding]:
    return filter_findings(detector.detect(text), allow_patterns, labels_to_block)
