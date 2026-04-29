"""Deterministic structured PII detection.

These regexes supplement model backends for high-precision structured values
that models can occasionally split or partially span. Phone numbers are not
regex-detected here because broad phone patterns false-positive on IDs,
versions, timestamps, and long numeric constants.
"""

from __future__ import annotations

import re

from .opf import PrivacyFinding

_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
_URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>'\"\])},;]+|\bwww\.[^\s<>'\"\])},;]+")


def _trim_url(value: str, start: int, end: int) -> tuple[str, int]:
    trimmed = value.rstrip(".,;:")
    return trimmed, end - (len(value) - len(trimmed))


def structured_findings(text: str) -> list[PrivacyFinding]:
    findings: list[PrivacyFinding] = []
    for match in _EMAIL_RE.finditer(text):
        findings.append(PrivacyFinding("private_email", match.group(0), match.start(), match.end()))
    for match in _URL_RE.finditer(text):
        value, end = _trim_url(match.group(0), match.start(), match.end())
        findings.append(PrivacyFinding("private_url", value, match.start(), end))
    return findings


def merge_findings(base: list[PrivacyFinding], extra: list[PrivacyFinding]) -> list[PrivacyFinding]:
    out = list(base)
    seen = {(f.label, f.start, f.end, f.text) for f in out}
    for finding in extra:
        key = (finding.label, finding.start, finding.end, finding.text)
        if key not in seen:
            seen.add(key)
            out.append(finding)
    return out
