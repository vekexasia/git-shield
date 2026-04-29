from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass


class SecretScanError(RuntimeError):
    pass


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    description: str
    line: int | None
    match: str


@dataclass(frozen=True)
class SecretScanResult:
    found: bool
    output: str
    findings: tuple[SecretFinding, ...] = ()


def scan_secrets_with_gitleaks(
    text: str,
    gitleaks_bin: str = "gitleaks",
    timeout_seconds: int = 120,
    runner=subprocess.run,
) -> SecretScanResult:
    if not text.strip():
        return SecretScanResult(False, "")

    resolved = shutil.which(gitleaks_bin) or gitleaks_bin
    if shutil.which(gitleaks_bin) is None and "/" not in gitleaks_bin:
        raise FileNotFoundError(gitleaks_bin)

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = f"{tmpdir}/gitleaks.json"
        proc = runner(
            [
                resolved,
                "stdin",
                "--redact",
                "--no-banner",
                "--no-color",
                "--report-format",
                "json",
                "--report-path",
                report_path,
            ],
            input=text,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        try:
            with open(report_path, "r", encoding="utf-8", errors="replace") as report:
                raw_report = report.read()
        except FileNotFoundError:
            raw_report = ""
    output = "\n".join(part for part in [proc.stdout.strip(), proc.stderr.strip()] if part)
    findings = _parse_gitleaks_report(raw_report)
    if proc.returncode == 0:
        return SecretScanResult(False, output, findings)
    if proc.returncode == 1:
        return SecretScanResult(True, output, findings)
    raise SecretScanError(f"gitleaks exited {proc.returncode}: {output[:500]}")


def _parse_gitleaks_report(raw: str) -> tuple[SecretFinding, ...]:
    if not raw.strip():
        return ()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return ()
    findings: list[SecretFinding] = []
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict):
            continue
        line = item.get("StartLine")
        findings.append(
            SecretFinding(
                rule_id=str(item.get("RuleID") or "unknown"),
                description=str(item.get("Description") or ""),
                line=line if isinstance(line, int) else None,
                match=str(item.get("Match") or ""),
            )
        )
    return tuple(findings)
