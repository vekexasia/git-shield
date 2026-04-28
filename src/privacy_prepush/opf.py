from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class PrivacyFinding:
    label: str
    text: str
    start: int | None = None
    end: int | None = None


class PrivacyDetector(Protocol):
    def detect(self, text: str) -> list[PrivacyFinding]: ...


class OpenAIPrivacyFilterDetector:
    """CLI adapter around OpenAI Privacy Filter's `opf` command.

    Keeping this as a subprocess adapter makes tests lightweight and avoids
    importing/loading the 2.8GB model unless the hook actually runs.
    """

    def __init__(self, opf_bin: str = "opf", device: str = "cuda", timeout_seconds: int = 120) -> None:
        self.opf_bin = opf_bin
        self.device = device
        self.timeout_seconds = timeout_seconds

    def detect(self, text: str) -> list[PrivacyFinding]:
        proc = subprocess.run(
            [
                self.opf_bin,
                "--device",
                self.device,
                "--format",
                "json",
                "--json-indent",
                "0",
                "--no-print-color-coded-text",
                text,
            ],
            check=True,
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
        )
        return parse_opf_json(proc.stdout)


def parse_opf_json(output: str) -> list[PrivacyFinding]:
    """Parse OPF JSON even when a summary line precedes it."""
    start = output.find("{")
    if start == -1:
        raise ValueError("OPF output did not contain JSON")
    payload = json.loads(output[start:])
    return [
        PrivacyFinding(
            label=span.get("label", "<unknown>"),
            text=span.get("text", ""),
            start=span.get("start"),
            end=span.get("end"),
        )
        for span in payload.get("detected_spans", [])
    ]
