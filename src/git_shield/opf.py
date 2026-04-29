from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Iterable, Protocol


class OpfError(RuntimeError):
    pass


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

    Subprocess-based on purpose: avoid loading the 2.8GB model in tests.
    """

    def __init__(
        self,
        opf_bin: str = "opf",
        device: str = "cuda",
        timeout_seconds: int = 120,
        runner=subprocess.run,
    ) -> None:
        self.opf_bin = opf_bin
        self.device = device
        self.timeout_seconds = timeout_seconds
        self._runner = runner

    def detect(self, text: str) -> list[PrivacyFinding]:
        if not text.strip():
            return []
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", errors="replace") as tmp:
            tmp.write(text)
            tmp.flush()
            proc = self._runner(
                [
                    self.opf_bin,
                    "--device",
                    self.device,
                    "--format",
                    "json",
                    "--json-indent",
                    "0",
                    "--no-print-color-coded-text",
                    "-f",
                    tmp.name,
                ],
                check=False,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
            )
        if proc.returncode != 0:
            raise OpfError(
                f"opf exited {proc.returncode}: {proc.stderr.strip()[:500]}"
            )
        return parse_opf_json(proc.stdout)


def detect_chunks(detector: PrivacyDetector, chunks: Iterable[str]) -> list[PrivacyFinding]:
    out: list[PrivacyFinding] = []
    for chunk in chunks:
        out.extend(detector.detect(chunk))
    return out


def _iter_json_objects(output: str):
    """Yield candidate balanced `{...}` slices, skipping `{` inside strings."""
    depth = 0
    start = -1
    in_string = False
    escape = False
    for i, ch in enumerate(output):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start != -1:
                yield output[start : i + 1]
                start = -1


def parse_opf_json(output: str) -> list[PrivacyFinding]:
    """Parse OPF JSON tolerantly: ignores summary/log lines surrounding it.

    Tries each balanced `{...}` candidate until one parses and looks like an
    OPF payload (has `detected_spans`).
    """
    last_err: Exception | None = None
    for blob in _iter_json_objects(output):
        try:
            payload = json.loads(blob)
        except json.JSONDecodeError as exc:
            last_err = exc
            continue
        if isinstance(payload, dict) and "detected_spans" in payload:
            return [
                PrivacyFinding(
                    label=span.get("label", "<unknown>"),
                    text=span.get("text", ""),
                    start=span.get("start"),
                    end=span.get("end"),
                )
                for span in payload.get("detected_spans", [])
            ]
    raise ValueError(
        f"OPF output did not contain JSON ({last_err})" if last_err else "OPF output did not contain JSON"
    )
