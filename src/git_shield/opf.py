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

    def _base_args(self) -> list[str]:
        return [
            self.opf_bin,
            "--device",
            self.device,
            "--format",
            "json",
            "--json-indent",
            "0",
            "--no-print-color-coded-text",
        ]

    def detect(self, text: str) -> list[PrivacyFinding]:
        return self.detect_many([text])[0] if text.strip() else []

    def detect_many(self, texts: list[str]) -> list[list[PrivacyFinding]]:
        if not texts:
            return []

        out: list[list[PrivacyFinding]] = [[] for _ in texts]
        non_empty = [(i, text) for i, text in enumerate(texts) if text.strip()]
        if not non_empty:
            return out

        with tempfile.TemporaryDirectory() as tmpdir:
            args = self._base_args()
            for index, text in non_empty:
                path = f"{tmpdir}/{index}.txt"
                with open(path, "w", encoding="utf-8", errors="replace") as tmp:
                    tmp.write(text)
                args.extend(["-f", path])

            proc = self._runner(
                args,
                check=False,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
            )

        if proc.returncode != 0:
            raise OpfError(
                f"opf exited {proc.returncode}: {proc.stderr.strip()[:500]}"
            )

        parsed = parse_opf_json_many(proc.stdout)
        if len(parsed) != len(non_empty):
            raise OpfError(f"opf returned {len(parsed)} JSON payloads for {len(non_empty)} inputs")

        for (index, _), findings in zip(non_empty, parsed):
            out[index] = findings
        return out


def detect_chunks(detector: PrivacyDetector, chunks: Iterable[str]) -> list[PrivacyFinding]:
    chunk_list = list(chunks)
    if hasattr(detector, "detect_many"):
        out: list[PrivacyFinding] = []
        for findings in detector.detect_many(chunk_list):  # type: ignore[attr-defined]
            out.extend(findings)
        return out

    out = []
    for chunk in chunk_list:
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


def _spans_to_findings(payload: dict) -> list[PrivacyFinding]:
    return [
        PrivacyFinding(
            label=span.get("label", "<unknown>"),
            text=span.get("text", ""),
            start=span.get("start"),
            end=span.get("end"),
        )
        for span in payload.get("detected_spans", [])
    ]


def parse_opf_json_many(output: str) -> list[list[PrivacyFinding]]:
    """Parse one or more OPF JSON objects from stdout."""
    last_err: Exception | None = None
    results: list[list[PrivacyFinding]] = []
    for blob in _iter_json_objects(output):
        try:
            payload = json.loads(blob)
        except json.JSONDecodeError as exc:
            last_err = exc
            continue
        if isinstance(payload, dict) and "detected_spans" in payload:
            results.append(_spans_to_findings(payload))
    if results:
        return results
    raise ValueError(
        f"OPF output did not contain JSON ({last_err})" if last_err else "OPF output did not contain JSON"
    )


def parse_opf_json(output: str) -> list[PrivacyFinding]:
    """Parse the first OPF JSON payload from stdout."""
    return parse_opf_json_many(output)[0]
