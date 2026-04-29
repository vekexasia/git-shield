#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.exists():
    sys.path.insert(0, str(SRC))

from git_shield.allowlist import load_patterns
from git_shield.opf import OpenAIPrivacyFilterDetector
from git_shield.scanner import DEFAULT_LABELS, filter_findings

EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PLUS_PHONE_RE = re.compile(r"(?<![\w+])\+[0-9][0-9 .()/-]{7,}[0-9](?!\w)")
PHONE_WITH_LABEL_RE = re.compile(
    r"(?i)\b(?:phone|mobile|cell|tel|telefono|whatsapp|contact)\b.{0,24}?([0-9][0-9 .()/-]{7,}[0-9])"
)
SECRET_RE = re.compile(r"(?i)\b(?:api[_-]?key|token|secret|password)\b\s*[:=]\s*['\"]?([^'\"\s]+)")


@dataclass(frozen=True)
class Case:
    id: str
    text: str
    labels: set[str]


def load_cases(path: Path) -> list[Case]:
    cases: list[Case] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        cases.append(Case(raw["id"], raw["text"], set(raw["labels"])))
    return cases


def allowed(value: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(value) for pattern in patterns)


def regex_detect(text: str, patterns: list[re.Pattern[str]]) -> set[str]:
    labels: set[str] = set()
    for match in EMAIL_RE.finditer(text):
        if not allowed(match.group(0), patterns):
            labels.add("private_email")
    for match in PLUS_PHONE_RE.finditer(text):
        if not allowed(match.group(0), patterns):
            labels.add("private_phone")
    for match in PHONE_WITH_LABEL_RE.finditer(text):
        if not allowed(match.group(1), patterns):
            labels.add("private_phone")
    for match in SECRET_RE.finditer(text):
        if not allowed(match.group(1), patterns):
            labels.add("secret")
    return labels


def opf_detect(detector: OpenAIPrivacyFilterDetector, text: str, patterns: list[re.Pattern[str]]) -> set[str]:
    findings = detector.detect(text)
    filtered = filter_findings(findings, patterns, DEFAULT_LABELS)
    return {finding.label for finding in filtered}


GLINER_LABELS = [
    "person",
    "email",
    "phone_number",
    "street_address",
    "address",
    "date",
    "date_of_birth",
    "api_key",
    "password",
    "secret",
    "url",
]

GLINER_MAP = {
    "person": "private_person",
    "email": "private_email",
    "phone_number": "private_phone",
    "street_address": "private_address",
    "address": "private_address",
    "date": "private_date",
    "date_of_birth": "private_date",
    "api_key": "secret",
    "password": "secret",
    "secret": "secret",
    "url": "private_url",
}


def gliner_detect(model, text: str, patterns: list[re.Pattern[str]], threshold: float) -> set[str]:
    labels: set[str] = set()
    for entity in model.predict_entities(text, GLINER_LABELS, threshold=threshold):
        value = entity.get("text", "")
        if allowed(value, patterns):
            continue
        mapped = GLINER_MAP.get(entity.get("label", ""))
        if mapped:
            labels.add(mapped)
    return labels


HF_LABEL_MAP = {
    "EMAIL": "private_email",
    "TEL": "private_phone",
    "PHONE": "private_phone",
    "GIVENNAME1": "private_person",
    "GIVENNAME2": "private_person",
    "LASTNAME1": "private_person",
    "LASTNAME2": "private_person",
    "LASTNAME3": "private_person",
    "TITLE": "private_person",
    "STREET": "private_address",
    "SECADDRESS": "private_address",
    "BUILDING": "private_address",
    "CITY": "private_address",
    "STATE": "private_address",
    "POSTCODE": "private_address",
    "COUNTRY": "private_address",
    "DATE": "private_date",
    "BOD": "private_date",
    "TIME": "private_date",
    "PASS": "secret",
    "PASSWORD": "secret",
    "USERNAME": "secret",
    "IP": "private_url",
}


def hf_token_detect(pipe, text: str, patterns: list[re.Pattern[str]], threshold: float) -> set[str]:
    labels: set[str] = set()
    for entity in pipe(text):
        score = float(entity.get("score", 0.0))
        if score < threshold:
            continue
        start = entity.get("start")
        end = entity.get("end")
        value = text[start:end] if isinstance(start, int) and isinstance(end, int) else entity.get("word", "")
        if allowed(value, patterns):
            continue
        raw_label = entity.get("entity_group") or entity.get("entity") or ""
        label = raw_label.removeprefix("B-").removeprefix("I-")
        mapped = HF_LABEL_MAP.get(label)
        if mapped:
            labels.add(mapped)
    return labels


def score(expected: set[str], predicted: set[str]) -> tuple[int, int, int]:
    tp = len(expected & predicted)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    return tp, fp, fn


def fmt_metric(tp: int, fp: int, fn: int) -> str:
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return f"precision={precision:.3f} recall={recall:.3f} f1={f1:.3f} tp={tp} fp={fp} fn={fn}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare PII detector backends on local fixture cases")
    parser.add_argument("--cases", type=Path, default=Path("examples/eval/pii_cases.jsonl"))
    parser.add_argument("--backend", action="append", choices=["regex", "opf", "gliner", "hf-token"], default=[])
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--gliner-model", default="nvidia/gliner-pii")
    parser.add_argument("--gliner-threshold", type=float, default=0.3)
    parser.add_argument("--hf-model", default="Dharma20/bert-finetuned-ner-pii-masking-300k")
    parser.add_argument("--hf-threshold", type=float, default=0.3)
    parser.add_argument("--show-passes", action="store_true")
    args = parser.parse_args(argv)

    backends = args.backend or ["regex", "opf"]
    cases = load_cases(args.cases)
    patterns = load_patterns([Path.home() / ".githooks" / "pii-allowlist.txt", Path(".pii-allowlist")])
    opf = OpenAIPrivacyFilterDetector(device=args.device, timeout_seconds=args.timeout) if "opf" in backends else None
    gliner = None
    hf_pipe = None
    if "gliner" in backends:
        try:
            from gliner import GLiNER
        except ImportError:
            print("Install GLiNER backend with: uv run --with gliner examples/eval_models.py --backend gliner", file=sys.stderr)
            return 2
        gliner = GLiNER.from_pretrained(args.gliner_model)
    if "hf-token" in backends:
        try:
            from transformers import pipeline
        except ImportError:
            print("Install HF backend with: uv run --with transformers --with torch examples/eval_models.py --backend hf-token", file=sys.stderr)
            return 2
        hf_pipe = pipeline("token-classification", model=args.hf_model, aggregation_strategy="simple", device=0 if args.device == "cuda" else -1)

    for backend in backends:
        total_tp = total_fp = total_fn = 0
        started = time.perf_counter()
        print(f"\n== {backend} ==")
        for case in cases:
            if backend == "regex":
                predicted = regex_detect(case.text, patterns)
            elif backend == "opf":
                assert opf is not None
                predicted = opf_detect(opf, case.text, patterns)
            elif backend == "gliner":
                assert gliner is not None
                predicted = gliner_detect(gliner, case.text, patterns, args.gliner_threshold)
            else:
                assert hf_pipe is not None
                predicted = hf_token_detect(hf_pipe, case.text, patterns, args.hf_threshold)
            tp, fp, fn = score(case.labels, predicted)
            total_tp += tp
            total_fp += fp
            total_fn += fn
            ok = fp == 0 and fn == 0
            if args.show_passes or not ok:
                print(
                    f"{case.id}: {'PASS' if ok else 'FAIL'} "
                    f"expected={sorted(case.labels)} predicted={sorted(predicted)}"
                )
        elapsed = time.perf_counter() - started
        print(fmt_metric(total_tp, total_fp, total_fn))
        print(f"elapsed={elapsed:.2f}s cases={len(cases)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
