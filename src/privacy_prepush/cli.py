from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from .allowlist import load_patterns
from .diff import added_text, git_diff
from .opf import OpenAIPrivacyFilterDetector
from .scanner import scan_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Pre-push PII guard powered by OpenAI Privacy Filter")
    parser.add_argument("--base", default="origin/main", help="base ref to diff against (default: origin/main)")
    parser.add_argument("--head", default="HEAD", help="head ref to diff (default: HEAD)")
    parser.add_argument("--device", default="cuda", help="OPF device (default: cuda; use cpu for portability)")
    parser.add_argument("--opf-bin", default="opf", help="path to opf executable")
    parser.add_argument("--timeout", type=int, default=180, help="OPF timeout seconds")
    parser.add_argument("--allowlist", action="append", type=Path, default=[], help="regex allowlist file")
    parser.add_argument("--skip-if-no-opf", action="store_true", help="skip instead of failing if opf is missing")
    parser.add_argument("--stdin", action="store_true", help="scan text from stdin instead of git diff")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if shutil.which(args.opf_bin) is None:
        message = f"[privacy-prepush] OPF executable not found: {args.opf_bin}"
        if args.skip_if_no_opf:
            print(message + " — skipping", file=sys.stderr)
            return 0
        print(message, file=sys.stderr)
        print("[privacy-prepush] Install OpenAI Privacy Filter first: pip install -e /path/to/openai/privacy-filter", file=sys.stderr)
        return 1

    text = sys.stdin.read() if args.stdin else added_text(git_diff(args.base, args.head))
    if not text.strip():
        print("[privacy-prepush] No added text to scan.", file=sys.stderr)
        return 0

    allow_paths = [Path.home() / ".githooks" / "pii-allowlist.txt", Path(".pii-allowlist"), *args.allowlist]
    findings = scan_text(
        OpenAIPrivacyFilterDetector(args.opf_bin, args.device, args.timeout),
        text,
        load_patterns(allow_paths),
    )

    if not findings:
        print("[privacy-prepush] No OPF PII findings.", file=sys.stderr)
        return 0

    print("[privacy-prepush] OpenAI Privacy Filter detected possible PII/secrets. Push blocked.", file=sys.stderr)
    for finding in findings[:50]:
        print(f"[privacy-prepush]   {finding.label}: {finding.redacted}", file=sys.stderr)
    if len(findings) > 50:
        print(f"[privacy-prepush]   ... and {len(findings) - 50} more", file=sys.stderr)
    print("[privacy-prepush] Add narrow public/test allowlist regexes or remove the data.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
