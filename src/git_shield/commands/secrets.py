"""`git-shield secrets` command."""

from __future__ import annotations

import argparse
import sys

from ..config import Config
from ..diff import added_text_by_file, staged_diff
from ..output import write_json
from ._scan_common import scan_secrets_text, scan_secrets_files


def cmd_secrets(args: argparse.Namespace) -> int:
    json_mode = getattr(args, "json", False)
    if args.stdin:
        code, findings = scan_secrets_text(
            sys.stdin.read(), args.gitleaks_bin, args.timeout, args.skip_if_no_gitleaks, json_mode=json_mode,
        )
    else:
        cfg = Config(gitleaks_bin=args.gitleaks_bin, timeout_seconds=args.timeout)
        files = added_text_by_file(staged_diff())
        code, findings = scan_secrets_files(
            files, cfg, skip_if_missing=args.skip_if_no_gitleaks, json_mode=json_mode,
        )
    if json_mode:
        write_json({"ok": code == 0, "kind": "secrets", "count": len(findings), "findings": findings})
        return code
    return code
