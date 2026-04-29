"""`git-shield prepush` command."""

from __future__ import annotations

import argparse
import sys

from ..config import Config
from .. import diff as diff_mod
from ..diff import parse_file_changes
from ..output import EXIT_CLEAN, info, write_json
from ..prepush import parse_prepush_stdin, resolve_base
from ._scan_common import FilePayload, payloads_from_changes, scan_file_payloads


def cmd_prepush(args: argparse.Namespace, cfg: Config) -> int:
    json_mode = getattr(args, "json", False)
    refs = parse_prepush_stdin(sys.stdin.read())
    if not refs:
        info("No refs on stdin; nothing to scan.")
        return EXIT_CLEAN

    payloads: dict[str, FilePayload] = {}
    for ref in refs:
        base = resolve_base(ref, fallback=args.fallback_base)
        if base is None:
            continue
        diff = diff_mod.diff_with_fallback(base, ref.local_sha)
        changes = parse_file_changes(diff, cfg.ignore_globs)
        for path, payload in payloads_from_changes(changes, head_ref=ref.local_sha).items():
            existing = payloads.get(path)
            if existing is None:
                payloads[path] = payload
                continue
            if payload.added_lines is None or existing.added_lines is None:
                merged_lines = None
            else:
                merged_lines = existing.added_lines | payload.added_lines
            merged_secret = "\n".join(part for part in [existing.secret_text, payload.secret_text] if part)
            merged_pii = payload.pii_text if payload.added_lines is not None else existing.pii_text
            payloads[path] = FilePayload(
                secret_text=merged_secret,
                pii_text=merged_pii,
                added_lines=merged_lines,
            )

    result = scan_file_payloads(
        payloads, cfg,
        skip_if_no_opf=args.skip_if_no_opf,
        skip_secrets=getattr(args, "skip_secrets", False),
        skip_if_no_gitleaks=args.skip_if_no_gitleaks,
        extra_allowlist=args.allowlist,
        json_mode=json_mode,
        use_cache=not getattr(args, "no_cache", False),
    )
    if json_mode:
        from ._scan_common import combine_exit_codes
        code = combine_exit_codes(
            EXIT_CLEAN if getattr(args, "skip_secrets", False) else (EXIT_CLEAN if not result.secret_findings else result.exit_code),
            EXIT_CLEAN if not result.pii_findings else result.exit_code,
        )
        write_json({
            "ok": result.exit_code == 0,
            "exit_code": result.exit_code,
            "secret_findings": result.secret_findings,
            "pii_findings": result.pii_findings,
        })
    return result.exit_code
