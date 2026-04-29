"""`git-shield scan` command."""

from __future__ import annotations

import argparse
import sys

from ..config import Config
from .. import diff as diff_mod
from ..diff import parse_file_changes
from ..output import EXIT_CLEAN, write_json
from ._scan_common import FilePayload, payloads_from_changes, scan_file_payloads, scan_pii_text, scan_secrets_text


def cmd_scan(args: argparse.Namespace, cfg: Config) -> int:
    json_mode = getattr(args, "json", False)
    if args.stdin:
        text = sys.stdin.read()
        if not args.skip_secrets:
            secret_code, secret_findings = scan_secrets_text(
                text, cfg.gitleaks_bin, cfg.timeout_seconds, args.skip_if_no_gitleaks, json_mode=json_mode,
            )
            if secret_code != EXIT_CLEAN:
                if json_mode:
                    write_json({"ok": False, "kind": "secrets", "count": len(secret_findings), "findings": secret_findings})
                return secret_code
        pii_code, pii_findings = scan_pii_text(
            text, cfg, skip_if_no_opf=args.skip_if_no_opf, extra_allowlist=args.allowlist,
        )
        if json_mode:
            from ._scan_common import combine_exit_codes
            code = combine_exit_codes(secret_code if not args.skip_secrets else EXIT_CLEAN, pii_code)
            write_json({
                "ok": code == 0,
                "exit_code": code,
                "secret_findings": secret_findings if not args.skip_secrets else [],
                "pii_findings": pii_findings,
            })
        return pii_code

    diff = diff_mod.diff_with_fallback(args.base, args.head)
    changes = parse_file_changes(diff, cfg.ignore_globs)
    payloads = payloads_from_changes(changes, head_ref=args.head)
    result = scan_file_payloads(
        payloads, cfg,
        skip_if_no_opf=args.skip_if_no_opf,
        skip_secrets=args.skip_secrets,
        skip_if_no_gitleaks=args.skip_if_no_gitleaks,
        extra_allowlist=args.allowlist,
        json_mode=json_mode,
        use_cache=not getattr(args, "no_cache", False),
    )
    if json_mode:
        from ._scan_common import combine_exit_codes
        code = combine_exit_codes(
            EXIT_CLEAN if args.skip_secrets else (EXIT_CLEAN if not result.secret_findings else result.exit_code),
            EXIT_CLEAN if not result.pii_findings else result.exit_code,
        )
        write_json({
            "ok": result.exit_code == 0,
            "exit_code": result.exit_code,
            "secret_findings": result.secret_findings,
            "pii_findings": result.pii_findings,
        })
    return result.exit_code
