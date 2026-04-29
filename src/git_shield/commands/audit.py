"""`git-shield audit` command."""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
from pathlib import Path

from ..config import Config
from ..output import EXIT_CLEAN, info, write_json
from ._scan_common import FilePayload, scan_file_payloads


def _repo_files(repo: Path, all_files: bool) -> list[str]:
    args = ["git", "ls-files"]
    if all_files:
        args.extend(["--cached", "--others", "--exclude-standard"])
    proc = subprocess.run(args, cwd=repo, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise FileNotFoundError("not a git repo or git ls-files failed")
    return [line for line in proc.stdout.splitlines() if line]


def _ignored_path(path: str, ignore_globs: tuple[str, ...]) -> bool:
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(path, glob) or fnmatch.fnmatch(name, glob) for glob in ignore_globs)


def cmd_audit(args: argparse.Namespace, cfg: Config) -> int:
    json_mode = getattr(args, "json", False)
    try:
        paths = _repo_files(args.repo, args.all_files)
    except FileNotFoundError as exc:
        info(str(exc))
        return 1
    payloads: dict[str, FilePayload] = {}
    skipped = 0
    for rel in paths:
        if _ignored_path(rel, cfg.ignore_globs):
            skipped += 1
            continue
        path = args.repo / rel
        try:
            if path.stat().st_size > args.max_file_bytes:
                skipped += 1
                continue
            text = path.read_text(errors="ignore")
        except OSError:
            skipped += 1
            continue
        if "\0" in text:
            skipped += 1
            continue
        payloads[rel] = FilePayload(secret_text=text, pii_text=text, added_lines=None)
    info(f"audit scanning {len(payloads)} files; skipped {skipped}")
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
