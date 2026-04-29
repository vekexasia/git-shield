"""`git-shield status` command."""

from __future__ import annotations

import argparse
from pathlib import Path

from ..doctor import collect_checks
from ..output import info, write_json


def _hook_status(path: Path) -> str:
    if not path.exists():
        return "missing"
    text = path.read_text(errors="replace")
    if "Installed by git-shield" in text:
        return "installed"
    return "foreign"


def cmd_status(args: argparse.Namespace) -> int:
    checks = collect_checks()
    root = Path.home() / ".githooks" if args.global_status else args.repo / ".git" / "hooks"
    cfg = args.repo / "git-shield.toml"
    allow = args.repo / ".pii-allowlist"
    payload = {
        "checks": [
            {"name": check.name, "ok": check.ok, "required": check.required, "detail": check.detail}
            for check in checks
        ],
        "hook_dir": str(root),
        "hooks": {
            "pre-commit": _hook_status(root / "pre-commit"),
            "pre-push": _hook_status(root / "pre-push"),
        },
        "config": str(cfg) if cfg.exists() else None,
        "allowlist": str(allow) if allow.exists() else None,
    }
    if args.json:
        write_json(payload)
        return 0
    for check in checks:
        status = "ok" if check.ok else ("missing" if check.required else "warn")
        info(f"{status}: {check.name}: {check.detail}")
    info(f"hook dir: {root}")
    info(f"pre-commit: {payload['hooks']['pre-commit']}")
    info(f"pre-push: {payload['hooks']['pre-push']}")
    info(f"config: {payload['config'] or 'not found'}")
    info(f"allowlist: {payload['allowlist'] or 'not found'}")
    return 0
