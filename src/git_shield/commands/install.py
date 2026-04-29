"""`git-shield install` command."""

from __future__ import annotations

import argparse
from pathlib import Path

from ..install import install_global_hook, install_hook
from ..output import info


def cmd_install(args: argparse.Namespace) -> int:
    if args.dry_run:
        if args.global_install:
            root = Path.home() / ".githooks"
            info(f"Would write {root / 'pre-commit'}")
            info(f"Would write {root / 'pre-push'}")
            info(f"Would set git config --global core.hooksPath {root}")
        else:
            root = args.repo / ".git" / "hooks"
            info(f"Would write {root / 'pre-commit'}")
            info(f"Would write {root / 'pre-push'}")
        return 0
    try:
        if args.global_install:
            path = install_global_hook(device=args.device, force=args.force)
        else:
            path = install_hook(args.repo, device=args.device, force=args.force)
    except (FileExistsError, FileNotFoundError) as exc:
        info(str(exc))
        return 1
    info(f"Installed hooks; pre-push hook at {path}")
    return 0
