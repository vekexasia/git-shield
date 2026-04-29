"""`git-shield uninstall` command."""

from __future__ import annotations

import argparse

from ..install import uninstall_global_hook, uninstall_hook
from ..output import info


def cmd_uninstall(args: argparse.Namespace) -> int:
    try:
        if args.global_install:
            changed = uninstall_global_hook(restore=not args.no_restore)
        else:
            changed = uninstall_hook(args.repo, restore=not args.no_restore)
    except (FileExistsError, FileNotFoundError) as exc:
        info(str(exc))
        return 1
    if not changed:
        info("No git-shield hooks found.")
        return 0
    for path in changed:
        info(f"Updated {path}")
    return 0
