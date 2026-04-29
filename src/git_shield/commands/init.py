"""`git-shield init` command."""

from __future__ import annotations

import argparse

from ..init_config import write_starter_files
from ..output import info


def cmd_init(args: argparse.Namespace) -> int:
    try:
        written = write_starter_files(args.repo, force=args.force)
    except FileExistsError as exc:
        info(str(exc))
        return 1
    for path in written:
        info(f"Wrote {path}")
    return 0
