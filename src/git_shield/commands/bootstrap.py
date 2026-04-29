"""`git-shield bootstrap` command."""

from __future__ import annotations

import argparse
from pathlib import Path

from ..init_config import write_starter_files
from ..output import info
from .doctor import cmd_doctor
from .install import cmd_install


def cmd_bootstrap(args: argparse.Namespace) -> int:
    info("checking dependencies")
    doctor_args = argparse.Namespace(opf_bin="opf", gitleaks_bin="gitleaks", smoke=args.smoke, device=args.device, timeout=180, json=False, install=getattr(args, 'install_deps', False))
    code = cmd_doctor(doctor_args)
    if code != 0:
        return code
    if not args.no_init:
        for path in [Path("git-shield.toml"), Path(".pii-allowlist")]:
            if path.exists() and not args.force:
                info(f"exists: {path}")
        if not args.dry_run:
            try:
                write_starter_files(Path("."), force=args.force)
                info("wrote starter config files")
            except FileExistsError:
                info("starter config files already exist; use --force to overwrite")
    if not args.no_install:
        install_args = argparse.Namespace(global_install=True, device=args.device, force=args.force, dry_run=args.dry_run)
        return cmd_install(install_args)
    return 0
