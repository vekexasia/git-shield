"""Git Shield CLI -- thin dispatcher over command modules."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import Config, ConfigError, load_config
from .output import set_verbosity


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--device", default=None, help="OPF device (default: from config or 'cuda')")
    p.add_argument("--backend", default=None, choices=["opf", "gliner"], help="PII detection backend (default: opf)")
    p.add_argument("--opf-bin", default=None)
    p.add_argument("--gitleaks-bin", default=None)
    p.add_argument("--timeout", type=int, default=None)
    p.add_argument("--allowlist", action="append", type=Path, default=[])
    p.add_argument("--skip-if-no-opf", action="store_true")
    p.add_argument("--config", type=Path, default=Path("git-shield.toml"))
    p.add_argument("--max-bytes", type=int, default=None, help="per-chunk byte limit")
    p.add_argument("--max-total-bytes", type=int, default=None)
    p.add_argument("--labels", default=None, help="comma-separated labels to block")
    p.add_argument("--cuda-policy", default=None, choices=["fail", "skip", "cpu-small"])
    p.add_argument("--skip-secrets", action="store_true", help="do not run gitleaks secret scanning")
    p.add_argument("--skip-if-no-gitleaks", action="store_true")
    p.add_argument("--json", action="store_true", help="write machine-readable JSON to stdout")
    p.add_argument("--no-cache", action="store_true", help="bypass scan result cache")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="git-shield", description="Pre-push PII guard")
    parser.add_argument("--version", action="version", version=f"git-shield {__version__}")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress non-error output")
    parser.add_argument("-v", "--verbose", action="store_true", help="show extra diagnostic output")
    sub = parser.add_subparsers(dest="cmd")

    scan = sub.add_parser("scan", help="scan a ref range or stdin")
    _add_common(scan)
    scan.add_argument("--base", default="origin/main")
    scan.add_argument("--head", default="HEAD")
    scan.add_argument("--stdin", action="store_true")

    pp = sub.add_parser("prepush", help="run as a Git pre-push hook (refs on stdin)")
    _add_common(pp)
    pp.add_argument("--fallback-base", default="origin/main")
    pp.add_argument("remote", nargs="?", default=None)
    pp.add_argument("url", nargs="?", default=None)

    sec = sub.add_parser("secrets", help="scan staged additions or stdin with gitleaks")
    sec.add_argument("--stdin", action="store_true")
    sec.add_argument("--staged", action="store_true", help="scan staged additions (default)")
    sec.add_argument("--gitleaks-bin", default="gitleaks")
    sec.add_argument("--timeout", type=int, default=120)
    sec.add_argument("--skip-if-no-gitleaks", action="store_true")
    sec.add_argument("--json", action="store_true", help="write machine-readable JSON to stdout")

    doctor = sub.add_parser("doctor", help="check external dependencies and runtime prerequisites")
    doctor.add_argument("--opf-bin", default="opf")
    doctor.add_argument("--gitleaks-bin", default="gitleaks")
    doctor.add_argument("--smoke", action="store_true", help="run synthetic secret and PII smoke tests")
    doctor.add_argument("--device", default="cuda")
    doctor.add_argument("--timeout", type=int, default=180)
    doctor.add_argument("--json", action="store_true", help="write machine-readable JSON to stdout")
    doctor.add_argument("--install", action="store_true", help="auto-install missing dependencies (gitleaks, opf)")
    doctor.add_argument("--check-updates", action="store_true", help="check whether a newer gitleaks release is available")

    status = sub.add_parser("status", help="show installed hooks, config, allowlists, and dependencies")
    status.add_argument("--repo", default=Path("."), type=Path)
    status.add_argument("--global", dest="global_status", action="store_true")
    status.add_argument("--json", action="store_true", help="write machine-readable JSON to stdout")

    audit = sub.add_parser("audit", help="scan repository files, not just a git diff")
    _add_common(audit)
    audit.add_argument("--repo", default=Path("."), type=Path)
    audit.add_argument("--all-files", action="store_true", help="scan tracked and untracked non-ignored files")
    audit.add_argument("--max-file-bytes", type=int, default=100_000)

    boot = sub.add_parser("bootstrap", help="doctor + init + global install")
    boot.add_argument("--device", default="cuda")
    boot.add_argument("--force", action="store_true")
    boot.add_argument("--no-init", action="store_true")
    boot.add_argument("--no-install", action="store_true")
    boot.add_argument("--dry-run", action="store_true")
    boot.add_argument("--smoke", action="store_true")
    boot.add_argument("--install-deps", action="store_true", help="auto-install missing dependencies (gitleaks, opf)")

    init = sub.add_parser("init", help="write starter config and allowlist files")
    init.add_argument("--repo", default=Path("."), type=Path)
    init.add_argument("--force", action="store_true")

    inst = sub.add_parser("install", help="write git hooks")
    inst.add_argument("--repo", default=Path("."), type=Path)
    inst.add_argument("--global", dest="global_install", action="store_true", help="install to ~/.githooks and set global core.hooksPath")
    inst.add_argument("--device", default="cuda")
    inst.add_argument("--force", action="store_true")
    inst.add_argument("--dry-run", action="store_true")

    uninst = sub.add_parser("uninstall", help="remove git-shield git hooks")
    uninst.add_argument("--repo", default=Path("."), type=Path)
    uninst.add_argument("--global", dest="global_install", action="store_true")
    uninst.add_argument("--no-restore", action="store_true", help="do not restore latest .bak hook")
    return parser


def _effective_config(args: argparse.Namespace) -> Config:
    cfg = load_config(args.config) if getattr(args, "config", None) else Config()
    return Config(
        device=args.device or cfg.device,
        backend=args.backend or cfg.backend,
        opf_bin=args.opf_bin or cfg.opf_bin,
        gitleaks_bin=args.gitleaks_bin or cfg.gitleaks_bin,
        timeout_seconds=args.timeout or cfg.timeout_seconds,
        max_bytes_per_chunk=args.max_bytes or cfg.max_bytes_per_chunk,
        max_total_bytes=args.max_total_bytes or cfg.max_total_bytes,
        labels=frozenset(args.labels.split(",")) if args.labels else cfg.labels,
        ignore_globs=cfg.ignore_globs,
        cuda_policy=args.cuda_policy or cfg.cuda_policy,
        cpu_small_threshold=cfg.cpu_small_threshold,
        allowlist_paths=cfg.allowlist_paths,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    set_verbosity(
        quiet=getattr(args, "quiet", False),
        verbose=getattr(args, "verbose", False),
    )

    if args.cmd is None:
        parser.print_help(sys.stderr)
        return 2

    # Commands that don't need _effective_config
    if args.cmd == "doctor":
        from .commands.doctor import cmd_doctor
        return cmd_doctor(args)
    if args.cmd == "status":
        from .commands.status import cmd_status
        return cmd_status(args)
    if args.cmd == "init":
        from .commands.init import cmd_init
        return cmd_init(args)
    if args.cmd == "install":
        from .commands.install import cmd_install
        return cmd_install(args)
    if args.cmd == "uninstall":
        from .commands.uninstall import cmd_uninstall
        return cmd_uninstall(args)
    if args.cmd == "bootstrap":
        from .commands.bootstrap import cmd_bootstrap
        return cmd_bootstrap(args)
    if args.cmd == "secrets":
        from .commands.secrets import cmd_secrets
        return cmd_secrets(args)

    # Commands that need _effective_config
    try:
        cfg = _effective_config(args)
    except ConfigError as exc:
        print(f"git-shield: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "scan":
        from .commands.scan import cmd_scan
        return cmd_scan(args, cfg)
    if args.cmd == "prepush":
        from .commands.prepush import cmd_prepush
        return cmd_prepush(args, cfg)
    if args.cmd == "audit":
        from .commands.audit import cmd_audit
        return cmd_audit(args, cfg)

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
