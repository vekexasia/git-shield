from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from .allowlist import load_patterns
from .chunking import chunk_text, chunk_text_offsets
from .config import Config, load_config
from .cuda import has_cuda, resolve_device
from .diff import added_text, added_text_by_file, diff_with_fallback, staged_diff
from .doctor import checks_ok, collect_checks, fix_hint
from .init_config import write_starter_files
from .install import install_global_hook, install_hook, uninstall_global_hook, uninstall_hook
from .opf import OpenAIPrivacyFilterDetector, OpfError, PrivacyFinding, detect_chunks
from .prepush import parse_prepush_stdin, resolve_base
from .scanner import filter_findings
from .secrets import SecretScanError, scan_secrets_with_gitleaks


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--device", default=None, help="OPF device (default: from config or 'cuda')")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="git-shield", description="Pre-push PII guard")
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

    doctor = sub.add_parser("doctor", help="check external dependencies and runtime prerequisites")
    doctor.add_argument("--opf-bin", default="opf")
    doctor.add_argument("--gitleaks-bin", default="gitleaks")

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


def _print(msg: str) -> None:
    print(f"[git-shield] {msg}", file=sys.stderr)


def _scan_secrets_payload(text: str, gitleaks_bin: str, timeout_seconds: int, skip_if_missing: bool) -> int:
    if not text.strip():
        _print("No added text to scan for secrets.")
        return 0
    try:
        result = scan_secrets_with_gitleaks(text, gitleaks_bin, timeout_seconds)
    except FileNotFoundError:
        msg = f"gitleaks executable not found: {gitleaks_bin}"
        if skip_if_missing:
            _print(msg + " — skipping")
            return 0
        _print(msg)
        _print("Install gitleaks or pass --skip-if-no-gitleaks.")
        return 1
    except SecretScanError as exc:
        _print(f"gitleaks failed: {exc}")
        return 1

    if not result.found:
        _print("No gitleaks secret findings.")
        return 0

    _print("gitleaks detected possible secrets. Operation blocked.")
    if result.findings:
        for finding in result.findings[:20]:
            where = f"line {finding.line}" if finding.line is not None else "line unknown"
            match = f": {finding.match}" if finding.match else ""
            _print(f"  <stdin>: {where}: {finding.rule_id}{match}")
    elif result.output:
        for line in result.output.splitlines()[-20:]:
            _print(f"  {line}")
    return 1


def _scan_secret_files(files: dict[str, str], cfg: Config, args: argparse.Namespace) -> int:
    if getattr(args, "skip_secrets", False):
        return 0
    blocked = False
    missing = False
    failed = False
    for path, text in files.items():
        if not text.strip():
            continue
        try:
            result = scan_secrets_with_gitleaks(text, cfg.gitleaks_bin, cfg.timeout_seconds)
        except FileNotFoundError:
            missing = True
            break
        except SecretScanError as exc:
            _print(f"gitleaks failed while scanning {path}: {exc}")
            failed = True
            continue
        if result.found:
            blocked = True
            _print(f"gitleaks detected possible secrets in {path}. Operation blocked.")
            if result.findings:
                for finding in result.findings[:20]:
                    where = f"line {finding.line}" if finding.line is not None else "line unknown"
                    match = f": {finding.match}" if finding.match else ""
                    _print(f"  {path}: {where}: {finding.rule_id}{match}")
            elif result.output:
                for line in result.output.splitlines()[-10:]:
                    _print(f"  {line}")
    if missing:
        msg = f"gitleaks executable not found: {cfg.gitleaks_bin}"
        if args.skip_if_no_gitleaks:
            _print(msg + " — skipping")
            return 0
        _print(msg)
        _print("Install gitleaks or pass --skip-if-no-gitleaks.")
        return 1
    if blocked or failed:
        return 1
    _print("No gitleaks secret findings.")
    return 0


def _scan_pii_files(files: dict[str, str], cfg: Config, args: argparse.Namespace) -> int:
    text = "\n".join(files.values())
    if not text.strip():
        _print("No added text to scan for PII.")
        return 0

    total_bytes = len(text.encode("utf-8"))
    if total_bytes > cfg.max_total_bytes:
        _print(f"Diff is {total_bytes} bytes (> {cfg.max_total_bytes}); refuse to scan.")
        return 1

    device, reason = resolve_device(
        cfg.device, cfg.cuda_policy, total_bytes, cfg.cpu_small_threshold, has_cuda()
    )
    if device is None:
        _print(f"CUDA unavailable, policy='{cfg.cuda_policy}' -> skipping ({reason}).")
        return 0
    if reason != "ok":
        _print(f"Device decision: {device} ({reason}).")

    if shutil.which(cfg.opf_bin) is None:
        msg = f"OPF executable not found: {cfg.opf_bin}"
        if args.skip_if_no_opf:
            _print(msg + " — skipping")
            return 0
        _print(msg)
        _print("Install OpenAI Privacy Filter: pip install -e /path/to/openai/privacy-filter")
        return 1

    detector = OpenAIPrivacyFilterDetector(cfg.opf_bin, device, cfg.timeout_seconds)
    allow_paths = [
        Path.home() / ".githooks" / "pii-allowlist.txt",
        Path(".pii-allowlist"),
        *cfg.allowlist_paths,
        *args.allowlist,
    ]
    allow_patterns = load_patterns(allow_paths)
    findings_by_file = []
    for path, file_text in files.items():
        if not file_text.strip():
            continue
        raw_findings: list[PrivacyFinding] = []
        for offset, chunk in chunk_text_offsets(file_text, cfg.max_bytes_per_chunk):
            try:
                chunk_findings = detector.detect(chunk)
            except OpfError as exc:
                _print(f"OPF failed while scanning {path}: {exc}")
                return 1
            for finding in chunk_findings:
                start = offset + finding.start if finding.start is not None else None
                end = offset + finding.end if finding.end is not None else None
                raw_findings.append(PrivacyFinding(finding.label, finding.text, start, end))
        for finding in filter_findings(raw_findings, allow_patterns, set(cfg.labels), source_text=file_text):
            findings_by_file.append((path, finding))

    if not findings_by_file:
        _print("No OPF PII findings.")
        return 0

    _print("OpenAI Privacy Filter detected possible PII/secrets. Operation blocked.")
    for path, finding in findings_by_file[:50]:
        where = f"line {finding.line}" if finding.line is not None else "line unknown"
        _print(f"  {path}: {where}: {finding.label}: {finding.redacted}")
    if len(findings_by_file) > 50:
        _print(f"  ... and {len(findings_by_file) - 50} more")
    _print("Add narrow public/test allowlist regexes or remove the data.")
    return 1


def _scan_file_payloads(files: dict[str, str], cfg: Config, args: argparse.Namespace) -> int:
    files = {path: text for path, text in files.items() if text.strip()}
    if not files:
        _print("No added text to scan.")
        return 0
    code = _scan_secret_files(files, cfg, args)
    if code != 0:
        return code
    return _scan_pii_files(files, cfg, args)


def _scan_payload(text: str, cfg: Config, args: argparse.Namespace) -> int:
    if not text.strip():
        _print("No added text to scan.")
        return 0

    if not args.skip_secrets:
        code = _scan_secrets_payload(
            text,
            cfg.gitleaks_bin,
            cfg.timeout_seconds,
            args.skip_if_no_gitleaks,
        )
        if code != 0:
            return code

    total_bytes = len(text.encode("utf-8"))
    if total_bytes > cfg.max_total_bytes:
        _print(f"Diff is {total_bytes} bytes (> {cfg.max_total_bytes}); refuse to scan.")
        return 1

    device, reason = resolve_device(
        cfg.device, cfg.cuda_policy, total_bytes, cfg.cpu_small_threshold, has_cuda()
    )
    if device is None:
        _print(f"CUDA unavailable, policy='{cfg.cuda_policy}' -> skipping ({reason}).")
        return 0
    if reason != "ok":
        _print(f"Device decision: {device} ({reason}).")

    if shutil.which(cfg.opf_bin) is None:
        msg = f"OPF executable not found: {cfg.opf_bin}"
        if args.skip_if_no_opf:
            _print(msg + " — skipping")
            return 0
        _print(msg)
        _print("Install OpenAI Privacy Filter: pip install -e /path/to/openai/privacy-filter")
        return 1

    detector = OpenAIPrivacyFilterDetector(cfg.opf_bin, device, cfg.timeout_seconds)
    allow_paths = [
        Path.home() / ".githooks" / "pii-allowlist.txt",
        Path(".pii-allowlist"),
        *cfg.allowlist_paths,
        *args.allowlist,
    ]
    chunks = chunk_text(text, cfg.max_bytes_per_chunk)
    try:
        raw_findings = detect_chunks(detector, chunks)
    except OpfError as exc:
        _print(f"OPF failed: {exc}")
        return 1

    findings = filter_findings(raw_findings, load_patterns(allow_paths), set(cfg.labels))
    if not findings:
        _print("No OPF PII findings.")
        return 0

    _print("OpenAI Privacy Filter detected possible PII/secrets. Operation blocked.")
    for f in findings[:50]:
        _print(f"  {f.label}: {f.redacted}")
    if len(findings) > 50:
        _print(f"  ... and {len(findings) - 50} more")
    _print("Add narrow public/test allowlist regexes or remove the data.")
    return 1


def _cmd_scan(args: argparse.Namespace) -> int:
    cfg = _effective_config(args)
    if args.stdin:
        return _scan_payload(sys.stdin.read(), cfg, args)
    files = added_text_by_file(diff_with_fallback(args.base, args.head), cfg.ignore_globs)
    return _scan_file_payloads(files, cfg, args)


def _cmd_prepush(args: argparse.Namespace) -> int:
    cfg = _effective_config(args)
    refs = parse_prepush_stdin(sys.stdin.read())
    if not refs:
        _print("No refs on stdin; nothing to scan.")
        return 0

    files: dict[str, str] = {}
    for ref in refs:
        base = resolve_base(ref, fallback=args.fallback_base)
        if base is None:
            continue
        diff = diff_with_fallback(base, ref.local_sha)
        for path, text in added_text_by_file(diff, cfg.ignore_globs).items():
            files[path] = "\n".join(part for part in [files.get(path, ""), text] if part)
    return _scan_file_payloads(files, cfg, args)


def _cmd_secrets(args: argparse.Namespace) -> int:
    if args.stdin:
        return _scan_secrets_payload(sys.stdin.read(), args.gitleaks_bin, args.timeout, args.skip_if_no_gitleaks)
    cfg = Config(gitleaks_bin=args.gitleaks_bin, timeout_seconds=args.timeout)
    files = added_text_by_file(staged_diff())
    return _scan_secret_files(files, cfg, args)


def _cmd_doctor(args: argparse.Namespace) -> int:
    checks = collect_checks(args.opf_bin, args.gitleaks_bin)
    for check in checks:
        status = "ok" if check.ok else ("missing" if check.required else "warn")
        _print(f"{status}: {check.name}: {check.detail}")
        hint = fix_hint(check)
        if hint:
            _print(f"  fix: {hint}")
    if not checks_ok(checks):
        _print("Install missing required dependencies before enabling hooks.")
        return 1
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    try:
        written = write_starter_files(args.repo, force=args.force)
    except FileExistsError as exc:
        _print(str(exc))
        return 1
    for path in written:
        _print(f"Wrote {path}")
    return 0


def _cmd_install(args: argparse.Namespace) -> int:
    if args.dry_run:
        if args.global_install:
            root = Path.home() / ".githooks"
            _print(f"Would write {root / 'pre-commit'}")
            _print(f"Would write {root / 'pre-push'}")
            _print(f"Would set git config --global core.hooksPath {root}")
        else:
            root = args.repo / ".git" / "hooks"
            _print(f"Would write {root / 'pre-commit'}")
            _print(f"Would write {root / 'pre-push'}")
        return 0
    try:
        if args.global_install:
            path = install_global_hook(device=args.device, force=args.force)
        else:
            path = install_hook(args.repo, device=args.device, force=args.force)
    except (FileExistsError, FileNotFoundError) as exc:
        _print(str(exc))
        return 1
    _print(f"Installed hooks; pre-push hook at {path}")
    return 0


def _cmd_uninstall(args: argparse.Namespace) -> int:
    try:
        if args.global_install:
            changed = uninstall_global_hook(restore=not args.no_restore)
        else:
            changed = uninstall_hook(args.repo, restore=not args.no_restore)
    except (FileExistsError, FileNotFoundError) as exc:
        _print(str(exc))
        return 1
    if not changed:
        _print("No git-shield hooks found.")
        return 0
    for path in changed:
        _print(f"Updated {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd is None:
        parser.print_help(sys.stderr)
        return 2
    if args.cmd == "install":
        return _cmd_install(args)
    if args.cmd == "uninstall":
        return _cmd_uninstall(args)
    if args.cmd == "init":
        return _cmd_init(args)
    if args.cmd == "doctor":
        return _cmd_doctor(args)
    if args.cmd == "secrets":
        return _cmd_secrets(args)
    if args.cmd == "prepush":
        return _cmd_prepush(args)
    return _cmd_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
