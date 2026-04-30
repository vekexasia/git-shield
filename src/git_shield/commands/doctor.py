"""`git-shield doctor` command."""

from __future__ import annotations

import argparse

from ..doctor import checks_ok, collect_checks, fix_hint
from ..output import EXIT_CLEAN, EXIT_ERROR, info, warn, write_json


def _cmd_smoke(gitleaks_bin: str, opf_bin: str, device: str, timeout: int, *, quiet: bool = False) -> int:
    from ..opf import OpenAIPrivacyFilterDetector, OpfError
    from ..scanner import filter_findings
    from ..secrets import SecretScanError, scan_secrets_with_gitleaks
    from ..allowlist import load_patterns

    def say(msg: str) -> None:
        if not quiet:
            info(msg)

    try:
        synthetic_key = "OPENAI" + "_API_KEY=" + "sk-" + "1234567890abcdef" * 3 + "\n"
        secret = scan_secrets_with_gitleaks(synthetic_key, gitleaks_bin, timeout)
    except (FileNotFoundError, SecretScanError) as exc:
        say(f"secret smoke failed: {exc}")
        return EXIT_ERROR
    if not secret.found:
        say("secret smoke failed: gitleaks did not flag synthetic key")
        return EXIT_ERROR
    say("ok: secret smoke detected synthetic key with redacted output")

    detector = OpenAIPrivacyFilterDetector(opf_bin, device, timeout)
    try:
        synthetic_person = "".join(chr(c) for c in [71, 105, 117, 115, 101, 112, 112, 101, 32, 86, 101, 114, 100, 105])
        synthetic_email = "".join(chr(c) for c in [103, 105, 117, 115, 101, 112, 112, 101, 46, 118, 101, 114, 100, 105, 64, 103, 109, 97, 105, 108, 46, 99, 111, 109])
        findings = filter_findings(
            detector.detect(f"{synthetic_person} email {synthetic_email}"),
            load_patterns(),
        )
    except OpfError as exc:
        say(f"PII smoke failed: {exc}")
        return EXIT_ERROR
    labels = {finding.label for finding in findings}
    if "private_email" not in labels:
        say("PII smoke failed: OPF did not flag synthetic email")
        return EXIT_ERROR
    say("ok: PII smoke detected synthetic email/person with redacted output")
    return EXIT_CLEAN


def _try_install_missing(checks, args: argparse.Namespace) -> None:
    """Attempt to auto-install missing dependencies when --install is passed."""
    from ..installer import install_gitleaks, install_opf

    missing = [c for c in checks if not c.ok and (c.required or c.name == "gitleaks-update")]
    if not missing:
        return

    for check in missing:
        if check.name in {"gitleaks", "gitleaks-update"}:
            info("Auto-installing gitleaks...")
            result = install_gitleaks()
            if result:
                # Update args so subsequent checks use the new binary
                args.gitleaks_bin = str(result)
        elif check.name == "opf":
            info("Auto-installing OpenAI Privacy Filter...")
            if install_opf():
                info("You may need to run 'opf --device cpu <text>' to download the model.")


def cmd_doctor(args: argparse.Namespace) -> int:
    do_install = getattr(args, "install", False) or getattr(args, "install_deps", False)

    check_updates = getattr(args, "check_updates", False)
    checks = collect_checks(args.opf_bin, args.gitleaks_bin, check_updates=check_updates)

    if do_install and not checks_ok(checks):
        _try_install_missing(checks, args)
        # Re-check after install attempts
        checks = collect_checks(args.opf_bin, args.gitleaks_bin, check_updates=check_updates)

    smoke = None
    if args.smoke and checks_ok(checks):
        smoke_code = _cmd_smoke(args.gitleaks_bin, args.opf_bin, args.device, args.timeout, quiet=args.json)
        smoke = {"ok": smoke_code == 0}
    if args.json:
        payload = {
            "ok": checks_ok(checks) and (smoke is None or smoke["ok"]),
            "checks": [
                {
                    "name": check.name,
                    "ok": check.ok,
                    "required": check.required,
                    "detail": check.detail,
                    "fix": fix_hint(check),
                }
                for check in checks
            ],
            "smoke": smoke,
        }
        write_json(payload)
        return EXIT_CLEAN if payload["ok"] else EXIT_ERROR
    for check in checks:
        status = "ok" if check.ok else ("missing" if check.required else "warn")
        info(f"{status}: {check.name}: {check.detail}")
        hint = fix_hint(check)
        if hint:
            info(f"  fix: {hint}")
    if not checks_ok(checks):
        info("Install missing required dependencies before enabling hooks.")
        return EXIT_ERROR
    if args.smoke:
        return EXIT_CLEAN if smoke and smoke["ok"] else EXIT_ERROR
    return EXIT_CLEAN
