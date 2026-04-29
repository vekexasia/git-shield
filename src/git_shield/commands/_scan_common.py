"""Shared scanning orchestration used by scan, prepush, and audit commands."""

from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from ..allowlist import load_patterns
from ..chunking import chunk_text, chunk_text_offsets
from ..config import Config
from .. import cuda
from ..cuda import resolve_device
from ..opf import OpenAIPrivacyFilterDetector, OpfError, PrivacyFinding, detect_chunks
from ..output import EXIT_BOTH, EXIT_CLEAN, EXIT_ERROR, EXIT_PII, EXIT_SECRETS, blocked, detail, error, info, success
from ..scanner import ScanFinding, filter_findings
from ..secrets import SecretScanError, scan_secrets_with_gitleaks
from .. import diff as diff_mod
from ..structured import merge_findings, structured_findings


@dataclass(frozen=True)
class FilePayload:
    secret_text: str
    pii_text: str
    # File line numbers in `pii_text` that count as "added" for PII purposes.
    # None means scan every line (audit mode or fallback when post-image is unavailable).
    added_lines: frozenset[int] | None


@dataclass
class ScanResult:
    exit_code: int
    secret_findings: list[dict[str, str | int | None]]
    pii_findings: list[dict[str, str | int | None]]


def payloads_from_changes(
    changes: dict,
    head_ref: str | None,
    cwd: str | None = None,
) -> dict[str, FilePayload]:
    """Build per-file payloads from a parsed diff.

    For PII context we fetch the post-image (`git show <head_ref>:<path>`) so the
    detector sees the file as it lands. If unavailable (new untracked file, ref
    missing, binary), we fall back to the synthesized added-text blob and scan
    every line of it (no line-set filter).
    """
    out: dict[str, FilePayload] = {}
    for path, change in changes.items():
        full = diff_mod.show_blob(head_ref, path, cwd=cwd) if head_ref else None
        if full is not None and full.strip():
            out[path] = FilePayload(
                secret_text=change.added_text,
                pii_text=full,
                added_lines=change.added_lines or None,
            )
        else:
            out[path] = FilePayload(
                secret_text=change.added_text,
                pii_text=change.added_text,
                added_lines=None,
            )
    return out


def _allowlist_paths(cfg: Config, extra: list[Path] | None = None) -> list[Path]:
    return [
        Path.home() / ".githooks" / "pii-allowlist.txt",
        Path(".pii-allowlist"),
        *cfg.allowlist_paths,
        *(extra or []),
    ]


def scan_secrets_text(
    text: str,
    gitleaks_bin: str,
    timeout_seconds: int,
    skip_if_missing: bool,
    *,
    json_mode: bool = False,
) -> tuple[int, list[dict[str, str | int | None]]]:
    """Scan a single text blob for secrets. Returns (exit_code, findings)."""
    if not text.strip():
        info("No added text to scan for secrets.")
        return EXIT_CLEAN, []
    try:
        result = scan_secrets_with_gitleaks(text, gitleaks_bin, timeout_seconds)
    except FileNotFoundError:
        msg = f"gitleaks executable not found: {gitleaks_bin}"
        if skip_if_missing:
            info(msg + " -- skipping")
            return EXIT_CLEAN, []
        error(msg)
        error("Install gitleaks or pass --skip-if-no-gitleaks.")
        return EXIT_ERROR, []
    except SecretScanError as exc:
        error(f"gitleaks failed: {exc}")
        return EXIT_ERROR, []

    if not result.found:
        success("No gitleaks secret findings.")
        return EXIT_CLEAN, []

    blocked("gitleaks detected possible secrets. Operation blocked.")
    findings: list[dict[str, str | int | None]] = []
    if result.findings:
        for finding in result.findings[:20]:
            where = f"line {finding.line}" if finding.line is not None else "line unknown"
            match = f": {finding.match}" if finding.match else ""
            detail(f"<stdin>: {where}: {finding.rule_id}{match}")
            findings.append({"file": "<stdin>", "line": finding.line, "rule": finding.rule_id, "match": finding.match})
    elif result.output:
        for line in result.output.splitlines()[-20:]:
            detail(line)
    return EXIT_SECRETS, findings


def _scan_one_secret(path: str, text: str, gitleaks_bin: str, timeout: int) -> tuple[str, "SecretScanResult | None", Exception | None]:
    """Scan a single file for secrets. Returns (path, result_or_None, exception)."""
    try:
        result = scan_secrets_with_gitleaks(text, gitleaks_bin, timeout)
        return path, result, None
    except FileNotFoundError:
        return path, None, FileNotFoundError(gitleaks_bin)
    except SecretScanError as exc:
        return path, None, exc


def scan_secrets_files(
    files: dict[str, str],
    cfg: Config,
    *,
    skip_if_missing: bool = False,
    json_mode: bool = False,
) -> tuple[int, list[dict[str, str | int | None]]]:
    """Scan per-file text payloads for secrets (parallel). Returns (exit_code, findings)."""
    if not files:
        return EXIT_CLEAN, []

    blocked_flag = False
    missing = False
    failed = False
    all_findings: list[dict[str, str | int | None]] = []

    # Parallel scan: each gitleaks call is an independent subprocess.
    max_workers = min(len(files), 4)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_scan_one_secret, path, text, cfg.gitleaks_bin, cfg.timeout_seconds): path
            for path, text in files.items()
            if text.strip()
        }
        for future in as_completed(futures):
            path, result, exc = future.result()
            if isinstance(exc, FileNotFoundError):
                missing = True
                continue
            if isinstance(exc, SecretScanError):
                error(f"gitleaks failed while scanning {path}: {exc}")
                failed = True
                continue
            if result is not None and result.found:
                blocked_flag = True
                blocked(f"gitleaks detected possible secrets in {path}. Operation blocked.")
                if result.findings:
                    for finding in result.findings[:20]:
                        where = f"line {finding.line}" if finding.line is not None else "line unknown"
                        match = f": {finding.match}" if finding.match else ""
                        detail(f"{path}: {where}: {finding.rule_id}{match}")
                        all_findings.append({"file": path, "line": finding.line, "rule": finding.rule_id, "match": finding.match})
                elif result.output:
                    for line in result.output.splitlines()[-10:]:
                        detail(line)

    if missing:
        msg = f"gitleaks executable not found: {cfg.gitleaks_bin}"
        if skip_if_missing:
            info(msg + " -- skipping")
            return EXIT_CLEAN, []
        error(msg)
        error("Install gitleaks or pass --skip-if-no-gitleaks.")
        return EXIT_ERROR, []
    if blocked_flag or failed:
        return EXIT_SECRETS, all_findings
    success("No gitleaks secret findings.")
    return EXIT_CLEAN, []


def _setup_detector(cfg: Config, skip_if_missing: bool, total_bytes: int) -> tuple[PrivacyDetector | None, int]:
    """Create the PII detector based on config.backend. Returns (detector_or_None, exit_code)."""
    if cfg.backend == "gliner":
        from ..gliner import create_gliner_detector
        detector = create_gliner_detector(device=cfg.device)
        if detector is None:
            msg = "GLiNER not installed. Install with: pip install gliner"
            if skip_if_missing:
                info(msg + " -- skipping")
                return None, EXIT_CLEAN
            error(msg)
            return None, EXIT_ERROR
        return detector, EXIT_CLEAN

    # Default: OpenAI Privacy Filter
    device, reason = resolve_device(
        cfg.device, cfg.cuda_policy, total_bytes, cfg.cpu_small_threshold, cuda.has_cuda()
    )
    if device is None:
        info(f"CUDA unavailable, policy='{cfg.cuda_policy}' -> skipping ({reason}).")
        return None, EXIT_CLEAN
    if reason != "ok":
        info(f"Device decision: {device} ({reason}).")

    if shutil.which(cfg.opf_bin) is None:
        msg = f"OPF executable not found: {cfg.opf_bin}"
        if skip_if_missing:
            info(msg + " -- skipping")
            return None, EXIT_CLEAN
        error(msg)
        error("Install OpenAI Privacy Filter: pip install -e /path/to/openai/privacy-filter")
        return None, EXIT_ERROR

    return OpenAIPrivacyFilterDetector(cfg.opf_bin, device, cfg.timeout_seconds), EXIT_CLEAN


def scan_pii_files(
    payloads: dict[str, FilePayload],
    cfg: Config,
    *,
    skip_if_no_opf: bool = False,
    extra_allowlist: list[Path] | None = None,
    json_mode: bool = False,
) -> tuple[int, list[dict[str, str | int | None]]]:
    """Scan per-file payloads for PII. Returns (exit_code, findings)."""
    payloads = {p: pl for p, pl in payloads.items() if pl.pii_text.strip()}
    if not payloads:
        info("No added text to scan for PII.")
        return EXIT_CLEAN, []

    total_bytes = sum(len(pl.pii_text.encode("utf-8")) for pl in payloads.values())
    if total_bytes > cfg.max_total_bytes:
        error(f"Diff is {total_bytes} bytes (> {cfg.max_total_bytes}); refuse to scan.")
        return EXIT_ERROR, []

    detector, code = _setup_detector(cfg, skip_if_no_opf, total_bytes)
    if detector is None:
        return code, []

    allow_paths = _allowlist_paths(cfg, extra_allowlist)
    allow_patterns = load_patterns(allow_paths)
    findings_by_file: list[tuple[str, ScanFinding]] = []

    raw_by_file: dict[str, list[PrivacyFinding]] = {
        path: structured_findings(payload.pii_text)
        for path, payload in payloads.items()
    }
    chunk_records: list[tuple[str, int, str]] = []
    for path, payload in payloads.items():
        for offset, chunk in chunk_text_offsets(payload.pii_text, cfg.max_bytes_per_chunk):
            if chunk.strip():
                chunk_records.append((path, offset, chunk))

    try:
        if hasattr(detector, "detect_many"):
            detected_batches = detector.detect_many([chunk for _, _, chunk in chunk_records])  # type: ignore[attr-defined]
        else:
            detected_batches = [detector.detect(chunk) for _, _, chunk in chunk_records]
    except OpfError as exc:
        error(f"OPF failed while scanning files: {exc}")
        return EXIT_ERROR, []

    for (path, offset, _chunk), chunk_findings in zip(chunk_records, detected_batches):
        for finding in chunk_findings:
            start = offset + finding.start if finding.start is not None else None
            end = offset + finding.end if finding.end is not None else None
            raw_by_file[path].append(PrivacyFinding(finding.label, finding.text, start, end))

    for path, payload in payloads.items():
        for finding in filter_findings(raw_by_file[path], allow_patterns, set(cfg.labels), source_text=payload.pii_text):
            if payload.added_lines is not None and (finding.line is None or finding.line not in payload.added_lines):
                continue
            findings_by_file.append((path, finding))

    if not findings_by_file:
        success("No OPF PII findings.")
        return EXIT_CLEAN, []

    blocked("OpenAI Privacy Filter detected possible PII/secrets. Operation blocked.")
    result_findings: list[dict[str, str | int | None]] = []
    for path, finding in findings_by_file[:50]:
        where = f"line {finding.line}" if finding.line is not None else "line unknown"
        detail(f"{path}: {where}: {finding.label}: {finding.redacted}")
        result_findings.append({"file": path, "line": finding.line, "label": finding.label, "redacted": finding.redacted})
    if len(findings_by_file) > 50:
        info(f"  ... and {len(findings_by_file) - 50} more")
    info("Add narrow public/test allowlist regexes or remove the data.")
    return EXIT_PII, result_findings


def scan_pii_text(
    text: str,
    cfg: Config,
    *,
    skip_if_no_opf: bool = False,
    extra_allowlist: list[Path] | None = None,
) -> tuple[int, list[dict[str, str | int | None]]]:
    """Scan a single text blob for PII. Returns (exit_code, findings)."""
    if not text.strip():
        info("No added text to scan for PII.")
        return EXIT_CLEAN, []

    total_bytes = len(text.encode("utf-8"))
    if total_bytes > cfg.max_total_bytes:
        error(f"Diff is {total_bytes} bytes (> {cfg.max_total_bytes}); refuse to scan.")
        return EXIT_ERROR, []

    detector, code = _setup_detector(cfg, skip_if_no_opf, total_bytes)
    if detector is None:
        return code, []

    allow_paths = _allowlist_paths(cfg, extra_allowlist)
    chunks = chunk_text(text, cfg.max_bytes_per_chunk)
    try:
        raw_findings = merge_findings(detect_chunks(detector, chunks), structured_findings(text))
    except OpfError as exc:
        error(f"OPF failed: {exc}")
        return EXIT_ERROR, []

    findings = filter_findings(raw_findings, load_patterns(allow_paths), set(cfg.labels))
    if not findings:
        success("No OPF PII findings.")
        return EXIT_CLEAN, []

    blocked("OpenAI Privacy Filter detected possible PII/secrets. Operation blocked.")
    result_findings: list[dict[str, str | int | None]] = []
    for f in findings[:50]:
        detail(f"{f.label}: {f.redacted}")
        result_findings.append({"label": f.label, "redacted": f.redacted})
    if len(findings) > 50:
        info(f"  ... and {len(findings) - 50} more")
    info("Add narrow public/test allowlist regexes or remove the data.")
    return EXIT_PII, result_findings


def scan_file_payloads(
    payloads: dict[str, FilePayload],
    cfg: Config,
    *,
    skip_if_no_opf: bool = False,
    skip_secrets: bool = False,
    skip_if_no_gitleaks: bool = False,
    extra_allowlist: list[Path] | None = None,
    json_mode: bool = False,
    use_cache: bool = True,
) -> ScanResult:
    """Full scan: secrets then PII. Returns ScanResult with combined exit code."""
    from ..cache import load_cache, save_cache, cache_lookup, cache_store

    payloads = {
        path: pl for path, pl in payloads.items()
        if pl.secret_text.strip() or pl.pii_text.strip()
    }
    if not payloads:
        info("No added text to scan.")
        return ScanResult(EXIT_CLEAN, [], [])

    # Cache: skip files whose content was previously scanned clean.
    cache = load_cache() if use_cache else {}
    cached_clean: set[str] = set()
    if cache:
        for path, pl in payloads.items():
            entry = cache_lookup(cache, pl.secret_text + pl.pii_text)
            if entry and entry.get("secret_clean") and entry.get("pii_clean"):
                cached_clean.add(path)
        if cached_clean:
            info(f"{len(cached_clean)} file(s) skipped (cached clean).")
            payloads = {p: pl for p, pl in payloads.items() if p not in cached_clean}
            if not payloads:
                return ScanResult(EXIT_CLEAN, [], [])

    secret_findings: list[dict[str, str | int | None]] = []
    secret_code = EXIT_CLEAN
    if not skip_secrets:
        secret_files = {path: pl.secret_text for path, pl in payloads.items() if pl.secret_text.strip()}
        if secret_files:
            secret_code, secret_findings = scan_secrets_files(
                secret_files, cfg, skip_if_missing=skip_if_no_gitleaks, json_mode=json_mode,
            )
    if secret_code != 0 and secret_code != EXIT_CLEAN:
        return ScanResult(secret_code, secret_findings, [])

    pii_code, pii_findings = scan_pii_files(
        payloads, cfg, skip_if_no_opf=skip_if_no_opf, extra_allowlist=extra_allowlist, json_mode=json_mode,
    )

    # Store clean results in cache.
    if use_cache and secret_code == EXIT_CLEAN and pii_code == EXIT_CLEAN:
        for path, pl in payloads.items():
            cache_store(cache, pl.secret_text + pl.pii_text, secret_clean=True, pii_clean=True)
        save_cache(cache)

    if secret_code != EXIT_CLEAN:
        return ScanResult(secret_code, secret_findings, pii_findings)
    return ScanResult(pii_code, secret_findings, pii_findings)


def combine_exit_codes(secret_code: int, pii_code: int) -> int:
    """Combine secret and PII exit codes into a single code."""
    if secret_code != EXIT_CLEAN and pii_code != EXIT_CLEAN:
        return EXIT_BOTH
    if secret_code != EXIT_CLEAN:
        return secret_code
    return pii_code
