"""Cache scan results by git blob SHA to avoid re-scanning unchanged files."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

from .output import info

# Cache location: .git/git-shield-cache.json (per-repo)
_CACHE_FILENAME = "git-shield-cache.json"
_MAX_CACHE_AGE_SECONDS = 7 * 24 * 3600  # 7 days
_MAX_ENTRIES = 5000


def _cache_path() -> Path:
    """Return the cache file path inside the current repo's .git directory."""
    proc = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        text=True, capture_output=True, check=False,
    )
    if proc.returncode != 0:
        return Path(".git") / _CACHE_FILENAME
    return Path(proc.stdout.strip()) / _CACHE_FILENAME


def _content_hash(text: str, signature: str | None = None) -> str:
    """Fast content/config hash for cache key."""
    payload = text if signature is None else f"{signature}\0{text}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def cache_signature(cfg: object, allowlist_paths: list[Path] | tuple[Path, ...] = ()) -> str:
    allowlists: list[dict[str, str | int | None]] = []
    for path in allowlist_paths:
        try:
            stat = path.stat()
            digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
            allowlists.append({"path": str(path), "mtime_ns": stat.st_mtime_ns, "sha256": digest})
        except OSError:
            allowlists.append({"path": str(path), "mtime_ns": None, "sha256": None})

    payload = {
        "version": 2,
        "backend": getattr(cfg, "backend", None),
        "device": getattr(cfg, "device", None),
        "cuda_policy": getattr(cfg, "cuda_policy", None),
        "opf_bin": getattr(cfg, "opf_bin", None),
        "gitleaks_bin": getattr(cfg, "gitleaks_bin", None),
        "max_bytes_per_chunk": getattr(cfg, "max_bytes_per_chunk", None),
        "max_total_bytes": getattr(cfg, "max_total_bytes", None),
        "labels": sorted(getattr(cfg, "labels", ())),
        "ignore_globs": list(getattr(cfg, "ignore_globs", ())),
        "cpu_small_threshold": getattr(cfg, "cpu_small_threshold", None),
        "allowlists": allowlists,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def load_cache() -> dict[str, dict]:
    """Load the scan result cache from disk."""
    path = _cache_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        return data
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(cache: dict[str, dict]) -> None:
    """Save the scan result cache to disk, pruning stale entries."""
    now = time.time()
    pruned = {
        k: v for k, v in cache.items()
        if now - v.get("ts", 0) < _MAX_CACHE_AGE_SECONDS
    }
    # Keep only the most recent entries
    if len(pruned) > _MAX_ENTRIES:
        sorted_items = sorted(pruned.items(), key=lambda kv: kv[1].get("ts", 0), reverse=True)
        pruned = dict(sorted_items[:_MAX_ENTRIES])

    path = _cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(json.dumps(pruned, indent=0), encoding="utf-8")
    except OSError:
        pass  # non-fatal


def cache_lookup(cache: dict[str, dict], text: str, signature: str | None = None) -> dict | None:
    """Look up cached scan results for a text/config payload.

    Returns the cached entry if found, None otherwise.
    """
    key = _content_hash(text, signature)
    entry = cache.get(key)
    if entry is None:
        return None
    if entry.get("hash") != key:
        return None
    if entry.get("signature") != signature:
        return None
    return entry


def cache_store(
    cache: dict[str, dict],
    text: str,
    secret_clean: bool,
    pii_clean: bool,
    signature: str | None = None,
) -> None:
    """Store scan results in the cache."""
    key = _content_hash(text, signature)
    cache[key] = {
        "hash": key,
        "signature": signature,
        "secret_clean": secret_clean,
        "pii_clean": pii_clean,
        "ts": time.time(),
    }
