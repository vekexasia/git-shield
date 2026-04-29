from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .scanner import EMAIL_LABELS, PERSON_LABELS, PHONE_LABELS, SECRET_LABELS

DEFAULT_LABELS: set[str] = EMAIL_LABELS | PHONE_LABELS | PERSON_LABELS | SECRET_LABELS

DEFAULT_IGNORE_GLOBS: tuple[str, ...] = (
    "*.lock",
    "*.lockb",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.webp",
    "*.pdf",
    "*.zip",
    "*.tar",
    "*.tgz",
    "*.gz",
    "*.bin",
    "*.exe",
    "*.dll",
    "*.so",
    "*.dylib",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.ico",
    ".pii-allowlist",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Cargo.lock",
    "uv.lock",
)


@dataclass(frozen=True)
class Config:
    device: str = "cuda"
    cuda_policy: str = "cpu-small"  # one of: fail, skip, cpu-small
    backend: str = "opf"  # one of: opf, gliner
    opf_bin: str = "opf"
    gitleaks_bin: str = "gitleaks"
    timeout_seconds: int = 180
    max_bytes_per_chunk: int = 64 * 1024
    max_total_bytes: int = 2 * 1024 * 1024
    labels: frozenset[str] = field(default_factory=lambda: frozenset(DEFAULT_LABELS))
    ignore_globs: tuple[str, ...] = DEFAULT_IGNORE_GLOBS
    cpu_small_threshold: int = 16 * 1024
    allowlist_paths: tuple[Path, ...] = ()


def load_config(path: Path | None) -> Config:
    if path is None or not path.exists():
        return Config()
    raw = tomllib.loads(path.read_text())
    section = raw.get("git_shield", raw.get("privacy_prepush", raw))
    return Config(
        device=section.get("device", "cuda"),
        backend=section.get("backend", "opf"),
        opf_bin=section.get("opf_bin", "opf"),
        gitleaks_bin=section.get("gitleaks_bin", "gitleaks"),
        timeout_seconds=int(section.get("timeout_seconds", 180)),
        max_bytes_per_chunk=int(section.get("max_bytes_per_chunk", 64 * 1024)),
        max_total_bytes=int(section.get("max_total_bytes", 2 * 1024 * 1024)),
        labels=frozenset(section.get("labels", list(DEFAULT_LABELS))),
        ignore_globs=tuple(section.get("ignore_globs", DEFAULT_IGNORE_GLOBS)),
        cuda_policy=section.get("cuda_policy", "cpu-small"),
        cpu_small_threshold=int(section.get("cpu_small_threshold", 16 * 1024)),
        allowlist_paths=tuple(Path(p) for p in section.get("allowlist_paths", [])),
    )
