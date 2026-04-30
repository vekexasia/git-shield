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


class ConfigError(ValueError):
    pass


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


def _string_list(section: dict, key: str, default: tuple[str, ...] | list[str]) -> list[str]:
    value = section.get(key, default)
    if not isinstance(value, list | tuple) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"git-shield config '{key}' must be a list of strings")
    return list(value)


def _positive_int(section: dict, key: str, default: int) -> int:
    value = section.get(key, default)
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"git-shield config '{key}' must be a positive integer") from exc
    if parsed <= 0:
        raise ConfigError(f"git-shield config '{key}' must be a positive integer")
    return parsed


def _string_value(section: dict, key: str, default: str) -> str:
    value = section.get(key, default)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"git-shield config '{key}' must be a non-empty string")
    return value


def load_config(path: Path | None) -> Config:
    if path is None or not path.exists():
        return Config()
    raw = tomllib.loads(path.read_text())
    section = raw.get("git_shield", raw.get("privacy_prepush", raw))
    if not isinstance(section, dict):
        raise ConfigError("git-shield config section must be a table")

    backend = _string_value(section, "backend", "opf")
    if backend not in {"opf", "gliner"}:
        raise ConfigError("git-shield config 'backend' must be one of: opf, gliner")
    cuda_policy = _string_value(section, "cuda_policy", "cpu-small")
    if cuda_policy not in {"fail", "skip", "cpu-small"}:
        raise ConfigError("git-shield config 'cuda_policy' must be one of: fail, skip, cpu-small")

    return Config(
        device=_string_value(section, "device", "cuda"),
        backend=backend,
        opf_bin=_string_value(section, "opf_bin", "opf"),
        gitleaks_bin=_string_value(section, "gitleaks_bin", "gitleaks"),
        timeout_seconds=_positive_int(section, "timeout_seconds", 180),
        max_bytes_per_chunk=_positive_int(section, "max_bytes_per_chunk", 64 * 1024),
        max_total_bytes=_positive_int(section, "max_total_bytes", 2 * 1024 * 1024),
        labels=frozenset(_string_list(section, "labels", list(DEFAULT_LABELS))),
        ignore_globs=tuple(_string_list(section, "ignore_globs", list(DEFAULT_IGNORE_GLOBS))),
        cuda_policy=cuda_policy,
        cpu_small_threshold=_positive_int(section, "cpu_small_threshold", 16 * 1024),
        allowlist_paths=tuple(Path(p) for p in _string_list(section, "allowlist_paths", [])),
    )
