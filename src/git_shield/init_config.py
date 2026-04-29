from __future__ import annotations

from pathlib import Path

CONFIG_TEMPLATE = """[git_shield]
device = "cuda"
cuda_policy = "cpu-small" # fail | skip | cpu-small
cpu_small_threshold = 16384
opf_bin = "opf"
gitleaks_bin = "gitleaks"
timeout_seconds = 180
max_bytes_per_chunk = 65536
max_total_bytes = 2097152
labels = ["private_email", "private_phone", "private_person", "secret"]
ignore_globs = [
  "*.lock",
  "*.lockb",
  "*.png",
  "*.jpg",
  "*.jpeg",
  "*.gif",
  "*.webp",
  "*.pdf",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "poetry.lock",
  "Cargo.lock",
  "uv.lock",
]
allowlist_paths = [".pii-allowlist"]
"""

ALLOWLIST_TEMPLATE = r"""# One regex per line. Keep entries narrow.
# Examples:
# (?i)^support@example\.com$
# (?i)^user\d+@test\.com$
"""


def write_starter_files(root: Path, force: bool = False) -> list[Path]:
    written: list[Path] = []
    for path, content in [
        (root / "git-shield.toml", CONFIG_TEMPLATE),
        (root / ".pii-allowlist", ALLOWLIST_TEMPLATE),
    ]:
        if path.exists() and not force:
            raise FileExistsError(f"{path} exists; pass --force to overwrite")
        path.write_text(content)
        written.append(path)
    return written
