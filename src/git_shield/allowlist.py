from __future__ import annotations

import re
from pathlib import Path

DEFAULT_ALLOW_PATTERNS = [
    r"(?i)^[^@\s]+@example\.(?:com|org|net)$",
    r"(?i)^[^@\s]+@test\.(?:com|org|net)$",
    r"(?i)^test@admin\.com$",
    r"(?i)^owner\d*@test\.com$",
    r"(?i)^user\d*@test\.com$",
    r"(?i)^lone@test\.com$",
    r"(?i)^[abc]@b\.com$",
    r"(?i)^git@github\.com$",
    r"(?i)^[^@\s]+@users\.noreply\.github\.com$",
]


def load_patterns(paths: list[Path] | None = None) -> list[re.Pattern[str]]:
    patterns = [re.compile(pattern) for pattern in DEFAULT_ALLOW_PATTERNS]
    for path in paths or []:
        if not path.exists():
            continue
        for raw in path.read_text(errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(re.compile(line))
    return patterns


def allowed(value: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(value) for pattern in patterns)
