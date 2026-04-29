from __future__ import annotations

import fnmatch
import re
import subprocess
from dataclasses import dataclass


_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass(frozen=True)
class AddedLine:
    path: str
    text: str
    line: int = 0  # 1-based new-file line; 0 if unknown


@dataclass(frozen=True)
class FileChange:
    path: str
    added_text: str
    added_lines: frozenset[int]


def _path_ignored(path: str, ignore_globs: tuple[str, ...]) -> bool:
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch(name, g) for g in ignore_globs)


def parse_added_lines(
    diff_text: str,
    ignore_globs: tuple[str, ...] = (),
) -> list[AddedLine]:
    """Extract added lines from a unified git diff, tagged with new-file line numbers.

    Skips:
      - diff metadata (`+++`/`---`)
      - hunks for files matching `ignore_globs`
      - hunks marked `Binary files ... differ`
    """
    current_path = "<unknown>"
    skip_current = False
    new_line_no = 0
    lines: list[AddedLine] = []

    for raw in diff_text.splitlines():
        if raw.startswith("diff --git "):
            current_path = "<unknown>"
            skip_current = False
            new_line_no = 0
            continue
        if raw.startswith("+++ b/"):
            current_path = raw[6:]
            skip_current = _path_ignored(current_path, ignore_globs)
            continue
        if raw.startswith("+++ "):
            current_path = raw[4:]
            skip_current = _path_ignored(current_path, ignore_globs)
            continue
        if raw.startswith("Binary files "):
            skip_current = True
            continue
        if skip_current:
            continue
        m = _HUNK_RE.match(raw)
        if m:
            new_line_no = int(m.group(1))
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            lines.append(AddedLine(current_path, raw[1:], new_line_no))
            new_line_no += 1
            continue
        if raw.startswith(" "):
            new_line_no += 1
            continue
        # `-` deletions and `\ No newline ...` markers do not advance the new-file counter.

    return lines


def added_text_by_file(diff_text: str, ignore_globs: tuple[str, ...] = ()) -> dict[str, str]:
    files: dict[str, list[str]] = {}
    for line in parse_added_lines(diff_text, ignore_globs):
        files.setdefault(line.path, []).append(line.text)
    return {path: "\n".join(lines) for path, lines in files.items()}


def parse_file_changes(diff_text: str, ignore_globs: tuple[str, ...] = ()) -> dict[str, FileChange]:
    """Group `parse_added_lines` output by file, exposing both joined added text
    and the set of new-file line numbers that were added."""
    grouped: dict[str, list[AddedLine]] = {}
    for line in parse_added_lines(diff_text, ignore_globs):
        grouped.setdefault(line.path, []).append(line)
    return {
        path: FileChange(
            path=path,
            added_text="\n".join(item.text for item in items),
            added_lines=frozenset(item.line for item in items if item.line),
        )
        for path, items in grouped.items()
    }


def added_text(diff_text: str, ignore_globs: tuple[str, ...] = ()) -> str:
    """Return added text with lightweight file markers."""
    chunks: list[str] = []
    for path, text in added_text_by_file(diff_text, ignore_globs).items():
        chunks.append(f"FILE: {path}\n{text}")
    return "\n".join(chunks)


def staged_diff(cwd: str | None = None, runner=subprocess.run) -> str:
    proc = runner(
        ["git", "diff", "--cached", "--unified=0", "--no-color", "--text", "--no-ext-diff"],
        text=True,
        capture_output=True,
        errors="replace",
        cwd=cwd,
        check=False,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout


def git_diff(
    base: str,
    head: str = "HEAD",
    cwd: str | None = None,
    runner=subprocess.run,
) -> str:
    """Return git diff for a ref range; empty string if base/head missing."""
    proc = runner(
        ["git", "diff", "--unified=0", "--no-color", "--text", "--no-ext-diff", f"{base}..{head}"],
        text=True,
        capture_output=True,
        errors="replace",
        cwd=cwd,
        check=False,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout


def merge_base(base: str, head: str, runner=subprocess.run) -> str | None:
    proc = runner(
        ["git", "merge-base", base, head],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    out = proc.stdout.strip()
    return out or None


def diff_with_fallback(
    base: str,
    head: str = "HEAD",
    cwd: str | None = None,
    runner=subprocess.run,
) -> str:
    """git_diff but try a merge-base if the direct ref pair is missing."""
    direct = git_diff(base, head, cwd, runner=runner)
    if direct:
        return direct
    mb = merge_base(base, head, runner=runner)
    if mb:
        return git_diff(mb, head, cwd, runner=runner)
    return ""


def show_blob(
    ref: str,
    path: str,
    cwd: str | None = None,
    runner=subprocess.run,
) -> str | None:
    """Return the file contents at `ref:path`, or None if missing/binary/unreadable."""
    proc = runner(
        ["git", "show", f"{ref}:{path}"],
        text=True,
        capture_output=True,
        errors="replace",
        cwd=cwd,
        check=False,
    )
    if proc.returncode != 0:
        return None
    if "\0" in proc.stdout:
        return None
    return proc.stdout
