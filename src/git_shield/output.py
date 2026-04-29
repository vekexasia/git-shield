"""Colored output, verbosity control, progress, and JSON serialization."""

from __future__ import annotations

import json
import sys
import time
import threading
from dataclasses import asdict, dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_CLEAN = 0
EXIT_SECRETS = 2
EXIT_PII = 3
EXIT_BOTH = 4
EXIT_ERROR = 1

# ---------------------------------------------------------------------------
# Color support
# ---------------------------------------------------------------------------

_COLOR_SUPPORT = hasattr(sys.stderr, "isatty") and sys.stderr.isatty()

_RESET = "\033[0m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _c(code: str, text: str) -> str:
    if not _COLOR_SUPPORT:
        return text
    return f"{code}{text}{_RESET}"


# ---------------------------------------------------------------------------
# Verbosity
# ---------------------------------------------------------------------------

_quiet = False
_verbose = False


def set_verbosity(*, quiet: bool = False, verbose: bool = False) -> None:
    global _quiet, _verbose
    _quiet = quiet
    _verbose = verbose


def is_quiet() -> bool:
    return _quiet


def is_verbose() -> bool:
    return _verbose


# ---------------------------------------------------------------------------
# Core print helpers
# ---------------------------------------------------------------------------

_PREFIX = "[git-shield]"


def _print(msg: str) -> None:
    print(f"{_PREFIX} {msg}", file=sys.stderr)


def info(msg: str) -> None:
    if _quiet:
        return
    _print(msg)


def success(msg: str) -> None:
    if _quiet:
        return
    _print(_c(_GREEN, msg))


def warn(msg: str) -> None:
    _print(_c(_YELLOW, f"warning: {msg}"))


def error(msg: str) -> None:
    _print(_c(_RED, msg))


def detail(msg: str) -> None:
    """Indented detail line (e.g. per-finding output)."""
    if _quiet:
        return
    _print(f"  {msg}")


def blocked(msg: str) -> None:
    _print(_c(_RED + _BOLD, msg))


# ---------------------------------------------------------------------------
# Progress spinner
# ---------------------------------------------------------------------------

class Spinner:
    """Minimal stderr spinner for long-running operations."""

    _FRAMES = "|/-\\"

    def __init__(self, message: str = "Scanning...") -> None:
        self._message = message
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if _quiet or not _COLOR_SUPPORT:
            _print(f"{self._message}")
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = self._FRAMES[i % len(self._FRAMES)]
            sys.stderr.write(f"\r{_PREFIX} {_c(_CYAN, frame)} {self._message}")
            sys.stderr.flush()
            i += 1
            self._stop.wait(0.1)

    def stop(self, final: str | None = None) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=0.5)
        if _COLOR_SUPPORT and not _quiet:
            sys.stderr.write("\r" + " " * (len(self._message) + 20) + "\r")
            sys.stderr.flush()
        if final:
            info(final)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def write_json(payload: Any) -> None:
    """Write JSON to stdout (for --json mode)."""
    print(json.dumps(payload, indent=2))


def findings_json(findings: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    """Wrap a list of findings in a standard JSON envelope."""
    return {
        "ok": len(findings) == 0,
        "kind": kind,
        "count": len(findings),
        "findings": findings,
    }
