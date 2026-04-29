from __future__ import annotations

import shutil
import subprocess


def has_cuda(runner=subprocess.run, which=shutil.which) -> bool:
    """Best-effort CUDA detection without importing torch.

    Returns True if `nvidia-smi` is on PATH and reports a device successfully.
    """
    if which("nvidia-smi") is None:
        return False
    try:
        proc = runner(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
    return proc.returncode == 0 and bool(proc.stdout.strip())


def resolve_device(
    requested: str,
    policy: str,
    diff_bytes: int,
    cpu_small_threshold: int,
    cuda_available: bool,
) -> tuple[str | None, str]:
    """Decide which device to actually use.

    Returns (device, reason). device is None when the run should be skipped.
    Policies (when CUDA is requested but missing):
      - 'fail'     -> return ('cuda', 'force') so caller errors out via OPF
      - 'skip'     -> ('', 'no-cuda-skip') with device=None
      - 'cpu-small'-> 'cpu' if diff small enough, else None for skip
    For non-cuda requests, always returns the requested device.
    """
    if requested != "cuda" or cuda_available:
        return requested, "ok"
    if policy == "fail":
        return "cuda", "force"
    if policy == "skip":
        return None, "no-cuda-skip"
    if policy == "cpu-small":
        if diff_bytes <= cpu_small_threshold:
            return "cpu", "cpu-fallback-small"
        return None, "no-cuda-too-big"
    raise ValueError(f"unknown cuda_policy: {policy}")
