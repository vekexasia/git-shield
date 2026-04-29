from types import SimpleNamespace

import pytest

from git_shield.cuda import has_cuda, resolve_device


def _ok(stdout="Tesla T4\n", code=0):
    def runner(*_a, **_kw):
        return SimpleNamespace(stdout=stdout, stderr="", returncode=code)
    return runner


def test_has_cuda_false_when_smi_missing():
    assert not has_cuda(which=lambda _: None)


def test_has_cuda_true_when_smi_lists_gpu():
    assert has_cuda(runner=_ok(), which=lambda _: "/usr/bin/nvidia-smi")


def test_has_cuda_false_when_smi_empty():
    assert not has_cuda(runner=_ok(stdout=""), which=lambda _: "/x")


def test_has_cuda_false_on_nonzero():
    assert not has_cuda(runner=_ok(code=42), which=lambda _: "/x")


def test_resolve_device_passthrough_for_cpu():
    assert resolve_device("cpu", "fail", 100, 1024, cuda_available=False) == ("cpu", "ok")


def test_resolve_device_cuda_available():
    assert resolve_device("cuda", "skip", 100, 1024, cuda_available=True) == ("cuda", "ok")


def test_resolve_device_fail_policy_returns_force():
    dev, reason = resolve_device("cuda", "fail", 100, 1024, cuda_available=False)
    assert dev == "cuda" and reason == "force"


def test_resolve_device_skip_policy_returns_none():
    assert resolve_device("cuda", "skip", 100, 1024, cuda_available=False) == (None, "no-cuda-skip")


def test_resolve_device_cpu_small_under_threshold():
    assert resolve_device("cuda", "cpu-small", 500, 1024, cuda_available=False) == (
        "cpu",
        "cpu-fallback-small",
    )


def test_resolve_device_cpu_small_over_threshold():
    assert resolve_device("cuda", "cpu-small", 5000, 1024, cuda_available=False) == (
        None,
        "no-cuda-too-big",
    )


def test_resolve_device_unknown_policy():
    with pytest.raises(ValueError):
        resolve_device("cuda", "wat", 100, 1024, cuda_available=False)
