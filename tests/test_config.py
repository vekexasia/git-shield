from pathlib import Path

import pytest

from git_shield.config import Config, ConfigError, DEFAULT_LABELS, load_config


def test_load_missing_file_returns_defaults(tmp_path: Path):
    cfg = load_config(tmp_path / "nope.toml")
    assert cfg == Config()
    assert "private_email" in cfg.labels


def test_load_full_toml(tmp_path: Path):
    path = tmp_path / "git-shield.toml"
    path.write_text(
        '''
[git_shield]
device = "cpu"
opf_bin = "/usr/local/bin/opf"
timeout_seconds = 30
max_bytes_per_chunk = 1024
max_total_bytes = 4096
labels = ["private_email", "secret"]
ignore_globs = ["*.lock", "vendor/*"]
cuda_policy = "cpu-small"
cpu_small_threshold = 2048
allowlist_paths = ["/etc/p.txt"]
'''
    )
    cfg = load_config(path)
    assert cfg.device == "cpu"
    assert cfg.opf_bin == "/usr/local/bin/opf"
    assert cfg.timeout_seconds == 30
    assert cfg.max_bytes_per_chunk == 1024
    assert cfg.labels == frozenset({"private_email", "secret"})
    assert cfg.ignore_globs == ("*.lock", "vendor/*")
    assert cfg.cuda_policy == "cpu-small"
    assert cfg.cpu_small_threshold == 2048
    assert cfg.allowlist_paths == (Path("/etc/p.txt"),)


def test_default_labels_cover_required():
    assert {"private_email", "private_phone", "private_person", "secret"} <= DEFAULT_LABELS


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ('backend = "bad"', "backend"),
        ('cuda_policy = "sometimes"', "cuda_policy"),
        ('timeout_seconds = 0', "timeout_seconds"),
        ('labels = "private_email"', "labels"),
    ],
)
def test_load_config_validates_values(tmp_path: Path, body: str, message: str):
    path = tmp_path / "git-shield.toml"
    path.write_text(f"[git_shield]\n{body}\n")

    with pytest.raises(ConfigError, match=message):
        load_config(path)
