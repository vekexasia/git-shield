import pytest

from git_shield.init_config import write_starter_files


def test_write_starter_files(tmp_path):
    written = write_starter_files(tmp_path)
    assert tmp_path / "git-shield.toml" in written
    assert tmp_path / ".pii-allowlist" in written
    assert "gitleaks_bin" in (tmp_path / "git-shield.toml").read_text()


def test_write_starter_files_refuses_overwrite(tmp_path):
    write_starter_files(tmp_path)
    with pytest.raises(FileExistsError):
        write_starter_files(tmp_path)
