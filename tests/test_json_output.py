import io
import json
from contextlib import redirect_stdout

from git_shield.cli import main


def test_doctor_json(monkeypatch):
    monkeypatch.setattr(
        "git_shield.commands.doctor.collect_checks",
        lambda *_args, **_kwargs: [],
    )
    out = io.StringIO()
    with redirect_stdout(out):
        code = main(["doctor", "--json"])
    assert code == 0
    payload = json.loads(out.getvalue())
    assert payload["ok"] is True
    assert payload["checks"] == []


def test_status_json(tmp_path, monkeypatch):
    monkeypatch.setattr("git_shield.commands.status.collect_checks", lambda: [])
    repo = tmp_path / "repo"
    (repo / ".git" / "hooks").mkdir(parents=True)
    out = io.StringIO()
    with redirect_stdout(out):
        code = main(["status", "--repo", str(repo), "--json"])
    assert code == 0
    payload = json.loads(out.getvalue())
    assert payload["hooks"]["pre-commit"] == "missing"
    assert payload["hooks"]["pre-push"] == "missing"
