from types import SimpleNamespace

from git_shield.prepush import PushRef, parse_prepush_stdin, resolve_base, ZERO


def test_parse_prepush_stdin_basic():
    text = (
        "refs/heads/main aaa refs/heads/main bbb\n"
        "refs/heads/feat ccc refs/heads/feat 0000000000000000000000000000000000000000\n"
    )
    refs = parse_prepush_stdin(text)
    assert len(refs) == 2
    assert refs[0] == PushRef("refs/heads/main", "aaa", "refs/heads/main", "bbb")
    assert refs[1].is_new_branch
    assert not refs[1].is_delete


def test_parse_prepush_stdin_ignores_blank_and_malformed():
    text = "\n   \nthree tokens only\n"
    assert parse_prepush_stdin(text) == []


def test_pushref_is_delete():
    ref = PushRef("refs/heads/x", ZERO, "refs/heads/x", "abc")
    assert ref.is_delete


def test_resolve_base_delete_returns_none():
    ref = PushRef("refs/heads/x", ZERO, "refs/heads/x", "abc")
    assert resolve_base(ref) is None


def test_resolve_base_update_uses_remote_sha():
    ref = PushRef("refs/heads/x", "aaa", "refs/heads/x", "bbb")
    assert resolve_base(ref) == "bbb"


def test_resolve_base_new_branch_uses_merge_base():
    ref = PushRef("refs/heads/feat", "ccc", "refs/heads/feat", ZERO)

    def runner(*_a, **_kw):
        return SimpleNamespace(returncode=0, stdout="deadbeef\n", stderr="")

    assert resolve_base(ref, fallback="origin/main", runner=runner) == "deadbeef"


def test_resolve_base_new_branch_falls_back_when_merge_base_fails():
    ref = PushRef("refs/heads/feat", "ccc", "refs/heads/feat", ZERO)

    def runner(*_a, **_kw):
        return SimpleNamespace(returncode=1, stdout="", stderr="not found")

    assert resolve_base(ref, fallback="origin/main", runner=runner) == "origin/main"
