from types import SimpleNamespace

from git_shield.diff import (
    added_text,
    diff_with_fallback,
    git_diff,
    merge_base,
    parse_added_lines,
    parse_file_changes,
)


def test_parse_added_lines_ignores_metadata():
    diff = """diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1,2 @@
 unchanged
+real.person@gmail.com
"""
    lines = parse_added_lines(diff)
    assert [l.text for l in lines] == ["real.person@gmail.com"]
    assert lines[0].path == "a.txt"


def test_parse_added_lines_skips_ignored_path():
    diff = """diff --git a/yarn.lock b/yarn.lock
--- a/yarn.lock
+++ b/yarn.lock
@@ -0,0 +1 @@
+secret-looking-stuff
diff --git a/src/x.py b/src/x.py
--- a/src/x.py
+++ b/src/x.py
@@ -0,0 +1 @@
+keep-this
"""
    lines = parse_added_lines(diff, ignore_globs=("yarn.lock",))
    assert [l.text for l in lines] == ["keep-this"]


def test_parse_added_lines_skips_glob_extension():
    diff = """diff --git a/img.png b/img.png
--- a/img.png
+++ b/img.png
@@ -0,0 +1 @@
+binary-bytes-pretending
"""
    assert parse_added_lines(diff, ignore_globs=("*.png",)) == []


def test_parse_added_lines_tracks_new_file_line_numbers():
    diff = """diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1,2 +1,4 @@
 keep
-old
+new1
+new2
@@ -10,0 +12,1 @@
+far-down
"""
    lines = parse_added_lines(diff)
    assert [(l.text, l.line) for l in lines] == [
        ("new1", 2),
        ("new2", 3),
        ("far-down", 12),
    ]


def test_parse_file_changes_groups_by_path_with_added_lines():
    diff = """diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -0,0 +1,2 @@
+hello
+world
diff --git a/b.txt b/b.txt
--- a/b.txt
+++ b/b.txt
@@ -5,0 +6,1 @@
+later
"""
    changes = parse_file_changes(diff)
    assert set(changes) == {"a.txt", "b.txt"}
    assert changes["a.txt"].added_text == "hello\nworld"
    assert changes["a.txt"].added_lines == frozenset({1, 2})
    assert changes["b.txt"].added_lines == frozenset({6})


def test_parse_added_lines_skips_binary_marker():
    diff = """diff --git a/blob.bin b/blob.bin
Binary files a/blob.bin and b/blob.bin differ
"""
    assert parse_added_lines(diff) == []


def test_added_text_includes_file_markers():
    diff = """diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -0,0 +1 @@
+hello
"""
    assert added_text(diff) == "FILE: a.txt\nhello"


def test_git_diff_returns_empty_on_failure():
    def runner(*_a, **_kw):
        return SimpleNamespace(returncode=128, stdout="", stderr="bad rev")
    assert git_diff("origin/main", "HEAD", runner=runner) == ""


def test_git_diff_passes_through_stdout():
    def runner(*_a, **_kw):
        return SimpleNamespace(returncode=0, stdout="DIFF", stderr="")
    assert git_diff("a", "b", runner=runner) == "DIFF"


def test_merge_base_none_on_failure():
    def runner(*_a, **_kw):
        return SimpleNamespace(returncode=1, stdout="", stderr="")
    assert merge_base("a", "b", runner=runner) is None


def test_diff_with_fallback_uses_merge_base():
    calls = []

    def runner(args, **_kw):
        calls.append(args)
        if args[1] == "diff" and args[-1] == "origin/main..HEAD":
            return SimpleNamespace(returncode=128, stdout="", stderr="bad")
        if args[1] == "merge-base":
            return SimpleNamespace(returncode=0, stdout="abc123\n", stderr="")
        if args[1] == "diff" and args[-1] == "abc123..HEAD":
            return SimpleNamespace(returncode=0, stdout="DIFF", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    assert diff_with_fallback("origin/main", "HEAD", runner=runner) == "DIFF"
    assert any(a[1] == "merge-base" for a in calls)
