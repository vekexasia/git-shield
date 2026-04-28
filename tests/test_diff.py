from privacy_prepush.diff import added_text, parse_added_lines


def test_parse_added_lines_ignores_metadata():
    diff = """diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1,2 @@
 unchanged
+real.person@gmail.com
+++ not metadata in content? nope this is metadata-like and ignored
"""
    lines = parse_added_lines(diff)
    assert lines == [] or lines[0].text == "real.person@gmail.com"
    assert all(not line.text.startswith("++") for line in lines)


def test_added_text_includes_file_markers():
    diff = """diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -0,0 +1 @@
+hello
"""
    assert added_text(diff) == "FILE: a.txt\nhello"
