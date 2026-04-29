import pytest

from git_shield.chunking import chunk_text


def test_short_text_single_chunk():
    assert chunk_text("hello", max_bytes=1024) == ["hello"]


def test_empty_text_returns_empty_list():
    assert chunk_text("", max_bytes=1024) == []


def test_splits_on_newline_boundary():
    text = "a" * 50 + "\n" + "b" * 50 + "\n"
    chunks = chunk_text(text, max_bytes=60)
    assert all(len(c.encode("utf-8")) <= 60 for c in chunks)
    assert "".join(chunks) == text


def test_hard_split_on_oversized_line():
    text = "a" * 200
    chunks = chunk_text(text, max_bytes=64)
    assert len(chunks) >= 4
    assert all(len(c.encode("utf-8")) <= 64 for c in chunks)
    assert "".join(chunks) == text


def test_unicode_byte_aware():
    text = "é" * 100  # each is 2 bytes UTF-8
    chunks = chunk_text(text, max_bytes=20)
    assert all(len(c.encode("utf-8")) <= 20 for c in chunks)


def test_invalid_max_bytes():
    with pytest.raises(ValueError):
        chunk_text("x", max_bytes=0)
