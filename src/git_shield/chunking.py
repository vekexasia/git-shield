from __future__ import annotations

DEFAULT_CHUNK_BYTES = 64 * 1024


def chunk_text(text: str, max_bytes: int = DEFAULT_CHUNK_BYTES) -> list[str]:
    """Split `text` into chunks no larger than `max_bytes` (UTF-8 measured).

    Splits on newline boundaries when possible; falls back to hard slicing for
    pathological single lines so that ARG_MAX cannot be exceeded.
    """
    return [chunk for _, chunk in chunk_text_offsets(text, max_bytes)]


def chunk_text_offsets(text: str, max_bytes: int = DEFAULT_CHUNK_BYTES) -> list[tuple[int, str]]:
    """Split text and keep each chunk's starting character offset."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if len(text.encode("utf-8")) <= max_bytes:
        return [(0, text)] if text else []

    chunks: list[tuple[int, str]] = []
    buf: list[str] = []
    size = 0
    buf_start = 0
    offset = 0
    for line in text.splitlines(keepends=True):
        encoded = line.encode("utf-8")
        if len(encoded) > max_bytes:
            if buf:
                chunks.append((buf_start, "".join(buf)))
                buf, size = [], 0
            for part_offset, part in _hard_split_offsets(line, max_bytes):
                chunks.append((offset + part_offset, part))
            offset += len(line)
            buf_start = offset
            continue
        if size + len(encoded) > max_bytes:
            chunks.append((buf_start, "".join(buf)))
            buf, size = [], 0
            buf_start = offset
        buf.append(line)
        size += len(encoded)
        offset += len(line)
    if buf:
        chunks.append((buf_start, "".join(buf)))
    return chunks


def _hard_split(line: str, max_bytes: int) -> list[str]:
    return [part for _, part in _hard_split_offsets(line, max_bytes)]


def _hard_split_offsets(line: str, max_bytes: int) -> list[tuple[int, str]]:
    encoded = line.encode("utf-8")
    out: list[tuple[int, str]] = []
    char_offset = 0
    for i in range(0, len(encoded), max_bytes):
        part = encoded[i : i + max_bytes].decode("utf-8", errors="replace")
        out.append((char_offset, part))
        char_offset += len(part)
    return out
