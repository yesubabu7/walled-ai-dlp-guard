import struct
import time

from agent.recent import find_recent_file, lnk_target


def make_lnk(target: str) -> bytes:
    """Minimal Shell Link with a LinkInfo carrying a Unicode local base path."""
    header = bytearray(0x4C)
    header[:4] = b"\x4c\x00\x00\x00"
    struct.pack_into("<I", header, 0x14, 0x2)  # HasLinkInfo
    path_u = target.encode("utf-16-le") + b"\x00\x00"
    path_a = target.encode("latin-1", "replace") + b"\x00"
    header_size = 0x24
    base_off = header_size
    unicode_off = base_off + len(path_a)
    size = unicode_off + len(path_u)
    info = struct.pack("<IIIIIIIII", size, header_size, 1, 0, base_off, 0, 0, 0, unicode_off)
    return bytes(header) + info + path_a + path_u


def test_lnk_target(tmp_path):
    link = tmp_path / "a.lnk"
    link.write_bytes(make_lnk(r"C:\Users\me\Documents\secret_note.txt"))
    assert lnk_target(link) == r"C:\Users\me\Documents\secret_note.txt"


def test_find_recent_file_by_content(tmp_path):
    recent = tmp_path / "Recent"
    recent.mkdir()
    real = tmp_path / "secret_note.txt"
    real.write_bytes(b"note WALLED_SENSITIVE")
    other = tmp_path / "other.txt"
    other.write_bytes(b"something else entirely")
    (recent / "other.lnk").write_bytes(make_lnk(str(other)))
    (recent / "secret_note.lnk").write_bytes(make_lnk(str(real)))
    assert find_recent_file(b"note WALLED_SENSITIVE", recent, now=time.time()) == "secret_note.txt"
    assert find_recent_file(b"no such content", recent, now=time.time()) is None


def test_old_shortcuts_ignored(tmp_path):
    recent = tmp_path / "Recent"
    recent.mkdir()
    real = tmp_path / "x.txt"
    real.write_bytes(b"abc")
    (recent / "x.lnk").write_bytes(make_lnk(str(real)))
    assert find_recent_file(b"abc", recent, now=time.time() + 3600) is None
