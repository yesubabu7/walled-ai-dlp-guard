"""Recover the real name of an uploaded file when the upload request doesn't carry it.

ChatGPT reserves an upload URL before saying which file it is, and PUTs the bytes to
".../raw". Windows records files chosen in a file picker under Recent Items
(%APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk). We resolve the newest shortcuts and pick the
target whose contents are identical to the uploaded bytes, so the name is verified, not guessed.
"""

import hashlib
import os
import struct
import time
from pathlib import Path

RECENT_DIR = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent"
WINDOW_S = 600
MAX_LINKS = 40


def lnk_target(path: Path) -> str | None:
    """Local target path of a Windows .lnk (MS-SHLLINK LinkInfo), or None."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 0x4C or data[:4] != b"\x4c\x00\x00\x00":
        return None
    flags = struct.unpack_from("<I", data, 0x14)[0]
    offset = 0x4C
    if flags & 0x1:  # HasLinkTargetIDList
        offset += 2 + struct.unpack_from("<H", data, offset)[0]
    if not flags & 0x2:  # HasLinkInfo
        return None
    info = offset
    header_size = struct.unpack_from("<I", data, info + 4)[0]
    if header_size >= 0x24:
        unicode_off = struct.unpack_from("<I", data, info + 0x1C)[0]
        if unicode_off:
            start = info + unicode_off
            end = data.find(b"\x00\x00", start)
            while end != -1 and (end - start) % 2:
                end = data.find(b"\x00\x00", end + 1)
            if end != -1:
                return data[start:end].decode("utf-16-le", errors="ignore") or None
    base_off = struct.unpack_from("<I", data, info + 0x10)[0]
    if not base_off:
        return None
    start = info + base_off
    end = data.find(b"\x00", start)
    return data[start:end].decode("mbcs" if os.name == "nt" else "latin-1", errors="ignore") or None


def find_recent_file(content: bytes, recent_dir: Path = RECENT_DIR, now: float | None = None) -> str | None:
    """Name of a recently opened file whose contents equal `content`."""
    if not content or not recent_dir.is_dir():
        return None
    now = time.time() if now is None else now
    links = sorted((p for p in recent_dir.glob("*.lnk") if now - p.stat().st_mtime < WINDOW_S),
                   key=lambda p: p.stat().st_mtime, reverse=True)[:MAX_LINKS]
    digest = hashlib.sha256(content).digest()
    for link in links:
        target = lnk_target(link)
        if not target:
            continue
        try:
            file = Path(target)
            if file.is_file() and file.stat().st_size == len(content) and \
                    hashlib.sha256(file.read_bytes()).digest() == digest:
                return file.name
        except OSError:
            continue
    return None
