"""Detect the WALLED_SENSITIVE marker in prompts and uploaded files.

Supported content:
  * text           - any decodable text file (txt, md, csv, json, code, ...)
  * PDF            - text layer via pypdf, plus OCR of embedded images (scanned PDFs)
  * images         - OCR via Tesseract (PNG, JPEG, GIF, BMP, TIFF, WEBP)
  * Office (bonus) - docx/xlsx/pptx are zip files of XML; their text is scanned too

Matching is tolerant on purpose (a DLP tool should prefer recall): case-insensitive and
ignoring spaces, underscores, line breaks and common OCR confusions (0->O, 1->I, 5->S),
so "walled_sensitive", "WALLED SENSITIVE" or an OCR'd "WALLED_5ENSITIVE" all match.
"""

import io
import logging
import os
import re
import shutil
import zipfile
from dataclasses import dataclass

log = logging.getLogger("walled_dlp.scanner")

MARKER = "WALLED_SENSITIVE"
_MARKER_KEY = "WALLEDSENSITIVE"
_OCR_FIXES = str.maketrans({"0": "O", "1": "I", "5": "S", "|": "I", "$": "S"})
_NON_ALNUM = re.compile(r"[^A-Z0-9]")
_EXACT = re.compile(r"walled[\s_\-]*sensitive", re.IGNORECASE)

MAX_PDF_PAGES = 200
MAX_PDF_IMAGES = 20
MAX_ZIP_XML_BYTES = 20 * 1024 * 1024

IMAGE_MAGIC = {
    b"\x89PNG": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"GIF8": "GIF",
    b"BM": "BMP",
    b"II*\x00": "TIFF",
    b"MM\x00*": "TIFF",
}


@dataclass
class ScanResult:
    found: bool
    kind: str            # "text" | "pdf" | "image" | "office" | "unknown"
    scanned: bool        # False when the content could not be inspected
    where: str = ""      # e.g. "page 2 text", "OCR", "embedded image on page 1"
    snippet: str = ""    # short context around the marker (shown to the user, never logged)
    note: str = ""       # why something could not be scanned


def normalize(text: str) -> str:
    return _NON_ALNUM.sub("", text.upper().translate(_OCR_FIXES))


def contains_marker(text: str) -> bool:
    return bool(text) and _MARKER_KEY in normalize(text)


def snippet_for(text: str, width: int = 40) -> str:
    match = _EXACT.search(text)
    if not match:
        return MARKER
    start, end = max(0, match.start() - width), min(len(text), match.end() + width)
    piece = " ".join(text[start:end].split())
    return ("..." if start else "") + piece + ("..." if end < len(text) else "")


def scan_text(text: str) -> ScanResult:
    if contains_marker(text):
        return ScanResult(True, "text", True, "prompt", snippet_for(text))
    return ScanResult(False, "text", True)


# ---------------------------------------------------------------- files

def detect_kind(name: str, mime: str, data: bytes) -> str:
    if data.startswith(b"%PDF"):
        return "pdf"
    if any(data.startswith(m) for m in IMAGE_MAGIC) or (data[:4] == b"RIFF" and data[8:12] == b"WEBP"):
        return "image"
    if data.startswith(b"PK\x03\x04"):
        return "office" if name.lower().endswith((".docx", ".xlsx", ".pptx", ".odt")) else "zip"
    if _looks_like_text(data):
        return "text"
    return "unknown"


def _looks_like_text(data: bytes) -> bool:
    sample = data[:4096]
    if not sample:
        return True
    if sample.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    if b"\x00" in sample:
        return False
    printable = sum(32 <= b < 127 or b in (9, 10, 13) or b >= 128 for b in sample)
    return printable / len(sample) > 0.9


def decode_text(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="ignore")
    return data.decode("utf-8-sig", errors="ignore")


def scan_file(name: str, mime: str, data: bytes) -> ScanResult:
    kind = detect_kind(name, mime, data)
    try:
        if kind == "text":
            text = decode_text(data)
            return _result(text, "text", "file text")
        if kind == "pdf":
            return _scan_pdf(data)
        if kind == "image":
            return _scan_image_bytes(data, "image", "OCR")
        if kind in ("office", "zip"):
            return _scan_zip_xml(data, kind)
    except Exception as exc:  # corrupt/unsupported content: report as unscanned, caller decides
        log.warning("could not scan %s (%s): %s", kind, mime, exc)
        return ScanResult(False, kind, False, note=f"could not read {kind}: {type(exc).__name__}")
    return ScanResult(False, kind, False, note="unsupported file type")


def _result(text: str, kind: str, where: str) -> ScanResult:
    if contains_marker(text):
        return ScanResult(True, kind, True, where, snippet_for(text))
    return ScanResult(False, kind, True)


def _scan_pdf(data: bytes) -> ScanResult:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted and not reader.decrypt(""):
        return ScanResult(False, "pdf", False, note="PDF is password-protected")

    pages = reader.pages[:MAX_PDF_PAGES]
    for number, page in enumerate(pages, start=1):
        text = page.extract_text() or ""
        if contains_marker(text):
            return ScanResult(True, "pdf", True, f"page {number} text", snippet_for(text))

    # Scanned PDFs have no text layer: OCR the embedded images.
    images_checked = 0
    for number, page in enumerate(pages, start=1):
        for image in page.images:
            if images_checked >= MAX_PDF_IMAGES:
                break
            images_checked += 1
            result = _scan_image_bytes(image.data, "pdf", f"image on page {number} (OCR)")
            if result.found:
                return result
    return ScanResult(False, "pdf", True)


def _scan_zip_xml(data: bytes, kind: str) -> ScanResult:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        budget = MAX_ZIP_XML_BYTES
        for info in archive.infolist():
            if not info.filename.endswith(".xml") or info.file_size > budget:
                continue
            budget -= info.file_size
            text = re.sub(r"<[^>]+>", " ", archive.read(info).decode("utf-8", errors="ignore"))
            if contains_marker(text):
                return ScanResult(True, kind, True, info.filename, snippet_for(text))
    return ScanResult(False, kind, True)


# ---------------------------------------------------------------- OCR

def find_tesseract() -> str | None:
    candidates = [
        os.environ.get("WALLED_TESSERACT", ""),
        shutil.which("tesseract") or "",
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
        "/usr/bin/tesseract",
        "/opt/homebrew/bin/tesseract",
        "/usr/local/bin/tesseract",
    ]
    return next((c for c in candidates if c and os.path.isfile(c)), None)


def ocr_available() -> bool:
    return find_tesseract() is not None


def _ocr_variants(image):
    """Yield progressively more aggressive preprocessing; stop at the first match."""
    from PIL import ImageOps

    gray = ImageOps.exif_transpose(image).convert("L")
    if gray.width < 1200:
        scale = 1200 / max(gray.width, 1)
        gray = gray.resize((int(gray.width * scale), int(gray.height * scale)))
    yield gray
    yield ImageOps.autocontrast(gray).point(lambda p: 255 if p > 140 else 0)
    yield ImageOps.invert(gray)  # light text on dark backgrounds


def _scan_image_bytes(data: bytes, kind: str, where: str) -> ScanResult:
    import pytesseract
    from PIL import Image

    tesseract = find_tesseract()
    if tesseract is None:
        return ScanResult(False, kind, False, note="OCR engine (Tesseract) not installed")
    pytesseract.pytesseract.tesseract_cmd = tesseract

    with Image.open(io.BytesIO(data)) as image:
        image.load()
        if getattr(image, "is_animated", False):
            image.seek(0)
        for variant in _ocr_variants(image):
            text = pytesseract.image_to_string(variant, config="--psm 6", timeout=30)
            if contains_marker(text):
                return ScanResult(True, kind, True, where, snippet_for(text))
    return ScanResult(False, kind, True)
