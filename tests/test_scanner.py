import io
import zipfile

import pytest

from agent.scanner import contains_marker, detect_kind, ocr_available, scan_file, scan_text

needs_ocr = pytest.mark.skipif(not ocr_available(), reason="Tesseract not installed")


@pytest.mark.parametrize("text", [
    "WALLED_SENSITIVE",
    "please summarise: walled_sensitive data",
    "WALLED SENSITIVE",
    "Walled-Sensitive",
    "WALLED_\nSENSITIVE",
    "WALLED_5ENSITIVE",  # typical OCR confusion
])
def test_marker_variants_match(text):
    assert contains_marker(text)


@pytest.mark.parametrize("text", ["", "walled garden", "SENSITIVE", "WALLED", "hello world"])
def test_clean_text_does_not_match(text):
    assert not contains_marker(text)


def test_scan_text_gives_snippet():
    result = scan_text("Here is my doc. Classification: WALLED_SENSITIVE. Thanks!")
    assert result.found and "WALLED_SENSITIVE" in result.snippet


def read(samples, name):
    return (samples / name).read_bytes()


@pytest.mark.parametrize("name, kind, where", [
    ("secret_note.txt", "text", "file text"),
    ("secret_report.pdf", "pdf", "page 1 text"),
])
def test_sensitive_text_and_pdf(samples, name, kind, where):
    r = scan_file(name, "", read(samples, name))
    assert (r.found, r.kind, r.where) == (True, kind, where)


@needs_ocr
@pytest.mark.parametrize("name, where", [
    ("secret_screenshot.png", "OCR"),
    ("secret_dark_mode.jpg", "OCR"),
    ("secret_scanned.pdf", "image on page 1 (OCR)"),
])
def test_ocr_finds_marker_in_images_and_scanned_pdfs(samples, name, where):
    r = scan_file(name, "", read(samples, name))
    assert r.found and r.where == where


@pytest.mark.parametrize("name", ["clean_note.txt", "clean_report.pdf",
                                  pytest.param("clean_screenshot.png", marks=needs_ocr)])
def test_clean_files_pass(samples, name):
    r = scan_file(name, "", read(samples, name))
    assert not r.found and r.scanned


def test_office_documents_are_scanned():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", "<w:t>Budget</w:t><w:t>WALLED_SENSITIVE</w:t>")
    r = scan_file("plan.docx", "", buf.getvalue())
    assert r.found and r.kind == "office"


def test_unknown_binary_is_reported_unscanned():
    r = scan_file("tool.exe", "", b"MZ\x00\x00\x03\x00\x00\x00" * 100)
    assert not r.found and not r.scanned and r.kind == "unknown"


def test_corrupt_pdf_is_unscanned_not_crash():
    r = scan_file("broken.pdf", "", b"%PDF-1.7 garbage")
    assert not r.found and not r.scanned and r.kind == "pdf"


def test_detect_kind_by_content_not_extension(samples):
    assert detect_kind("renamed.txt", "", read(samples, "secret_report.pdf")) == "pdf"
    assert detect_kind("photo.pdf", "", read(samples, "secret_screenshot.png")) == "image"
