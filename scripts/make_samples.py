"""Generate demo/test files in samples/: each sensitive file has a clean twin.

    python scripts/make_samples.py
"""

from pathlib import Path

from fpdf import FPDF
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "samples"

SECRET_LINES = [
    "Q3 acquisition plan - internal only",
    "Classification: WALLED_SENSITIVE",
    "Target valuation and board notes follow.",
]
CLEAN_LINES = [
    "Team offsite agenda",
    "Classification: public",
    "Lunch at 1pm, demos at 3pm.",
]


def font(size: int):
    for name in ("arialbd.ttf", "arial.ttf", "DejaVuSans-Bold.ttf", "DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default(size)


def text_image(lines, path: Path, dark: bool = False) -> None:
    bg, fg = ((24, 24, 27), (240, 240, 240)) if dark else ((255, 255, 255), (20, 20, 20))
    img = Image.new("RGB", (1100, 320), bg)
    draw = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        draw.text((50, 50 + i * 80), line, fill=fg, font=font(44))
    img.save(path)


def text_pdf(lines, path: Path) -> None:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=16)
    for line in lines:
        pdf.cell(0, 12, line, new_x="LMARGIN", new_y="NEXT")
    pdf.output(str(path))


def scanned_pdf(lines, path: Path) -> None:
    """A PDF with no text layer - only a picture of the text, like a scanned document."""
    image_path = OUT / "_scan_page.png"
    text_image(lines, image_path)
    pdf = FPDF()
    pdf.add_page()
    pdf.image(str(image_path), x=10, y=20, w=190)
    pdf.output(str(path))
    image_path.unlink()


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "secret_note.txt").write_text("\n".join(SECRET_LINES) + "\n", encoding="utf-8")
    (OUT / "clean_note.txt").write_text("\n".join(CLEAN_LINES) + "\n", encoding="utf-8")
    text_pdf(SECRET_LINES, OUT / "secret_report.pdf")
    text_pdf(CLEAN_LINES, OUT / "clean_report.pdf")
    scanned_pdf(SECRET_LINES, OUT / "secret_scanned.pdf")
    text_image(SECRET_LINES, OUT / "secret_screenshot.png")
    text_image(SECRET_LINES, OUT / "secret_dark_mode.jpg", dark=True)
    text_image(CLEAN_LINES, OUT / "clean_screenshot.png")
    for p in sorted(OUT.iterdir()):
        print(f"{p.name:24} {p.stat().st_size:>8} bytes")


if __name__ == "__main__":
    main()
