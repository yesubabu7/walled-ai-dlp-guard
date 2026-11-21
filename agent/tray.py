"""Optional system-tray icon: shows the agent is running and how many checks it has done."""

import logging
import os
import sys
import threading
import webbrowser
from pathlib import Path

from PIL import Image, ImageDraw

log = logging.getLogger("walled_dlp.tray")


def _icon_image(color=(37, 99, 235, 255)) -> Image.Image:
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.polygon([(32, 4), (58, 14), (54, 40), (32, 60), (10, 40), (6, 14)], fill=color)
    draw.rectangle([22, 28, 42, 46], fill=(255, 255, 255, 255))             # padlock body
    draw.arc([24, 16, 40, 34], 180, 360, fill=(255, 255, 255, 255), width=4)  # shackle
    return img


class Tray:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.checks = 0
        self.flagged = 0
        self._icon = None

    def title(self) -> str:
        return f"Walled DLP Guard - {self.checks} checks, {self.flagged} flagged"

    def start(self) -> None:
        import pystray

        menu = pystray.Menu(
            pystray.MenuItem(lambda _i: self.title(), None, enabled=False),
            pystray.MenuItem("Open log", lambda: self.open_log()),
        )
        self._icon = pystray.Icon("walled-dlp-guard", _icon_image(), self.title(), menu)
        threading.Thread(target=self._icon.run, name="tray", daemon=True).start()

    def record(self, flagged: bool) -> None:
        self.checks += 1
        self.flagged += int(flagged)
        if self._icon is not None:
            self._icon.title = self.title()
            self._icon.update_menu()

    def open_log(self) -> None:
        try:
            if sys.platform == "win32":
                os.startfile(self.log_path)  # noqa: S606 - our own log file
            else:
                webbrowser.open(self.log_path.as_uri())
        except OSError:
            log.exception("could not open log")

    def stop(self) -> None:
        if self._icon is not None:
            self._icon.stop()
